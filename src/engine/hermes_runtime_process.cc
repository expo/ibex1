#include "hermes_runtime_internal.h"

// PATH_MAX / realpath live in <limits.h> on Linux; macOS pulls them in
// transitively. Spell it out so the realpath() path-resolution helpers build
// on Linux. @ref LLP 0008#sockets-dns-and-process
#include <limits.h>

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <csignal>
#include <fcntl.h>
#include <mutex>
#include <optional>
#include <poll.h>
#include <spawn.h>
#include <string>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>

#if defined(__APPLE__)
#include <TargetConditionals.h>
#include <crt_externs.h>
#else
extern "C" char** environ;
#endif

namespace {
extern "C" uint64_t ex_hermes_current_runtime_nonce();

// tvOS apps cannot create processes (the SDK marks fork/execve unavailable),
// so every child_process spawn there takes the existing fork-failure path.
pid_t s_forkChild() {
#if defined(__APPLE__) && TARGET_OS_TV
  errno = ENOSYS;
  return -1;
#else
  return fork();
#endif
}

void s_execChild(const char *path, char *const argv[], char *const envp[]) {
#if defined(__APPLE__) && TARGET_OS_TV
  (void)path;
  (void)argv;
  (void)envp;
#else
  execve(path, argv, envp);
#endif
}

// @ref LLP 0008#sockets-dns-and-process — a cancellable timeout watchdog for the
// SYNCHRONOUS child_process paths (ENG-23113: __exactExecSync /
// __exactSpawnSync). Its destructor cancels + JOINS the worker, so the worker
// thread can never outlive this object's frame (the old code detached a thread
// that captured stack `std::atomic<bool>`s BY REFERENCE — on a fast child it woke
// after the host function returned and read/wrote the freed frame, and for
// spawnSync could `kill(pid, SIGKILL)` an unrelated recycled PID). Once the child
// is reaped the main path calls cancelAndJoin(): the worker either already fired
// while the child was alive (a real timeout) or is cancelled before it can wake.
struct SyncTimeoutWatchdog {
  std::mutex mtx;
  std::condition_variable cv;
  bool finished = false;  // set by the main path to cancel the worker
  std::atomic<bool> timedOut{false};
  std::atomic<bool> childExited{false};
  std::thread worker;

  ~SyncTimeoutWatchdog() { cancelAndJoin(); }

  // Cancel the watchdog (so it will not fire) and join the worker. Idempotent —
  // the main path calls it once the child is reaped; the destructor is a no-op
  // second call on every early-exit / exception path.
  void cancelAndJoin() {
    {
      std::lock_guard<std::mutex> lk(mtx);
      finished = true;
    }
    cv.notify_all();
    if (worker.joinable()) worker.join();
  }
};

// Process handles are numeric at the JS boundary and therefore forgeable.
// Keep an unforgeable runtime nonce alongside principal/capability ownership;
// different runtimes commonly reuse the same principal ids.
struct SpawnedProcess {
  uint64_t runtimeNonce = 0;
  uint64_t owner = 0;
  std::string capability;
  pid_t pid = -1;
  int stdinFd = -1;
  int stdoutFd = -1;
  int stderrFd = -1;
  int ipcFd = -1;
  std::vector<int> extraFds;
  bool exited = false;
  // @ref LLP 0008#sockets-dns-and-process — Node's ChildProcess.ref()/unref()
  // controls whether the process keeps its owning runtime alive. Runtime
  // teardown may kill referenced children to
  // reclaim them, but an explicitly unref'ed child is intentionally orphaned
  // and must be allowed to finish independently.
  bool referenced = true;
  int exitCode = -1;
  int exitSignal = 0;
};

std::unordered_map<int, std::shared_ptr<SpawnedProcess>> s_spawnedProcesses;
uint64_t s_nextSpawnHandle = 1;
std::mutex s_spawnMutex;

std::optional<int> allocateSpawnHandleLocked() {
  if (s_nextSpawnHandle == 0 ||
      s_nextSpawnHandle > static_cast<uint64_t>(std::numeric_limits<int>::max())) {
    return std::nullopt;
  }
  return static_cast<int>(s_nextSpawnHandle++);
}

void closeSpawnedProcessFds(const std::shared_ptr<SpawnedProcess>& proc) {
  if (!proc) return;
  if (proc->stdinFd >= 0) close(proc->stdinFd);
  if (proc->stdoutFd >= 0) close(proc->stdoutFd);
  if (proc->stderrFd >= 0) close(proc->stderrFd);
  if (proc->ipcFd >= 0) close(proc->ipcFd);
  for (int fd : proc->extraFds) {
    if (fd >= 0) close(fd);
  }
  proc->stdinFd = proc->stdoutFd = proc->stderrFd = proc->ipcFd = -1;
  for (int& fd : proc->extraFds) fd = -1;
}

// A process-global, detached reaper prevents children intentionally orphaned
// by ChildProcess.unref() from becoming zombies when a Hermes runtime is
// destroyed while its native host process continues running. The state is
// deliberately process-lifetime storage: a detached worker must never observe
// function-static teardown during C++ global destruction.
struct UnreferencedSpawnReaper {
  std::mutex mutex;
  std::condition_variable cv;
  std::vector<pid_t> pids;
  bool workerStarted = false;
};

UnreferencedSpawnReaper& unreferencedSpawnReaper() {
  static auto* state = new UnreferencedSpawnReaper();
  return *state;
}

void runUnreferencedSpawnReaper(UnreferencedSpawnReaper* state) {
  for (;;) {
    std::vector<pid_t> candidates;
    {
      std::unique_lock<std::mutex> lock(state->mutex);
      state->cv.wait(lock, [state] { return !state->pids.empty(); });
      candidates = state->pids;
    }

    std::vector<pid_t> finished;
    for (pid_t pid : candidates) {
      int status = 0;
      pid_t result;
      do {
        result = waitpid(pid, &status, WNOHANG);
      } while (result < 0 && errno == EINTR);
      // ECHILD means another legitimate waiter already reaped it. Treat other
      // permanent waitpid errors as terminal too, avoiding a hot retry loop.
      if (result == pid || result < 0) finished.push_back(pid);
    }

    std::unique_lock<std::mutex> lock(state->mutex);
    for (pid_t pid : finished) {
      state->pids.erase(
          std::remove(state->pids.begin(), state->pids.end(), pid),
          state->pids.end());
    }
    if (!state->pids.empty()) {
      state->cv.wait_for(lock, std::chrono::milliseconds(50));
    }
  }
}

void reapUnreferencedSpawnEventually(pid_t pid) {
  if (pid <= 0) return;
  auto& state = unreferencedSpawnReaper();
  bool startWorker = false;
  {
    std::lock_guard<std::mutex> lock(state.mutex);
    if (std::find(state.pids.begin(), state.pids.end(), pid) == state.pids.end()) {
      state.pids.push_back(pid);
    }
    if (!state.workerStarted) {
      state.workerStarted = true;
      startWorker = true;
    }
  }
  if (startWorker) {
    try {
      std::thread(runUnreferencedSpawnReaper, &state).detach();
    } catch (...) {
      // Never allow a resource-exhaustion exception to escape the C teardown
      // ABI. A later enqueue retries worker creation; process exit still hands
      // the child to the OS reaper if this was the final runtime.
      std::lock_guard<std::mutex> lock(state.mutex);
      state.workerStarted = false;
    }
  }
  state.cv.notify_one();
}
}  // namespace

static void s_skipJsonWhitespace(const std::string& value, size_t& pos) {
  while (pos < value.size()) {
    char ch = value[pos];
    if (ch != ' ' && ch != '\n' && ch != '\r' && ch != '\t') break;
    pos++;
  }
}

static int s_jsonHex(char ch) {
  if (ch >= '0' && ch <= '9') return ch - '0';
  if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
  if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
  return -1;
}

static bool s_readJsonCodeUnit(const std::string& value, size_t& pos, uint32_t& out) {
  if (pos + 4 > value.size()) return false;
  out = 0;
  for (int i = 0; i < 4; ++i) {
    int nibble = s_jsonHex(value[pos++]);
    if (nibble < 0) return false;
    out = (out << 4) | static_cast<uint32_t>(nibble);
  }
  return true;
}

static void s_appendUtf8(std::string& out, uint32_t cp) {
  if (cp <= 0x7f) out.push_back(static_cast<char>(cp));
  else if (cp <= 0x7ff) {
    out.push_back(static_cast<char>(0xc0 | (cp >> 6)));
    out.push_back(static_cast<char>(0x80 | (cp & 0x3f)));
  } else if (cp <= 0xffff) {
    out.push_back(static_cast<char>(0xe0 | (cp >> 12)));
    out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3f)));
    out.push_back(static_cast<char>(0x80 | (cp & 0x3f)));
  } else {
    out.push_back(static_cast<char>(0xf0 | (cp >> 18)));
    out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3f)));
    out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3f)));
    out.push_back(static_cast<char>(0x80 | (cp & 0x3f)));
  }
}

static std::string s_parseJsonString(const std::string& value, size_t& pos) {
  std::string out;
  if (pos >= value.size() || value[pos] != '"') return out;
  ++pos;
  while (pos < value.size()) {
    char ch = value[pos++];
    if (ch == '\\' && pos < value.size()) {
      char escaped = value[pos++];
      if (escaped == 'b') out.push_back('\b');
      else if (escaped == 'f') out.push_back('\f');
      else if (escaped == 'n') out.push_back('\n');
      else if (escaped == 't') out.push_back('\t');
      else if (escaped == 'r') out.push_back('\r');
      else if (escaped == '"') out.push_back('"');
      else if (escaped == '\\') out.push_back('\\');
      else if (escaped == '/') out.push_back('/');
      else if (escaped == 'u') {
        uint32_t code = 0;
        if (!s_readJsonCodeUnit(value, pos, code)) {
          s_appendUtf8(out, 0xfffd);
        } else if (code >= 0xd800 && code <= 0xdbff &&
                   pos + 6 <= value.size() && value[pos] == '\\' &&
                   value[pos + 1] == 'u') {
          size_t lowPos = pos + 2;
          uint32_t low = 0;
          if (s_readJsonCodeUnit(value, lowPos, low) && low >= 0xdc00 && low <= 0xdfff) {
            pos = lowPos;
            s_appendUtf8(out, 0x10000 + ((code - 0xd800) << 10) + (low - 0xdc00));
          } else {
            s_appendUtf8(out, 0xfffd);
          }
        } else if (code >= 0xd800 && code <= 0xdfff) {
          s_appendUtf8(out, 0xfffd);
        } else {
          s_appendUtf8(out, code);
        }
      }
      else out.push_back(escaped);
      continue;
    }
    if (ch == '"') break;
    out.push_back(ch);
  }
  return out;
}

struct ScopedSpawnFd {
  int fd = -1;
  ScopedSpawnFd() = default;
  explicit ScopedSpawnFd(int source) {
    if (source >= 0) fd = fcntl(source, F_DUPFD_CLOEXEC, 10);
  }
  ~ScopedSpawnFd() {
    if (fd >= 0) close(fd);
  }
  ScopedSpawnFd(const ScopedSpawnFd&) = delete;
  ScopedSpawnFd& operator=(const ScopedSpawnFd&) = delete;
};

// Numeric child-stdio inheritance is a descriptor alias. The closed Host ABI
// route is checked before fcntl/dup2: fd 1/fd 2 and protected worker handles
// are refused, while fd 0's virtual EOF view may only feed child stdin.
static void requireSpawnDescriptorAlias(
    facebook::jsi::Runtime& runtime,
    int fd,
    bool needsRead,
    bool needsWrite,
    const char* syscall) {
  if (fd < 0) return;
  int32_t route = ex_host_session_descriptor_alias_source_route(fd);
  if (route == 0 || (route == 1 && needsRead && !needsWrite)) return;
  throw facebook::jsi::JSError(
      runtime,
      std::string("EACCES: permission denied, ") + syscall + " '/dev/fd/" +
          std::to_string(fd) + "'");
}

// Move every child-side source above the complete target-fd range before
// fork. Besides avoiding `dup2(fd, fd); close(fd)`, this prevents one mapping
// from overwriting a source needed by a later mapping (stdio swaps and extra
// descriptors). The parent performs this allocation while it is still safe to
// call allocator-backed libc internals.
static bool s_liftChildFd(int& fd, int firstSafeFd) {
  if (fd < 0 || fd >= firstSafeFd) return true;
  int lifted = fcntl(fd, F_DUPFD_CLOEXEC, firstSafeFd);
  if (lifted < 0) return false;
  close(fd);
  fd = lifted;
  return true;
}

// Async-signal-safe child mapping. dup2 clears FD_CLOEXEC when source and
// target differ; for the equal case clear it explicitly and never close the
// target. Returns errno-style 0/specific failure for the exec-error pipe.
static int s_mapChildFd(int source, int target) {
  if (source < 0) return EBADF;
  if (source == target) {
    int flags = fcntl(target, F_GETFD, 0);
    if (flags < 0) return errno;
    if (fcntl(target, F_SETFD, flags & ~FD_CLOEXEC) < 0) return errno;
    return 0;
  }
  if (dup2(source, target) < 0) return errno;
  // POSIX specifies that dup2 clears FD_CLOEXEC on the new descriptor, but
  // make that postcondition explicit: these sources are deliberately marked
  // close-on-exec before fork, and every mapped child descriptor must survive
  // the immediately following execve on every supported libc/kernel pair.
  int flags = fcntl(target, F_GETFD, 0);
  if (flags < 0) return errno;
  if (fcntl(target, F_SETFD, flags & ~FD_CLOEXEC) < 0) return errno;
  close(source);
  return 0;
}

[[noreturn]] static void s_reportChildSetupFailure(int errorFd, int error) {
  if (errorFd >= 0) {
    ssize_t written = write(errorFd, &error, sizeof(error));
    (void)written;
  }
  _exit(127);
}

static bool s_skipJsonValue(const std::string& value, size_t& pos) {
  s_skipJsonWhitespace(value, pos);
  if (pos >= value.size()) return false;
  if (value[pos] == '"') {
    s_parseJsonString(value, pos);
    return true;
  }
  if (value[pos] == '{' || value[pos] == '[') {
    int depth = 0;
    while (pos < value.size()) {
      char ch = value[pos];
      if (ch == '"') {
        s_parseJsonString(value, pos);
        continue;
      }
      if (ch == '{' || ch == '[') {
        depth++;
      } else if (ch == '}' || ch == ']') {
        depth--;
        pos++;
        if (depth == 0) return true;
        continue;
      }
      pos++;
    }
    return false;
  }
  while (pos < value.size() && value[pos] != ',' && value[pos] != '}' && value[pos] != ']') {
    pos++;
  }
  return true;
}

static bool s_findTopLevelJsonValue(const std::string& optsJson,
                                    const char* key,
                                    size_t& valuePos) {
  size_t pos = 0;
  s_skipJsonWhitespace(optsJson, pos);
  if (pos >= optsJson.size() || optsJson[pos] != '{') return false;
  pos++;
  while (pos < optsJson.size()) {
    s_skipJsonWhitespace(optsJson, pos);
    if (pos >= optsJson.size() || optsJson[pos] == '}') return false;
    if (optsJson[pos] != '"') return false;
    auto parsedKey = s_parseJsonString(optsJson, pos);
    s_skipJsonWhitespace(optsJson, pos);
    if (pos >= optsJson.size() || optsJson[pos] != ':') return false;
    pos++;
    s_skipJsonWhitespace(optsJson, pos);
    if (parsedKey == key) {
      valuePos = pos;
      return true;
    }
    if (!s_skipJsonValue(optsJson, pos)) return false;
    s_skipJsonWhitespace(optsJson, pos);
    if (pos < optsJson.size() && optsJson[pos] == ',') {
      pos++;
    }
  }
  return false;
}

using TopLevelJsonIndex = std::unordered_map<std::string, size_t>;

static bool s_indexTopLevelJsonValues(
    const std::string& optsJson,
    TopLevelJsonIndex& index) {
  size_t pos = 0;
  s_skipJsonWhitespace(optsJson, pos);
  if (pos >= optsJson.size() || optsJson[pos] != '{') return false;
  pos++;
  while (pos < optsJson.size()) {
    s_skipJsonWhitespace(optsJson, pos);
    if (pos < optsJson.size() && optsJson[pos] == ',') {
      pos++;
      s_skipJsonWhitespace(optsJson, pos);
    }
    if (pos >= optsJson.size()) return false;
    if (optsJson[pos] == '}') return true;
    if (optsJson[pos] != '"') return false;
    auto key = s_parseJsonString(optsJson, pos);
    s_skipJsonWhitespace(optsJson, pos);
    if (pos >= optsJson.size() || optsJson[pos] != ':') return false;
    pos++;
    s_skipJsonWhitespace(optsJson, pos);
    // Match the old first-key-wins lookup semantics for duplicate keys.
    index.emplace(std::move(key), pos);
    if (!s_skipJsonValue(optsJson, pos)) return false;
  }
  return false;
}

static bool s_indexedTopLevelJsonValue(
    const TopLevelJsonIndex& index,
    const char* key,
    size_t& valuePos) {
  auto found = index.find(key);
  if (found == index.end()) return false;
  valuePos = found->second;
  return true;
}

static bool s_parseIndexedJsonString(
    const std::string& optsJson,
    const TopLevelJsonIndex& index,
    const char* key,
    std::string& out) {
  size_t pos = 0;
  if (!s_indexedTopLevelJsonValue(index, key, pos) || pos >= optsJson.size() ||
      optsJson[pos] != '"') {
    return false;
  }
  out = s_parseJsonString(optsJson, pos);
  return true;
}

static bool s_parseIndexedJsonBool(
    const std::string& optsJson,
    const TopLevelJsonIndex& index,
    const char* key,
    bool& out) {
  size_t pos = 0;
  if (!s_indexedTopLevelJsonValue(index, key, pos)) return false;
  if (optsJson.compare(pos, 4, "true") == 0) {
    out = true;
    return true;
  }
  if (optsJson.compare(pos, 5, "false") == 0) {
    out = false;
    return true;
  }
  return false;
}

static bool s_parseIndexedJsonUnsigned(
    const std::string& optsJson,
    const TopLevelJsonIndex& index,
    const char* key,
    unsigned long long& out) {
  size_t pos = 0;
  if (!s_indexedTopLevelJsonValue(index, key, pos) || pos >= optsJson.size() ||
      optsJson[pos] < '0' || optsJson[pos] > '9') {
    return false;
  }
  char* end = nullptr;
  auto parsed = std::strtoull(optsJson.c_str() + pos, &end, 10);
  if (end == optsJson.c_str() + pos) return false;
  out = parsed;
  return true;
}

static bool s_parseIndexedJsonLong(
    const std::string& optsJson,
    const TopLevelJsonIndex& index,
    const char* key,
    long& out) {
  size_t pos = 0;
  if (!s_indexedTopLevelJsonValue(index, key, pos)) return false;
  char* end = nullptr;
  auto parsed = std::strtol(optsJson.c_str() + pos, &end, 10);
  if (end == optsJson.c_str() + pos) return false;
  out = parsed;
  return true;
}

static bool s_parseTopLevelJsonString(const std::string& optsJson,
                                      const char* key,
                                      std::string& out) {
  size_t pos = 0;
  if (!s_findTopLevelJsonValue(optsJson, key, pos) || pos >= optsJson.size() ||
      optsJson[pos] != '"') {
    return false;
  }
  out = s_parseJsonString(optsJson, pos);
  return true;
}

static bool s_parseTopLevelJsonBool(const std::string& optsJson,
                                    const char* key,
                                    bool& out) {
  size_t pos = 0;
  if (!s_findTopLevelJsonValue(optsJson, key, pos)) return false;
  if (optsJson.compare(pos, 4, "true") == 0) {
    out = true;
    return true;
  }
  if (optsJson.compare(pos, 5, "false") == 0) {
    out = false;
    return true;
  }
  return false;
}

static bool s_parseTopLevelJsonLong(const std::string& optsJson, const char* key, long& out) {
  size_t pos = 0;
  if (!s_findTopLevelJsonValue(optsJson, key, pos)) return false;
  char* end = nullptr;
  auto parsed = std::strtol(optsJson.c_str() + pos, &end, 10);
  if (end == optsJson.c_str() + pos) return false;
  out = parsed;
  return true;
}

static std::vector<std::string> s_parseEnvAt(
    const std::string& optsJson,
    size_t pos) {
  std::vector<std::string> envVec;
  if (pos >= optsJson.size() || optsJson[pos] != '{') {
    return envVec;
  }
  pos++;
  while (pos < optsJson.size()) {
    s_skipJsonWhitespace(optsJson, pos);
    if (pos < optsJson.size() && optsJson[pos] == ',') {
      pos++;
      s_skipJsonWhitespace(optsJson, pos);
    }
    if (pos >= optsJson.size() || optsJson[pos] == '}') break;
    if (optsJson[pos] != '"') break;
    auto key = s_parseJsonString(optsJson, pos);
    s_skipJsonWhitespace(optsJson, pos);
    if (pos >= optsJson.size() || optsJson[pos] != ':') break;
    pos++;
    s_skipJsonWhitespace(optsJson, pos);
    if (pos >= optsJson.size()) break;
    if (optsJson[pos] == '"') {
      auto val = s_parseJsonString(optsJson, pos);
      envVec.push_back(key + "=" + val);
    } else {
      s_skipJsonValue(optsJson, pos);
    }
  }
  return envVec;
}

static std::vector<std::string> s_parseEnvFromOpts(
    const std::string& optsJson,
    bool& envPresent) {
  size_t pos = 0;
  envPresent = s_findTopLevelJsonValue(optsJson, "env", pos);
  if (!envPresent) return {};
  return s_parseEnvAt(optsJson, pos);
}

static std::vector<std::string> s_parseIndexedEnvFromOpts(
    const std::string& optsJson,
    const TopLevelJsonIndex& index,
    bool& envPresent) {
  size_t pos = 0;
  envPresent = s_indexedTopLevelJsonValue(index, "env", pos);
  if (!envPresent) return {};
  return s_parseEnvAt(optsJson, pos);
}

static char** s_processEnvironment() {
#if defined(__APPLE__)
  return *_NSGetEnviron();
#else
  return environ;
#endif
}

static void s_setEnvEntry(std::vector<std::string>& entries,
                          const std::string& key,
                          const std::string& value) {
  const std::string prefix = key + "=";
  for (auto& entry : entries) {
    if (entry.compare(0, prefix.size(), prefix) == 0) {
      entry = prefix + value;
      return;
    }
  }
  entries.push_back(prefix + value);
}

static void s_removeEnvEntry(
    std::vector<std::string>& entries,
    const std::string& key) {
  const std::string prefix = key + "=";
  entries.erase(
      std::remove_if(
          entries.begin(),
          entries.end(),
          [&](const std::string& entry) {
            return entry.compare(0, prefix.size(), prefix) == 0;
          }),
      entries.end());
}

static void s_projectProcessIpcEnvironment(
    std::vector<std::string>& entries,
    int ipcFd) {
  // The inherited marker is a construction-only native handoff. A child gets
  // it only when this exact spawn also maps an IPC socket; every other process
  // launch must lose both the descriptor spelling and its codec companion.
  // @ref LLP 0021#wp7--close-loader-process-inspector-stdio-and-escape-surfaces
  // @ref LLP 0022#7-capabilities-principals-and-affordance-parity
  s_removeEnvEntry(entries, "EXACT_IPC_FD");
  if (ipcFd < 0) {
    s_removeEnvEntry(entries, "EXACT_IPC_SERIALIZATION");
  } else {
    s_setEnvEntry(entries, "EXACT_IPC_FD", std::to_string(ipcFd));
  }
}

static std::optional<std::string> s_envValue(
    const std::vector<std::string>& entries,
    const std::string& key) {
  const std::string prefix = key + "=";
  for (const auto& entry : entries) {
    if (entry.compare(0, prefix.size(), prefix) == 0) {
      return entry.substr(prefix.size());
    }
  }
  return std::nullopt;
}

static std::optional<size_t> s_parseExtraStreamName(
    const std::string& streamName) {
  constexpr char kPrefix[] = "extra:";
  if (streamName.compare(0, sizeof(kPrefix) - 1, kPrefix) != 0) {
    return std::nullopt;
  }
  const char* start = streamName.c_str() + sizeof(kPrefix) - 1;
  if (*start == '\0') return std::nullopt;
  for (const char* current = start; *current != '\0'; ++current) {
    if (*current < '0' || *current > '9') return std::nullopt;
  }
  errno = 0;
  char* end = nullptr;
  unsigned long long parsed = std::strtoull(start, &end, 10);
  if (errno != 0 || end == start || *end != '\0' ||
      parsed > static_cast<unsigned long long>(std::numeric_limits<size_t>::max())) {
    return std::nullopt;
  }
  return static_cast<size_t>(parsed);
}

static std::string s_absoluteChildPath(const std::string& path,
                                       const std::string& cwd) {
  if (path.empty() || path[0] == '/') return path;
  char current[PATH_MAX];
  const char* base = nullptr;
  std::string resolvedBase;
  if (!cwd.empty()) {
    if (cwd[0] == '/') {
      base = cwd.c_str();
    } else if (getcwd(current, sizeof(current)) != nullptr) {
      resolvedBase = std::string(current) + "/" + cwd;
      base = resolvedBase.c_str();
    }
  } else if (getcwd(current, sizeof(current)) != nullptr) {
    base = current;
  }
  return base ? std::string(base) + "/" + path : path;
}

static std::string s_resolveExecutable(const std::string& file,
                                       const std::string& cwd,
                                       const std::vector<std::string>& env) {
  if (file.find('/') != std::string::npos) {
    return s_absoluteChildPath(file, cwd);
  }
  auto configuredSearch = s_envValue(env, "PATH");
  // A missing PATH gets the platform's deterministic default search path.
  // An explicitly empty PATH is different: it contains one empty component,
  // so only the child's working directory is searched. Falling back for both
  // cases lets `env: { PATH: '' }` unexpectedly execute a parent-installed
  // binary.
  std::string search =
      configuredSearch.value_or("/usr/local/bin:/usr/bin:/bin");
  size_t start = 0;
  while (start <= search.size()) {
    size_t end = search.find(':', start);
    if (end == std::string::npos) end = search.size();
    std::string dir = search.substr(start, end - start);
    if (dir.empty()) dir = ".";
    auto candidate = s_absoluteChildPath(dir + "/" + file, cwd);
    if (access(candidate.c_str(), X_OK) == 0) return candidate;
    start = end + 1;
  }
  // Preserve the normal ENOENT report through the exec error pipe.
  return s_absoluteChildPath(file, cwd);
}

// Everything that may allocate or lock is constructed before fork. The child
// only reads these stable buffers and calls POSIX async-signal-safe syscalls
// (dup2/close/open/fcntl/chdir/set*id/setsid/execve/write/_exit).
// @ref LLP 0008#sockets-dns-and-process — multithreaded runtimes must not run
// C++ allocation, setenv, or PATH-resolution logic after fork (ENG-24262).
struct SpawnExecPlan {
  std::vector<std::string> envEntries;
  std::vector<char*> envp;
  std::vector<std::string> argvEntries;
  std::vector<char*> argv;
  std::string executable;
};

static void s_finishSpawnExecPlan(SpawnExecPlan& plan) {
  plan.envp.reserve(plan.envEntries.size() + 1);
  for (auto& entry : plan.envEntries) plan.envp.push_back(entry.data());
  plan.envp.push_back(nullptr);
  plan.argv.reserve(plan.argvEntries.size() + 1);
  for (auto& arg : plan.argvEntries) plan.argv.push_back(arg.data());
  plan.argv.push_back(nullptr);
}

static SpawnExecPlan s_buildExecSyncPlan(const std::string& command) {
  SpawnExecPlan plan;
  for (char** current = s_processEnvironment(); current && *current; ++current) {
    plan.envEntries.emplace_back(*current);
  }
  s_projectProcessIpcEnvironment(plan.envEntries, -1);
  plan.executable = "/bin/sh";
  // Preserve the historical execl("/bin/sh", "sh", "-c", ...) argv shape.
  plan.argvEntries = {"sh", "-c", command};
  s_finishSpawnExecPlan(plan);
  return plan;
}

static SpawnExecPlan s_buildSpawnExecPlan(
    const std::string& file,
    const std::vector<std::string>& args,
    const std::string& argv0,
    bool useShell,
    const std::string& shellPath,
    const std::string& cwd,
    const std::vector<std::string>& customEnv,
    bool customEnvPresent,
    int ipcFd) {
  SpawnExecPlan plan;
  // Presence, not entry count, selects inheritance. `env: {}` is a deliberate
  // empty environment and must not inherit parent secrets.
  if (!customEnvPresent) {
    for (char** current = s_processEnvironment(); current && *current; ++current) {
      plan.envEntries.emplace_back(*current);
    }
  } else {
    plan.envEntries = customEnv;
  }
  s_setEnvEntry(plan.envEntries, "EXACT_QUIET", "1");
  // Never let a caller-supplied/stale IPC marker reach a child without a
  // corresponding native IPC socket. The actual mapped slot is authoritative.
  s_projectProcessIpcEnvironment(plan.envEntries, ipcFd);

  if (useShell) {
    std::string shell = shellPath.empty() ? "/bin/sh" : shellPath;
    plan.executable = s_resolveExecutable(shell, cwd, plan.envEntries);
    std::string command = file;
    for (const auto& arg : args) command += " " + arg;
    plan.argvEntries = {shell, "-c", std::move(command)};
  } else {
    plan.executable = s_resolveExecutable(file, cwd, plan.envEntries);
    plan.argvEntries.reserve(args.size() + 1);
    plan.argvEntries.push_back(argv0.empty() ? file : argv0);
    plan.argvEntries.insert(plan.argvEntries.end(), args.begin(), args.end());
  }
  s_finishSpawnExecPlan(plan);
  return plan;
}

// (ENG-23485) Parse options.uid/options.gid for the spawn child. Trust a
// "uid"/"gid" key only when it appears BEFORE the env object in the options
// JSON — JS serializes credentials ahead of env, so an env *value* containing
// the byte sequence '"uid":0' can never be mistaken for the option (raw fd/
// credential integers are forgeable inputs; see LLP 0013's policy concerns).
// The digit guard rejects quoted lookalikes such as {"env":{"uid":"1000"}}.
static void s_parseSpawnCredentials(const std::string& optsJson,
                                    long& spawnUid,
                                    long& spawnGid) {
  long parsed = -1;
  if (s_parseTopLevelJsonLong(optsJson, "uid", parsed) && parsed >= 0) {
    spawnUid = parsed;
  }
  parsed = -1;
  if (s_parseTopLevelJsonLong(optsJson, "gid", parsed) && parsed >= 0) {
    spawnGid = parsed;
  }
}

static void s_parseIndexedSpawnCredentials(
    const std::string& optsJson,
    const TopLevelJsonIndex& index,
    long& spawnUid,
    long& spawnGid) {
  long parsed = -1;
  if (s_parseIndexedJsonLong(optsJson, index, "uid", parsed) && parsed >= 0) {
    spawnUid = parsed;
  }
  parsed = -1;
  if (s_parseIndexedJsonLong(optsJson, index, "gid", parsed) && parsed >= 0) {
    spawnGid = parsed;
  }
}

// (ENG-23485) Apply options.gid/options.uid in the forked child, gid before
// uid (once uid drops privileges setgid would fail) — libuv's order. Returns
// 0 on success; on failure returns the errno so the caller can report it
// through the exec error pipe instead of silently running the child with the
// parent's credentials.
static int s_applySpawnCredentials(long spawnGid, long spawnUid) {
  if (spawnGid >= 0 && setgid(static_cast<gid_t>(spawnGid)) != 0) {
    return errno != 0 ? errno : EPERM;
  }
  if (spawnUid >= 0 && setuid(static_cast<uid_t>(spawnUid)) != 0) {
    return errno != 0 ? errno : EPERM;
  }
  return 0;
}

void installChildProcessHostFunctions(ExactHermesRuntime* handle) {
  auto& rt = *handle->runtime;

#if defined(EXACT_PLATFORM_ANDROID)
  const char* unavailableMessage =
      "child_process is not available in Android app sandboxes";
  const char* spawnSyncUnavailableJson =
      "{\"stdout\":\"\",\"stderr\":\"\",\"status\":null,\"pid\":0,"
      "\"error\":\"child_process is not available in Android app sandboxes\","
      "\"code\":\"ERR_FEATURE_UNAVAILABLE_ON_PLATFORM\",\"errno\":0,"
      "\"message\":\"child_process is not available in Android app sandboxes\","
      "\"platform\":\"android\"}";
  const char* spawnUnavailableJson =
      "{\"error\":\"child_process is not available in Android app sandboxes\","
      "\"code\":\"ERR_FEATURE_UNAVAILABLE_ON_PLATFORM\",\"errno\":0,"
      "\"message\":\"child_process is not available in Android app sandboxes\","
      "\"platform\":\"android\"}";

  auto makeUnsupportedJsonFn =
      [&rt](const char* name, const char* json) {
        return facebook::jsi::Function::createFromHostFunction(
            rt,
            facebook::jsi::PropNameID::forAscii(rt, name),
            3,
            [json](facebook::jsi::Runtime& runtime,
                   const facebook::jsi::Value&,
                   const facebook::jsi::Value*,
                   size_t) -> facebook::jsi::Value {
              // @ref LLP 0013#phase-0 — the canonical capability is
              // `process:spawn` (capability_bits.rs bit 9). The old
              // `child_process` string was not in the manifest, so this check
              // could never match a policy grant.
              if (!checkCapability("process:spawn")) {
                throw facebook::jsi::JSError(
                    runtime,
                    "Permission denied: process:spawn capability required");
              }
              return facebook::jsi::Value(
                  facebook::jsi::String::createFromUtf8(runtime, json));
            });
      };

  // @ref LLP 0008#android-backend-matrix — Android app sandboxes do not offer
  // desktop Node child_process semantics, so fail explicitly instead of
  // attempting POSIX fork/exec/popen in app code.
  rt.global().setProperty(
      rt,
      "__exactExecSync",
      makeUnsupportedJsonFn("__exactExecSync", spawnSyncUnavailableJson));
  rt.global().setProperty(
      rt,
      "__exactSpawnSync",
      makeUnsupportedJsonFn("__exactSpawnSync", spawnSyncUnavailableJson));
  rt.global().setProperty(
      rt,
      "__exactSpawn",
      makeUnsupportedJsonFn("__exactSpawn", spawnUnavailableJson));

  auto emptyReadFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactSpawnRead"),
      2,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value*,
         size_t) -> facebook::jsi::Value {
        return facebook::jsi::String::createFromUtf8(runtime, "");
      });
  rt.global().setProperty(rt, "__exactSpawnRead", std::move(emptyReadFn));

  auto falseFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactSpawnWrite"),
      3,
      [](facebook::jsi::Runtime&,
         const facebook::jsi::Value&,
         const facebook::jsi::Value*,
         size_t) -> facebook::jsi::Value {
        return facebook::jsi::Value(false);
      });
  rt.global().setProperty(rt, "__exactSpawnWrite", std::move(falseFn));

  auto killFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactSpawnKill"),
      2,
      [](facebook::jsi::Runtime&,
         const facebook::jsi::Value&,
         const facebook::jsi::Value*,
         size_t) -> facebook::jsi::Value {
        return facebook::jsi::Value(false);
      });
  rt.global().setProperty(rt, "__exactSpawnKill", std::move(killFn));

  auto setReferencedFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactSpawnSetReferenced"),
      2,
      [](facebook::jsi::Runtime&,
         const facebook::jsi::Value&,
         const facebook::jsi::Value*,
         size_t) -> facebook::jsi::Value {
        return facebook::jsi::Value(false);
      });
  rt.global().setProperty(
      rt, "__exactSpawnSetReferenced", std::move(setReferencedFn));

  auto closeFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactSpawnCloseStdin"),
      2,
      [](facebook::jsi::Runtime&,
         const facebook::jsi::Value&,
         const facebook::jsi::Value*,
         size_t) -> facebook::jsi::Value {
        return facebook::jsi::Value::undefined();
      });
  rt.global().setProperty(rt, "__exactSpawnCloseStdin", std::move(closeFn));

  auto pollFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactSpawnPoll"),
      1,
      [unavailableMessage](facebook::jsi::Runtime& runtime,
                           const facebook::jsi::Value&,
                           const facebook::jsi::Value*,
                           size_t) -> facebook::jsi::Value {
        std::string json =
            std::string("{\"exited\":true,\"status\":null,\"signal\":null,\"error\":\"")
            + unavailableMessage + "\"}";
        return facebook::jsi::Value(
            facebook::jsi::String::createFromUtf8(runtime, json));
      });
  rt.global().setProperty(rt, "__exactSpawnPoll", std::move(pollFn));

  auto getFdFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactSpawnGetFd"),
      2,
      [](facebook::jsi::Runtime&,
         const facebook::jsi::Value&,
         const facebook::jsi::Value*,
         size_t) -> facebook::jsi::Value {
        return facebook::jsi::Value(-1);
      });
  rt.global().setProperty(rt, "__exactSpawnGetFd", std::move(getFdFn));

  auto sendMsgFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactSpawnSendMsg"),
      3,
      [](facebook::jsi::Runtime&,
         const facebook::jsi::Value&,
         const facebook::jsi::Value*,
         size_t) -> facebook::jsi::Value {
        // -1 (hard failure), not 0/false: 0 means EAGAIN to the JS send queue
        // (ENG-23231), which would retry forever on platforms without spawn.
        return facebook::jsi::Value(-1);
      });
  rt.global().setProperty(rt, "__exactSpawnSendMsg", std::move(sendMsgFn));

  auto recvMsgFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactSpawnRecvMsg"),
      1,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value*,
         size_t) -> facebook::jsi::Value {
        return facebook::jsi::Value(
            facebook::jsi::String::createFromUtf8(runtime, "{\"messages\":[]}"));
      });
  rt.global().setProperty(rt, "__exactSpawnRecvMsg", std::move(recvMsgFn));
  return;
#endif

  // __exactExecSync(command, optionsJSON) -> JSON string { stdout, stderr, status, error }
  // Executes a shell command synchronously using popen and returns result.
  auto execSyncFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactExecSync"),
      2,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (!checkCapability("process:spawn")) {
          throw facebook::jsi::JSError(runtime, "Permission denied: process:spawn capability required");
        }
        if (count == 0 || !args[0].isString()) {
          throw facebook::jsi::JSError(runtime, "__exactExecSync: command string required");
        }
        auto command = args[0].toString(runtime).utf8(runtime);

        // Parse options
        std::string cwd;
        uint32_t timeout_ms = 0;
        uint32_t max_buffer = 1024 * 1024; // 1MB default

        if (count > 1 && args[1].isString()) {
          auto optsJson = args[1].toString(runtime).utf8(runtime);
          auto cwdPos = optsJson.find("\"cwd\":\"");
          if (cwdPos != std::string::npos) {
            auto start = cwdPos + 7;
            auto end = optsJson.find("\"", start);
            if (end != std::string::npos) {
              cwd = optsJson.substr(start, end - start);
            }
          }
          auto timeoutPos = optsJson.find("\"timeout\":");
          if (timeoutPos != std::string::npos) {
            auto start = timeoutPos + 10;
            timeout_ms = static_cast<uint32_t>(std::stoul(optsJson.substr(start)));
          }
          auto maxBufPos = optsJson.find("\"maxBuffer\":");
          if (maxBufPos != std::string::npos) {
            auto start = maxBufPos + 12;
            max_buffer = static_cast<uint32_t>(std::stoul(optsJson.substr(start)));
          }
        }

        // Construct argv and a private-bootstrap-free environment before fork.
        // `execl` inherited the raw Host-to-engine IPC markers even though the
        // JavaScript process.env facade hid them; execve consumes this stable
        // plan without allocating or locking in the multithreaded child.
        auto execPlan = s_buildExecSyncPlan(command);

        // Redirect stderr to a temp file so we can capture it separately
        char stderrTmpPath[] = "/tmp/ex_stderr_XXXXXX";
        int stderrFd = mkstemp(stderrTmpPath);
        if (stderrFd < 0) {
          throw facebook::jsi::JSError(runtime, "Failed to create temp file for stderr");
        }
        int stdoutPipe[2] = {-1, -1};
        if (pipe(stdoutPipe) != 0) {
          close(stderrFd);
          unlink(stderrTmpPath);
          throw facebook::jsi::JSError(runtime, "Failed to create stdout pipe");
        }
        if (!s_liftChildFd(stdoutPipe[1], 3) || !s_liftChildFd(stderrFd, 3)) {
          close(stderrFd);
          close(stdoutPipe[0]);
          close(stdoutPipe[1]);
          unlink(stderrTmpPath);
          throw facebook::jsi::JSError(runtime, "Failed to reserve child stdio descriptors");
        }

        // ENG-23113 — cancellable, self-joining timeout watchdog (see
        // SyncTimeoutWatchdog): the previous detached thread wrote a stack
        // `timedOut` that had been freed once a fast command returned.
        SyncTimeoutWatchdog watchdog;

        pid_t pid = s_forkChild();
        if (pid < 0) {
          close(stderrFd);
          close(stdoutPipe[0]);
          close(stdoutPipe[1]);
          unlink(stderrTmpPath);
          throw facebook::jsi::JSError(runtime, "Failed to execute command");
        }
        if (pid == 0) {
          close(stdoutPipe[0]);
          if (s_mapChildFd(stdoutPipe[1], STDOUT_FILENO) != 0 ||
              s_mapChildFd(stderrFd, STDERR_FILENO) != 0) {
            _exit(127);
          }
          if (!cwd.empty() && chdir(cwd.c_str()) != 0) {
            _exit(127);
          }
          s_execChild(
              execPlan.executable.c_str(),
              execPlan.argv.data(),
              execPlan.envp.data());
          _exit(127);
        }

        close(stderrFd);
        close(stdoutPipe[1]);

        // Start timeout thread if needed
        if (timeout_ms > 0) {
          watchdog.worker = std::thread([&watchdog, timeout_ms]() {
            std::unique_lock<std::mutex> lk(watchdog.mtx);
            if (!watchdog.cv.wait_for(
                    lk, std::chrono::milliseconds(timeout_ms),
                    [&] { return watchdog.finished; })) {
              watchdog.timedOut.store(true);
            }
          });
        }

        // Read stdout
        std::string stdoutStr;
        char buf[4096];
        bool stdoutOpen = true;
        bool childReaped = false;
        int childStatus = 0;
        while (stdoutOpen || !childReaped) {
          if (watchdog.timedOut.load() && !childReaped) {
            kill(pid, SIGKILL);
          }
          if (stdoutOpen) {
            struct pollfd pfd;
            pfd.fd = stdoutPipe[0];
            pfd.events = POLLIN | POLLHUP | POLLERR;
            pfd.revents = 0;
            int pollResult = poll(&pfd, 1, 20);
            if (pollResult > 0 && (pfd.revents & (POLLIN | POLLHUP | POLLERR))) {
              ssize_t bytesRead = read(stdoutPipe[0], buf, sizeof(buf));
              if (bytesRead < 0) {
                if (errno != EINTR) {
                  stdoutOpen = false;
                }
              } else if (bytesRead == 0) {
                stdoutOpen = false;
              } else if (stdoutStr.size() < max_buffer) {
                size_t remaining = max_buffer - stdoutStr.size();
                size_t toAppend = std::min(static_cast<size_t>(bytesRead), remaining);
                stdoutStr.append(buf, toAppend);
              }
            } else if (pollResult < 0 && errno != EINTR) {
              stdoutOpen = false;
            }
          }
          if (!childReaped) {
            pid_t waited = waitpid(pid, &childStatus, WNOHANG);
            if (waited == pid) {
              childReaped = true;
            } else if (waited < 0 && errno != EINTR) {
              childReaped = true;
            }
          }
        }
        close(stdoutPipe[0]);

        int exitStatus = WIFEXITED(childStatus) ? WEXITSTATUS(childStatus) : -1;

        // Command finished: cancel + join the watchdog before this frame can
        // return (or throw building the result), so it can never wake late and
        // write freed memory. ENG-23113
        watchdog.cancelAndJoin();

        // Read stderr from temp file
        std::string stderrStr;
        FILE* stderrFile = fopen(stderrTmpPath, "r");
        if (stderrFile) {
          while (true) {
            size_t bytesRead = fread(buf, 1, sizeof(buf), stderrFile);
            if (bytesRead == 0) break;
            stderrStr.append(buf, bytesRead);
          }
          fclose(stderrFile);
        }
        unlink(stderrTmpPath);

        // JSON escape helper
        auto jsonEscape = [](const std::string& s) -> std::string {
          std::string result;
          result.reserve(s.size() + 16);
          for (char c : s) {
            switch (c) {
              case '"': result += "\\\""; break;
              case '\\': result += "\\\\"; break;
              case '\n': result += "\\n"; break;
              case '\r': result += "\\r"; break;
              case '\t': result += "\\t"; break;
              case '\b': result += "\\b"; break;
              case '\f': result += "\\f"; break;
              default:
                if (static_cast<unsigned char>(c) < 0x20) {
                  char hex[8];
                  snprintf(hex, sizeof(hex), "\\u%04x", static_cast<unsigned char>(c));
                  result += hex;
                } else {
                  result += c;
                }
                break;
            }
          }
          return result;
        };

        std::string errorStr = "";
        if (watchdog.timedOut.load()) {
          errorStr = "Command timed out";
          exitStatus = -1;
        }

        std::string resultJson = "{\"stdout\":\"" + jsonEscape(stdoutStr)
            + "\",\"stderr\":\"" + jsonEscape(stderrStr)
            + "\",\"status\":" + std::to_string(exitStatus);
        if (!errorStr.empty()) {
          resultJson += ",\"error\":\"" + jsonEscape(errorStr) + "\"";
        }
        resultJson += "}";

        return facebook::jsi::Value(
            facebook::jsi::String::createFromUtf8(runtime, resultJson));
      });
  rt.global().setProperty(rt, "__exactExecSync", std::move(execSyncFn));

  // Env helpers defined as static functions above (s_parseEnvJsonStr, s_parseEnvFromOpts)

  // __exactSpawnSync(file, argsJSON, optionsJSON) -> JSON string { stdout, stderr, status, pid, error }
  // Spawns a process synchronously using fork/exec and returns result.
  auto spawnSyncFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactSpawnSync"),
      3,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (!checkCapability("process:spawn")) {
          throw facebook::jsi::JSError(runtime, "Permission denied: process:spawn capability required");
        }
        if (count == 0 || !args[0].isString()) {
          throw facebook::jsi::JSError(runtime, "__exactSpawnSync: file path required");
        }
        auto file = args[0].toString(runtime).utf8(runtime);

        // Parse args array from JSON
        std::vector<std::string> spawnArgs;
        if (count > 1 && args[1].isString()) {
          auto argsJson = args[1].toString(runtime).utf8(runtime);
          if (argsJson.size() > 2 && argsJson[0] == '[') {
            size_t pos = 1;
            while (pos < argsJson.size()) {
              while (pos < argsJson.size() && (argsJson[pos] == ' ' || argsJson[pos] == ',' || argsJson[pos] == '\n')) pos++;
              if (pos >= argsJson.size() || argsJson[pos] == ']') break;
              if (argsJson[pos] == '"') {
                pos++;
                std::string arg;
                while (pos < argsJson.size() && argsJson[pos] != '"') {
                  if (argsJson[pos] == '\\' && pos + 1 < argsJson.size()) {
                    pos++;
                    if (argsJson[pos] == 'n') arg += '\n';
                    else if (argsJson[pos] == 't') arg += '\t';
                    else if (argsJson[pos] == 'r') arg += '\r';
                    else arg += argsJson[pos];
                  } else {
                    arg += argsJson[pos];
                  }
                  pos++;
                }
                if (pos < argsJson.size()) pos++;
                spawnArgs.push_back(arg);
              } else {
                while (pos < argsJson.size() && argsJson[pos] != ',' && argsJson[pos] != ']') pos++;
              }
            }
          }
        }

        // Parse options
        std::string cwd;
        bool useShell = false;
        std::string shellPath; // (ENG-23032) custom shell binary; empty -> /bin/sh
        uint32_t timeout_ms = 0;
        // (ENG-23008) maxBuffer is now enforced here (byte-counted, child killed
        // on exceed) instead of post-hoc in JS. Default matches Node (1MB); a
        // value of 0 means unlimited (JS maps Infinity -> 0). kill_signal is the
        // numeric signal to send when the limit is exceeded (Node killSignal,
        // default SIGTERM=15).
        size_t max_buffer = 1024 * 1024;
        bool max_buffer_unlimited = false;
        int kill_signal = 15;
        std::vector<std::string> envEntries;
        bool envPresent = false;
        std::string stdinInput;
        bool hasStdinInput = false;
        bool inputIsBase64 = false;
        std::string argv0;
        // (ENG-23025) Per-fd stdio modes. Default: capture stdout/stderr, leave
        // stdin inherited (or fed from `input`). Set together by the string form
        // ("pipe"/"inherit"/"ignore") and per-index by the array form.
        std::string stdinMode = "pipe";
        std::string stdoutMode = "pipe";
        std::string stderrMode = "pipe";
        // (ENG-23485) options.uid/options.gid for the child; -1 = not set.
        long spawnUid = -1;
        long spawnGid = -1;

        if (count > 2 && args[2].isString()) {
          auto optsJson = args[2].toString(runtime).utf8(runtime);
          TopLevelJsonIndex optsIndex;
          s_indexTopLevelJsonValues(optsJson, optsIndex);
          s_parseIndexedJsonString(optsJson, optsIndex, "cwd", cwd);
          bool shellBool = false;
          if (s_parseIndexedJsonBool(optsJson, optsIndex, "shell", shellBool) && shellBool) {
            useShell = true;
          }
          if (s_parseIndexedJsonString(optsJson, optsIndex, "shell", shellPath)) {
            useShell = true;
          }
          unsigned long long parsedUnsigned = 0;
          if (s_parseIndexedJsonUnsigned(optsJson, optsIndex, "timeout", parsedUnsigned)) {
            timeout_ms = static_cast<uint32_t>(parsedUnsigned);
          }
          if (s_parseIndexedJsonUnsigned(optsJson, optsIndex, "maxBuffer", parsedUnsigned)) {
            if (parsedUnsigned == 0ULL) {
              max_buffer_unlimited = true;
            } else {
              max_buffer = static_cast<size_t>(parsedUnsigned);
            }
          }
          if (s_parseIndexedJsonUnsigned(optsJson, optsIndex, "killSignal", parsedUnsigned)) {
            int parsedSig = static_cast<int>(parsedUnsigned);
            if (parsedSig > 0) kill_signal = parsedSig;
          }
          s_parseIndexedSpawnCredentials(optsJson, optsIndex, spawnUid, spawnGid);
          envEntries =
              s_parseIndexedEnvFromOpts(optsJson, optsIndex, envPresent);
          // Parse stdio: string form ("inherit"/"pipe"/"ignore") sets all three
          // fds; (ENG-23025) array form ["ignore","inherit","inherit"] sets them
          // per-index. JS serializes mixed modes as a JSON array, but this path
          // previously parsed only the string form and silently left the default
          // "pipe" — so an array-form stdio was ignored (stdout/stderr captured
          // instead of reaching the terminal; stdin left inherited).
          size_t stdioPos = 0;
          if (s_indexedTopLevelJsonValue(optsIndex, "stdio", stdioPos) &&
              stdioPos < optsJson.size() && optsJson[stdioPos] == '"') {
            std::string mode = s_parseJsonString(optsJson, stdioPos);
            stdinMode = mode;
            stdoutMode = mode;
            stderrMode = mode;
          } else {
            size_t pos = 0;
            if (s_indexedTopLevelJsonValue(optsIndex, "stdio", pos) &&
                pos < optsJson.size() && optsJson[pos] == '[') {
              pos++;
              std::string* slots[3] = {&stdinMode, &stdoutMode, &stderrMode};
              int slot = 0;
              while (pos < optsJson.size() && optsJson[pos] != ']') {
                s_skipJsonWhitespace(optsJson, pos);
                if (pos < optsJson.size() && optsJson[pos] == ',') {
                  pos++;
                  s_skipJsonWhitespace(optsJson, pos);
                }
                if (pos >= optsJson.size() || optsJson[pos] == ']') break;
                if (optsJson[pos] == '"') {
                  std::string val = s_parseJsonString(optsJson, pos);
                  if (slot < 3) *slots[slot] = val;
                } else {
                  // non-string entry (number fd / null): skip, keep default
                  s_skipJsonValue(optsJson, pos);
                }
                slot++;
              }
            }
          }
          // Parse input option for stdin
          std::string inputStr;
          if (s_parseIndexedJsonString(optsJson, optsIndex, "input", inputStr)) {
            stdinInput = inputStr;
            hasStdinInput = true;
          }
          // (ENG-23009) When JS marks the stdin payload as base64 the raw bytes
          // were preserved across the JSON boundary; decode below before writing.
          std::string inputEncoding;
          if (s_parseIndexedJsonString(optsJson, optsIndex, "inputEncoding", inputEncoding) &&
              inputEncoding == "base64") {
            inputIsBase64 = true;
          }
          // Parse argv0 option for custom process.argv[0]
          s_parseIndexedJsonString(optsJson, optsIndex, "argv0", argv0);
        }

        const bool syncStdoutPipe = (stdoutMode == "pipe");
        const bool syncStderrPipe = (stderrMode == "pipe");
        const bool syncStdoutIgnore = (stdoutMode == "ignore");
        const bool syncStderrIgnore = (stderrMode == "ignore");
        // stdin is fed from `input` when present (pipe); otherwise "ignore" ->
        // /dev/null and anything else -> inherit the parent's stdin.
        const bool syncStdinIgnore = (stdinMode == "ignore");

        // (ENG-23485) fd:N stdio entries (Node numeric stdio semantics:
        // "share this parent fd with the child"), dup2'd in the child below.
        // The trusted JS layer resolves fd:N-equals-slot to 'inherit' before
        // it reaches this bridge (Node's stdio:[0,1,2]), so every fd:N seen
        // here is a genuinely foreign fd and must pass the capability layer —
        // raw fd integers are forgeable
        // (@ref LLP 0013#policy — same rule as the async spawn redirects).
        auto parseSyncFdMode = [](const std::string& mode) -> int {
          if (mode.size() > 3 && mode.compare(0, 3, "fd:") == 0) {
            return std::atoi(mode.c_str() + 3);
          }
          return -1;
        };
        int syncStdinFdRedirect = parseSyncFdMode(stdinMode);
        int syncStdoutFdRedirect = parseSyncFdMode(stdoutMode);
        int syncStderrFdRedirect = parseSyncFdMode(stderrMode);
        if (syncStdinFdRedirect >= 0) {
          requireSpawnDescriptorAlias(
              runtime, syncStdinFdRedirect, true, false,
              "__exactSpawnSync stdio[0]");
          exactRequireFdReadable(runtime, syncStdinFdRedirect, "__exactSpawnSync stdio[0]");
        }
        if (syncStdoutFdRedirect >= 0) {
          requireSpawnDescriptorAlias(
              runtime, syncStdoutFdRedirect, false, true,
              "__exactSpawnSync stdio[1]");
          exactRequireFdWritable(runtime, syncStdoutFdRedirect, "__exactSpawnSync stdio[1]");
        }
        if (syncStderrFdRedirect >= 0) {
          requireSpawnDescriptorAlias(
              runtime, syncStderrFdRedirect, false, true,
              "__exactSpawnSync stdio[2]");
          exactRequireFdWritable(runtime, syncStderrFdRedirect, "__exactSpawnSync stdio[2]");
        }
        ScopedSpawnFd safeSyncStdin(syncStdinFdRedirect);
        ScopedSpawnFd safeSyncStdout(syncStdoutFdRedirect);
        ScopedSpawnFd safeSyncStderr(syncStderrFdRedirect);
        if ((syncStdinFdRedirect >= 0 && safeSyncStdin.fd < 0) ||
            (syncStdoutFdRedirect >= 0 && safeSyncStdout.fd < 0) ||
            (syncStderrFdRedirect >= 0 && safeSyncStderr.fd < 0)) {
          throw facebook::jsi::JSError(runtime, "Failed to duplicate stdio redirect");
        }

        // JSON escape helper
        auto jsonEscape = [](const std::string& s) -> std::string {
          std::string result;
          result.reserve(s.size() + 16);
          for (char c : s) {
            switch (c) {
              case '"': result += "\\\""; break;
              case '\\': result += "\\\\"; break;
              case '\n': result += "\\n"; break;
              case '\r': result += "\\r"; break;
              case '\t': result += "\\t"; break;
              case '\b': result += "\\b"; break;
              case '\f': result += "\\f"; break;
              default:
                if (static_cast<unsigned char>(c) < 0x20) {
                  char hex[8];
                  snprintf(hex, sizeof(hex), "\\u%04x", static_cast<unsigned char>(c));
                  result += hex;
                } else {
                  result += c;
                }
                break;
            }
          }
          return result;
        };

        // (ENG-23009) Base64 transport for binary stdout/stderr/stdin. JSON
        // strings must be valid UTF-8 for createFromUtf8, but child output is
        // arbitrary bytes; base64 (ASCII) is a byte-preserving, JSON-safe
        // channel that survives the native->JS boundary without corruption.
        auto base64Encode = [](const std::string& in) -> std::string {
          static const char* tbl =
              "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
          std::string out;
          out.reserve(((in.size() + 2) / 3) * 4);
          size_t i = 0;
          while (i + 2 < in.size()) {
            uint32_t n = (static_cast<uint8_t>(in[i]) << 16) |
                         (static_cast<uint8_t>(in[i + 1]) << 8) |
                         static_cast<uint8_t>(in[i + 2]);
            out.push_back(tbl[(n >> 18) & 63]);
            out.push_back(tbl[(n >> 12) & 63]);
            out.push_back(tbl[(n >> 6) & 63]);
            out.push_back(tbl[n & 63]);
            i += 3;
          }
          size_t rem = in.size() - i;
          if (rem == 1) {
            uint32_t n = static_cast<uint8_t>(in[i]) << 16;
            out.push_back(tbl[(n >> 18) & 63]);
            out.push_back(tbl[(n >> 12) & 63]);
            out.push_back('=');
            out.push_back('=');
          } else if (rem == 2) {
            uint32_t n = (static_cast<uint8_t>(in[i]) << 16) |
                         (static_cast<uint8_t>(in[i + 1]) << 8);
            out.push_back(tbl[(n >> 18) & 63]);
            out.push_back(tbl[(n >> 12) & 63]);
            out.push_back(tbl[(n >> 6) & 63]);
            out.push_back('=');
          }
          return out;
        };
        auto base64Decode = [](const std::string& in) -> std::string {
          auto dec = [](char c) -> int {
            if (c >= 'A' && c <= 'Z') return c - 'A';
            if (c >= 'a' && c <= 'z') return c - 'a' + 26;
            if (c >= '0' && c <= '9') return c - '0' + 52;
            if (c == '+') return 62;
            if (c == '/') return 63;
            return -1;
          };
          std::string out;
          out.reserve((in.size() / 4) * 3);
          int buffer = 0;
          int bits = 0;
          for (char c : in) {
            if (c == '=' || c == '\n' || c == '\r' || c == ' ') continue;
            int v = dec(c);
            if (v < 0) continue;
            buffer = (buffer << 6) | v;
            bits += 6;
            if (bits >= 8) {
              bits -= 8;
              out.push_back(static_cast<char>((buffer >> bits) & 0xff));
            }
          }
          return out;
        };
        if (inputIsBase64 && hasStdinInput) {
          stdinInput = base64Decode(stdinInput);
        }

        // Create pipes for stdout, stderr, and optionally stdin
        int stdoutPipe[2] = {-1, -1}, stderrPipe[2] = {-1, -1}, stdinPipe[2] = {-1, -1};
        if (syncStdoutPipe) {
          if (pipe(stdoutPipe) != 0) {
            throw facebook::jsi::JSError(runtime, "Failed to create stdout pipe");
          }
        }
        if (syncStderrPipe) {
          if (pipe(stderrPipe) != 0) {
            if (stdoutPipe[0] >= 0) { close(stdoutPipe[0]); close(stdoutPipe[1]); }
            throw facebook::jsi::JSError(runtime, "Failed to create stderr pipe");
          }
        }
        if (hasStdinInput) {
          if (pipe(stdinPipe) != 0) {
            if (stdoutPipe[0] >= 0) { close(stdoutPipe[0]); close(stdoutPipe[1]); }
            if (stderrPipe[0] >= 0) { close(stderrPipe[0]); close(stderrPipe[1]); }
            throw facebook::jsi::JSError(runtime, "Failed to create stdin pipe");
          }
        }
        int execErrPipe[2] = {-1, -1};
        if (pipe(execErrPipe) != 0) {
          if (stdoutPipe[0] >= 0) { close(stdoutPipe[0]); close(stdoutPipe[1]); }
          if (stderrPipe[0] >= 0) { close(stderrPipe[0]); close(stderrPipe[1]); }
          if (hasStdinInput) { close(stdinPipe[0]); close(stdinPipe[1]); }
          throw facebook::jsi::JSError(runtime, "Failed to create exec error pipe");
        }
        fcntl(execErrPipe[1], F_SETFD, FD_CLOEXEC);

        bool childFdsReserved = s_liftChildFd(execErrPipe[1], 3) &&
            (!syncStdoutPipe || s_liftChildFd(stdoutPipe[1], 3)) &&
            (!syncStderrPipe || s_liftChildFd(stderrPipe[1], 3)) &&
            (!hasStdinInput || s_liftChildFd(stdinPipe[0], 3)) &&
            s_liftChildFd(safeSyncStdout.fd, 3) &&
            s_liftChildFd(safeSyncStderr.fd, 3) &&
            s_liftChildFd(safeSyncStdin.fd, 3);
        if (!childFdsReserved) {
          close(execErrPipe[0]);
          close(execErrPipe[1]);
          if (stdoutPipe[0] >= 0) close(stdoutPipe[0]);
          if (stdoutPipe[1] >= 0) close(stdoutPipe[1]);
          if (stderrPipe[0] >= 0) close(stderrPipe[0]);
          if (stderrPipe[1] >= 0) close(stderrPipe[1]);
          if (stdinPipe[0] >= 0) close(stdinPipe[0]);
          if (stdinPipe[1] >= 0) close(stdinPipe[1]);
          throw facebook::jsi::JSError(runtime, "Failed to reserve child stdio descriptors");
        }

        // Precompute argv/env/PATH resolution while every runtime thread and
        // allocator lock is still valid. The child must not allocate.
        auto execPlan = s_buildSpawnExecPlan(
            file, spawnArgs, argv0, useShell, shellPath, cwd, envEntries,
            envPresent, -1);

        pid_t pid = s_forkChild();
        if (pid < 0) {
          close(execErrPipe[0]);
          close(execErrPipe[1]);
          if (stdoutPipe[0] >= 0) { close(stdoutPipe[0]); close(stdoutPipe[1]); }
          if (stderrPipe[0] >= 0) { close(stderrPipe[0]); close(stderrPipe[1]); }
          if (hasStdinInput) { close(stdinPipe[0]); close(stdinPipe[1]); }
          throw facebook::jsi::JSError(runtime, "Failed to fork process");
        }

        if (pid == 0) {
          // Child process
          close(execErrPipe[0]);
          if (syncStdoutPipe) {
            close(stdoutPipe[0]);
            int mapError = s_mapChildFd(stdoutPipe[1], STDOUT_FILENO);
            if (mapError != 0) s_reportChildSetupFailure(execErrPipe[1], mapError);
          } else if (safeSyncStdout.fd >= 0) {
            int mapError = s_mapChildFd(safeSyncStdout.fd, STDOUT_FILENO);
            if (mapError != 0) s_reportChildSetupFailure(execErrPipe[1], mapError);
          } else if (syncStdoutIgnore) {
            int nullFd = open("/dev/null", O_WRONLY);
            if (nullFd >= 0) {
              int mapError = s_mapChildFd(nullFd, STDOUT_FILENO);
              if (mapError != 0) s_reportChildSetupFailure(execErrPipe[1], mapError);
            }
          }
          // else inherit: do nothing, keep parent's stdout

          if (syncStderrPipe) {
            close(stderrPipe[0]);
            int mapError = s_mapChildFd(stderrPipe[1], STDERR_FILENO);
            if (mapError != 0) s_reportChildSetupFailure(execErrPipe[1], mapError);
          } else if (safeSyncStderr.fd >= 0) {
            int mapError = s_mapChildFd(safeSyncStderr.fd, STDERR_FILENO);
            if (mapError != 0) s_reportChildSetupFailure(execErrPipe[1], mapError);
          } else if (syncStderrIgnore) {
            int nullFd = open("/dev/null", O_WRONLY);
            if (nullFd >= 0) {
              int mapError = s_mapChildFd(nullFd, STDERR_FILENO);
              if (mapError != 0) s_reportChildSetupFailure(execErrPipe[1], mapError);
            }
          }
          // else inherit: do nothing, keep parent's stderr

          if (hasStdinInput) {
            close(stdinPipe[1]);
            int mapError = s_mapChildFd(stdinPipe[0], STDIN_FILENO);
            if (mapError != 0) s_reportChildSetupFailure(execErrPipe[1], mapError);
          } else if (safeSyncStdin.fd >= 0) {
            int mapError = s_mapChildFd(safeSyncStdin.fd, STDIN_FILENO);
            if (mapError != 0) s_reportChildSetupFailure(execErrPipe[1], mapError);
          } else if (syncStdinIgnore) {
            int nullFd = open("/dev/null", O_RDONLY);
            if (nullFd >= 0) {
              int mapError = s_mapChildFd(nullFd, STDIN_FILENO);
              if (mapError != 0) s_reportChildSetupFailure(execErrPipe[1], mapError);
            }
          }

          if (!cwd.empty()) {
            if (chdir(cwd.c_str()) != 0) {
              int chdirErrno = errno;
              ssize_t nw = write(execErrPipe[1], &chdirErrno, sizeof(chdirErrno));
              (void)nw;
              _exit(127);
            }
          }

          // (ENG-23485) Apply options.gid/options.uid (gid first) between fork
          // and exec; failure reports through the exec error pipe so JS
          // surfaces spawn EPERM instead of silently keeping parent credentials.
          {
            int credErrno = s_applySpawnCredentials(spawnGid, spawnUid);
            if (credErrno != 0) {
              ssize_t nw = write(execErrPipe[1], &credErrno, sizeof(credErrno));
              (void)nw;
              _exit(127);
            }
          }

          s_execChild(execPlan.executable.c_str(), execPlan.argv.data(), execPlan.envp.data());
          {
            int execErrno = errno;
            ssize_t nw = write(execErrPipe[1], &execErrno, sizeof(execErrno));
            (void)nw;
          }
          _exit(127);
        }

        // Parent process
        close(execErrPipe[1]);
        {
          int childErrno = 0;
          ssize_t n = read(execErrPipe[0], &childErrno, sizeof(childErrno));
          close(execErrPipe[0]);
          if (n > 0) {
            // (ENG-23023) On exec failure close BOTH ends of the stdout/stderr
            // pipes. The success path closes the write ends at :799-800, but this
            // early-return branch previously closed only the read ends, leaking
            // stdoutPipe[1]/stderrPipe[1] on every failed spawnSync (e.g. ENOENT).
            if (syncStdoutPipe) { close(stdoutPipe[0]); close(stdoutPipe[1]); }
            if (syncStderrPipe) { close(stderrPipe[0]); close(stderrPipe[1]); }
            if (hasStdinInput) {
              close(stdinPipe[0]);
              close(stdinPipe[1]);
            }
            int status = 0;
            waitpid(pid, &status, 0);
            std::string errorStr = "Command not found: " + file;
            if (childErrno == EACCES || childErrno == EPERM) {
              errorStr = "Permission denied: " + file;
            } else if (childErrno != ENOENT) {
              errorStr = std::string("exec failed: ") + std::strerror(childErrno);
            }
            // (ENG-23485) Precise code so JS reports EPERM for setuid/setgid
            // failures (previously "Permission denied" was remapped to EACCES).
            std::string errCode;
            if (childErrno == EPERM) errCode = "EPERM";
            else if (childErrno == EACCES) errCode = "EACCES";
            else if (childErrno == ENOENT) errCode = "ENOENT";
            std::string codeField;
            if (!errCode.empty()) {
              codeField = ",\"code\":\"" + errCode + "\",\"errno\":"
                  + std::to_string(-childErrno);
            }
            std::string resultJson = "{\"stdout\":\"\",\"stderr\":\"\",\"stdioEncoding\":\"base64\",\"status\":127,\"pid\":"
                + std::to_string(static_cast<int>(pid))
                + ",\"error\":\"" + jsonEscape(errorStr) + "\"" + codeField + "}";
            return facebook::jsi::Value(
                facebook::jsi::String::createFromUtf8(runtime, resultJson));
          }
        }
        if (syncStdoutPipe) close(stdoutPipe[1]);
        if (syncStderrPipe) close(stderrPipe[1]);

        std::string stdoutStr, stderrStr;
        char buf[4096];
        // ENG-23113 — cancellable, self-joining timeout watchdog (see
        // SyncTimeoutWatchdog). The worker fires SIGKILL only while the child is
        // still alive; once the child is reaped the main path cancels + joins it,
        // so it can never wake after this frame returns and SIGKILL a recycled PID
        // (or read/write the freed stack `childExited`/`timedOut`).
        SyncTimeoutWatchdog watchdog;

        if (timeout_ms > 0) {
          watchdog.worker = std::thread([&watchdog, timeout_ms, pid, kill_signal]() {
            std::unique_lock<std::mutex> lk(watchdog.mtx);
            if (!watchdog.cv.wait_for(
                    lk, std::chrono::milliseconds(timeout_ms),
                    [&] { return watchdog.finished; })) {
              // Not cancelled -> a real timeout. The childExited guard closes the
              // window where the child was reaped between wait_for waking and this
              // check: no reap has happened yet unless childExited is set, so pid
              // is not recycled.
              if (!watchdog.childExited.load() && kill(pid, kill_signal) == 0) {
                watchdog.timedOut.store(true);
              }
            }
          });
        }

        // (ENG-23008) Enforce maxBuffer by BYTES on each stream. When cumulative
        // bytes exceed the limit, truncate the captured output to maxBuffer and
        // KILL the child with killSignal (matching Node), instead of buffering up
        // to 256MB and never terminating the child.
        bool maxBufferExceeded = false;

        // (ENG-23025) Multiplex stdin-write / stdout-read / stderr-read with
        // poll() on non-blocking fds. The previous path wrote all of stdin, then
        // drained stdout to EOF, then stderr to EOF, each with fully-blocking
        // I/O. A child that filled the ~64KB kernel buffer of a pipe the parent
        // was not currently draining (e.g. >64KB to stderr while the parent
        // blocked in the stdout read loop, or >64KB of stdin while the child
        // blocked writing stdout the parent hadn't begun reading) deadlocked
        // forever — there is no default timeout and typical output is under the
        // 1MB maxBuffer, so neither guard fired. Node/libuv multiplex; so do we.
        int stdinWriteFd = -1;
        const char* stdinData = nullptr;
        size_t stdinRemaining = 0;
        if (hasStdinInput) {
          close(stdinPipe[0]); // parent only writes to the child's stdin
          stdinWriteFd = stdinPipe[1];
          stdinData = stdinInput.data();
          stdinRemaining = stdinInput.size();
          int flags = fcntl(stdinWriteFd, F_GETFL, 0);
          if (flags >= 0) fcntl(stdinWriteFd, F_SETFL, flags | O_NONBLOCK);
          if (stdinRemaining == 0) {
            close(stdinWriteFd);
            stdinWriteFd = -1;
          }
        }
        int stdoutReadFd = syncStdoutPipe ? stdoutPipe[0] : -1;
        int stderrReadFd = syncStderrPipe ? stderrPipe[0] : -1;
        if (stdoutReadFd >= 0) {
          int f = fcntl(stdoutReadFd, F_GETFL, 0);
          if (f >= 0) fcntl(stdoutReadFd, F_SETFL, f | O_NONBLOCK);
        }
        if (stderrReadFd >= 0) {
          int f = fcntl(stderrReadFd, F_GETFL, 0);
          if (f >= 0) fcntl(stderrReadFd, F_SETFL, f | O_NONBLOCK);
        }

        // Append bytes to a capture buffer enforcing maxBuffer; returns false
        // when the stream hit the limit and should stop being read.
        auto appendCapped = [&](std::string& dst, const char* data, size_t len) -> bool {
          if (max_buffer_unlimited) {
            dst.append(data, len);
            return true;
          }
          if (dst.size() + len > max_buffer) {
            size_t room = max_buffer > dst.size() ? max_buffer - dst.size() : 0;
            dst.append(data, room);
            maxBufferExceeded = true;
            if (!watchdog.childExited.load()) kill(pid, kill_signal);
            return false;
          }
          dst.append(data, len);
          return true;
        };

        // Drain a readable fd until EAGAIN/EOF. On EOF or a hard error, closes
        // the fd and sets *fdSlot to -1 so it drops out of the poll set.
        auto drainReadable = [&](int* fdSlot, std::string& dst) {
          int fd = *fdSlot;
          while (true) {
            ssize_t br = read(fd, buf, sizeof(buf));
            if (br > 0) {
              if (!appendCapped(dst, buf, static_cast<size_t>(br))) {
                close(fd);
                *fdSlot = -1;
                return;
              }
            } else if (br == 0) {
              close(fd); // EOF
              *fdSlot = -1;
              return;
            } else {
              if (errno == EAGAIN || errno == EWOULDBLOCK) return; // drained
              if (errno == EINTR) continue;
              close(fd);
              *fdSlot = -1;
              return;
            }
          }
        };

        while (stdinWriteFd >= 0 || stdoutReadFd >= 0 || stderrReadFd >= 0) {
          struct pollfd pfds[3];
          int idxStdin = -1, idxStdout = -1, idxStderr = -1;
          nfds_t nfds = 0;
          if (stdinWriteFd >= 0) {
            pfds[nfds].fd = stdinWriteFd;
            pfds[nfds].events = POLLOUT;
            pfds[nfds].revents = 0;
            idxStdin = static_cast<int>(nfds++);
          }
          if (stdoutReadFd >= 0) {
            pfds[nfds].fd = stdoutReadFd;
            pfds[nfds].events = POLLIN;
            pfds[nfds].revents = 0;
            idxStdout = static_cast<int>(nfds++);
          }
          if (stderrReadFd >= 0) {
            pfds[nfds].fd = stderrReadFd;
            pfds[nfds].events = POLLIN;
            pfds[nfds].revents = 0;
            idxStderr = static_cast<int>(nfds++);
          }

          // 100ms tick so the watchdog thread's SIGKILL (timeout_ms) is observed
          // even when every fd is quiet; on timeout the child's write ends close
          // and the reads below see EOF, ending the loop.
          int pr = poll(pfds, nfds, 100);
          if (pr < 0) {
            if (errno == EINTR) continue;
            break; // unexpected poll failure: stop draining
          }
          if (pr == 0) {
            continue; // tick with no readiness
          }

          if (idxStdin >= 0) {
            short re = pfds[idxStdin].revents;
            if (re & (POLLERR | POLLHUP | POLLNVAL)) {
              // Reader is gone (child closed stdin or exited); stop writing.
              close(stdinWriteFd);
              stdinWriteFd = -1;
            } else if (re & POLLOUT) {
              ssize_t w = write(stdinWriteFd, stdinData, stdinRemaining);
              if (w > 0) {
                stdinData += w;
                stdinRemaining -= static_cast<size_t>(w);
                if (stdinRemaining == 0) {
                  close(stdinWriteFd);
                  stdinWriteFd = -1;
                }
              } else if (w < 0 && errno != EAGAIN && errno != EWOULDBLOCK &&
                         errno != EINTR) {
                close(stdinWriteFd);
                stdinWriteFd = -1;
              }
            }
          }
          if (idxStdout >= 0 && (pfds[idxStdout].revents &
                                 (POLLIN | POLLHUP | POLLERR | POLLNVAL))) {
            drainReadable(&stdoutReadFd, stdoutStr);
          }
          if (idxStderr >= 0 && (pfds[idxStderr].revents &
                                 (POLLIN | POLLHUP | POLLERR | POLLNVAL))) {
            drainReadable(&stderrReadFd, stderrStr);
          }
        }

        // Wait for child
        int status = 0;
        waitpid(pid, &status, 0);
        watchdog.childExited.store(true);
        // Child reaped: cancel + join the watchdog before this frame can return
        // (or throw building the result JSON), so it can never wake late and
        // SIGKILL a recycled PID. ENG-23113
        watchdog.cancelAndJoin();
        int exitStatus = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
        if (WIFSIGNALED(status)) {
          exitStatus = -WTERMSIG(status);
        }

        std::string errorStr;
        if (watchdog.timedOut.load()) {
          errorStr = "Command timed out";
        } else if (exitStatus == 127) {
          errorStr = "Command not found: " + file;
        }

        // (ENG-23009) stdout/stderr are emitted base64 so binary output round-
        // trips exactly; JS decodes back to a Buffer.
        std::string resultJson = "{\"stdout\":\"" + base64Encode(stdoutStr)
            + "\",\"stderr\":\"" + base64Encode(stderrStr)
            + "\",\"stdioEncoding\":\"base64\",\"status\":" + std::to_string(exitStatus)
            + ",\"pid\":" + std::to_string(static_cast<int>(pid))
            + ",\"maxBufferExceeded\":" + (maxBufferExceeded ? "true" : "false");
        if (!errorStr.empty()) {
          resultJson += ",\"error\":\"" + jsonEscape(errorStr) + "\"";
        }
        resultJson += "}";

        return facebook::jsi::Value(
            facebook::jsi::String::createFromUtf8(runtime, resultJson));
      });
  rt.global().setProperty(rt, "__exactSpawnSync", std::move(spawnSyncFn));

  // --- Async spawn support ---
  auto requireSpawnHandleOwnership =
      [](facebook::jsi::Runtime& runtime, int handle, const char* syscall)
          -> std::shared_ptr<SpawnedProcess> {
        std::shared_ptr<SpawnedProcess> proc;
        {
          std::lock_guard<std::mutex> lock(s_spawnMutex);
          auto it = s_spawnedProcesses.find(handle);
          if (it == s_spawnedProcesses.end()) {
                throw facebook::jsi::JSError(runtime, std::string(syscall) + ": invalid handle");
          }
          proc = it->second;
        }
        if (proc->runtimeNonce != ex_hermes_current_runtime_nonce()) {
          throw facebook::jsi::JSError(
              runtime, std::string(syscall) + ": handle belongs to a different runtime");
        }
        // Permissive policy does not make numeric handles ambient. Ownership
        // is an object-capability boundary independent of whether authority
        // checks are configured to allow all operations.
        if (proc->owner != currentPrincipalId()) {
          throw facebook::jsi::JSError(runtime, "Permission denied");
        }
        return proc;
      };

  auto requireSpawnHandle =
      [requireSpawnHandleOwnership](facebook::jsi::Runtime& runtime,
                                    int handle,
                                    const char* syscall)
          -> std::shared_ptr<SpawnedProcess> {
        auto proc = requireSpawnHandleOwnership(runtime, handle, syscall);
        if (!proc->capability.empty() && !checkCapability(proc->capability)) {
          throw facebook::jsi::JSError(runtime, "Permission denied");
        }
        return proc;
      };

  auto trySpawnHandle =
      [requireSpawnHandle](facebook::jsi::Runtime& runtime, int handle, const char* syscall) {
        try {
          return requireSpawnHandle(runtime, handle, syscall);
        } catch (const facebook::jsi::JSError&) {
          return std::shared_ptr<SpawnedProcess>();
        }
      };

  // __exactSpawn(file, argsJSON, optionsJSON) -> JSON string {"handle":N,"pid":N} or {"error":"..."}
  auto spawnFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactSpawn"),
      3,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (!checkCapability("process:spawn")) {
          throw facebook::jsi::JSError(runtime, "Permission denied: process:spawn capability required");
        }
        if (count == 0 || !args[0].isString()) {
          throw facebook::jsi::JSError(runtime, "__exactSpawn: file path required");
        }
        auto file = args[0].toString(runtime).utf8(runtime);

        // Parse args array from JSON
        std::vector<std::string> spawnArgs;
        if (count > 1 && args[1].isString()) {
          auto argsJson = args[1].toString(runtime).utf8(runtime);
          if (argsJson.size() > 2 && argsJson[0] == '[') {
            size_t pos = 1;
            while (pos < argsJson.size()) {
              while (pos < argsJson.size() && (argsJson[pos] == ' ' || argsJson[pos] == ',' || argsJson[pos] == '\n')) pos++;
              if (pos >= argsJson.size() || argsJson[pos] == ']') break;
              if (argsJson[pos] == '"') {
                pos++;
                std::string arg;
                while (pos < argsJson.size() && argsJson[pos] != '"') {
                  if (argsJson[pos] == '\\' && pos + 1 < argsJson.size()) {
                    pos++;
                    if (argsJson[pos] == 'n') arg += '\n';
                    else if (argsJson[pos] == 't') arg += '\t';
                    else if (argsJson[pos] == 'r') arg += '\r';
                    else arg += argsJson[pos];
                  } else {
                    arg += argsJson[pos];
                  }
                  pos++;
                }
                if (pos < argsJson.size()) pos++;
                spawnArgs.push_back(arg);
              } else {
                while (pos < argsJson.size() && argsJson[pos] != ',' && argsJson[pos] != ']') pos++;
              }
            }
          }
        }

        // Parse options
        std::string cwd;
        bool useShell = false;
        std::string shellPath; // (ENG-23032) custom shell binary; empty -> /bin/sh
        bool detached = false; // (ENG-23032) start child in a new session/pgroup
        // (ENG-23485) options.uid/options.gid for the child; -1 = not set.
        long spawnUid = -1;
        long spawnGid = -1;
        std::vector<std::string> stdioModes = {"pipe", "pipe", "pipe", "pipe"};
        std::vector<std::string> envEntries;
        bool envPresent = false;

        auto normalizeStdioMode = [](const std::string& value) {
          if (value == "ignore") return std::string("ignore");
          if (value == "inherit") return std::string("inherit");
          if (value == "pipe") return std::string("pipe");
          if (value == "overlapped") return std::string("pipe");
          if (value == "ipc") return std::string("ipc");
          // fd:N - redirect to existing file descriptor
          if (value.size() > 3 && value.substr(0, 3) == "fd:") return value;
          return std::string("pipe");
        };

        if (count > 2 && args[2].isString()) {
          auto optsJson = args[2].toString(runtime).utf8(runtime);
          s_parseTopLevelJsonString(optsJson, "cwd", cwd);
          bool shellBool = false;
          if (s_parseTopLevelJsonBool(optsJson, "shell", shellBool) && shellBool) {
            useShell = true;
          }
          if (s_parseTopLevelJsonString(optsJson, "shell", shellPath)) {
            useShell = true;
          }
          // (ENG-23032) `detached` was never parsed, so JS honored it only via
          // child.unref(): the child stayed in the parent's process group and
          // session, so process.kill(-pid) missed it and terminal SIGINT still
          // reached it. Plumb it through and setsid() in the child below.
          bool detachedBool = false;
          if (s_parseTopLevelJsonBool(optsJson, "detached", detachedBool) && detachedBool) {
            detached = true;
          }
          s_parseSpawnCredentials(optsJson, spawnUid, spawnGid);

          size_t modePos = 0;
          if (s_findTopLevelJsonValue(optsJson, "stdio", modePos)) {
            if (modePos < optsJson.size()) {
              if (optsJson[modePos] == '"') {
                auto parsed = s_parseJsonString(optsJson, modePos);
                auto normalized = normalizeStdioMode(parsed);
                stdioModes[0] = normalized;
                stdioModes[1] = normalized;
                stdioModes[2] = normalized;
                stdioModes[3] = normalized;
              } else if (optsJson[modePos] == '[') {
                ++modePos;
                int slot = 0;
                while (modePos < optsJson.size()) {
                  s_skipJsonWhitespace(optsJson, modePos);
                  if (modePos >= optsJson.size() || optsJson[modePos] == ']') break;
                  std::string parsed;
                  if (optsJson[modePos] == '"') {
                    parsed = s_parseJsonString(optsJson, modePos);
                  } else {
                    if (optsJson.compare(modePos, 4, "null") == 0) {
                      modePos += 4;
                    } else {
                      while (modePos < optsJson.size() &&
                             optsJson[modePos] != ',' &&
                             optsJson[modePos] != ']') {
                        modePos++;
                      }
                    }
                  }
                  if (slot < (int)stdioModes.size()) {
                    stdioModes[slot] = normalizeStdioMode(parsed);
                  } else {
                    stdioModes.push_back(normalizeStdioMode(parsed));
                  }
                  slot++;
                  s_skipJsonWhitespace(optsJson, modePos);
                  if (modePos < optsJson.size() && optsJson[modePos] == ',') {
                    modePos++;
                  }
                }
              }
            }
          }
          envEntries = s_parseEnvFromOpts(optsJson, envPresent);
        }

        const bool stdinPipeRequested = stdioModes[0] == "pipe";
        const bool stdoutPipeRequested = stdioModes[1] == "pipe";
        const bool stderrPipeRequested = stdioModes[2] == "pipe";
        const bool ipcRequested = stdioModes[3] == "ipc";
        const bool stdinIgnoreRequested = stdioModes[0] == "ignore";
        const bool stdoutIgnoreRequested = stdioModes[1] == "ignore";
        const bool stderrIgnoreRequested = stdioModes[2] == "ignore";

        // Parse fd:N modes for stdio redirection to existing file descriptors
        int stdinFdRedirect = -1, stdoutFdRedirect = -1, stderrFdRedirect = -1;
        auto parseFdMode = [](const std::string& mode) -> int {
          if (mode.substr(0, 3) == "fd:") {
            return std::atoi(mode.c_str() + 3);
          }
          return -1;
        };
        stdinFdRedirect = parseFdMode(stdioModes[0]);
        stdoutFdRedirect = parseFdMode(stdioModes[1]);
        stderrFdRedirect = parseFdMode(stdioModes[2]);
        // (ENG-23485) NOTE: the trusted JS layer resolves fd:N-equals-slot to
        // 'inherit' before it reaches this bridge (Node's stdio:[0,1,2]), so
        // every fd:N seen here is a genuinely foreign fd and is always
        // ownership-checked below (ENG-22906: spawn authority does not imply
        // raw fd authority).

        auto currentPrincipalOwnsSpawnFd = [](int fd, bool needsRead, bool needsWrite) {
          if (fd < 0) {
            return false;
          }
          auto principal = currentPrincipalId();
          auto runtimeNonce = ex_hermes_current_runtime_nonce();
          std::lock_guard<std::mutex> lock(s_spawnMutex);
          for (const auto& pair : s_spawnedProcesses) {
            const auto& proc = pair.second;
            if (!proc || proc->runtimeNonce != runtimeNonce ||
                proc->owner != principal) {
              continue;
            }
            if (fd == proc->stdinFd) {
              if (needsRead) return false;
              if (needsWrite) return true;
            }
            if (fd == proc->stdoutFd || fd == proc->stderrFd) {
              if (needsWrite) return false;
              if (needsRead) return true;
            }
            if (fd == proc->ipcFd) {
              return true;
            }
            for (int extraFd : proc->extraFds) {
              if (fd == extraFd) {
                return true;
              }
            }
          }
          return false;
        };

        auto requireRedirectFd = [&](int fd, bool needsRead, bool needsWrite, const char* syscall) {
          if (fd < 0) {
            return;
          }
          requireSpawnDescriptorAlias(runtime, fd, needsRead, needsWrite, syscall);
          if (currentPrincipalOwnsSpawnFd(fd, needsRead, needsWrite)) {
            return;
          }
          try {
            if (needsRead) {
              exactRequireFdReadable(runtime, fd, syscall);
            }
            if (needsWrite) {
              exactRequireFdWritable(runtime, fd, syscall);
            }
          } catch (const facebook::jsi::JSError&) {
            throw facebook::jsi::JSError(
                runtime, std::string(syscall) + ": fd is not owned by this principal");
          }
        };

        // @ref LLP 0013#policy — raw fd integers are forgeable. Validate every
        // fd:N stdio redirect before fork so process:spawn cannot smuggle an
        // unowned host/internal descriptor into the child.
        requireRedirectFd(stdinFdRedirect, true, false, "__exactSpawn stdio[0]");
        requireRedirectFd(stdoutFdRedirect, false, true, "__exactSpawn stdio[1]");
        requireRedirectFd(stderrFdRedirect, false, true, "__exactSpawn stdio[2]");
        ScopedSpawnFd safeStdinRedirect(stdinFdRedirect);
        ScopedSpawnFd safeStdoutRedirect(stdoutFdRedirect);
        ScopedSpawnFd safeStderrRedirect(stderrFdRedirect);
        if ((stdinFdRedirect >= 0 && safeStdinRedirect.fd < 0) ||
            (stdoutFdRedirect >= 0 && safeStdoutRedirect.fd < 0) ||
            (stderrFdRedirect >= 0 && safeStderrRedirect.fd < 0)) {
          return facebook::jsi::Value(facebook::jsi::String::createFromUtf8(
              runtime, "{\"error\":\"Failed to duplicate stdio redirect\"}"));
        }

        // Create pipes for stdin, stdout, stderr
        int stdinPipeFd[2] = {-1, -1};
        int stdoutPipeFd[2] = {-1, -1};
        int stderrPipeFd[2] = {-1, -1};
        int ipcPair[2] = {-1, -1};

        if (stdinPipeRequested && pipe(stdinPipeFd) != 0) {
          return facebook::jsi::Value(
              facebook::jsi::String::createFromUtf8(runtime, "{\"error\":\"Failed to create stdin pipe\"}"));
        }
        if (stdoutPipeRequested && pipe(stdoutPipeFd) != 0) {
          if (stdinPipeFd[0] >= 0) {
            close(stdinPipeFd[0]);
          }
          if (stdinPipeFd[1] >= 0) {
            close(stdinPipeFd[1]);
          }
          return facebook::jsi::Value(
              facebook::jsi::String::createFromUtf8(runtime, "{\"error\":\"Failed to create stdout pipe\"}"));
        }
        if (stderrPipeRequested && pipe(stderrPipeFd) != 0) {
          if (stdinPipeFd[0] >= 0) close(stdinPipeFd[0]);
          if (stdinPipeFd[1] >= 0) close(stdinPipeFd[1]);
          if (stdoutPipeFd[0] >= 0) close(stdoutPipeFd[0]);
          if (stdoutPipeFd[1] >= 0) close(stdoutPipeFd[1]);
          return facebook::jsi::Value(
              facebook::jsi::String::createFromUtf8(runtime, "{\"error\":\"Failed to create stderr pipe\"}"));
        }
        if (ipcRequested && socketpair(AF_UNIX, SOCK_STREAM, 0, ipcPair) != 0) {
          if (stdinPipeFd[0] >= 0) close(stdinPipeFd[0]);
          if (stdinPipeFd[1] >= 0) close(stdinPipeFd[1]);
          if (stdoutPipeFd[0] >= 0) close(stdoutPipeFd[0]);
          if (stdoutPipeFd[1] >= 0) close(stdoutPipeFd[1]);
          if (stderrPipeFd[0] >= 0) close(stderrPipeFd[0]);
          if (stderrPipeFd[1] >= 0) close(stderrPipeFd[1]);
          return facebook::jsi::Value(
              facebook::jsi::String::createFromUtf8(runtime, "{\"error\":\"Failed to create IPC socketpair\"}"));
        }

        // Set FD_CLOEXEC on parent-retained pipe fds so they don't leak
        // to subsequently spawned child processes.  Without this, piping
        // echo | grep | sed fails because sed inherits the write end of
        // grep's stdin pipe, preventing grep from seeing EOF.
        if (stdinPipeRequested && stdinPipeFd[1] >= 0)
          fcntl(stdinPipeFd[1], F_SETFD, FD_CLOEXEC);
        if (stdoutPipeRequested && stdoutPipeFd[0] >= 0)
          fcntl(stdoutPipeFd[0], F_SETFD, FD_CLOEXEC);
        if (stderrPipeRequested && stderrPipeFd[0] >= 0)
          fcntl(stderrPipeFd[0], F_SETFD, FD_CLOEXEC);
        // ENG-23113 — the CHILD-side ends also need FD_CLOEXEC. This child
        // dup2's them onto STDIN/OUT/ERR and closes the originals before exec, so
        // CLOEXEC does not affect it; but without CLOEXEC a *concurrently* spawned
        // child (another fork racing between this fork and exec) inherits them and
        // they leak into it — the same leak the parent ends above guard against.
        if (stdinPipeRequested && stdinPipeFd[0] >= 0)
          fcntl(stdinPipeFd[0], F_SETFD, FD_CLOEXEC);
        if (stdoutPipeRequested && stdoutPipeFd[1] >= 0)
          fcntl(stdoutPipeFd[1], F_SETFD, FD_CLOEXEC);
        if (stderrPipeRequested && stderrPipeFd[1] >= 0)
          fcntl(stderrPipeFd[1], F_SETFD, FD_CLOEXEC);
        if (ipcRequested) {
          if (ipcPair[0] >= 0) fcntl(ipcPair[0], F_SETFD, FD_CLOEXEC);
          if (ipcPair[1] >= 0) fcntl(ipcPair[1], F_SETFD, FD_CLOEXEC);
        }

        // Create pipes for extra stdio entries (index 4+)
        std::vector<std::pair<int,int>> extraPipes; // (parentFd, childFd) pairs
        for (size_t i = 4; i < stdioModes.size(); i++) {
          if (stdioModes[i] == "pipe") {
            int ep[2] = {-1, -1};
            if (socketpair(AF_UNIX, SOCK_STREAM, 0, ep) != 0) {
              // Clean up on failure
              for (auto& p : extraPipes) { close(p.first); close(p.second); }
              if (stdinPipeFd[0] >= 0) close(stdinPipeFd[0]);
              if (stdinPipeFd[1] >= 0) close(stdinPipeFd[1]);
              if (stdoutPipeFd[0] >= 0) close(stdoutPipeFd[0]);
              if (stdoutPipeFd[1] >= 0) close(stdoutPipeFd[1]);
              if (stderrPipeFd[0] >= 0) close(stderrPipeFd[0]);
              if (stderrPipeFd[1] >= 0) close(stderrPipeFd[1]);
              if (ipcPair[0] >= 0) close(ipcPair[0]);
              if (ipcPair[1] >= 0) close(ipcPair[1]);
              return facebook::jsi::Value(
                  facebook::jsi::String::createFromUtf8(runtime, "{\"error\":\"Failed to create extra stdio pipe\"}"));
            }
            fcntl(ep[0], F_SETFD, FD_CLOEXEC);
            // ENG-23113 — CLOEXEC the child end too (this child dup2's + closes
            // it before exec; keeps it from leaking into a concurrently spawned child).
            fcntl(ep[1], F_SETFD, FD_CLOEXEC);
            extraPipes.push_back({ep[0], ep[1]});
          } else {
            extraPipes.push_back({-1, -1});
          }
        }

        // Create an exec error pipe to detect ENOENT and other exec failures.
        // The write end has CLOEXEC so it auto-closes on successful exec.
        // If exec fails, the child writes errno to this pipe before _exit.
        int execErrPipe[2] = {-1, -1};
        if (pipe(execErrPipe) != 0) {
          if (stdinPipeFd[0] >= 0) close(stdinPipeFd[0]);
          if (stdinPipeFd[1] >= 0) close(stdinPipeFd[1]);
          if (stdoutPipeFd[0] >= 0) close(stdoutPipeFd[0]);
          if (stdoutPipeFd[1] >= 0) close(stdoutPipeFd[1]);
          if (stderrPipeFd[0] >= 0) close(stderrPipeFd[0]);
          if (stderrPipeFd[1] >= 0) close(stderrPipeFd[1]);
          if (ipcPair[0] >= 0) close(ipcPair[0]);
          if (ipcPair[1] >= 0) close(ipcPair[1]);
          return facebook::jsi::Value(
              facebook::jsi::String::createFromUtf8(runtime, "{\"error\":\"Failed to create exec error pipe\"}"));
        }
        fcntl(execErrPipe[1], F_SETFD, FD_CLOEXEC);

        int ipcFd = -1;
        if (ipcRequested) {
          for (size_t si = 0; si < stdioModes.size(); si++) {
            if (stdioModes[si] == "ipc") {
              ipcFd = static_cast<int>(si);
              break;
            }
          }
        }
        int firstSafeChildFd = std::max<int>(4, static_cast<int>(stdioModes.size()));
        bool childFdsReserved = s_liftChildFd(execErrPipe[1], firstSafeChildFd) &&
            (!stdinPipeRequested || s_liftChildFd(stdinPipeFd[0], firstSafeChildFd)) &&
            (!stdoutPipeRequested || s_liftChildFd(stdoutPipeFd[1], firstSafeChildFd)) &&
            (!stderrPipeRequested || s_liftChildFd(stderrPipeFd[1], firstSafeChildFd)) &&
            (!ipcRequested || s_liftChildFd(ipcPair[0], firstSafeChildFd)) &&
            s_liftChildFd(safeStdinRedirect.fd, firstSafeChildFd) &&
            s_liftChildFd(safeStdoutRedirect.fd, firstSafeChildFd) &&
            s_liftChildFd(safeStderrRedirect.fd, firstSafeChildFd);
        for (auto& pipePair : extraPipes) {
          childFdsReserved = childFdsReserved &&
              s_liftChildFd(pipePair.second, firstSafeChildFd);
        }
        if (!childFdsReserved) {
          close(execErrPipe[0]);
          close(execErrPipe[1]);
          if (stdinPipeFd[0] >= 0) close(stdinPipeFd[0]);
          if (stdinPipeFd[1] >= 0) close(stdinPipeFd[1]);
          if (stdoutPipeFd[0] >= 0) close(stdoutPipeFd[0]);
          if (stdoutPipeFd[1] >= 0) close(stdoutPipeFd[1]);
          if (stderrPipeFd[0] >= 0) close(stderrPipeFd[0]);
          if (stderrPipeFd[1] >= 0) close(stderrPipeFd[1]);
          if (ipcPair[0] >= 0) close(ipcPair[0]);
          if (ipcPair[1] >= 0) close(ipcPair[1]);
          for (auto& pipePair : extraPipes) {
            if (pipePair.first >= 0) close(pipePair.first);
            if (pipePair.second >= 0) close(pipePair.second);
          }
          return facebook::jsi::Value(facebook::jsi::String::createFromUtf8(
              runtime, "{\"error\":\"Failed to reserve child descriptors\"}"));
        }
        auto execPlan = s_buildSpawnExecPlan(
            file, spawnArgs, "", useShell, shellPath, cwd, envEntries,
            envPresent, ipcFd);

        pid_t pid = s_forkChild();
        if (pid < 0) {
          close(execErrPipe[0]);
          close(execErrPipe[1]);
          if (stdinPipeFd[0] >= 0) close(stdinPipeFd[0]);
          if (stdinPipeFd[1] >= 0) close(stdinPipeFd[1]);
          if (stdoutPipeFd[0] >= 0) close(stdoutPipeFd[0]);
          if (stdoutPipeFd[1] >= 0) close(stdoutPipeFd[1]);
          if (stderrPipeFd[0] >= 0) close(stderrPipeFd[0]);
          if (stderrPipeFd[1] >= 0) close(stderrPipeFd[1]);
          // ENG-23113 — no SpawnedProcess is stored on failure, so close every
          // fd the parent still holds. Previously ipcPair and extraPipes leaked here.
          if (ipcPair[0] >= 0) close(ipcPair[0]);
          if (ipcPair[1] >= 0) close(ipcPair[1]);
          for (auto& p : extraPipes) {
            if (p.first >= 0) close(p.first);
            if (p.second >= 0) close(p.second);
          }
          return facebook::jsi::Value(
              facebook::jsi::String::createFromUtf8(runtime, "{\"error\":\"Failed to fork process\"}"));
        }

        if (pid == 0) {
          // Child process
          close(execErrPipe[0]); // close read end in child
          // (ENG-23032) When detached, start a new session so the child becomes
          // the leader of its own process group (pgid == pid). This makes
          // process.kill(-pid) target the child's group and detaches it from the
          // controlling terminal's signal delivery (Node's detached behavior).
          // A freshly forked child is never already a group leader, so setsid()
          // succeeds; guard with setpgid as a defensive fallback.
          if (detached) {
            if (setsid() < 0) {
              setpgid(0, 0);
            }
          }
          if (stdinPipeRequested) {
            close(stdinPipeFd[1]);
            int mapError = s_mapChildFd(stdinPipeFd[0], STDIN_FILENO);
            if (mapError != 0) s_reportChildSetupFailure(execErrPipe[1], mapError);
          } else if (safeStdinRedirect.fd >= 0) {
            int mapError = s_mapChildFd(safeStdinRedirect.fd, STDIN_FILENO);
            if (mapError != 0) s_reportChildSetupFailure(execErrPipe[1], mapError);
            int stdinFlags = fcntl(STDIN_FILENO, F_GETFL, 0);
            if (stdinFlags >= 0 && (stdinFlags & O_NONBLOCK)) {
              fcntl(STDIN_FILENO, F_SETFL, stdinFlags & ~O_NONBLOCK);
            }
          } else if (stdinIgnoreRequested) {
            int nullStdin = open("/dev/null", O_RDONLY);
            if (nullStdin >= 0) {
              int mapError = s_mapChildFd(nullStdin, STDIN_FILENO);
              if (mapError != 0) s_reportChildSetupFailure(execErrPipe[1], mapError);
            }
          }

          if (stdoutPipeRequested) {
            close(stdoutPipeFd[0]);
            int mapError = s_mapChildFd(stdoutPipeFd[1], STDOUT_FILENO);
            if (mapError != 0) s_reportChildSetupFailure(execErrPipe[1], mapError);
          } else if (safeStdoutRedirect.fd >= 0) {
            int mapError = s_mapChildFd(safeStdoutRedirect.fd, STDOUT_FILENO);
            if (mapError != 0) s_reportChildSetupFailure(execErrPipe[1], mapError);
            int stdoutFlags = fcntl(STDOUT_FILENO, F_GETFL, 0);
            if (stdoutFlags >= 0 && (stdoutFlags & O_NONBLOCK)) {
              fcntl(STDOUT_FILENO, F_SETFL, stdoutFlags & ~O_NONBLOCK);
            }
          } else if (stdoutIgnoreRequested) {
            int nullStdout = open("/dev/null", O_WRONLY);
            if (nullStdout >= 0) {
              int mapError = s_mapChildFd(nullStdout, STDOUT_FILENO);
              if (mapError != 0) s_reportChildSetupFailure(execErrPipe[1], mapError);
            }
          }

          if (stderrPipeRequested) {
            close(stderrPipeFd[0]);
            int mapError = s_mapChildFd(stderrPipeFd[1], STDERR_FILENO);
            if (mapError != 0) s_reportChildSetupFailure(execErrPipe[1], mapError);
          } else if (safeStderrRedirect.fd >= 0) {
            int mapError = s_mapChildFd(safeStderrRedirect.fd, STDERR_FILENO);
            if (mapError != 0) s_reportChildSetupFailure(execErrPipe[1], mapError);
            int stderrFlags = fcntl(STDERR_FILENO, F_GETFL, 0);
            if (stderrFlags >= 0 && (stderrFlags & O_NONBLOCK)) {
              fcntl(STDERR_FILENO, F_SETFL, stderrFlags & ~O_NONBLOCK);
            }
          } else if (stderrIgnoreRequested) {
            int nullStderr = open("/dev/null", O_WRONLY);
            if (nullStderr >= 0) {
              int mapError = s_mapChildFd(nullStderr, STDERR_FILENO);
              if (mapError != 0) s_reportChildSetupFailure(execErrPipe[1], mapError);
            }
          }

          if (ipcRequested) {
            close(ipcPair[1]);
            int mapError = s_mapChildFd(ipcPair[0], ipcFd);
            if (mapError != 0) s_reportChildSetupFailure(execErrPipe[1], mapError);
            // Set IPC fd to non-blocking so child's poll reads don't hang
            int ipcFlags = fcntl(ipcFd, F_GETFL, 0);
            if (ipcFlags >= 0) {
              fcntl(ipcFd, F_SETFL, ipcFlags | O_NONBLOCK);
            }
          }

          // Set up extra stdio pipes (index 4+)
          for (size_t i = 0; i < extraPipes.size(); i++) {
            if (extraPipes[i].second >= 0) {
              close(extraPipes[i].first); // close parent end in child
              int targetFd = static_cast<int>(i + 4);
              int mapError = s_mapChildFd(extraPipes[i].second, targetFd);
              if (mapError != 0) s_reportChildSetupFailure(execErrPipe[1], mapError);
            }
          }

          if (!stdinPipeRequested) {
            if (stdinPipeFd[0] >= 0) close(stdinPipeFd[0]);
            if (stdinPipeFd[1] >= 0) close(stdinPipeFd[1]);
          }
          if (!stdoutPipeRequested) {
            if (stdoutPipeFd[0] >= 0) close(stdoutPipeFd[0]);
            if (stdoutPipeFd[1] >= 0) close(stdoutPipeFd[1]);
          }
          if (!stderrPipeRequested) {
            if (stderrPipeFd[0] >= 0) close(stderrPipeFd[0]);
            if (stderrPipeFd[1] >= 0) close(stderrPipeFd[1]);
          }
          if (!ipcRequested) {
            if (ipcPair[0] >= 0) close(ipcPair[0]);
            if (ipcPair[1] >= 0) close(ipcPair[1]);
          }

          if (!cwd.empty()) {
            if (chdir(cwd.c_str()) != 0) {
              int chdirErrno = errno;
              ssize_t nw = write(execErrPipe[1], &chdirErrno, sizeof(chdirErrno));
              (void)nw;
              _exit(127);
            }
          }

          // (ENG-23485) Apply options.gid/options.uid (gid first) between fork
          // and exec; failure reports through the exec error pipe so JS
          // surfaces spawn EPERM instead of silently keeping parent credentials.
          {
            int credErrno = s_applySpawnCredentials(spawnGid, spawnUid);
            if (credErrno != 0) {
              ssize_t nw = write(execErrPipe[1], &credErrno, sizeof(credErrno));
              (void)nw;
              _exit(127);
            }
          }

          s_execChild(execPlan.executable.c_str(), execPlan.argv.data(), execPlan.envp.data());
          // exec failed - write errno to parent via the error pipe
          {
            int execErrno = errno;
            ssize_t nw = write(execErrPipe[1], &execErrno, sizeof(execErrno));
            (void)nw;
          }
          _exit(127);
        }

        // Parent process - check if exec succeeded or failed
        close(execErrPipe[1]); // close write end in parent
        {
          int childErrno = 0;
          ssize_t n = read(execErrPipe[0], &childErrno, sizeof(childErrno));
          close(execErrPipe[0]);

          if (n > 0) {
            // Exec failed in the child - reap it and return error
            int wstatus;
            waitpid(pid, &wstatus, 0);
            // ENG-23113 — close EVERY fd the parent still holds. No
            // SpawnedProcess is stored on exec failure, so there is no
            // __exactSpawnDispose to reclaim these later. Previously only the
            // parent-retained ends below were closed; the child-side ends the
            // parent also holds (the child exited, but the parent's copies remain)
            // and every extraPipes fd leaked permanently -> EMFILE for a process
            // that probes for optional/missing binaries.
            // Parent-retained ends:
            if (stdinPipeRequested && stdinPipeFd[1] >= 0) close(stdinPipeFd[1]);
            if (stdoutPipeRequested && stdoutPipeFd[0] >= 0) close(stdoutPipeFd[0]);
            if (stderrPipeRequested && stderrPipeFd[0] >= 0) close(stderrPipeFd[0]);
            if (ipcRequested && ipcPair[1] >= 0) close(ipcPair[1]);
            // Child-side ends the parent still holds (the success path closes
            // these once the child has inherited them; here the child is gone):
            if (stdinPipeRequested && stdinPipeFd[0] >= 0) close(stdinPipeFd[0]);
            if (stdoutPipeRequested && stdoutPipeFd[1] >= 0) close(stdoutPipeFd[1]);
            if (stderrPipeRequested && stderrPipeFd[1] >= 0) close(stderrPipeFd[1]);
            if (ipcRequested && ipcPair[0] >= 0) close(ipcPair[0]);
            for (auto& p : extraPipes) {
              if (p.first >= 0) close(p.first);
              if (p.second >= 0) close(p.second);
            }

            std::string errName;
            if (childErrno == ENOENT) errName = "ENOENT";
            else if (childErrno == EACCES) errName = "EACCES";
            else if (childErrno == EPERM) errName = "EPERM";
            else if (childErrno == ENOEXEC) errName = "ENOEXEC";
            else errName = "UNKNOWN";

            std::string errorJson = "{\"error\":\"" + errName
                + "\",\"errno\":" + std::to_string(childErrno)
                + ",\"path\":\"" + file + "\"}";
            return facebook::jsi::Value(
                facebook::jsi::String::createFromUtf8(runtime, errorJson));
          }
        }

        if (stdinPipeRequested) close(stdinPipeFd[0]);   // close read end of stdin pipe (child reads)
        if (stdoutPipeRequested) close(stdoutPipeFd[1]); // close write end of stdout pipe (child writes)
        if (stderrPipeRequested) close(stderrPipeFd[1]); // close write end of stderr pipe (child writes)
        if (ipcRequested) close(ipcPair[0]); // close read end in parent

        if (stdinPipeRequested) {
          int flags = fcntl(stdinPipeFd[1], F_GETFL, 0);
          if (flags >= 0) {
            fcntl(stdinPipeFd[1], F_SETFL, flags | O_NONBLOCK);
          }
        }
        if (stdoutPipeRequested) fcntl(stdoutPipeFd[0], F_SETFL, O_NONBLOCK);
        if (stderrPipeRequested) fcntl(stderrPipeFd[0], F_SETFL, O_NONBLOCK);
        if (ipcRequested) {
          int flags = fcntl(ipcPair[1], F_GETFL, 0);
          if (flags >= 0) {
            fcntl(ipcPair[1], F_SETFL, flags | O_NONBLOCK);
          }
        }

        auto proc = std::make_shared<SpawnedProcess>();
        proc->runtimeNonce = ex_hermes_current_runtime_nonce();
        proc->owner = currentPrincipalId();
        proc->capability = "process:spawn";
        proc->pid = pid;
        proc->stdinFd = stdinPipeRequested ? stdinPipeFd[1] : -1;
        proc->stdoutFd = stdoutPipeRequested ? stdoutPipeFd[0] : -1;
        proc->stderrFd = stderrPipeRequested ? stderrPipeFd[0] : -1;
        proc->ipcFd = ipcRequested ? ipcPair[1] : -1;
        for (size_t i = 0; i < extraPipes.size(); i++) {
          int extraFlags = fcntl(extraPipes[i].first, F_GETFL, 0);
          if (extraFlags >= 0) {
            fcntl(extraPipes[i].first, F_SETFL, extraFlags | O_NONBLOCK);
          }
          proc->extraFds.push_back(extraPipes[i].first);
          if (extraPipes[i].second >= 0) close(extraPipes[i].second);
        }

        std::optional<int> handle;
        {
          std::lock_guard<std::mutex> lock(s_spawnMutex);
          handle = allocateSpawnHandleLocked();
          if (handle) {
            auto [_, inserted] = s_spawnedProcesses.emplace(*handle, proc);
            if (!inserted) handle.reset();
          }
        }
        if (!handle) {
          kill(pid, SIGKILL);
          while (waitpid(pid, nullptr, 0) < 0 && errno == EINTR) {}
          closeSpawnedProcessFds(proc);
          return facebook::jsi::Value(facebook::jsi::String::createFromUtf8(
              runtime,
              "{\"error\":\"ERR_OUT_OF_RANGE\",\"errno\":-1,\"message\":\"spawn handle space exhausted\"}"));
        }

        std::string resultJson = "{\"handle\":" + std::to_string(*handle)
            + ",\"pid\":" + std::to_string(static_cast<int>(pid)) + "}";
        return facebook::jsi::Value(
            facebook::jsi::String::createFromUtf8(runtime, resultJson));
      });
  rt.global().setProperty(rt, "__exactSpawn", std::move(spawnFn));

  // __exactSpawnRead(handle, stream) -> Uint8Array (raw bytes read, empty if
  // nothing available). `_exactEof` distinguishes EOF from EAGAIN. One bounded
  // read per call prevents a chatty child from monopolizing the JS turn.
  // (ENG-23009) The data channel is byte-accurate: child output is handed to JS
  // as raw bytes rather than a UTF-8 string, so bytes >= 0x80 and NULs survive
  // the native->JS boundary instead of being mangled by createFromUtf8/U+FFFD.
  // IPC callers UTF-8 decode the bytes themselves (packets are ASCII/UTF-8 JSON).
  auto spawnReadFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactSpawnRead"),
      2,
      [trySpawnHandle](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        auto makeReadResult = [&](std::vector<uint8_t> bytes, bool eof) {
          auto value = makeUint8Array(runtime, std::move(bytes));
          auto object = value.asObject(runtime);
          object.setProperty(runtime, "_exactEof", facebook::jsi::Value(eof));
          return facebook::jsi::Value(std::move(object));
        };
        if (count < 2 || !args[0].isNumber()) {
          return makeReadResult({}, true);
        }
        int handle = static_cast<int>(args[0].asNumber());
        auto proc = trySpawnHandle(runtime, handle, "__exactSpawnRead");
        if (!proc) {
          return makeReadResult({}, true);
        }
        std::string streamName;
        if (args[1].isString()) {
          streamName = args[1].toString(runtime).utf8(runtime);
        } else if (args[1].isNumber()) {
          int streamIndex = static_cast<int>(args[1].asNumber());
          switch (streamIndex) {
            case 1:
              streamName = "stdout";
              break;
            case 2:
              streamName = "stderr";
              break;
            case 3:
              streamName = "ipc";
              break;
            default:
              if (streamIndex >= 4) {
                streamName = "extra:" + std::to_string(streamIndex - 4);
              } else {
                return makeReadResult({}, true);
              }
          }
        } else {
          return makeReadResult({}, true);
        }

        int fd = -1;
        if (streamName == "stdout") {
          fd = proc->stdoutFd;
        } else if (streamName == "stderr") {
          fd = proc->stderrFd;
        } else if (streamName == "ipc") {
          fd = proc->ipcFd;
        } else if (auto extraIdx = s_parseExtraStreamName(streamName)) {
          if (*extraIdx < proc->extraFds.size()) {
            fd = proc->extraFds[*extraIdx];
          }
        }

        if (fd < 0) {
          if (streamName == "ipc" && startup_trace_enabled()) {
            fprintf(stderr, "[spawn_read] ipc fd=-1 for handle %d\n", handle);
          }
          return makeReadResult({}, true);
        }

        // One non-blocking chunk per call. JS owns the scheduling/backpressure
        // policy and will promptly call again after activity.
        char buf[65536];
        std::vector<uint8_t> result;
        ssize_t n;
        do {
          n = read(fd, buf, sizeof(buf));
        } while (n < 0 && errno == EINTR);
        bool eof = n == 0;
        if (n > 0) result.insert(result.end(), buf, buf + n);
        if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) eof = true;
        if (streamName == "ipc" && startup_trace_enabled() && n < 0) {
          fprintf(stderr, "[spawn_read] ipc fd=%d errno=%d (%s)\n", fd, errno, strerror(errno));
        }

        if (!result.empty() && streamName == "ipc" && startup_trace_enabled()) {
          fprintf(stderr, "[spawn_read] ipc fd=%d got %zu bytes\n", fd, result.size());
        }

        return makeReadResult(std::move(result), eof);
      });
  rt.global().setProperty(rt, "__exactSpawnRead", std::move(spawnReadFn));

  // __exactSpawnGetFd(handle, streamIndex) -> raw fd or -1
  // streamIndex: 0=stdin, 1=stdout, 2=stderr, 3=ipc
  auto spawnGetFdFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactSpawnGetFd"),
      2,
      [trySpawnHandle](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 2 || !args[0].isNumber() || !args[1].isNumber()) {
          return facebook::jsi::Value(-1);
        }
        int handle = static_cast<int>(args[0].asNumber());
        auto proc = trySpawnHandle(runtime, handle, "__exactSpawnGetFd");
        if (!proc) {
          return facebook::jsi::Value(-1);
        }
        int streamIndex = static_cast<int>(args[1].asNumber());
        switch (streamIndex) {
          case 0: return facebook::jsi::Value(proc->stdinFd);
          case 1: return facebook::jsi::Value(proc->stdoutFd);
          case 2: return facebook::jsi::Value(proc->stderrFd);
          case 3: return facebook::jsi::Value(proc->ipcFd);
          default: {
            int extraIdx = streamIndex - 4;
            if (extraIdx >= 0 && extraIdx < (int)proc->extraFds.size()) {
              return facebook::jsi::Value(proc->extraFds[extraIdx]);
            }
            return facebook::jsi::Value(-1);
          }
        }
      });
  rt.global().setProperty(rt, "__exactSpawnGetFd", std::move(spawnGetFdFn));

  // __exactSpawnWrite(handle, data, stream?) -> number
  // For stdio pipes this returns the number of bytes written (0 on EAGAIN).
  // IPC writes still attempt to write the full payload and return bytes written.
  // (ENG-23009) `data` may be a Uint8Array/ArrayBuffer (byte-accurate, used for
  // stdin/relay writes so bytes >= 0x80 are not UTF-8 re-encoded) or a string
  // (used by the IPC JSON packet path, which is ASCII/UTF-8 already).
  auto spawnWriteFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactSpawnWrite"),
      3,
      [trySpawnHandle](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 2 || !args[0].isNumber()) {
          return facebook::jsi::Value(-1);
        }
        int handle = static_cast<int>(args[0].asNumber());
        auto proc = trySpawnHandle(runtime, handle, "__exactSpawnWrite");
        if (!proc) {
          return facebook::jsi::Value(-1);
        }
        // Collect the payload as raw bytes from either a string or a byte view.
        std::string strHolder;
        const uint8_t* payload = nullptr;
        size_t payloadLen = 0;
        if (args[1].isString()) {
          strHolder = args[1].toString(runtime).utf8(runtime);
          payload = reinterpret_cast<const uint8_t*>(strHolder.data());
          payloadLen = strHolder.size();
        } else if (args[1].isObject()) {
          auto obj = args[1].asObject(runtime);
          if (!extractArrayBufferView(runtime, obj, payload, payloadLen)) {
            return facebook::jsi::Value(-1);
          }
        } else {
          return facebook::jsi::Value(-1);
        }
        auto streamName = std::string("stdin");
        if (count > 2 && args[2].isString()) {
          streamName = args[2].toString(runtime).utf8(runtime);
        }

        int fd = -1;
        if (streamName == "stdin") {
          fd = proc->stdinFd;
        } else if (streamName == "ipc") {
          fd = proc->ipcFd;
        } else if (auto extraIdx = s_parseExtraStreamName(streamName)) {
          if (*extraIdx < proc->extraFds.size()) {
            fd = proc->extraFds[*extraIdx];
          }
        }

        if (fd < 0) {
          if (streamName == "ipc" && startup_trace_enabled()) {
            fprintf(stderr, "[spawn_write] ipc fd=-1 for handle %d\n", handle);
          }
          return facebook::jsi::Value(-1);
        }

        if (streamName == "ipc" && startup_trace_enabled()) {
          fprintf(stderr, "[spawn_write] ipc fd=%d data_len=%zu\n", fd, payloadLen);
        }

        if (streamName != "ipc") {
          while (true) {
            ssize_t n = write(fd, payload, payloadLen);
            if (n < 0) {
              if (errno == EINTR) continue;
              if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return facebook::jsi::Value(0);
              }
              return facebook::jsi::Value(-1);
            }
            return facebook::jsi::Value(static_cast<int>(n));
          }
        }

        size_t totalWritten = 0;
        while (totalWritten < payloadLen) {
          ssize_t n = write(fd, payload + totalWritten, payloadLen - totalWritten);
          if (n < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
              return facebook::jsi::Value(static_cast<int>(totalWritten));
            }
            if (startup_trace_enabled()) {
              fprintf(stderr, "[spawn_write] ipc write error: fd=%d errno=%d (%s)\n", fd, errno, strerror(errno));
            }
            return facebook::jsi::Value(-1);
          }
          totalWritten += static_cast<size_t>(n);
        }
        return facebook::jsi::Value(static_cast<int>(totalWritten));
      });
  rt.global().setProperty(rt, "__exactSpawnWrite", std::move(spawnWriteFn));

  // __exactSpawnSendMsg(handle, data, sendFd?) -> number
  // Sends data to the child's IPC socket using sendmsg and returns the byte
  // count the kernel accepted (0 on EAGAIN — retry later) or -1 on a hard
  // failure. `data` may be a string or a Uint8Array/ArrayBuffer view. If
  // sendFd >= 0 the descriptor rides SCM_RIGHTS on this call, so the caller
  // must attach it only to the FIRST chunk of a framed packet (ENG-23231:
  // partial sends are queued and resumed by the JS side, mirroring the
  // child-side __exactIpcSendMsg contract).
  auto spawnSendMsgFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactSpawnSendMsg"),
      3,
      [trySpawnHandle](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 2 || !args[0].isNumber()) {
          return facebook::jsi::Value(-1);
        }
        int handle = static_cast<int>(args[0].asNumber());
        auto proc = trySpawnHandle(runtime, handle, "__exactSpawnSendMsg");
        if (!proc) {
          return facebook::jsi::Value(-1);
        }
        std::string strHolder;
        const uint8_t* payload = nullptr;
        size_t payloadLen = 0;
        if (args[1].isString()) {
          strHolder = args[1].toString(runtime).utf8(runtime);
          payload = reinterpret_cast<const uint8_t*>(strHolder.data());
          payloadLen = strHolder.size();
        } else if (args[1].isObject()) {
          auto obj = args[1].asObject(runtime);
          if (!extractArrayBufferView(runtime, obj, payload, payloadLen)) {
            return facebook::jsi::Value(-1);
          }
        } else {
          return facebook::jsi::Value(-1);
        }
        int sendFd = -1;
        if (count > 2 && args[2].isNumber()) {
          sendFd = static_cast<int>(args[2].asNumber());
        }
        if (sendFd >= 0) {
          exactRequireTransferableFd(runtime, sendFd, "__exactSpawnSendMsg");
        }

        int ipcFd = proc->ipcFd;
        if (ipcFd < 0) return facebook::jsi::Value(-1);

        struct iovec iov;
        iov.iov_base = const_cast<uint8_t*>(payload);
        iov.iov_len = payloadLen;

        struct msghdr msg = {};
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;

        union {
          char buf[CMSG_SPACE(sizeof(int))];
          struct cmsghdr align;
        } cmsgBuf;

        if (sendFd >= 0) {
          memset(&cmsgBuf, 0, sizeof(cmsgBuf));
          msg.msg_control = cmsgBuf.buf;
          msg.msg_controllen = sizeof(cmsgBuf.buf);
          struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
          cmsg->cmsg_level = SOL_SOCKET;
          cmsg->cmsg_type = SCM_RIGHTS;
          cmsg->cmsg_len = CMSG_LEN(sizeof(int));
          memcpy(CMSG_DATA(cmsg), &sendFd, sizeof(int));
        }

        while (true) {
          ssize_t sent = ::sendmsg(ipcFd, &msg, 0);
          if (sent < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
              return facebook::jsi::Value(0);
            }
            return facebook::jsi::Value(-1);
          }
          return facebook::jsi::Value(static_cast<int>(sent));
        }
      });
  rt.global().setProperty(rt, "__exactSpawnSendMsg", std::move(spawnSendMsgFn));

  // __exactSpawnRecvMsg(handle) -> {data: Uint8Array, fd: number} or null
  // Receives data from the child's IPC socket using recvmsg. Returns
  // any SCM_RIGHTS file descriptor in the fd field (-1 if none).
  // (ENG-23485) data is raw bytes; JS decodes with a streaming UTF-8 decoder.
  auto spawnRecvMsgFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactSpawnRecvMsg"),
      1,
      [trySpawnHandle](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 1 || !args[0].isNumber()) {
          return facebook::jsi::Value::null();
        }
        int handle = static_cast<int>(args[0].asNumber());
        auto proc = trySpawnHandle(runtime, handle, "__exactSpawnRecvMsg");
        if (!proc) {
          return facebook::jsi::Value::null();
        }

        int ipcFd = proc->ipcFd;
        if (ipcFd < 0) return facebook::jsi::Value::null();

        char buf[65536];
        struct iovec iov;
        iov.iov_base = buf;
        iov.iov_len = sizeof(buf);

        union {
          char cbuf[CMSG_SPACE(sizeof(int))];
          struct cmsghdr align;
        } cmsgBuf;
        memset(&cmsgBuf, 0, sizeof(cmsgBuf));

        struct msghdr msg = {};
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsgBuf.cbuf;
        msg.msg_controllen = sizeof(cmsgBuf.cbuf);

        ssize_t bytesRead = ::recvmsg(ipcFd, &msg, 0);
        if (bytesRead <= 0) {
          return facebook::jsi::Value::null();
        }

        int recvFd = -1;
        struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
        while (cmsg != nullptr) {
          if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS) {
            memcpy(&recvFd, CMSG_DATA(cmsg), sizeof(int));
            if (recvFd >= 0) {
              fcntl(recvFd, F_SETFD, FD_CLOEXEC);
              if (!exactRegisterReceivedFdForCurrentPrincipal(recvFd)) {
                recvFd = -1;
              }
            }
            break;
          }
          cmsg = CMSG_NXTHDR(&msg, cmsg);
        }

        auto result = facebook::jsi::Object(runtime);
        // (ENG-23485) Hand JS the raw bytes, not a UTF-8 string: a 64KB
        // recvmsg chunk can split a multibyte UTF-8 sequence, and
        // createFromUtf8 replaced the halves with U+FFFD before JS could
        // reassemble them (the corrupted JSON line was then silently
        // dropped). JS feeds these bytes to a persistent streaming decoder,
        // same as the __exactSpawnRead byte channel (ENG-23009).
        std::vector<uint8_t> dataBytes(buf, buf + static_cast<size_t>(bytesRead));
        result.setProperty(runtime, "data", makeUint8Array(runtime, std::move(dataBytes)));
        result.setProperty(runtime, "fd", facebook::jsi::Value(recvFd));
        return result;
      });
  rt.global().setProperty(rt, "__exactSpawnRecvMsg", std::move(spawnRecvMsgFn));

  // __exactSpawnPoll(handle) -> JSON string {"exited":bool,"exitCode":N,"signal":N}
  // Uses waitpid with WNOHANG for non-blocking check.
  auto spawnPollFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactSpawnPoll"),
      1,
      [trySpawnHandle](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 1 || !args[0].isNumber()) {
          return facebook::jsi::Value(
              facebook::jsi::String::createFromUtf8(runtime, "{\"exited\":false,\"exitCode\":-1,\"signal\":0}"));
        }
        int handle = static_cast<int>(args[0].asNumber());
        auto proc = trySpawnHandle(runtime, handle, "__exactSpawnPoll");
        if (!proc) {
          return facebook::jsi::Value(
              facebook::jsi::String::createFromUtf8(runtime, "{\"exited\":true,\"exitCode\":-1,\"signal\":0}"));
        }

        if (proc->exited) {
          std::string json = "{\"exited\":true,\"exitCode\":" + std::to_string(proc->exitCode)
              + ",\"signal\":" + std::to_string(proc->exitSignal) + "}";
          return facebook::jsi::Value(
              facebook::jsi::String::createFromUtf8(runtime, json));
        }

        int status = 0;
        pid_t result = waitpid(proc->pid, &status, WNOHANG);
        if (result == 0) {
          // Still running
          return facebook::jsi::Value(
              facebook::jsi::String::createFromUtf8(runtime, "{\"exited\":false,\"exitCode\":-1,\"signal\":0}"));
        } else if (result > 0) {
          // Process exited
          proc->exited = true;
          if (WIFEXITED(status)) {
            proc->exitCode = WEXITSTATUS(status);
            proc->exitSignal = 0;
          } else if (WIFSIGNALED(status)) {
            proc->exitCode = -1;
            proc->exitSignal = WTERMSIG(status);
          }
          std::string json = "{\"exited\":true,\"exitCode\":" + std::to_string(proc->exitCode)
              + ",\"signal\":" + std::to_string(proc->exitSignal) + "}";
          return facebook::jsi::Value(
              facebook::jsi::String::createFromUtf8(runtime, json));
        } else {
          // waitpid error
          proc->exited = true;
          proc->exitCode = -1;
          std::string json = "{\"exited\":true,\"exitCode\":-1,\"signal\":0}";
          return facebook::jsi::Value(
              facebook::jsi::String::createFromUtf8(runtime, json));
        }
      });
  rt.global().setProperty(rt, "__exactSpawnPoll", std::move(spawnPollFn));

  // __exactSpawnKill(handle, signal) -> boolean (success)
  // signal: number (e.g. 15 for SIGTERM, 9 for SIGKILL)
  auto spawnKillFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactSpawnKill"),
      2,
      [trySpawnHandle](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 1 || !args[0].isNumber()) {
          return facebook::jsi::Value(false);
        }
        int handle = static_cast<int>(args[0].asNumber());
        auto proc = trySpawnHandle(runtime, handle, "__exactSpawnKill");
        if (!proc) {
          return facebook::jsi::Value(false);
        }
        int sig = SIGTERM; // default
        if (count > 1 && args[1].isNumber()) {
          sig = static_cast<int>(args[1].asNumber());
        }

        if (proc->exited) {
          return facebook::jsi::Value(false);
        }

        int killResult = kill(proc->pid, sig);
        return facebook::jsi::Value(killResult == 0);
      });
  rt.global().setProperty(rt, "__exactSpawnKill", std::move(spawnKillFn));

  // __exactSpawnSetReferenced(handle, referenced) -> boolean
  // Lifecycle reference state is object authority, not an ambient numeric
  // handle. Validate both runtime nonce and principal before changing it. This
  // intentionally does not re-check process:spawn: a capability revocation
  // must not prevent the owning process object from being safely unref'ed.
  auto spawnSetReferencedFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactSpawnSetReferenced"),
      2,
      [requireSpawnHandleOwnership](facebook::jsi::Runtime& runtime,
                                    const facebook::jsi::Value&,
                                    const facebook::jsi::Value* args,
                                    size_t count) -> facebook::jsi::Value {
        if (count < 2 || !args[0].isNumber() || !args[1].isBool()) {
          throw facebook::jsi::JSError(
              runtime,
              "__exactSpawnSetReferenced: numeric handle and boolean state required");
        }
        int handle = static_cast<int>(args[0].asNumber());
        auto proc = requireSpawnHandleOwnership(
            runtime, handle, "__exactSpawnSetReferenced");
        bool updated = false;
        {
          std::lock_guard<std::mutex> lock(s_spawnMutex);
          auto it = s_spawnedProcesses.find(handle);
          if (it != s_spawnedProcesses.end() && it->second == proc) {
            proc->referenced = args[1].getBool();
            updated = true;
          }
        }
        return facebook::jsi::Value(updated);
      });
  rt.global().setProperty(
      rt, "__exactSpawnSetReferenced", std::move(spawnSetReferencedFn));

  // __exactSpawnCloseStdin(handle, stream?, fullClose?) -> void
  // stdin/ipc close outright. Extra socketpairs half-close their writable side
  // for Duplex.end(), while Duplex.destroy() requests a full close.
  auto spawnCloseStdinFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactSpawnCloseStdin"),
      2,
      [trySpawnHandle](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 1 || !args[0].isNumber()) {
          return facebook::jsi::Value::undefined();
        }
        int handle = static_cast<int>(args[0].asNumber());
        auto proc = trySpawnHandle(runtime, handle, "__exactSpawnCloseStdin");
        if (!proc) {
          return facebook::jsi::Value::undefined();
        }
        auto streamName = std::string("stdin");
        if (count > 1 && args[1].isString()) {
          streamName = args[1].toString(runtime).utf8(runtime);
        }
        bool fullClose = count > 2 && args[2].isBool() && args[2].getBool();

        if (streamName == "ipc") {
          // Only close the IPC fd, not stdin
          if (proc->ipcFd >= 0) {
            close(proc->ipcFd);
            proc->ipcFd = -1;
          }
        } else if (streamName == "stdin") {
          if (proc->stdinFd >= 0) {
            close(proc->stdinFd);
            proc->stdinFd = -1;
          }
        } else if (auto extraIdx = s_parseExtraStreamName(streamName)) {
          if (*extraIdx < proc->extraFds.size()) {
            int& fd = proc->extraFds[*extraIdx];
            if (fd >= 0) {
              if (fullClose) {
                close(fd);
                fd = -1;
              } else {
                // Ignore ENOTCONN/EPIPE: a child may have closed first. Keep
                // the readable half registered until EOF or disposal.
                shutdown(fd, SHUT_WR);
              }
            }
          }
        }
        return facebook::jsi::Value::undefined();
      });
  rt.global().setProperty(rt, "__exactSpawnCloseStdin", std::move(spawnCloseStdinFn));

  // __exactSpawnDispose(handle) -> void
  // (ENG-23023) Release every parent-side fd captured for an async child and
  // drop its s_spawnedProcesses entry. The JS `close` handler calls this once the
  // child has exited and its streams are drained. Without it, each async spawn
  // permanently leaked its stdout/stderr (and any ipc/extra) read fds plus a map
  // entry, so a repeated spawn loop or per-request exec() marched to EMFILE. The
  // JS-only stub in child-process.js merely dropped the JS bookkeeping object;
  // installing this native fn overrides that stub so the kernel fds are freed.
  auto spawnDisposeFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactSpawnDispose"),
      1,
      [trySpawnHandle](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 1 || !args[0].isNumber()) {
          return facebook::jsi::Value::undefined();
        }
        int handle = static_cast<int>(args[0].asNumber());
        auto proc = trySpawnHandle(runtime, handle, "__exactSpawnDispose");
        if (!proc) {
          return facebook::jsi::Value::undefined();
        }

        // Detach the entry under the lock, then close its fds outside the lock.
        {
          std::lock_guard<std::mutex> lock(s_spawnMutex);
          auto it = s_spawnedProcesses.find(handle);
          if (it != s_spawnedProcesses.end() && it->second == proc) {
            s_spawnedProcesses.erase(it);
          } else {
            return facebook::jsi::Value::undefined();
          }
        }

        // The child has already been reaped by __exactSpawnPoll; here we only
        // reclaim the parent-side descriptors. Each may already be -1 if closed
        // earlier (e.g. stdin via __exactSpawnCloseStdin, ipc via disconnect).
        closeSpawnedProcessFds(proc);
        return facebook::jsi::Value::undefined();
      });
  rt.global().setProperty(rt, "__exactSpawnDispose", std::move(spawnDisposeFn));

  // __exactWhich(command) -> string path or null
  // Searches PATH for the given command, similar to the `which` utility.
  auto whichFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactWhich"),
      1,
      [handle](facebook::jsi::Runtime& runtime,
               const facebook::jsi::Value&,
               const facebook::jsi::Value* args,
               size_t count) -> facebook::jsi::Value {
        if (count == 0 || !args[0].isString()) {
          return facebook::jsi::Value::null();
        }
        auto command = args[0].asString(runtime).utf8(runtime);

#if defined(IBEX_INSECURE_BUILD)
        (void)handle;
        // The ambient host lookup exists only in the explicit no-sandbox
        // build. Secure binaries have no runtime-selectable fallback to it.
        // @ref LLP 0038#fully-open-mode-insecure
        // @ref LLP 0039#the-default-is-secure-and-fail-closed
        // If command contains a slash, check it directly
        if (command.find('/') != std::string::npos) {
          if (access(command.c_str(), X_OK) == 0) {
            return facebook::jsi::String::createFromUtf8(runtime, command);
          }
          return facebook::jsi::Value::null();
        }

        // Get PATH environment variable
        const char* pathEnv = getenv("PATH");
        if (!pathEnv) {
          return facebook::jsi::Value::null();
        }

        std::string pathStr(pathEnv);
        std::string::size_type start = 0;
        while (start < pathStr.size()) {
          auto end = pathStr.find(':', start);
          if (end == std::string::npos) end = pathStr.size();

          std::string dir = pathStr.substr(start, end - start);
          if (!dir.empty()) {
            std::string fullPath = dir + "/" + command;
            if (access(fullPath.c_str(), X_OK) == 0) {
              // Resolve to real path
              char resolved[PATH_MAX];
              if (realpath(fullPath.c_str(), resolved) != nullptr) {
                return facebook::jsi::String::createFromUtf8(runtime, std::string(resolved));
              }
              return facebook::jsi::String::createFromUtf8(runtime, fullPath);
            }
          }

          start = end + 1;
        }

        return facebook::jsi::Value::null();
#else
        if (!handle->armed) {
          return facebook::jsi::Value::null();
        }

        // Direct spellings do not consult PATH. Their sole effect branch is
        // the staged fs:list walk performed by exactWhichArmed.
        // @ref LLP 0021#effects-and-decision-sets
        if (command.find('/') != std::string::npos) {
          auto result = exactWhichArmed(runtime, command);
          return result.has_value()
              ? facebook::jsi::Value(
                    facebook::jsi::String::createFromUtf8(runtime, *result))
              : facebook::jsi::Value::null();
        }

        const std::string pathName = "PATH";
        authorizeTypedWhichPathEnvironmentRead(runtime, pathName);
        const auto principal = currentPrincipalId();
        const auto principalOverlay =
            handle->environment_principal_overlays.find(principal);
        if (principalOverlay == handle->environment_principal_overlays.end()) {
          return facebook::jsi::Value::null();
        }
        const auto pathValue = principalOverlay->second.find(pathName);
        if (pathValue == principalOverlay->second.end()) {
          return facebook::jsi::Value::null();
        }

        const std::string& path = pathValue->second;
        std::string::size_type start = 0;
        while (start < path.size()) {
          auto end = path.find(':', start);
          if (end == std::string::npos) end = path.size();
          const std::string directory = path.substr(start, end - start);
          if (!directory.empty()) {
            auto result = exactWhichArmed(
                runtime, directory + "/" + command);
            if (result.has_value()) {
              return facebook::jsi::String::createFromUtf8(runtime, *result);
            }
          }
          start = end + 1;
        }
        return facebook::jsi::Value::null();
#endif
      });
  rt.global().setProperty(rt, "__exactWhich", std::move(whichFn));

}

extern "C" void exactCleanupRuntimeSpawnedProcesses(uint64_t runtimeNonce) {
  if (runtimeNonce == 0) return;

  std::vector<std::shared_ptr<SpawnedProcess>> owned;
  {
    std::lock_guard<std::mutex> lock(s_spawnMutex);
    for (auto it = s_spawnedProcesses.begin(); it != s_spawnedProcesses.end();) {
      if (it->second && it->second->runtimeNonce == runtimeNonce) {
        owned.push_back(it->second);
        it = s_spawnedProcesses.erase(it);
      } else {
        ++it;
      }
    }
  }

  for (const auto& proc : owned) {
    if (!proc->exited && proc->pid > 0) {
      if (proc->referenced) {
        // An unreaped child keeps its pid reserved, so kill-before-wait cannot
        // hit a recycled process. Referenced children belong to this runtime
        // and are reclaimed synchronously during teardown.
        kill(proc->pid, SIGKILL);
        while (waitpid(proc->pid, nullptr, 0) < 0 && errno == EINTR) {}
        proc->exited = true;
      } else {
        // Explicit ChildProcess.unref() transfers lifetime out of the runtime.
        // Do not kill it; keep the native host zombie-free if it remains alive.
        reapUnreferencedSpawnEventually(proc->pid);
      }
    }
    closeSpawnedProcessFds(proc);
  }
}
