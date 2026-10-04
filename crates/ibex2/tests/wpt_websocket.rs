//! Unmodified, engine-independent WPT `websockets/*.any.js` fixtures against
//! a local RFC 6455 echo peer. The runner supplies only the substitutions and
//! helpers that WPT's Python server normally injects.

#![cfg(all(feature = "hermes", feature = "websocket"))]

use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use ibex2::engine::hermes::{DynamicCode, Hermes};

const FILES: &[&str] = &[
    "constructor.any.js",
    "Create-invalid-urls.any.js",
    "Create-http-urls.any.js",
    "Create-asciiSep-protocol-string.any.js",
    "Create-nonAscii-protocol-string.any.js",
    "Create-protocol-with-space.any.js",
    "Create-protocols-repeated.any.js",
    "Create-protocols-repeated-case-insensitive.any.js",
    "Create-valid-url-binaryType-blob.any.js",
    "binaryType-wrong-value.any.js",
    "close-invalid.any.js",
    "Close-Reason-124Bytes.any.js",
    "Close-onlyReason.any.js",
    "Close-undefined.any.js",
    "eventhandlers.any.js",
    "Send-before-open.any.js",
    "Create-valid-url.any.js",
    "Create-valid-url-array-protocols.any.js",
    "Create-valid-url-protocol-setCorrectly.any.js",
    "Create-valid-url-protocol-empty.any.js",
    "Close-1000-reason.any.js",
    "Close-2999-reason.any.js",
    "Close-3000-reason.any.js",
    "Close-readyState-Closing.any.js",
    "Close-readyState-Closed.any.js",
    "Create-extensions-empty.any.js",
];

fn wpt_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../third_party/wpt/websockets")
}

fn server_frame(opcode: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![0x80 | opcode];
    match payload.len() {
        length if length < 126 => out.push(length as u8),
        length if length <= u16::MAX as usize => {
            out.push(126);
            out.extend_from_slice(&(length as u16).to_be_bytes());
        }
        length => {
            out.push(127);
            out.extend_from_slice(&(length as u64).to_be_bytes());
        }
    }
    out.extend_from_slice(payload);
    out
}

fn client_frame(stream: &mut TcpStream) -> Option<(u8, Vec<u8>)> {
    let mut head = [0u8; 2];
    stream.read_exact(&mut head).ok()?;
    if head[1] & 0x80 == 0 {
        return None;
    }
    let length = match head[1] & 0x7f {
        126 => {
            let mut bytes = [0u8; 2];
            stream.read_exact(&mut bytes).ok()?;
            u16::from_be_bytes(bytes) as usize
        }
        127 => {
            let mut bytes = [0u8; 8];
            stream.read_exact(&mut bytes).ok()?;
            usize::try_from(u64::from_be_bytes(bytes)).ok()?
        }
        length => length as usize,
    };
    let mut mask = [0u8; 4];
    stream.read_exact(&mut mask).ok()?;
    let mut payload = vec![0; length];
    stream.read_exact(&mut payload).ok()?;
    for (index, byte) in payload.iter_mut().enumerate() {
        *byte ^= mask[index % 4];
    }
    Some((head[0] & 0x0f, payload))
}

fn serve(mut stream: TcpStream) {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if stream.read(&mut byte).unwrap_or(0) == 0 {
            return;
        }
        head.push(byte[0]);
        if head.len() > 16 << 10 {
            return;
        }
    }
    let head = String::from_utf8_lossy(&head);
    let Some(key) = head
        .lines()
        .find_map(|line| line.strip_prefix("Sec-WebSocket-Key: "))
        .map(str::trim)
    else {
        return;
    };
    let selected = head
        .lines()
        .find_map(|line| line.strip_prefix("Sec-WebSocket-Protocol: "))
        .and_then(|values| {
            values
                .split(',')
                .map(str::trim)
                .find(|value| *value == "echo")
        });
    let protocol = selected.map_or(String::new(), |value| {
        format!("Sec-WebSocket-Protocol: {value}\r\n")
    });
    let accept = ibex2::stdlib::websocket::accept_key(key);
    let answer = format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n{protocol}\r\n"
    );
    if stream.write_all(answer.as_bytes()).is_err() {
        return;
    }
    while let Some((opcode, payload)) = client_frame(&mut stream) {
        match opcode {
            0x1 | 0x2 => {
                if stream.write_all(&server_frame(opcode, &payload)).is_err() {
                    return;
                }
            }
            0x8 => {
                let _ = stream.write_all(&server_frame(0x8, &payload));
                return;
            }
            0x9 => {
                let _ = stream.write_all(&server_frame(0xA, &payload));
            }
            _ => {}
        }
    }
    let _ = stream.shutdown(Shutdown::Both);
}

fn echo_peer() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            std::thread::spawn(move || serve(stream));
        }
    });
    port
}

fn prelude(port: u16) -> String {
    format!(
        r#"
        globalThis.location = {{
          protocol: "http:", host: "127.0.0.1:{port}", hostname: "127.0.0.1",
          origin: "http://127.0.0.1:{port}", href: "http://127.0.0.1:{port}/",
          search: "", toString: function () {{ return this.href; }}
        }};
        var SCHEME_DOMAIN_PORT = "ws://127.0.0.1:{port}";
        var __PATH = "echo";
        function IsWebSocket() {{
          assert_true(!!self.WebSocket, "runtime supports WebSocket");
        }}
        function CreateWebSocketNonAsciiProtocol(value) {{
          IsWebSocket(); return new WebSocket(SCHEME_DOMAIN_PORT + "/" + __PATH, value);
        }}
        function CreateWebSocketWithAsciiSep(value) {{
          IsWebSocket(); return new WebSocket(SCHEME_DOMAIN_PORT + "/" + __PATH, value);
        }}
        function CreateWebSocketWithSpaceInProtocol(value) {{
          IsWebSocket(); return new WebSocket(SCHEME_DOMAIN_PORT + "/" + __PATH, value);
        }}
        function CreateWebSocketWithRepeatedProtocols() {{
          IsWebSocket(); return new WebSocket(SCHEME_DOMAIN_PORT + "/" + __PATH, ["echo", "echo"]);
        }}
        function CreateWebSocketWithRepeatedProtocolsCaseInsensitive() {{
          IsWebSocket(); return new WebSocket(SCHEME_DOMAIN_PORT + "/" + __PATH, ["echo", "eCho"]);
        }}
        function CreateWebSocket(protocol, protocols) {{
          IsWebSocket();
          var url = SCHEME_DOMAIN_PORT + "/" + __PATH;
          if (protocol) return new WebSocket(url, "echo");
          if (protocols) return new WebSocket(url, ["echo", "chat"]);
          return new WebSocket(url);
        }}
        "#
    )
}

fn eval_fixture(runtime: &mut Hermes, root: &Path, name: &str) {
    let path = root.join(name);
    let source = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("vendored {}: {error}", path.display()));
    runtime
        .eval(&source)
        .unwrap_or_else(|error| panic!("{name} failed to evaluate: {error}"));
}

fn run_file(port: u16, name: &str) -> Vec<(String, bool, String)> {
    let grants = ibex2::grant::GrantSet::parse(&format!(
        "net.websocket ws://127.0.0.1:{port}\nnet.websocket wss://127.0.0.1:{port}\n"
    ))
    .unwrap();
    let context = ibex2::bindings::Context::new(grants);
    let mut runtime = Hermes::new(DynamicCode::Closed).expect("runtime");
    let groups = ibex2::bindings::Groups::PURE
        | ibex2::bindings::Groups::EVENTS
        | ibex2::bindings::Groups::WEBSOCKET;
    runtime.install_runtime(groups, &context).expect("bindings");
    runtime.install_test_harness().expect("test harness");
    runtime.eval(&prelude(port)).expect("WPT substitutions");
    runtime.eval("__ibex2_reset_results()").expect("reset");
    eval_fixture(&mut runtime, &wpt_root(), name);

    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        runtime.pump().expect("pump");
        let pending = runtime
            .eval("String(__ibex2_pending_tests())")
            .expect("pending test count");
        if pending == "0" {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "{name} left {pending} test(s) pending"
        );
        std::thread::sleep(Duration::from_millis(2));
    }

    let raw = runtime.eval("__ibex2_test_results()").expect("results");
    serde_json::from_str::<Vec<serde_json::Value>>(&raw)
        .expect("results json")
        .into_iter()
        .map(|value| {
            (
                value["name"].as_str().unwrap_or("").to_string(),
                value["ok"].as_bool().unwrap_or(false),
                value["message"].as_str().unwrap_or("").to_string(),
            )
        })
        .collect()
}

fn run_suite() -> (usize, Vec<String>) {
    let port = echo_peer();
    let mut total = 0;
    let mut failures = Vec::new();
    for file in FILES {
        for (name, passed, message) in run_file(port, file) {
            total += 1;
            if !passed {
                failures.push(format!("{file}: {name}: {message}"));
            }
        }
    }
    (total, failures)
}

#[test]
#[ignore]
fn wpt_websocket_report() {
    let port = echo_peer();
    let (mut total, mut passed) = (0, 0);
    println!("\n=== WPT websockets (local echo, default variant) ===");
    for file in FILES {
        let results = run_file(port, file);
        let ok = results.iter().filter(|(_, ok, _)| *ok).count();
        total += results.len();
        passed += ok;
        println!("  {file:56} {ok}/{}", results.len());
        for (name, is_ok, message) in results {
            if !is_ok {
                println!("      FAIL {name}: {message}");
            }
        }
    }
    println!("\n  {passed}/{total} pass");
}

#[test]
fn wpt_websocket_all_pass() {
    let (total, failures) = run_suite();
    assert_eq!(
        total, 41,
        "the vendored suite changed size; re-baseline deliberately"
    );
    assert!(
        failures.is_empty(),
        "WPT WebSocket regressions:\n  {}",
        failures.join("\n  ")
    );
}
