#![cfg(feature = "hermes")]

use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;
use std::time::Duration;

use ibex2::bindings::{Context, Groups};
use ibex2::engine::hermes::{DynamicCode, Hermes};
use ibex2::grant::GrantSet;
use ibex2::loader::{ModuleGrants, Root};
use ibex2::stdlib::multipart::{EncodedMultipart, FormData};

fn runtime(groups: Groups, harden: bool) -> Hermes {
    runtime_with_grants(groups, harden, GrantSet::none())
}

fn runtime_with_grants(groups: Groups, harden: bool, grants: GrantSet) -> Hermes {
    let mut runtime = Hermes::new(DynamicCode::Closed).unwrap();
    let context = Context::new(grants);
    runtime.install(groups, &context).unwrap();
    if harden {
        runtime.harden().unwrap();
    }
    runtime
}

fn capture(
    response_type: &str,
    response_body: &[u8],
) -> (String, thread::JoinHandle<(String, Vec<u8>)>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let response_type = response_type.to_string();
    let response_body = response_body.to_vec();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            let mut byte = [0];
            stream.read_exact(&mut byte).unwrap();
            head.push(byte[0]);
            assert!(head.len() < 64 * 1024);
        }
        let head = String::from_utf8(head).unwrap();
        let length = head
            .split("\r\n")
            .filter_map(|line| line.split_once(':'))
            .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
            .map(|(_, value)| value.trim().parse().unwrap())
            .unwrap_or(0);
        let mut body = vec![0; length];
        stream.read_exact(&mut body).unwrap();
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Type: {response_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            response_body.len()
        )
        .unwrap();
        stream.write_all(&response_body).unwrap();
        (head, body)
    });
    (format!("http://{address}"), server)
}

fn header<'a>(head: &'a str, wanted: &str) -> Option<&'a str> {
    head.split("\r\n")
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.eq_ignore_ascii_case(wanted))
        .map(|(_, value)| value.trim())
}

fn run_fetch_module(name: &str, origin: &str, source: &str) -> Vec<String> {
    run_fetch_module_with_groups(name, origin, source, Groups::DEFAULT | Groups::BLOB)
}

fn run_fetch_module_with_groups(
    name: &str,
    origin: &str,
    source: &str,
    groups: Groups,
) -> Vec<String> {
    static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let directory = std::env::temp_dir().join(format!(
        "ibex2-blob-{name}-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&directory).unwrap();
    std::fs::write(directory.join("index.js"), source).unwrap();
    let mut runtime = Hermes::new(DynamicCode::Closed).unwrap();
    let context = Context::new(GrantSet::none());
    runtime.install_runtime(groups, &context).unwrap();
    runtime
        .set_loader(
            Root::Declared(directory.clone()),
            ModuleGrants::parse(&format!("[*]\nnet.fetch {origin}\n")).unwrap(),
        )
        .unwrap();
    runtime.harden().unwrap();
    runtime.run_entry("./index.js").unwrap();
    runtime.run_to_quiescence(Duration::from_secs(10));
    let output = runtime
        .drain_console()
        .into_iter()
        .map(|record| record.message)
        .collect();
    std::fs::remove_dir_all(directory).unwrap();
    output
}

#[test]
fn blob_constructs_every_part_type_and_reads_fresh_bytes() {
    let mut runtime = runtime(Groups::PURE | Groups::BLOB, true);
    runtime
        .eval(
            r#"
            globalThis.__result = 'pending';
            const buffer = new Uint8Array([4, 5]).buffer;
            const source = new Uint8Array([9, 1, 2, 3, 8]);
            const data = new DataView(new Uint8Array([6, 7, 8]).buffer, 1, 1);
            const nested = new Blob(['é']);
            const blob = new Blob(['A', buffer, source.subarray(1, 4), data, nested],
                                  {type: 'Text/PLAIN'});
            source[1] = 99;
            Promise.all([blob.text(), blob.arrayBuffer(), blob.bytes()]).then(values => {
              const first = Array.from(new Uint8Array(values[1]));
              const second = Array.from(values[2]);
              values[2][0] = 0;
              return blob.bytes().then(third => {
                __result = JSON.stringify({size: blob.size, type: blob.type, text: values[0],
                  first, second, third: Array.from(third), stream: typeof blob.stream,
                  tag: Object.prototype.toString.call(blob)});
              });
            });
            "#,
        )
        .unwrap();
    runtime.run_to_quiescence(Duration::from_secs(5));
    let value: serde_json::Value =
        serde_json::from_str(&runtime.eval("__result").unwrap()).unwrap();
    let expected = serde_json::json!([65, 4, 5, 1, 2, 3, 7, 195, 169]);
    assert_eq!(value["size"], 9);
    assert_eq!(value["type"], "text/plain");
    assert_eq!(value["text"], "A\u{4}\u{5}\u{1}\u{2}\u{3}\u{7}é");
    assert_eq!(value["first"], expected);
    assert_eq!(value["second"], expected);
    assert_eq!(value["third"], expected);
    assert_eq!(value["stream"], "undefined");
    assert_eq!(value["tag"], "[object Blob]");
}

#[test]
fn blob_slice_type_endings_and_brand_edges() {
    let mut runtime = runtime(Groups::PURE | Groups::BLOB, true);
    runtime
        .eval(
            r#"
            globalThis.__result = 'pending';
            const blob = new Blob(['012345'], {type:'TEXT/PLAIN'});
            const slices = [blob.slice(1, 4), blob.slice(-3), blob.slice(-99, 99, 'IMAGE/PNG'),
                            blob.slice(4, 2), blob.slice(Infinity), blob.slice(0, -1)];
            Promise.all(slices.map(x => x.text())).then(text => {
              let native, invalid, brand;
              try { new Blob([], {endings:'native'}); } catch (e) { native = e.name + ':' + e.message; }
              try { new Blob([], {endings:'other'}); } catch (e) { invalid = e.name; }
              try { Object.getOwnPropertyDescriptor(Blob.prototype, 'size').get({}); } catch (e) { brand = e.name; }
              __result = JSON.stringify({text, types:slices.map(x => x.type), native, invalid, brand,
                badType:new Blob([], {type:'text/雪'}).type});
            });
            "#,
        )
        .unwrap();
    runtime.run_to_quiescence(Duration::from_secs(5));
    let value: serde_json::Value =
        serde_json::from_str(&runtime.eval("__result").unwrap()).unwrap();
    assert_eq!(
        value["text"],
        serde_json::json!(["123", "345", "012345", "", "", "01234"])
    );
    assert_eq!(
        value["types"],
        serde_json::json!(["", "", "image/png", "", "", ""])
    );
    assert!(value["native"].as_str().unwrap().contains("transparent"));
    assert_eq!(value["invalid"], "TypeError");
    assert_eq!(value["brand"], "TypeError");
    assert_eq!(value["badType"], "");
}

#[test]
fn blob_slice_uses_clamped_long_long_ties_to_even() {
    let mut runtime = runtime(Groups::PURE | Groups::BLOB, true);
    runtime
        .eval(
            r#"
            globalThis.__result = 'pending';
            const blob = new Blob(['abcd']);
            const starts = [1.5, 2.5, 0.5, 3.5, -0.5, -1.5, -2.5,
                            Infinity, -Infinity, NaN];
            Promise.all(starts.map(start => blob.slice(start).text())).then(values => {
              __result = JSON.stringify(values);
            });
            "#,
        )
        .unwrap();
    runtime.run_to_quiescence(Duration::from_secs(5));
    assert_eq!(
        runtime.eval("__result").unwrap(),
        r#"["cd","cd","abcd","","abcd","cd","cd","","abcd","abcd"]"#
    );
}

#[test]
fn file_fields_and_every_form_data_operation_follow_entry_order() {
    let mut runtime = runtime(Groups::PURE | Groups::BLOB, true);
    let value = runtime
        .eval(
            r#"
            (() => {
              const file = new File(['file'], 'a.txt', {type:'TEXT/PLAIN', lastModified:1234});
              const blob = new Blob(['blob'], {type:'application/custom'});
              const form = new FormData();
              form.append('a', 'one');
              form.append('a', 'two');
              form.append('blob', blob);
              form.append('file', file);
              form.append('named', blob, 'renamed.bin');
              const blobFile = form.get('blob'), keptFile = form.get('file'), named = form.get('named');
              const before = Array.from(form, e => e[0] + ':' + (typeof e[1] === 'string' ? e[1] : e[1].name));
              form.set('a', 'replacement');
              form.set('new', 'last');
              form.delete('blob');
              const each = [];
              form.forEach((value, name, owner) => each.push(name + ':' +
                (typeof value === 'string' ? value : value.name) + ':' + (owner === form)));
              return JSON.stringify({
                file:[file.name,file.type,file.size,file.lastModified,file instanceof Blob,Object.prototype.toString.call(file)],
                converted:[blobFile.name,blobFile.type,blobFile instanceof File,keptFile === file,named.name,named.type],
                before,
                get:form.get('a'), all:form.getAll('a'), has:[form.has('blob'),form.has('new')],
                entries:Array.from(form.entries(), e => e[0]), keys:Array.from(form.keys()),
                values:Array.from(form.values(), v => typeof v === 'string' ? v : v.name), each,
                helpers:[typeof __ibex2_multipart_boundary, typeof __ibex2_multipart_encode]
              });
            })()
            "#,
        )
        .unwrap();
    let value: serde_json::Value = serde_json::from_str(&value).unwrap();
    assert_eq!(
        value["file"],
        serde_json::json!(["a.txt", "text/plain", 4, 1234, true, "[object File]"])
    );
    assert_eq!(
        value["converted"],
        serde_json::json!([
            "blob",
            "application/custom",
            true,
            true,
            "renamed.bin",
            "application/custom"
        ])
    );
    assert_eq!(
        value["before"],
        serde_json::json!([
            "a:one",
            "a:two",
            "blob:blob",
            "file:a.txt",
            "named:renamed.bin"
        ])
    );
    assert_eq!(value["get"], "replacement");
    assert_eq!(value["all"], serde_json::json!(["replacement"]));
    assert_eq!(value["has"], serde_json::json!([false, true]));
    assert_eq!(
        value["entries"],
        serde_json::json!(["a", "file", "named", "new"])
    );
    assert_eq!(
        value["keys"],
        serde_json::json!(["a", "file", "named", "new"])
    );
    assert_eq!(
        value["values"],
        serde_json::json!(["replacement", "a.txt", "renamed.bin", "last"])
    );
    assert_eq!(
        value["each"],
        serde_json::json!([
            "a:replacement:true",
            "file:a.txt:true",
            "named:renamed.bin:true",
            "new:last:true"
        ])
    );
    assert_eq!(
        value["helpers"],
        serde_json::json!(["undefined", "undefined"])
    );
}

#[test]
fn form_data_uses_web_idl_filename_overload_selection() {
    let mut runtime = runtime(Groups::PURE | Groups::BLOB, true);
    let value = runtime
        .eval(
            r#"
            (() => {
              const file = new File(['file'], 'kept.txt');
              const blob = new Blob(['blob']);
              const form = new FormData(undefined);
              form.append('append-file', file, undefined);
              form.append('append-blob', blob, undefined);
              form.append('append-text', 'text', undefined);
              form.set('set-file', file, undefined);
              form.set('set-blob', blob, undefined);
              form.set('set-text', 'text', undefined);
              const errors = [];
              for (const method of ['append', 'set']) {
                try { form[method]('bad-' + method, 'text', 'named.txt'); }
                catch (error) { errors.push(error instanceof TypeError); }
              }
              return JSON.stringify({
                names: [
                  form.get('append-file').name,
                  form.get('append-blob').name,
                  form.get('set-file').name,
                  form.get('set-blob').name
                ],
                text: [form.get('append-text'), form.get('set-text')],
                errors,
                size: Array.from(form).length
              });
            })()
            "#,
        )
        .unwrap();
    let value: serde_json::Value = serde_json::from_str(&value).unwrap();
    assert_eq!(
        value,
        serde_json::json!({
            "names": ["kept.txt", "blob", "kept.txt", "blob"],
            "text": ["text", "text"],
            "errors": [true, true],
            "size": 6
        })
    );
}

#[test]
fn array_buffer_slice_override_does_not_change_blob_results() {
    let mut runtime = runtime(Groups::PURE | Groups::BLOB, false);
    runtime
        .eval(
            r#"
            const blob = new Blob([new Uint8Array([1,2,3]).buffer]);
            ArrayBuffer.prototype.slice = function () { throw new Error('hostile slice'); };
            globalThis.__result = 'pending';
            Promise.all([blob.arrayBuffer(), blob.slice(1).bytes()]).then(values => {
              __result = JSON.stringify([Array.from(new Uint8Array(values[0])), Array.from(values[1])]);
            });
            "#,
        )
        .unwrap();
    runtime.run_to_quiescence(Duration::from_secs(5));
    assert_eq!(runtime.eval("__result").unwrap(), "[[1,2,3],[2,3]]");
}

#[test]
fn typed_array_buffer_override_cannot_redirect_blob_private_bytes() {
    let mut runtime = runtime(Groups::PURE | Groups::BLOB, false);
    runtime
        .eval(
            r#"
            const attacker = new Uint8Array([90, 91, 92]).buffer;
            Object.defineProperty(Uint8Array.prototype, 'buffer', {
              configurable: true,
              get() { return attacker; }
            });
            const source = new Uint8Array([1, 2, 3]);
            const blob = new Blob([source]);
            new Uint8Array(attacker).fill(255);
            source.fill(0);
            globalThis.__result = 'pending';
            blob.bytes().then(bytes => { __result = Array.from(bytes).join(','); });
            "#,
        )
        .unwrap();
    runtime.run_to_quiescence(Duration::from_secs(5));
    assert_eq!(runtime.eval("__result").unwrap(), "1,2,3");
}

#[test]
fn blob_group_is_explicit_and_does_not_arrive_with_fetch() {
    let mut runtime = runtime(Groups::PURE | Groups::ABORT | Groups::FETCH, true);
    assert_eq!(
        runtime
            .eval("[typeof Blob, typeof File, typeof FormData, typeof Request, typeof Response].join(',')")
            .unwrap(),
        "undefined,undefined,undefined,undefined,undefined"
    );
}

#[test]
fn fetch_request_blob_and_response_blob_use_content_types_and_bytes() {
    let (origin, server) = capture("Text/Custom", b"response bytes");
    let output = run_fetch_module(
        "request-blob",
        &origin,
        &format!(
            r#"
            const request = new Request('{origin}/blob', {{
              method:'POST', body:new Blob(['blob-', new Uint8Array([98,111,100,121])],
                                            {{type:'Application/X-Test'}})
            }});
            fetch(request).then(async response => {{
              let formError;
              try {{ await response.formData(); }} catch (error) {{ formError = [error.name, error instanceof DOMException]; }}
              const blob = await response.blob();
              console.log(JSON.stringify({{request:[request.method,request.url,request.headers.get('content-type')],
                response:[blob.type,blob.size,await blob.text()], formError}}));
            }}, error => console.log('error:' + error));
            "#
        ),
    );
    let value: serde_json::Value = serde_json::from_str(&output[0]).unwrap();
    assert_eq!(
        value["request"],
        serde_json::json!(["POST", format!("{origin}/blob"), "application/x-test"])
    );
    assert_eq!(
        value["response"],
        serde_json::json!(["text/custom", 14, "response bytes"])
    );
    assert_eq!(
        value["formError"],
        serde_json::json!(["NotSupportedError", true])
    );
    let (head, body) = server.join().unwrap();
    assert_eq!(header(&head, "content-type"), Some("application/x-test"));
    assert_eq!(body, b"blob-body");
}

#[test]
fn response_blob_uses_fetch_mime_type_extraction() {
    for (name, header_value, expected_type) in [
        ("invalid", "not a mime", ""),
        (
            "parameterized",
            "TEXT/PLAIN; Charset=UTF-8; title=\"A B\"",
            "text/plain;charset=utf-8;title=\"a b\"",
        ),
    ] {
        let (origin, server) = capture(header_value, b"response");
        let output = run_fetch_module(
            &format!("response-blob-mime-{name}"),
            &origin,
            &format!(
                "fetch('{origin}/mime').then(r => r.blob()).then(async b => console.log(JSON.stringify([b.type, await b.text()])));"
            ),
        );
        assert_eq!(
            output,
            [serde_json::to_string(&serde_json::json!([expected_type, "response"])).unwrap()],
            "{name}"
        );
        server.join().unwrap();
    }
}

#[test]
fn request_rejects_get_and_head_bodies() {
    let output = run_fetch_module(
        "request-get-head-body",
        "https://example.invalid",
        r#"
            const sync = [];
            for (const init of [
              {body:new Blob(['x'])},
              {method:'HEAD', body:new Uint8Array([1])},
              {method:'get', body:''}
            ]) {
              try { new Request('https://example.invalid/', init); sync.push(false); }
              catch (error) { sync.push(error instanceof TypeError); }
            }
            const form = new FormData();
            form.append('a', 'b');
            Promise.all([
              fetch('https://example.invalid/', {body:form}).then(() => false, e => e instanceof TypeError),
              fetch('https://example.invalid/', {method:'HEAD', body:new URLSearchParams('a=b')})
                .then(() => false, e => e instanceof TypeError)
            ]).then(asyncErrors => {
              console.log(JSON.stringify({sync, asyncErrors}));
            });
            "#,
    );
    assert_eq!(
        output,
        [r#"{"sync":[true,true,true],"asyncErrors":[true,true]}"#]
    );
}

#[test]
fn request_snapshots_buffer_source_bodies_at_construction() {
    let (origin, server) = capture("text/plain", b"ok");
    let output = run_fetch_module(
        "request-buffer-source-snapshot",
        &origin,
        &format!(
            r#"
            const backing = new Uint8Array([9, 1, 2, 3, 8]);
            const body = backing.subarray(1, 4);
            const request = new Request('{origin}/snapshot', {{method:'POST', body}});
            backing.fill(7);
            fetch(request).then(response => response.text()).then(console.log);
            "#
        ),
    );
    assert_eq!(output, ["ok"]);
    let (_, body) = server.join().unwrap();
    assert_eq!(body, [1, 2, 3]);
}

#[test]
fn fetch_form_data_uses_rust_multipart_and_preserves_authored_content_type() {
    let (origin, server) = capture("text/plain", b"ok");
    let output = run_fetch_module(
        "form-data",
        &origin,
        &format!(
            r#"
            const form = new FormData();
            form.append('title', 'hello\nworld');
            form.append('upload', new Blob([new Uint8Array([0,1,255])], {{type:'application/test'}}), 'x\"\n雪.bin');
            fetch('{origin}/form', {{method:'POST', body:form}})
              .then(response => response.text()).then(console.log,
                    error => console.log('error:' + error));
            "#
        ),
    );
    assert_eq!(output, ["ok"]);
    let (head, body) = server.join().unwrap();
    let content_type = header(&head, "content-type").unwrap();
    let boundary = content_type
        .strip_prefix("multipart/form-data; boundary=")
        .unwrap();
    let mut form = FormData::new();
    form.append_text("title", "hello\nworld");
    form.append_file("upload", vec![0, 1, 255], "x\"\n雪.bin", "application/test");
    let expected = EncodedMultipart::with_boundary(&form, boundary).unwrap();
    assert_eq!(body, expected.as_bytes());

    let (origin, server) = capture("text/plain", b"ok");
    let _ = run_fetch_module(
        "form-data-authored-type",
        &origin,
        &format!(
            "const f=new FormData(); f.append('a','b'); fetch('{origin}/form', {{method:'POST', body:f, headers:{{'Content-Type':'application/custom'}}}}).then(r => r.text()).then(console.log);"
        ),
    );
    let (head, _) = server.join().unwrap();
    assert_eq!(header(&head, "content-type"), Some("application/custom"));
}

#[test]
fn fetch_without_blob_matches_the_pre_lane_surface_and_wire_behavior() {
    let groups = Groups::PURE | Groups::CONSOLE | Groups::ABORT | Groups::FETCH;
    let cases: [(&str, &str, &[u8]); 5] = [
        ("string", "'ordinary request'", b"ordinary request"),
        ("bytes", "new Uint8Array([1,2,3])", &[1, 2, 3]),
        ("search-params", "new URLSearchParams([['a b','c+d']])", b""),
        ("number", "123", b""),
        ("object", "({a:1})", b""),
    ];

    for (name, body_expression, expected_body) in cases {
        let (origin, server) = capture("text/plain", b"ordinary response");
        let output = run_fetch_module_with_groups(
            &format!("fetch-without-blob-{name}"),
            &origin,
            &format!(
                "console.log([typeof Blob,typeof File,typeof FormData,typeof Request,typeof Response].join(','));\n\
                 fetch('{origin}/{name}', {{method:'POST',body:{body_expression}}}).then(r => r.text()).then(console.log);"
            ),
            groups,
        );
        assert_eq!(
            output,
            [
                "undefined,undefined,undefined,undefined,undefined",
                "ordinary response"
            ],
            "{name}"
        );
        let (head, body) = server.join().unwrap();
        assert_eq!(body, expected_body, "{name}");
        let expected_type =
            (!expected_body.is_empty()).then_some("application/x-www-form-urlencoded");
        assert_eq!(header(&head, "content-type"), expected_type, "{name}");
    }
}
