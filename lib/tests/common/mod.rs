use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// Spawn a loopback server and record every request head.
pub async fn spawn_dynamic_server(
    response: impl Fn(&str) -> String + Send + 'static,
) -> (String, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let requests = Arc::new(Mutex::new(Vec::new()));
    let recorded = requests.clone();
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = Vec::new();
            loop {
                let mut chunk = [0u8; 4096];
                let n = stream.read(&mut chunk).await.unwrap();
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&chunk[..n]);
                if buf.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
                    break;
                }
                assert!(buf.len() < 65536, "request head too large");
            }
            let request = String::from_utf8_lossy(&buf).to_lowercase();
            let response = response(&request);
            recorded.lock().unwrap().push(request);
            stream.write_all(response.as_bytes()).await.unwrap();
            stream.shutdown().await.ok();
        }
    });
    (base, requests)
}

pub fn redirect_to(location: &str) -> String {
    format!(
        "HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    )
}

pub fn payment_required() -> String {
    // Public token metadata and a synthetic recipient; no settlement is performed.
    let body = serde_json::json!({
        "x402Version": 1,
        "error": "Payment Required",
        "accepts": [{
            "scheme": "exact",
            "network": "base-sepolia",
            "maxAmountRequired": "1000",
            "asset": "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
            "payTo": "0x0000000000000000000000000000000000000001",
            "resource": "http://example.com/paid",
            "description": "Local test",
            "mimeType": "application/json",
            "maxTimeoutSeconds": 300,
            "extra": {"name": "USDC", "version": "2"}
        }]
    })
    .to_string();
    format!(
        "HTTP/1.1 402 Payment Required\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

pub const OK: &str = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";

pub fn has_payment_credential(request: &str) -> bool {
    request.contains("\r\nx-payment:") || request.contains("\r\npayment-signature:")
}
