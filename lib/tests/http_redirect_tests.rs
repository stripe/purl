//! Regression tests for redirect handling of credential-bearing requests

use purl_lib::HttpClientBuilder;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// Spawn a loopback server that answers every request with `response` and records
/// the raw request heads it receives.
async fn spawn_server(response: String) -> (String, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let requests = Arc::new(Mutex::new(Vec::new()));
    let recorded = requests.clone();
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 8192];
            let n = stream.read(&mut buf).await.unwrap();
            recorded
                .lock()
                .unwrap()
                .push(String::from_utf8_lossy(&buf[..n]).to_lowercase());
            stream.write_all(response.as_bytes()).await.unwrap();
            stream.shutdown().await.ok();
        }
    });
    (base, requests)
}

fn redirect_to(location: &str) -> String {
    format!(
        "HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    )
}

const PAYMENT_REQUIRED: &str =
    "HTTP/1.1 402 Payment Required\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

#[tokio::test]
async fn response_url_reports_redirect_destination() {
    let (payment_origin, _) = spawn_server(PAYMENT_REQUIRED.to_string()).await;
    let (redirector, _) = spawn_server(redirect_to(&format!("{payment_origin}/paid"))).await;

    let client = HttpClientBuilder::new()
        .follow_redirects(true)
        .build()
        .unwrap();
    let response = client.get(&format!("{redirector}/start")).await.unwrap();

    assert_eq!(response.status_code, 402);
    assert_eq!(response.url, format!("{payment_origin}/paid"));
}

#[tokio::test]
async fn same_origin_only_does_not_forward_credentials_cross_origin() {
    let (other_origin, other_requests) = spawn_server(PAYMENT_REQUIRED.to_string()).await;
    let (origin, _) = spawn_server(redirect_to(&format!("{other_origin}/steal"))).await;

    let client = HttpClientBuilder::new()
        .follow_redirects(true)
        .same_origin_redirects_only(true)
        .header("Payment-Signature", "secret-credential")
        .build()
        .unwrap();
    let response = client.get(&format!("{origin}/paid")).await.unwrap();

    assert_eq!(response.status_code, 302);
    assert_eq!(response.url, format!("{origin}/paid"));
    assert!(other_requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn same_origin_only_still_follows_same_origin_redirects() {
    // A server that always redirects to itself: following must continue until the
    // redirect limit is hit, proving same-origin redirects are honored.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let hits = Arc::new(Mutex::new(0usize));
    let counter = hits.clone();
    let location = format!("{base}/loop");
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 8192];
            let _ = stream.read(&mut buf).await.unwrap();
            *counter.lock().unwrap() += 1;
            stream
                .write_all(redirect_to(&location).as_bytes())
                .await
                .unwrap();
            stream.shutdown().await.ok();
        }
    });

    let client = HttpClientBuilder::new()
        .follow_redirects(true)
        .same_origin_redirects_only(true)
        .build()
        .unwrap();
    let result = client.get(&format!("{base}/start")).await;

    assert!(result.is_err());
    assert!(*hits.lock().unwrap() > 1);
}
