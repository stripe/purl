//! Regression tests for payment origin and credential-bearing redirects

use purl_lib::client::PaymentResult;
use purl_lib::{Config, HttpClientBuilder, HttpResponse, PurlClient, PurlError};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// Spawn a loopback server that answers every request with `response` and records
/// the raw request heads it receives.
async fn spawn_server(response: String) -> (String, Arc<Mutex<Vec<String>>>) {
    spawn_dynamic_server(move |_| response.clone()).await
}

mod common;
use common::{has_payment_credential, payment_required, redirect_to, spawn_dynamic_server, OK};

#[test]
fn payment_origin_comparison() {
    for (original, destination, allowed) in [
        (
            "https://example.com/start",
            "https://example.com/paid?x=1",
            true,
        ),
        ("https://EXAMPLE.com:443", "https://example.com", true),
        ("http://example.com:80", "http://example.com", true),
        ("http://[::1]:80/start", "http://[::1]/paid", true),
        ("http://example.com", "https://example.com", false),
        ("https://example.com", "https://other.example.com", false),
        ("https://example.com", "https://example.com:444", false),
        (
            "https://example.com",
            "https://example.com.evil.test",
            false,
        ),
        ("invalid", "https://example.com", false),
        ("https://example.com", "invalid", false),
        ("file:///a", "file:///a", false),
        ("ftp://example.com", "ftp://example.com", false),
        ("data:text/plain,test", "data:text/plain,test", false),
        ("https://example.com", "https://[invalid", false),
    ] {
        let response = HttpResponse {
            status_code: 402,
            url: destination.to_string(),
            headers: HashMap::new(),
            body: Vec::new(),
        };
        assert_eq!(
            response.validate_payment_origin(original).is_ok(),
            allowed,
            "{original} -> {destination}"
        );
    }
}

#[tokio::test]
async fn client_rejects_cross_origin_before_wallet_access() {
    let (destination, destination_requests) = spawn_server(payment_required()).await;
    let (origin, origin_requests) = spawn_server(redirect_to(&format!("{destination}/paid"))).await;
    for dry_run in [false, true] {
        let mut client = PurlClient::with_config(Config {
            evm_private_key: Some("invalid".to_string()),
            ..Default::default()
        })
        .follow_redirects()
        .max_amount("1000000");
        if dry_run {
            client = client.dry_run();
        }
        let error = client.get(&format!("{origin}/start")).await.unwrap_err();
        assert!(matches!(error, PurlError::Http(_)));
        assert!(error.to_string().contains("Payment origin changed"));
    }
    for requests in [origin_requests, destination_requests] {
        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 2);
        assert!(requests.iter().all(|r| !has_payment_credential(r)));
    }
}

#[tokio::test]
async fn client_allows_ordinary_cross_origin_redirect() {
    let (destination, _) = spawn_server(OK.to_string()).await;
    let (origin, _) = spawn_server(redirect_to(&destination)).await;
    let result = PurlClient::with_config(Config::default())
        .follow_redirects()
        .get(&origin)
        .await
        .unwrap();
    assert!(matches!(result, PaymentResult::Success(_)));
}

#[cfg(feature = "evm")]
#[tokio::test]
async fn client_pays_same_origin_redirect_destination() {
    let (origin, requests) = spawn_dynamic_server(|request| {
        if request.starts_with("get /start ") {
            redirect_to("/paid?test=1")
        } else if has_payment_credential(request) {
            OK.to_string()
        } else {
            payment_required()
        }
    })
    .await;
    let client = PurlClient::with_config(Config {
        evm_private_key: Some(format!("{:064x}", 1)),
        ..Default::default()
    })
    .follow_redirects();
    let result = client.get(&format!("{origin}/start")).await.unwrap();
    assert!(matches!(result, PaymentResult::Paid { response, .. } if response.status_code == 200));
    let requests = requests.lock().unwrap();
    assert_eq!(requests.len(), 3);
    assert!(!has_payment_credential(&requests[0]));
    assert!(!has_payment_credential(&requests[1]));
    assert!(has_payment_credential(&requests[2]));
    assert!(requests[2].starts_with("get /paid?test=1 "));
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
