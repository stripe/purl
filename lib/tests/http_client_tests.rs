//! Integration tests for HTTP client and builder

use purl_lib::HttpClientBuilder;

#[test]
fn test_http_client_builder_basic_builders() {
    let test_cases: Vec<Box<dyn Fn() -> HttpClientBuilder>> = vec![
        Box::new(HttpClientBuilder::default),
        Box::new(HttpClientBuilder::new),
        Box::new(|| HttpClientBuilder::new().verbose(true)),
        Box::new(|| HttpClientBuilder::new().timeout(30)),
        Box::new(|| HttpClientBuilder::new().follow_redirects(true)),
        Box::new(|| HttpClientBuilder::new().user_agent("TestAgent/1.0")),
        Box::new(|| HttpClientBuilder::new().header("X-Custom-Header", "custom-value")),
    ];

    for (i, builder_fn) in test_cases.iter().enumerate() {
        let builder = builder_fn();
        let client = builder.build();
        assert!(client.is_ok(), "Builder test case {i} should succeed");
    }
}

#[test]
fn test_http_client_builder_with_multiple_headers() {
    let headers = vec![
        ("X-Header-1".to_string(), "value1".to_string()),
        ("X-Header-2".to_string(), "value2".to_string()),
    ];
    let builder = HttpClientBuilder::new().headers(&headers);
    let client = builder.build();
    assert!(client.is_ok());
}

#[test]
fn test_http_client_builder_chained() {
    let builder = HttpClientBuilder::new()
        .verbose(true)
        .timeout(60)
        .follow_redirects(true)
        .user_agent("TestAgent/1.0")
        .header("X-Custom", "value");

    let client = builder.build();
    assert!(client.is_ok());
}

#[test]
fn test_http_client_builder_multiple_headers_via_header_method() {
    let builder = HttpClientBuilder::new()
        .header("X-Header-1", "value1")
        .header("X-Header-2", "value2")
        .header("X-Header-3", "value3");

    let client = builder.build();
    assert!(client.is_ok());
}

#[test]
fn test_http_client_builder_mixed_header_methods() {
    let headers = vec![("X-Batch-1".to_string(), "batch-value".to_string())];

    let builder = HttpClientBuilder::new()
        .header("X-Single", "single-value")
        .headers(&headers)
        .header("X-Another", "another-value");

    let client = builder.build();
    assert!(client.is_ok());
}

#[test]
fn test_http_client_builder_empty_headers() {
    let headers: Vec<(String, String)> = vec![];
    let builder = HttpClientBuilder::new().headers(&headers);
    let client = builder.build();
    assert!(client.is_ok());
}

#[test]
fn test_http_client_builder_boolean_options() {
    let test_cases: Vec<Box<dyn Fn(bool) -> HttpClientBuilder>> = vec![
        Box::new(|v| HttpClientBuilder::new().verbose(v)),
        Box::new(|v| HttpClientBuilder::new().follow_redirects(v)),
    ];

    for builder_fn in test_cases {
        for value in [true, false] {
            let builder = builder_fn(value);
            let client = builder.build();
            assert!(client.is_ok(), "Builder with value {value} should succeed");
        }
    }
}

#[test]
fn test_http_client_builder_minimal_config() {
    // Just build with no configuration
    let client = HttpClientBuilder::new().build();
    assert!(client.is_ok());
}

#[test]
fn test_http_client_builder_maximal_config() {
    let headers = vec![
        ("X-Header-1".to_string(), "value1".to_string()),
        ("X-Header-2".to_string(), "value2".to_string()),
        ("X-Header-3".to_string(), "value3".to_string()),
    ];

    let builder = HttpClientBuilder::new()
        .verbose(true)
        .timeout(120)
        .follow_redirects(true)
        .user_agent("MaximalAgent/2.0")
        .headers(&headers)
        .header("X-Extra", "extra-value");

    let client = builder.build();
    assert!(client.is_ok());
}

#[test]
fn test_http_client_builder_string_conversions() {
    // Test that Into<String> works properly
    let builder = HttpClientBuilder::new()
        .header(String::from("X-String"), String::from("string-value"))
        .header("X-Str", "str-value")
        .user_agent(String::from("StringAgent/1.0"));

    let client = builder.build();
    assert!(client.is_ok());
}
