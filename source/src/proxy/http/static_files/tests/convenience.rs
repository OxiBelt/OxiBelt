use bytes::Bytes;
use http::header::{
  ACCEPT, ACCEPT_ENCODING, CACHE_CONTROL, CONTENT_ENCODING, CONTENT_TYPE, RANGE, VARY,
};
use http::{HeaderValue, Method, Request, StatusCode};
use http_body_util::{BodyExt, Empty};

use crate::config::{
  ProxyStaticFilesConfig, RouteStaticFileErrorPagesConfig, RouteStaticFilesConfig,
  StaticPrecompressedEncoding,
};

use super::{
  common, hot_object_cache_config, request, runtime_for_root, serve_with_options,
  serve_with_runtime_and_options,
};

#[tokio::test]
async fn directory_index_serves_configured_index_file_without_listing() {
  let temp_dir = common::TempDir::new("static-directory-index");
  let root = temp_dir.path().join("public");
  tokio::fs::create_dir_all(root.join("docs")).await.unwrap();
  tokio::fs::write(root.join("docs").join("index.html"), "<h1>docs</h1>")
    .await
    .unwrap();
  let static_options = RouteStaticFilesConfig {
    directory_index: vec!["index.html".to_string()],
    ..RouteStaticFilesConfig::default()
  };

  let response = serve_with_options(
    &request("/assets/docs"),
    "assets",
    "/assets",
    &root,
    &static_options,
  )
  .await;

  assert_eq!(response.status(), StatusCode::OK);
  assert_eq!(
    response.headers().get(CONTENT_TYPE).unwrap(),
    "text/html; charset=utf-8"
  );
  let body = response.into_body().collect().await.unwrap().to_bytes();
  assert_eq!(body, Bytes::from_static(b"<h1>docs</h1>"));
}

#[tokio::test]
async fn try_files_uses_path_placeholder_after_primary_miss() {
  let temp_dir = common::TempDir::new("static-try-files");
  let root = temp_dir.path().join("public");
  tokio::fs::create_dir_all(&root).await.unwrap();
  tokio::fs::write(root.join("guide.html"), "guide page")
    .await
    .unwrap();
  let static_options = RouteStaticFilesConfig {
    try_files: vec!["{path}.html".to_string(), "/index.html".to_string()],
    ..RouteStaticFilesConfig::default()
  };

  let response = serve_with_options(
    &request("/assets/guide"),
    "assets",
    "/assets",
    &root,
    &static_options,
  )
  .await;

  assert_eq!(response.status(), StatusCode::OK);
  let body = response.into_body().collect().await.unwrap().to_bytes();
  assert_eq!(body, Bytes::from_static(b"guide page"));
}

#[tokio::test]
async fn spa_fallback_is_limited_to_html_extensionless_misses() {
  let temp_dir = common::TempDir::new("static-spa-fallback");
  let root = temp_dir.path().join("public");
  tokio::fs::create_dir_all(&root).await.unwrap();
  tokio::fs::write(root.join("index.html"), "spa shell")
    .await
    .unwrap();
  let static_options = RouteStaticFilesConfig {
    spa_fallback: Some("/index.html".to_string()),
    ..RouteStaticFilesConfig::default()
  };
  let html_request = Request::builder()
    .method(Method::GET)
    .uri("/assets/dashboard")
    .header(
      ACCEPT,
      "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    )
    .body(Empty::new())
    .unwrap();
  let asset_request = Request::builder()
    .method(Method::GET)
    .uri("/assets/app.js")
    .header(ACCEPT, "text/html")
    .body(Empty::new())
    .unwrap();

  let html_response =
    serve_with_options(&html_request, "assets", "/assets", &root, &static_options).await;
  let asset_response =
    serve_with_options(&asset_request, "assets", "/assets", &root, &static_options).await;
  let no_accept_response = serve_with_options(
    &request("/assets/settings"),
    "assets",
    "/assets",
    &root,
    &static_options,
  )
  .await;

  assert_eq!(html_response.status(), StatusCode::OK);
  assert_eq!(
    html_response
      .into_body()
      .collect()
      .await
      .unwrap()
      .to_bytes(),
    Bytes::from_static(b"spa shell")
  );
  assert_eq!(asset_response.status(), StatusCode::NOT_FOUND);
  assert_eq!(no_accept_response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn precompressed_variant_uses_accept_encoding_quality_and_preserves_logical_type() {
  let temp_dir = common::TempDir::new("static-precompressed");
  let root = temp_dir.path().join("public");
  tokio::fs::create_dir_all(&root).await.unwrap();
  tokio::fs::write(root.join("app.js"), "plain javascript")
    .await
    .unwrap();
  tokio::fs::write(root.join("app.js.br"), "brotli bytes")
    .await
    .unwrap();
  tokio::fs::write(root.join("app.js.gz"), "gzip bytes")
    .await
    .unwrap();
  let static_options = RouteStaticFilesConfig {
    precompressed: vec![
      StaticPrecompressedEncoding::Gzip,
      StaticPrecompressedEncoding::Br,
    ],
    ..RouteStaticFilesConfig::default()
  };
  let request = Request::builder()
    .method(Method::GET)
    .uri("/assets/app.js")
    .header(ACCEPT_ENCODING, "gzip;q=0.5, br;q=1.0")
    .body(Empty::new())
    .unwrap();

  let response = serve_with_options(&request, "assets", "/assets", &root, &static_options).await;

  assert_eq!(response.status(), StatusCode::OK);
  assert_eq!(response.headers().get(CONTENT_ENCODING).unwrap(), "br");
  assert_eq!(response.headers().get(VARY).unwrap(), "Accept-Encoding");
  assert_eq!(
    response.headers().get(CONTENT_TYPE).unwrap(),
    "application/javascript; charset=utf-8"
  );
  let body = response.into_body().collect().await.unwrap().to_bytes();
  assert_eq!(body, Bytes::from_static(b"brotli bytes"));

  let plain_response = serve_with_options(
    &super::request("/assets/app.js"),
    "assets",
    "/assets",
    &root,
    &static_options,
  )
  .await;
  assert_eq!(plain_response.status(), StatusCode::OK);
  assert!(!plain_response.headers().contains_key(CONTENT_ENCODING));
  assert_eq!(
    plain_response.headers().get(VARY).unwrap(),
    "Accept-Encoding"
  );
  let body = plain_response
    .into_body()
    .collect()
    .await
    .unwrap()
    .to_bytes();
  assert_eq!(body, Bytes::from_static(b"plain javascript"));
}

#[tokio::test]
async fn range_requests_bypass_precompressed_variants() {
  let temp_dir = common::TempDir::new("static-precompressed-range");
  let root = temp_dir.path().join("public");
  tokio::fs::create_dir_all(&root).await.unwrap();
  tokio::fs::write(root.join("app.js"), "plain javascript")
    .await
    .unwrap();
  tokio::fs::write(root.join("app.js.br"), "brotli bytes")
    .await
    .unwrap();
  let static_options = RouteStaticFilesConfig {
    precompressed: vec![StaticPrecompressedEncoding::Br],
    ..RouteStaticFilesConfig::default()
  };
  let mut request = request("/assets/app.js");
  request
    .headers_mut()
    .insert(ACCEPT_ENCODING, HeaderValue::from_static("br"));
  request
    .headers_mut()
    .insert(RANGE, HeaderValue::from_static("bytes=0-4"));

  let response = serve_with_options(&request, "assets", "/assets", &root, &static_options).await;

  assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
  assert!(!response.headers().contains_key(CONTENT_ENCODING));
  assert!(!response.headers().contains_key(VARY));
  let body = response.into_body().collect().await.unwrap().to_bytes();
  assert_eq!(body, Bytes::from_static(b"plain"));
}

#[tokio::test]
async fn mime_overrides_and_cache_control_apply_to_successful_static_responses() {
  let temp_dir = common::TempDir::new("static-mime-cache-control");
  let root = temp_dir.path().join("public");
  tokio::fs::create_dir_all(&root).await.unwrap();
  tokio::fs::write(root.join("module.wasm"), "wasm")
    .await
    .unwrap();
  tokio::fs::write(root.join("app.js"), "js").await.unwrap();
  let static_options = RouteStaticFilesConfig {
    cache_control: Some("public, max-age=60".to_string()),
    cache_control_by_extension: [("js".to_string(), "public, max-age=31536000".to_string())]
      .into_iter()
      .collect(),
    mime_overrides: [("wasm".to_string(), "application/x-test-wasm".to_string())]
      .into_iter()
      .collect(),
    ..RouteStaticFilesConfig::default()
  };

  let wasm = serve_with_options(
    &request("/assets/module.wasm"),
    "assets",
    "/assets",
    &root,
    &static_options,
  )
  .await;
  let js = serve_with_options(
    &request("/assets/app.js"),
    "assets",
    "/assets",
    &root,
    &static_options,
  )
  .await;

  assert_eq!(wasm.status(), StatusCode::OK);
  assert_eq!(
    wasm.headers().get(CONTENT_TYPE).unwrap(),
    "application/x-test-wasm"
  );
  assert_eq!(
    wasm.headers().get(CACHE_CONTROL).unwrap(),
    "public, max-age=60"
  );
  assert_eq!(js.status(), StatusCode::OK);
  assert_eq!(
    js.headers().get(CACHE_CONTROL).unwrap(),
    "public, max-age=31536000"
  );
}

#[tokio::test]
async fn custom_not_found_page_uses_configured_file_without_cache_control() {
  let temp_dir = common::TempDir::new("static-custom-404");
  let root = temp_dir.path().join("public");
  tokio::fs::create_dir_all(&root).await.unwrap();
  tokio::fs::write(root.join("404.html"), "missing page")
    .await
    .unwrap();
  let static_options = RouteStaticFilesConfig {
    cache_control: Some("public, max-age=60".to_string()),
    error_pages: RouteStaticFileErrorPagesConfig {
      not_found: Some("/404.html".to_string()),
      server_error: None,
    },
    ..RouteStaticFilesConfig::default()
  };

  let response = serve_with_options(
    &request("/assets/missing"),
    "assets",
    "/assets",
    &root,
    &static_options,
  )
  .await;

  assert_eq!(response.status(), StatusCode::NOT_FOUND);
  assert!(!response.headers().contains_key(CACHE_CONTROL));
  assert_eq!(
    response.headers().get(CONTENT_TYPE).unwrap(),
    "text/html; charset=utf-8"
  );
  let body = response.into_body().collect().await.unwrap().to_bytes();
  assert_eq!(body, Bytes::from_static(b"missing page"));
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn custom_server_error_page_is_used_when_static_root_path_disappears() {
  let temp_dir = common::TempDir::new("static-custom-50x");
  let root = temp_dir.path().join("public");
  let moved_root = temp_dir.path().join("moved-public");
  tokio::fs::create_dir_all(&root).await.unwrap();
  tokio::fs::write(root.join("50x.html"), "static unavailable")
    .await
    .unwrap();
  let runtime = runtime_for_root(&root, ProxyStaticFilesConfig::default());
  tokio::fs::rename(&root, &moved_root).await.unwrap();
  let static_options = RouteStaticFilesConfig {
    error_pages: RouteStaticFileErrorPagesConfig {
      not_found: None,
      server_error: Some("/50x.html".to_string()),
    },
    ..RouteStaticFilesConfig::default()
  };

  let response = serve_with_runtime_and_options(
    &request("/assets/missing"),
    "assets",
    "/assets",
    &root,
    &runtime,
    &static_options,
    16 * 1024,
  )
  .await;

  assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
  let body = response.into_body().collect().await.unwrap().to_bytes();
  assert_eq!(body, Bytes::from_static(b"static unavailable"));
}

#[tokio::test]
async fn bad_custom_error_page_falls_back_without_directory_listing() {
  let temp_dir = common::TempDir::new("static-bad-custom-error");
  let root = temp_dir.path().join("public");
  tokio::fs::create_dir_all(root.join("errors"))
    .await
    .unwrap();
  let static_options = RouteStaticFilesConfig {
    error_pages: RouteStaticFileErrorPagesConfig {
      not_found: Some("/errors".to_string()),
      server_error: None,
    },
    ..RouteStaticFilesConfig::default()
  };

  let response = serve_with_options(
    &request("/assets/missing"),
    "assets",
    "/assets",
    &root,
    &static_options,
  )
  .await;

  assert_eq!(response.status(), StatusCode::NOT_FOUND);
  let body = response.into_body().collect().await.unwrap().to_bytes();
  assert_eq!(body, Bytes::from_static(b"not found"));
}

#[tokio::test]
async fn convenience_candidates_do_not_escape_static_root_at_runtime() {
  let temp_dir = common::TempDir::new("static-convenience-traversal");
  let root = temp_dir.path().join("public");
  let outside = temp_dir.path().join("outside.txt");
  tokio::fs::create_dir_all(root.join("nested"))
    .await
    .unwrap();
  tokio::fs::write(&outside, "outside secret").await.unwrap();

  let directory_index_options = RouteStaticFilesConfig {
    directory_index: vec!["../../outside.txt".to_string()],
    ..RouteStaticFilesConfig::default()
  };
  let directory_index_response = serve_with_options(
    &request("/assets/nested"),
    "assets",
    "/assets",
    &root,
    &directory_index_options,
  )
  .await;
  assert_eq!(directory_index_response.status(), StatusCode::FORBIDDEN);

  let try_files_options = RouteStaticFilesConfig {
    try_files: vec!["/../outside.txt".to_string()],
    ..RouteStaticFilesConfig::default()
  };
  let try_files_response = serve_with_options(
    &request("/assets/missing"),
    "assets",
    "/assets",
    &root,
    &try_files_options,
  )
  .await;
  assert_eq!(try_files_response.status(), StatusCode::FORBIDDEN);

  let spa_options = RouteStaticFilesConfig {
    spa_fallback: Some("/../outside.txt".to_string()),
    ..RouteStaticFilesConfig::default()
  };
  let spa_request = Request::builder()
    .method(Method::GET)
    .uri("/assets/dashboard")
    .header(ACCEPT, "text/html")
    .body(Empty::new())
    .unwrap();
  let spa_response =
    serve_with_options(&spa_request, "assets", "/assets", &root, &spa_options).await;
  assert_eq!(spa_response.status(), StatusCode::FORBIDDEN);

  let error_options = RouteStaticFilesConfig {
    error_pages: RouteStaticFileErrorPagesConfig {
      not_found: Some("/../outside.txt".to_string()),
      server_error: None,
    },
    ..RouteStaticFilesConfig::default()
  };
  let error_response = serve_with_options(
    &request("/assets/missing"),
    "assets",
    "/assets",
    &root,
    &error_options,
  )
  .await;
  assert_eq!(error_response.status(), StatusCode::NOT_FOUND);
  let body = error_response
    .into_body()
    .collect()
    .await
    .unwrap()
    .to_bytes();
  assert_eq!(body, Bytes::from_static(b"not found"));
  assert_ne!(body, Bytes::from_static(b"outside secret"));
}

#[tokio::test]
async fn hot_object_cache_keys_include_static_response_metadata() {
  let temp_dir = common::TempDir::new("static-hot-cache-metadata");
  let root = temp_dir.path().join("public");
  tokio::fs::create_dir_all(&root).await.unwrap();
  tokio::fs::write(root.join("asset.bin"), "first")
    .await
    .unwrap();
  let runtime = runtime_for_root(&root, hot_object_cache_config(4, 3_600_000, 1024));
  let text_options = RouteStaticFilesConfig {
    mime_overrides: [("bin".to_string(), "text/plain".to_string())]
      .into_iter()
      .collect(),
    ..RouteStaticFilesConfig::default()
  };
  let default_options = RouteStaticFilesConfig::default();

  let first = serve_with_runtime_and_options(
    &request("/assets/asset.bin"),
    "assets",
    "/assets",
    &root,
    &runtime,
    &text_options,
    16 * 1024,
  )
  .await;
  assert_eq!(first.status(), StatusCode::OK);
  assert_eq!(first.headers().get(CONTENT_TYPE).unwrap(), "text/plain");

  tokio::fs::write(root.join("asset.bin"), "second")
    .await
    .unwrap();
  let second = serve_with_runtime_and_options(
    &request("/assets/asset.bin"),
    "assets",
    "/assets",
    &root,
    &runtime,
    &default_options,
    16 * 1024,
  )
  .await;

  assert_eq!(second.status(), StatusCode::OK);
  assert_eq!(
    second.headers().get(CONTENT_TYPE).unwrap(),
    "application/octet-stream"
  );
  let body = second.into_body().collect().await.unwrap().to_bytes();
  assert_eq!(body, Bytes::from_static(b"second"));
}
