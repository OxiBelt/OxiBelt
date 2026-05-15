#[allow(dead_code)]
mod common {
  include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../tests/rust/common/mod.rs"
  ));
}

use std::path::Path;

use bytes::Bytes;
use http::header::{CONTENT_LENGTH, CONTENT_RANGE, CONTENT_TYPE, ETAG, IF_NONE_MATCH, RANGE};
use http::{HeaderValue, Method, Request, StatusCode};
use http_body_util::{BodyExt, Empty};
use pretty_assertions::assert_eq;

use super::*;

fn request(path: &str) -> Request<Empty<Bytes>> {
  Request::builder()
    .method(Method::GET)
    .uri(path)
    .body(Empty::new())
    .expect("request should build")
}

#[tokio::test]
async fn serves_regular_file_with_validator_headers() {
  let temp_dir = common::TempDir::new("static-ok");
  let root = temp_dir.path().join("public");
  tokio::fs::create_dir_all(&root).await.unwrap();
  tokio::fs::write(root.join("app.txt"), "hello static")
    .await
    .unwrap();

  let response = serve(&request("/assets/app.txt"), "assets", "/assets", &root).await;

  assert_eq!(response.status(), StatusCode::OK);
  assert_eq!(
    response.headers().get(CONTENT_TYPE).unwrap(),
    "text/plain; charset=utf-8"
  );
  assert!(response.headers().contains_key(ETAG));
  let body = response.into_body().collect().await.unwrap().to_bytes();
  assert_eq!(body, Bytes::from_static(b"hello static"));
}

#[tokio::test]
async fn head_uses_file_headers_without_body() {
  let temp_dir = common::TempDir::new("static-head");
  let root = temp_dir.path().join("public");
  tokio::fs::create_dir_all(&root).await.unwrap();
  tokio::fs::write(root.join("app.txt"), "hello")
    .await
    .unwrap();
  let request = Request::builder()
    .method(Method::HEAD)
    .uri("/assets/app.txt")
    .body(Empty::new())
    .unwrap();

  let response = serve(&request, "assets", "/assets", &root).await;

  assert_eq!(response.status(), StatusCode::OK);
  assert_eq!(response.headers().get(CONTENT_LENGTH).unwrap(), "5");
  let body = response.into_body().collect().await.unwrap().to_bytes();
  assert!(body.is_empty());
}

#[tokio::test]
async fn rejects_directory_listing() {
  let temp_dir = common::TempDir::new("static-dir");
  let root = temp_dir.path().join("public");
  tokio::fs::create_dir_all(root.join("nested"))
    .await
    .unwrap();

  let response = serve(&request("/assets/nested"), "assets", "/assets", &root).await;

  assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn rejects_symlink_escape() {
  let temp_dir = common::TempDir::new("static-symlink");
  let root = temp_dir.path().join("public");
  let outside = temp_dir.path().join("secret.txt");
  tokio::fs::create_dir_all(&root).await.unwrap();
  tokio::fs::write(&outside, "secret").await.unwrap();
  std::os::unix::fs::symlink(&outside, root.join("link.txt")).unwrap();

  let response = serve(&request("/assets/link.txt"), "assets", "/assets", &root).await;

  assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn supports_single_byte_range() {
  let temp_dir = common::TempDir::new("static-range");
  let root = temp_dir.path().join("public");
  tokio::fs::create_dir_all(&root).await.unwrap();
  tokio::fs::write(root.join("app.txt"), "hello static")
    .await
    .unwrap();
  let mut request = request("/assets/app.txt");
  request
    .headers_mut()
    .insert(RANGE, HeaderValue::from_static("bytes=6-11"));

  let response = serve(&request, "assets", "/assets", &root).await;

  assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
  assert_eq!(
    response.headers().get(CONTENT_RANGE).unwrap(),
    "bytes 6-11/12"
  );
  let body = response.into_body().collect().await.unwrap().to_bytes();
  assert_eq!(body, Bytes::from_static(b"static"));
}

#[tokio::test]
async fn conditional_etag_returns_not_modified() {
  let temp_dir = common::TempDir::new("static-etag");
  let root = temp_dir.path().join("public");
  tokio::fs::create_dir_all(&root).await.unwrap();
  tokio::fs::write(root.join("app.txt"), "hello")
    .await
    .unwrap();
  let first = serve(&request("/assets/app.txt"), "assets", "/assets", &root).await;
  let etag = first.headers().get(ETAG).unwrap().clone();
  let mut request = request("/assets/app.txt");
  request.headers_mut().insert(IF_NONE_MATCH, etag);

  let response = serve(&request, "assets", "/assets", &root).await;

  assert_eq!(response.status(), StatusCode::NOT_MODIFIED);
  let body = response.into_body().collect().await.unwrap().to_bytes();
  assert!(body.is_empty());
}

#[test]
fn resolver_rejects_encoded_separators_and_dot_segments() {
  let root = Path::new("/tmp");

  assert_eq!(
    resolve_request_path(root, "/assets", "/assets/%2e%2e/secret").unwrap_err(),
    StaticPathError::Forbidden
  );
  assert_eq!(
    resolve_request_path(root, "/assets", "/assets/%2fsecret").unwrap_err(),
    StaticPathError::Invalid
  );
}
