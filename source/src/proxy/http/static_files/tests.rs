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
#[cfg(target_os = "linux")]
use tokio::io::AsyncReadExt;

use super::*;

fn request(path: &str) -> Request<Empty<Bytes>> {
  Request::builder()
    .method(Method::GET)
    .uri(path)
    .body(Empty::new())
    .expect("request should build")
}

async fn serve_test(
  request: &Request<Empty<Bytes>>,
  route_name: &str,
  route_prefix: &str,
  static_root: &Path,
) -> Response<ProxyBody> {
  serve(request, route_name, route_prefix, static_root, 16 * 1024).await
}

#[tokio::test]
async fn serves_regular_file_with_validator_headers() {
  let temp_dir = common::TempDir::new("static-ok");
  let root = temp_dir.path().join("public");
  tokio::fs::create_dir_all(&root).await.unwrap();
  tokio::fs::write(root.join("app.txt"), "hello static")
    .await
    .unwrap();

  let response = serve_test(&request("/assets/app.txt"), "assets", "/assets", &root).await;

  assert_eq!(response.status(), StatusCode::OK);
  assert_eq!(
    response.headers().get(CONTENT_TYPE).unwrap(),
    "text/plain; charset=utf-8"
  );
  assert!(response.headers().contains_key(ETAG));
  let body = response.into_body().collect().await.unwrap().to_bytes();
  assert_eq!(body, Bytes::from_static(b"hello static"));
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn linux_openat2_secure_open_reads_regular_file_with_descriptor_verification() {
  let temp_dir = common::TempDir::new("static-openat2");
  let root = temp_dir.path().join("public");
  let path = root.join("app.txt");
  tokio::fs::create_dir_all(&root).await.unwrap();
  tokio::fs::write(&path, "openat2 static").await.unwrap();

  let Some(mut opened) = open_verified_file_with_openat2_for_tests(&root, &path)
    .await
    .expect("openat2 helper should not fail when the syscall is available")
  else {
    return;
  };
  let mut body = String::new();
  opened.file.read_to_string(&mut body).await.unwrap();

  assert_eq!(opened.path, path);
  assert_eq!(opened.metadata.len(), "openat2 static".len() as u64);
  assert_eq!(body, "openat2 static");
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn linux_openat2_rejects_static_root_swap_after_validation() {
  let temp_dir = common::TempDir::new("static-openat2-root-swap");
  let configured_root = temp_dir.path().join("public");
  let attacker_root = temp_dir.path().join("attacker-controlled");
  tokio::fs::create_dir_all(&configured_root).await.unwrap();
  tokio::fs::create_dir_all(&attacker_root).await.unwrap();
  tokio::fs::write(configured_root.join("secret.txt"), "INSIDE_VALIDATED_ROOT")
    .await
    .unwrap();
  tokio::fs::write(attacker_root.join("secret.txt"), "OUTSIDE_VALIDATED_ROOT")
    .await
    .unwrap();
  let validated_root = validate_static_root(&configured_root).unwrap();
  tokio::fs::remove_dir_all(&configured_root).await.unwrap();
  std::os::unix::fs::symlink(&attacker_root, &configured_root).unwrap();
  let request_path = validated_root.join("secret.txt");

  match open_verified_file_with_openat2_for_tests(&validated_root, &request_path).await {
    Ok(None) => {}
    Ok(Some(mut opened)) => {
      let mut body = String::new();
      opened.file.read_to_string(&mut body).await.unwrap();
      panic!("openat2 served a swapped static_root file outside confinement: {body}");
    }
    Err(StaticOpenError::Forbidden(error)) => {
      assert!(
        error
          .chain()
          .any(|cause| cause.to_string().contains("escapes static_root")),
        "unexpected error: {error}"
      );
    }
    Err(StaticOpenError::NotFound) => {
      panic!("swapped static_root should be rejected, not treated as missing");
    }
  }
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn serve_rejects_static_root_swap_after_validation() {
  let temp_dir = common::TempDir::new("static-serve-root-swap");
  let configured_root = temp_dir.path().join("public");
  let attacker_root = temp_dir.path().join("attacker-controlled");
  tokio::fs::create_dir_all(&configured_root).await.unwrap();
  tokio::fs::create_dir_all(&attacker_root).await.unwrap();
  tokio::fs::write(configured_root.join("secret.txt"), "INSIDE_VALIDATED_ROOT")
    .await
    .unwrap();
  tokio::fs::write(attacker_root.join("secret.txt"), "OUTSIDE_VALIDATED_ROOT")
    .await
    .unwrap();
  let validated_root = validate_static_root(&configured_root).unwrap();
  tokio::fs::remove_dir_all(&configured_root).await.unwrap();
  std::os::unix::fs::symlink(&attacker_root, &configured_root).unwrap();

  let response = serve_test(
    &request("/assets/secret.txt"),
    "assets",
    "/assets",
    &validated_root,
  )
  .await;

  assert_eq!(response.status(), StatusCode::FORBIDDEN);
  let body = response.into_body().collect().await.unwrap().to_bytes();
  assert_eq!(body, Bytes::from_static(b"forbidden"));
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

  let response = serve_test(&request, "assets", "/assets", &root).await;

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

  let response = serve_test(&request("/assets/nested"), "assets", "/assets", &root).await;

  assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn missing_file_returns_not_found() {
  let temp_dir = common::TempDir::new("static-missing");
  let root = temp_dir.path().join("public");
  tokio::fs::create_dir_all(&root).await.unwrap();

  let response = serve_test(&request("/assets/missing.txt"), "assets", "/assets", &root).await;

  assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn rejects_symlink_escape() {
  let temp_dir = common::TempDir::new("static-symlink");
  let root = temp_dir.path().join("public");
  let outside = temp_dir.path().join("secret.txt");
  tokio::fs::create_dir_all(&root).await.unwrap();
  tokio::fs::write(&outside, "secret").await.unwrap();
  std::os::unix::fs::symlink(&outside, root.join("link.txt")).unwrap();

  let response = serve_test(&request("/assets/link.txt"), "assets", "/assets", &root).await;

  assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn planned_response_body_uses_original_verified_fd_after_path_swap() {
  let temp_dir = common::TempDir::new("static-fd-race");
  let root = temp_dir.path().join("public");
  let public_path = root.join("race.txt");
  let outside = temp_dir.path().join("outside-secret.txt");
  tokio::fs::create_dir_all(&root).await.unwrap();
  tokio::fs::write(&public_path, "public race body")
    .await
    .unwrap();
  tokio::fs::write(&outside, "outside secret body")
    .await
    .unwrap();
  let request = request("/assets/race.txt");

  let plan = plan_response(
    request.method(),
    request.headers(),
    request.uri().path(),
    "assets",
    "/assets",
    &root,
  )
  .await;
  assert_eq!(plan.status, StatusCode::OK);
  assert!(matches!(&plan.body, StaticBodyPlan::File(_)));

  tokio::fs::remove_file(&public_path).await.unwrap();
  std::os::unix::fs::symlink(&outside, &public_path).unwrap();

  let response = response_from_plan(plan, 16 * 1024).await;

  assert_eq!(response.status(), StatusCode::OK);
  let body = response.into_body().collect().await.unwrap().to_bytes();
  assert_eq!(body, Bytes::from_static(b"public race body"));
  assert_ne!(body, Bytes::from_static(b"outside secret body"));
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

  let response = serve_test(&request, "assets", "/assets", &root).await;

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
  let first = serve_test(&request("/assets/app.txt"), "assets", "/assets", &root).await;
  let etag = first.headers().get(ETAG).unwrap().clone();
  let mut request = request("/assets/app.txt");
  request.headers_mut().insert(IF_NONE_MATCH, etag);

  let response = serve_test(&request, "assets", "/assets", &root).await;

  assert_eq!(response.status(), StatusCode::NOT_MODIFIED);
  let body = response.into_body().collect().await.unwrap().to_bytes();
  assert!(body.is_empty());
}

#[tokio::test]
async fn small_file_inline_threshold_marks_known_small_body() {
  let temp_dir = common::TempDir::new("static-inline");
  let root = temp_dir.path().join("public");
  tokio::fs::create_dir_all(&root).await.unwrap();
  tokio::fs::write(root.join("app.txt"), "small")
    .await
    .unwrap();

  let response = serve(&request("/assets/app.txt"), "assets", "/assets", &root, 16).await;

  assert_eq!(response.status(), StatusCode::OK);
  assert!(
    response
      .extensions()
      .get::<KnownSmallResponseBody>()
      .is_some()
  );
  let body = response.into_body().collect().await.unwrap().to_bytes();
  assert_eq!(body, Bytes::from_static(b"small"));
}

#[tokio::test]
async fn zero_inline_threshold_uses_streaming_body() {
  let temp_dir = common::TempDir::new("static-no-inline");
  let root = temp_dir.path().join("public");
  tokio::fs::create_dir_all(&root).await.unwrap();
  tokio::fs::write(root.join("app.txt"), "small")
    .await
    .unwrap();

  let response = serve(&request("/assets/app.txt"), "assets", "/assets", &root, 0).await;

  assert_eq!(response.status(), StatusCode::OK);
  assert!(
    response
      .extensions()
      .get::<KnownSmallResponseBody>()
      .is_none()
  );
  let body = response.into_body().collect().await.unwrap().to_bytes();
  assert_eq!(body, Bytes::from_static(b"small"));
}

#[tokio::test]
async fn opened_file_validation_rejects_fd_outside_static_root() {
  let temp_dir = common::TempDir::new("static-fd-root");
  let root = temp_dir.path().join("public");
  let outside = temp_dir.path().join("outside.txt");
  tokio::fs::create_dir_all(&root).await.unwrap();
  tokio::fs::write(&outside, "secret").await.unwrap();
  let file = tokio::fs::File::open(&outside).await.unwrap();
  let root = root.canonicalize().unwrap();

  let error = verify_opened_file(&file, &root).unwrap_err();

  assert!(
    error.to_string().contains("escapes static_root"),
    "unexpected error: {error}"
  );
}

#[test]
fn resolver_rejects_encoded_separators_and_dot_segments() {
  let root = Path::new("/tmp");

  assert_eq!(
    resolve_request_path(root, "/assets", "/assets/%2e%2e/secret").unwrap_err(),
    StaticPathError::Forbidden
  );
  for request_path in [
    "/assets/%2fsecret",
    "/assets/%2Fsecret",
    "/assets/%5csecret",
    "/assets/%5Csecret",
  ] {
    assert_eq!(
      resolve_request_path(root, "/assets", request_path).unwrap_err(),
      StaticPathError::Invalid,
      "{request_path} should be rejected"
    );
  }
}

#[test]
fn resolver_builds_lexical_path_without_requiring_existing_file() {
  let root = Path::new("/tmp/oxibelt-static-root");

  let resolved = resolve_request_path(root, "/assets", "/assets/missing/app.txt")
    .expect("lexical path should resolve before file open");

  assert_eq!(resolved, root.join("missing").join("app.txt"));
}
