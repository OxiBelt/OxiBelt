use super::*;
use pretty_assertions::assert_eq;

#[test]
fn hot_object_cache_hits_by_resolved_path() {
  let temp_dir = common::TempDir::new("static-hot-object-cache-hit");
  let root = temp_dir.path().join("public");
  std::fs::create_dir_all(&root).unwrap();
  let path = root.join("app.txt");
  let runtime = runtime_for_root(&root, hot_object_cache_config(4, 10_000, 1024));

  runtime.store_object(
    &root,
    path.clone(),
    "W/\"cache-hit\"".to_owned(),
    None,
    Bytes::from_static(b"cached body"),
  );
  let cached = runtime
    .cached_object(&root.join("unused-root-key"), &path)
    .expect("object should be cached by resolved path");

  assert_eq!(cached.path, path);
  assert_eq!(cached.body, Bytes::from_static(b"cached body"));
  assert_eq!(cached.full_content_length_header.unwrap(), "11");
  assert_eq!(cached.content_type_header, "text/plain; charset=utf-8");
}

#[test]
fn hot_object_cache_expires_entries() {
  let temp_dir = common::TempDir::new("static-hot-object-cache-expiry");
  let root = temp_dir.path().join("public");
  std::fs::create_dir_all(&root).unwrap();
  let path = root.join("app.txt");
  let runtime = runtime_for_root(&root, hot_object_cache_config(4, 1, 1024));

  runtime.store_object(
    &root,
    path.clone(),
    "W/\"cache-expiry\"".to_owned(),
    None,
    Bytes::from_static(b"cached body"),
  );
  std::thread::sleep(Duration::from_millis(10));

  assert!(runtime.cached_object(&root, &path).is_none());
}

#[test]
fn hot_object_cache_evicts_oldest_entry_when_full() {
  let temp_dir = common::TempDir::new("static-hot-object-cache-eviction");
  let root = temp_dir.path().join("public");
  std::fs::create_dir_all(&root).unwrap();
  let first = root.join("first.txt");
  let second = root.join("second.txt");
  let runtime = runtime_for_root(&root, hot_object_cache_config(1, 10_000, 1024));

  runtime.store_object(
    &root,
    first.clone(),
    "W/\"first\"".to_owned(),
    None,
    Bytes::from_static(b"first"),
  );
  runtime.store_object(
    &root,
    second.clone(),
    "W/\"second\"".to_owned(),
    None,
    Bytes::from_static(b"second"),
  );

  assert!(runtime.cached_object(&root, &first).is_none());
  assert_eq!(
    runtime.cached_object(&root, &second).unwrap().body,
    Bytes::from_static(b"second")
  );
}

async fn collect_response_body(response: Response<ProxyBody>) -> Bytes {
  response.into_body().collect().await.unwrap().to_bytes()
}

#[tokio::test]
async fn hot_object_cache_serves_cached_body_before_ttl() {
  let temp_dir = common::TempDir::new("static-hot-object-cache-hit");
  let root = temp_dir.path().join("public");
  tokio::fs::create_dir_all(&root).await.unwrap();
  tokio::fs::write(root.join("app.txt"), "safe body")
    .await
    .unwrap();
  let runtime = runtime_for_root(&root, hot_object_cache_config(4, 3_600_000, 1024));

  let first = serve(
    &request("/assets/app.txt"),
    "assets",
    "/assets",
    &root,
    &runtime,
    16 * 1024,
  )
  .await;
  assert_eq!(first.status(), StatusCode::OK);
  assert_eq!(
    collect_response_body(first).await,
    Bytes::from_static(b"safe body")
  );

  tokio::fs::write(root.join("app.txt"), "updated body")
    .await
    .unwrap();
  let cached = serve(
    &request("/assets/app.txt"),
    "assets",
    "/assets",
    &root,
    &runtime,
    16 * 1024,
  )
  .await;
  assert_eq!(
    collect_response_body(cached).await,
    Bytes::from_static(b"safe body")
  );
}

#[tokio::test]
async fn hot_object_cache_revalidates_after_ttl() {
  let temp_dir = common::TempDir::new("static-hot-object-cache-revalidate");
  let root = temp_dir.path().join("public");
  tokio::fs::create_dir_all(&root).await.unwrap();
  tokio::fs::write(root.join("app.txt"), "safe body")
    .await
    .unwrap();
  let runtime = runtime_for_root(&root, hot_object_cache_config(4, 1, 1024));

  let first = serve(
    &request("/assets/app.txt"),
    "assets",
    "/assets",
    &root,
    &runtime,
    16 * 1024,
  )
  .await;
  assert_eq!(first.status(), StatusCode::OK);
  assert_eq!(
    collect_response_body(first).await,
    Bytes::from_static(b"safe body")
  );

  tokio::fs::write(root.join("app.txt"), "updated body")
    .await
    .unwrap();

  tokio::time::sleep(Duration::from_millis(20)).await;
  let refreshed = serve(
    &request("/assets/app.txt"),
    "assets",
    "/assets",
    &root,
    &runtime,
    16 * 1024,
  )
  .await;
  assert_eq!(
    collect_response_body(refreshed).await,
    Bytes::from_static(b"updated body")
  );
}

#[tokio::test]
async fn hot_object_cache_fails_closed_on_symlink_escape_after_ttl() {
  let temp_dir = common::TempDir::new("static-hot-object-cache-symlink");
  let root = temp_dir.path().join("public");
  let outside = temp_dir.path().join("outside-secret.txt");
  tokio::fs::create_dir_all(&root).await.unwrap();
  tokio::fs::write(root.join("app.txt"), "safe body")
    .await
    .unwrap();
  tokio::fs::write(&outside, "outside secret").await.unwrap();
  let runtime = runtime_for_root(&root, hot_object_cache_config(4, 1, 1024));

  let first = serve(
    &request("/assets/app.txt"),
    "assets",
    "/assets",
    &root,
    &runtime,
    16 * 1024,
  )
  .await;
  assert_eq!(first.status(), StatusCode::OK);
  assert_eq!(
    collect_response_body(first).await,
    Bytes::from_static(b"safe body")
  );

  tokio::fs::remove_file(root.join("app.txt")).await.unwrap();
  std::os::unix::fs::symlink(&outside, root.join("app.txt")).unwrap();
  tokio::time::sleep(Duration::from_millis(20)).await;
  let escaped = serve(
    &request("/assets/app.txt"),
    "assets",
    "/assets",
    &root,
    &runtime,
    16 * 1024,
  )
  .await;

  assert_eq!(escaped.status(), StatusCode::FORBIDDEN);
  let body = collect_response_body(escaped).await;
  assert_ne!(body, Bytes::from_static(b"outside secret"));
}
