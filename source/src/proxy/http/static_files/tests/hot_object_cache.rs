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
    StaticResponseMetadata::for_path(&path),
    Bytes::from_static(b"cached body"),
  );
  let cached = runtime
    .cached_object(&root, &path, &StaticResponseMetadata::for_path(&path))
    .expect("object should be cached by resolved path and metadata");

  assert_eq!(cached.path.as_path(), path.as_path());
  assert_eq!(cached.body.as_ref(), b"cached body");
  assert_eq!(
    cached.response_metadata.content_type,
    "text/plain; charset=utf-8"
  );
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
    StaticResponseMetadata::for_path(&path),
    Bytes::from_static(b"cached body"),
  );
  std::thread::sleep(Duration::from_millis(10));

  assert!(
    runtime
      .cached_object(&root, &path, &StaticResponseMetadata::for_path(&path))
      .is_none()
  );
}

#[test]
fn hot_object_cache_refreshes_matching_expired_entry() {
  let temp_dir = common::TempDir::new("static-hot-object-cache-refresh-expired");
  let root = temp_dir.path().join("public");
  std::fs::create_dir_all(&root).unwrap();
  let path = root.join("app.txt");
  std::fs::write(&path, "cached body").unwrap();
  let runtime = runtime_for_root(&root, hot_object_cache_config(4, 1, 1024));
  let metadata = std::fs::metadata(&path).unwrap();
  let etag = etag_for_metadata(&metadata);
  let modified = metadata.modified().ok();
  let response_metadata = StaticResponseMetadata::for_path(&path);

  runtime.store_object(
    &root,
    path.clone(),
    etag.clone(),
    modified,
    response_metadata.clone(),
    Bytes::from_static(b"cached body"),
  );
  std::thread::sleep(Duration::from_millis(10));

  assert!(
    runtime
      .cached_object(&root, &path, &response_metadata)
      .is_none()
  );
  let refreshed = runtime
    .refresh_cached_object(&root, &path, &response_metadata, &etag, modified)
    .expect("matching expired object should refresh");
  assert_eq!(refreshed.body.as_ref(), b"cached body");
  assert!(
    runtime
      .cached_object(&root, &path, &response_metadata)
      .is_some()
  );
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
    StaticResponseMetadata::for_path(&first),
    Bytes::from_static(b"first"),
  );
  runtime.store_object(
    &root,
    second.clone(),
    "W/\"second\"".to_owned(),
    None,
    StaticResponseMetadata::for_path(&second),
    Bytes::from_static(b"second"),
  );

  assert!(
    runtime
      .cached_object(&root, &first, &StaticResponseMetadata::for_path(&first))
      .is_none()
  );
  assert_eq!(
    runtime
      .cached_object(&root, &second, &StaticResponseMetadata::for_path(&second))
      .unwrap()
      .body,
    Bytes::from_static(b"second")
  );
}

async fn collect_response_body(response: Response<ProxyBody>) -> Bytes {
  response.into_body().collect().await.unwrap().to_bytes()
}

#[tokio::test]
async fn hot_object_cache_refreshes_replaced_file_before_ttl() {
  let temp_dir = common::TempDir::new("static-hot-object-cache-refresh-replaced");
  let root = temp_dir.path().join("public");
  tokio::fs::create_dir_all(&root).await.unwrap();
  tokio::fs::write(root.join("app.txt"), "safe body")
    .await
    .unwrap();
  let runtime = runtime_for_root(&root, hot_object_cache_config(4, 3_600_000, 1024));

  let first = serve_with_runtime(
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
  tokio::fs::write(root.join("app.txt"), "updated body")
    .await
    .unwrap();
  let refreshed = serve_with_runtime(
    &request("/assets/app.txt"),
    "assets",
    "/assets",
    &root,
    &runtime,
    16 * 1024,
  )
  .await;
  assert_eq!(refreshed.status(), StatusCode::OK);
  assert_eq!(
    collect_response_body(refreshed).await,
    Bytes::from_static(b"updated body")
  );
}

#[tokio::test]
async fn hot_object_cache_revalidates_deleted_file_before_ttl() {
  let temp_dir = common::TempDir::new("static-hot-object-cache-deleted-revalidate");
  let root = temp_dir.path().join("public");
  tokio::fs::create_dir_all(&root).await.unwrap();
  tokio::fs::write(root.join("app.txt"), "safe body")
    .await
    .unwrap();
  let runtime = runtime_for_root(&root, hot_object_cache_config(4, 3_600_000, 1024));

  let first = serve_with_runtime(
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
  let revalidated = serve_with_runtime(
    &request("/assets/app.txt"),
    "assets",
    "/assets",
    &root,
    &runtime,
    16 * 1024,
  )
  .await;
  assert_eq!(revalidated.status(), StatusCode::NOT_FOUND);
  let body = collect_response_body(revalidated).await;
  assert_eq!(body, Bytes::from_static(b"not found"));
  assert_ne!(body, Bytes::from_static(b"safe body"));
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

  let first = serve_with_runtime(
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
  let refreshed = serve_with_runtime(
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
async fn hot_object_cache_fails_closed_on_symlink_escape_before_ttl() {
  let temp_dir = common::TempDir::new("static-hot-object-cache-symlink");
  let root = temp_dir.path().join("public");
  let outside = temp_dir.path().join("outside-secret.txt");
  tokio::fs::create_dir_all(&root).await.unwrap();
  tokio::fs::write(root.join("app.txt"), "safe body")
    .await
    .unwrap();
  tokio::fs::write(&outside, "outside secret").await.unwrap();
  let runtime = runtime_for_root(&root, hot_object_cache_config(4, 3_600_000, 1024));

  let first = serve_with_runtime(
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
  let escaped = serve_with_runtime(
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

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn hot_object_cache_fifo_revalidation_does_not_block_runtime_worker() {
  use std::os::unix::fs::OpenOptionsExt;
  use std::time::Instant;

  let temp_dir = common::TempDir::new("static-hot-object-cache-fifo");
  let root = temp_dir.path().join("public");
  let probe = root.join("probe.txt");
  let app = root.join("app.txt");
  tokio::fs::create_dir_all(&root).await.unwrap();
  tokio::fs::write(&probe, "openat2 probe").await.unwrap();
  tokio::fs::write(&app, "safe body").await.unwrap();
  let runtime = runtime_for_root(&root, hot_object_cache_config(4, 3_600_000, 1024));
  let root_handle = runtime.root_handle(&root);
  let Some(_) = open_verified_file_with_openat2_for_tests(&root_handle, &probe)
    .await
    .expect("openat2 helper should not fail when the syscall is available")
  else {
    return;
  };

  let first = serve_with_runtime(
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

  tokio::fs::remove_file(&app).await.unwrap();
  make_fifo(&app);
  let writer_app = app.clone();
  let writer = std::thread::spawn(move || {
    std::thread::sleep(Duration::from_millis(500));
    let _ = std::fs::OpenOptions::new()
      .write(true)
      .custom_flags(libc::O_NONBLOCK)
      .open(&writer_app);
  });
  let serve_task = tokio::spawn({
    let root = root.clone();
    let runtime = runtime.clone();
    async move {
      serve_with_runtime(
        &request("/assets/app.txt"),
        "assets",
        "/assets",
        &root,
        &runtime,
        16 * 1024,
      )
      .await
    }
  });

  let started = Instant::now();
  let revalidated = tokio::time::timeout(Duration::from_millis(350), serve_task)
    .await
    .expect("cached FIFO revalidation should not block the runtime worker")
    .expect("serve task should not panic");
  let elapsed = started.elapsed();
  writer.join().expect("FIFO writer thread should not panic");
  assert!(
    elapsed < Duration::from_millis(350),
    "cached FIFO revalidation took {elapsed:?}"
  );
  assert_eq!(revalidated.status(), StatusCode::FORBIDDEN);
}
