# OxiBelt Cache Conformance Matrix

Status: Draft
Target project: OxiBelt Rust-based reverse proxy

OxiBelt's cache behavior targets RFC 9111 HTTP caching semantics and RFC 9110 byte-range response semantics. This matrix documents the behavior covered by Rust and Docker tests.

| Area | Behavior | Coverage |
| --- | --- | --- |
| Freshness directives | `s-maxage` takes priority over `max-age`; `max-age=0`, valid past `Expires`, response `no-store`, `private`, and `Set-Cookie` do not store. | Rust `rfc9111_freshness_directives_are_stable`; Docker `cache/rfc9111-semantics`. |
| Revalidation | `no-cache`, `must-revalidate`, `proxy-revalidate`, `Pragma: no-cache`, `ETag`, and `Last-Modified` drive foreground revalidation. | Rust cache lookup tests; Docker `cache/rfc9111-semantics`. |
| Fresh conditional hits | Fresh cached `GET` and `HEAD` hits evaluate downstream `If-None-Match` and `If-Modified-Since` and can synthesize `304` without upstream validation. | Rust `cached_entry_response_handles_conditional_hit_with_age`. |
| Age | Cached hits attach `Age` based on persisted `stored_at`; disk metadata without `stored_at` loads with the current time for backward compatibility. | Rust cache metadata and conditional hit tests. |
| Range | Cached full responses support single ranges, suffix/open-ended ranges, unsatisfiable `416`, `If-Range`, and multipart `206 multipart/byteranges`. | Rust range tests; Docker `cache/range-hit` and `cache/multi-range-hit`. |
| HEAD | `HEAD` can reuse a cached `GET` entry, but a `HEAD` miss is not stored. | Rust `head_can_read_get_cache_but_head_miss_does_not_store`. |
| Streaming fill | With `stream_large_objects = true`, known-length cacheable responses that exceed the memory collect limit can stream to local disk for `disk` and `memory_then_disk` policies. Temporary files are removed on body errors or limit overflow and atomically committed at EOF. | Rust `cache_fill_streams_large_disk_body_and_serves_file_backed_ranges`; Docker `cache/huge-object-streaming-disk`. |
| Shared cache | Shared L2 continues to store collected bodies. Streaming disk fill is local L1 only in this release. | Documented exception; existing shared-cache Docker cases cover collected-body L2 behavior. |
| Isolation and spoofing | Credential-bearing requests bypass by default; `Vary` isolates variants; `Vary: *` and variant explosions are rejected; upstream `X-OxiBelt-Cache*` headers are stripped. | Rust cache/security tests; Docker `cache/vary-header-isolation`, `cache/vary-explosion-rejection`. |
| Surrogate and purge | `Surrogate-Control` can override origin cache directives and is stripped downstream when configured. Cache purge authorization is audited without adding raw URI/query payloads to the audit summary. | Rust surrogate tests; Docker `cache/surrogate-control`, `cache/purge-audit`. |
