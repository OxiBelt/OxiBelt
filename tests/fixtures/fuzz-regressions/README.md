# Fuzz regressions

Store only minimized, reviewed reproducers for confirmed fuzz defects under a
directory named after the target in `fuzz/targets.toml`. Every fixture must be
replayed by `tests/rust/fuzz_regressions.rs` or by a narrower owner-local unit
test before the fix is merged. Never commit an unreviewed generated corpus,
crash log, certificate, private key, or input that may contain production data.
