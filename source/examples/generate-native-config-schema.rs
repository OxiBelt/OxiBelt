fn main() -> anyhow::Result<()> {
  let schema = oxibelt::config::generate_native_config_schema()?;
  if let Some(path) = std::env::args_os().nth(1) {
    std::fs::write(path, schema)?;
  } else {
    print!("{schema}");
  }
  Ok(())
}
