#[tokio::main]
async fn main() {
  if let Err(error) = oxibelt_gateway_controller::run().await {
    eprintln!("{error:#}");
    std::process::exit(1);
  }
}
