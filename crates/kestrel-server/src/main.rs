use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,sqlx=warn,tower_http=warn,h2=warn"));
    if std::env::var("KESTREL_LOG_FORMAT")
        .map(|v| v == "json")
        .unwrap_or(false)
    {
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .json()
            .init();
    } else {
        tracing_subscriber::fmt().with_env_filter(filter).init();
    }
    if std::env::args().nth(1).as_deref() == Some("--version") {
        println!("kestrel-server {}", kestrel_common::VERSION);
        return Ok(());
    }
    let cfg = kestrel_server::config::Config::from_env()?;
    kestrel_server::run(cfg).await
}
