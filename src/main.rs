mod graph;
mod http;
mod laada;
mod ldap;

#[macro_use]
extern crate log;
use figment::{
    providers::{Env, Format, Toml},
    Figment,
};
use futures::lock::Mutex;
use laada::LaadaConfig;
use laada::LaadaServer;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), std::io::Error> {
    env_logger::init();

    let raw_config = Figment::new()
        .merge(Toml::file("laada.toml"))
        .merge(Env::prefixed("LAADA_"));
    let cfg = match raw_config.extract::<LaadaConfig>() {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to parse configuration! {:?}", e);
            std::process::exit(1);
        }
    };

    let srv = Arc::new(Mutex::new(LaadaServer::new(cfg.clone()).await));

    // Initiate the acceptor task.
    tokio::spawn(ldap::serve(Arc::clone(&srv)));
    tokio::spawn(http::serve(cfg));

    tokio::signal::ctrl_c().await?;
    Ok(())
}
