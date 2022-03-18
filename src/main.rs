mod graph;
mod http;
mod laada;
mod ldap;

#[macro_use]
extern crate log;

use config::Config;
use futures::lock::Mutex;
use laada::LaadaServer;
use std::collections::HashMap;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), ::std::io::Error> {
    env_logger::init();

    let cfg = Config::builder()
        .add_source(config::File::with_name("laada"))
        .add_source(config::Environment::with_prefix("LAADA").separator("_"))
        .build()
        .unwrap()
        .try_deserialize::<laada::LaadaConfig>()
        .unwrap();

    let srv = Arc::new(Mutex::new(LaadaServer::new(cfg).await));

    // Initiate the acceptor task.
    tokio::spawn(ldap::serve(Arc::clone(&srv)));
    tokio::spawn(http::serve(Arc::clone(&srv)));

    tokio::signal::ctrl_c().await?;
    Ok(())
}
