use futures::lock::Mutex;
use std::net;
use std::sync::Arc;
use warp::Filter;

use crate::laada::LaadaServer;

pub async fn serve(srv: Arc<Mutex<LaadaServer>>) {
    let cfg = srv.lock().await.cfg.clone().web.unwrap_or_default();
    let addr: net::SocketAddr = format!("{}:{}", cfg.host, cfg.port).parse().unwrap();
    let root = warp::path::end().map(|| "Hello");
    let routes = warp::get().and(root.or(warp::fs::dir(".")));
    info!("started ldap listener on {:?}", addr);
    warp::serve(routes).run(addr).await;
}
