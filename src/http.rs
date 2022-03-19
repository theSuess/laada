use futures::lock::Mutex;
use std::collections::HashMap;
use std::convert::Infallible;
use std::net;
use std::sync::Arc;
use warp::hyper::Uri;
use warp::{Filter, Rejection, Reply};

use crate::laada::LaadaServer;

pub async fn login_handler(
    host: String,
    srv: Arc<Mutex<LaadaServer>>,
) -> Result<impl Reply, Rejection> {
    let url: Uri = srv
        .lock()
        .await
        .cfg
        .oauth_request(format!("http://{}/login/callback", host).as_str())
        .parse()
        .unwrap();
    Ok(warp::redirect::temporary(url))
}

pub async fn callback_handler(
    host: String,
    q: HashMap<String, String>,
    srv: Arc<Mutex<LaadaServer>>,
) -> Result<impl Reply, Rejection> {
    let code = q.get("code");
    trace!("Access Code {:?}", code);
    let mut req = srv
        .lock()
        .await
        .cfg
        .oauth_client()
        .access_code(code.unwrap())
        .redirect_uri(format!("http://{}/login/callback", host).as_str())
        .build_async()
        .code_flow();

    trace!("req {:?}", req);
    let token = req.access_token().send().await.unwrap();
    trace!("Access Token {:?}", token.bearer_token());
    Ok(warp::redirect::temporary(Uri::from_static("/")))
}
fn with_srv(
    srv: Arc<Mutex<LaadaServer>>,
) -> impl Filter<Extract = (Arc<Mutex<LaadaServer>>,), Error = Infallible> + Clone {
    warp::any().map(move || srv.clone())
}

pub async fn serve(srv: Arc<Mutex<LaadaServer>>) {
    let cfg = srv.lock().await.cfg.clone().web.unwrap_or_default();
    let addr: net::SocketAddr = format!("{}:{}", cfg.host, cfg.port).parse().unwrap();
    let root = warp::path::end().map(|| "Hello");
    let login_route = warp::path!("login")
        .and(warp::header::<String>("Host"))
        .and(with_srv(srv.clone()))
        .and_then(login_handler);
    let callback_route = warp::path!("login" / "callback")
        .and(warp::header::<String>("Host"))
        .and(warp::query::<HashMap<String, String>>())
        .and(with_srv(srv.clone()))
        .and_then(callback_handler);
    let routes = root.or(login_route).or(callback_route);
    info!("started ldap listener on {:?}", addr);
    warp::serve(routes).run(addr).await;
}
