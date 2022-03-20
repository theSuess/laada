use futures::lock::Mutex;
use graph_rs_sdk::error::GraphResult;
use graph_rs_sdk::prelude::GraphResponse;
use graph_rs_sdk::{http::AsyncHttpClient, oauth::AccessToken, prelude::Graph};
use handlebars::Handlebars;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::convert::Infallible;
use std::net;
use std::sync::Arc;
use warp::hyper::Uri;
use warp::{Filter, Rejection, Reply};

use crate::graph::*;
use crate::laada::LaadaServer;
use rust_embed::RustEmbed;

#[derive(RustEmbed)]
#[folder = "static/"]
struct Assets;

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
    trace!("Claims {:?}", token.jwt().unwrap().claims());
    let redir = warp::redirect::temporary(Uri::from_static("/manage"));
    Ok(warp::reply::with_header(
        redir,
        "set-cookie",
        format!("token={}; Path=/", token.bearer_token()),
    ))
}

pub async fn manage_handler(
    token: AccessToken,
    hbs: Arc<Handlebars<'_>>,
) -> Result<impl Reply, Rejection> {
    let cl: Graph<AsyncHttpClient> = Graph::from(&token);
    let resp: GraphResult<GraphResponse<LaadaExtension>> =
        cl.v1().me().get_extensions(EXTENSION_NAME).json().await;
    trace!("found extensions: {:?}", resp);
    // TODO: there has to be a better way
    let mut claims: HashMap<String, String> = token
        .jwt()
        .unwrap()
        .claims()
        .unwrap()
        .iter()
        .map(|c| {
            (
                c.key(),
                c.value()
                    .as_str()
                    .unwrap_or(c.value().to_string().as_str())
                    .to_string(),
            )
        })
        .collect();
    match resp {
        Ok(r) => {
            claims.insert("laada_token".to_string(), r.body().token.to_owned());
        }
        _ => {}
    }
    let data = hbs
        .render("manage.html.hbs", &claims)
        .map_err(|_| warp::reject::not_found())?;
    Ok(warp::reply::html(data))
}
pub async fn register_handler(token: AccessToken) -> Result<impl Reply, Rejection> {
    let cl: Graph<AsyncHttpClient> = Graph::from(&token);
    let e = LaadaExtension::new("FOO".to_string());
    let existing = cl.v1().me().get_extensions(EXTENSION_NAME).send().await;
    if existing.is_err() {
        let resp = cl.v1().me().create_extensions(&e).send().await;
        trace!("created: {:?}", resp);
    } else {
        let resp = cl
            .v1()
            .me()
            .update_extensions(EXTENSION_NAME, &e)
            .send()
            .await;
        trace!("updated: {:?}", resp);
    }
    Ok("method registered")
}
fn with_srv(
    srv: Arc<Mutex<LaadaServer>>,
) -> impl Filter<Extract = (Arc<Mutex<LaadaServer>>,), Error = Infallible> + Clone {
    warp::any().map(move || srv.clone())
}
fn with_hbs(
    hbs: Arc<Handlebars>,
) -> impl Filter<Extract = (Arc<Handlebars>,), Error = Infallible> + Clone {
    warp::any().map(move || hbs.clone())
}
fn serve_static(path: &str) -> Result<impl Reply, Rejection> {
    let asset = Assets::get(path).ok_or_else(warp::reject::not_found)?;
    Ok(warp::reply::html(asset.data))
}

pub async fn serve(srv: Arc<Mutex<LaadaServer>>) {
    let cfg = srv.lock().await.cfg.clone().web.unwrap_or_default();
    let addr: net::SocketAddr = format!("{}:{}", cfg.host, cfg.port).parse().unwrap();

    let mut hb = Handlebars::new();
    hb.register_embed_templates::<Assets>();
    let hb = Arc::new(hb);

    let login_route = warp::path!("login")
        .and(warp::header::<String>("Host"))
        .and(with_srv(srv.clone()))
        .and_then(login_handler);
    let callback_route = warp::path!("login" / "callback")
        .and(warp::header::<String>("Host"))
        .and(warp::query::<HashMap<String, String>>())
        .and(with_srv(srv.clone()))
        .and_then(callback_handler);
    let manage_route = warp::path!("manage")
        .and(warp::cookie::<String>("token"))
        .map(|token: String| AccessToken::new("Bearer", 3600, "", token.as_str()))
        .and(with_hbs(hb))
        .and_then(manage_handler);
    let register_route = warp::post()
        .and(warp::path!("manage" / "register"))
        .and(warp::cookie::<String>("token"))
        .map(|token: String| AccessToken::new("Bearer", 3600, "", token.as_str()))
        .and_then(register_handler);

    let root = warp::get().and(warp::fs::dir("static/"));
    let routes = root
        .or(login_route)
        .or(callback_route)
        .or(manage_route)
        .or(register_route);
    info!("started ldap listener on {:?}", addr);
    warp::serve(routes).run(addr).await;
}
