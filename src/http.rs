use graph_rs_sdk::error::GraphResult;
use graph_rs_sdk::prelude::GraphResponse;
use graph_rs_sdk::{http::AsyncHttpClient, oauth::AccessToken, prelude::Graph};
use handlebars::Handlebars;
use libreauth::oath::TOTPBuilder;
use qrcode_generator::QrCodeEcc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::convert::Infallible;
use std::net;
use std::sync::Arc;
use warp::hyper::Uri;
use warp::reject::Reject;
use warp::{Filter, Rejection, Reply};

use crate::graph::*;
use crate::laada::LaadaConfig;
use rust_embed::RustEmbed;

#[derive(RustEmbed)]
#[folder = "static/"]
struct Assets;

#[derive(Debug)]
struct CryptoError {}
impl Reject for CryptoError {}

#[derive(Serialize, Deserialize)]
struct ManageData {
    pub user: String,
    pub oid: String,
    pub token: Option<LaadaExtension>,
}

#[derive(Serialize, Deserialize)]
struct RegisterData {
    pub uri: String,
    pub qrcode: String,
}

pub async fn login_handler(host: String, cfg: LaadaConfig) -> Result<impl Reply, Rejection> {
    let url: Uri = cfg
        .oauth_request(format!("http://{}/login/callback", host).as_str())
        .parse()
        .unwrap();
    Ok(warp::redirect::temporary(url))
}

pub async fn callback_handler(
    host: String,
    q: HashMap<String, String>,
    cfg: LaadaConfig,
) -> Result<impl Reply, Rejection> {
    let code = q.get("code");
    trace!("Access Code {:?}", code);
    let mut req = cfg
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
    // TODO: there has to be a better way
    let claims: HashMap<String, String> = token
        .jwt()
        .unwrap()
        .claims()
        .unwrap()
        .iter()
        .map(|c| {
            (
                c.key(),
                match c.value().as_str() {
                    Some(s) => s.to_string(),
                    None => c.value().to_string(),
                },
            )
        })
        .collect();
    trace!("claims: {:?}", claims);
    let token = resp.ok().map(|x| x.body().clone());
    let data = ManageData {
        user: claims.get("name").unwrap().to_string(),
        oid: claims.get("oid").unwrap().to_string(),
        token,
    };
    let rendered = hbs
        .render("manage.html.hbs", &data)
        .map_err(|_| warp::reject::not_found())?;
    Ok(warp::reply::html(rendered))
}
pub async fn register_handler(
    token: AccessToken,
    cfg: LaadaConfig,
    hbs: Arc<Handlebars<'_>>,
) -> Result<impl Reply, Rejection> {
    let cl: Graph<AsyncHttpClient> = Graph::from(&token);
    let mut token = [0u8; 128];
    let mut nonce = [0u8; 12];
    getrandom::getrandom(&mut token).map_err(|_| warp::reject::custom(CryptoError {}))?;
    getrandom::getrandom(&mut nonce).map_err(|_| warp::reject::custom(CryptoError {}))?;
    let enc = cfg.encrypt_token(&token, &nonce);
    let e = LaadaExtension::new(enc, nonce.to_vec());
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

    let totp = TOTPBuilder::new().key(&token).finalize().unwrap();

    let uri = totp.key_uri_format("laada", "test").finalize();
    let qrcode = base64::encode(
        qrcode_generator::to_svg_to_string(&uri, QrCodeEcc::Low, 1024, None::<&str>).unwrap(),
    );
    let data = RegisterData { uri, qrcode };
    let rendered = hbs
        .render("register.html.hbs", &data)
        .map_err(|_| warp::reject::not_found())?;
    Ok(warp::reply::html(rendered))
}
fn with_hbs(
    hbs: Arc<Handlebars>,
) -> impl Filter<Extract = (Arc<Handlebars>,), Error = Infallible> + Clone {
    warp::any().map(move || hbs.clone())
}
fn with_cfg(cfg: LaadaConfig) -> impl Filter<Extract = (LaadaConfig,), Error = Infallible> + Clone {
    warp::any().map(move || cfg.clone())
}

pub async fn serve(cfg: LaadaConfig) {
    let webcfg = cfg.clone().web.unwrap_or_default();
    let addr: net::SocketAddr = format!("{}:{}", webcfg.host, webcfg.port).parse().unwrap();

    let mut hb = Handlebars::new();
    hb.register_embed_templates::<Assets>()
        .expect("failed to bundle static assets");
    let hb = Arc::new(hb);

    let login_route = warp::path!("login")
        .and(warp::header::<String>("Host"))
        .and(with_cfg(cfg.clone()))
        .and_then(login_handler);
    let callback_route = warp::path!("login" / "callback")
        .and(warp::header::<String>("Host"))
        .and(warp::query::<HashMap<String, String>>())
        .and(with_cfg(cfg.clone()))
        .and_then(callback_handler);
    let manage_route = warp::path!("manage")
        .and(warp::cookie::<String>("token"))
        .map(|token: String| AccessToken::new("Bearer", 3600, "", token.as_str()))
        .and(with_hbs(hb.clone()))
        .and_then(manage_handler);
    let register_route = warp::post()
        .and(warp::path!("manage" / "register"))
        .and(warp::cookie::<String>("token"))
        .map(|token: String| AccessToken::new("Bearer", 3600, "", token.as_str()))
        .and(with_cfg(cfg.clone()))
        .and(with_hbs(hb.clone()))
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
