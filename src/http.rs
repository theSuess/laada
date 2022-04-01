use actix_web::{cookie::Cookie, dev::ConnectionInfo, error};
use actix_web::{get, post, web, App, FromRequest, HttpResponse, HttpServer};
use futures_util::future::{err, ok, Ready};
use graph_rs_sdk::error::GraphResult;
use graph_rs_sdk::prelude::GraphResponse;
use graph_rs_sdk::{http::AsyncHttpClient, oauth::AccessToken, prelude::Graph};
use handlebars::Handlebars;
use libreauth::oath::TOTPBuilder;
use mime_guess::from_path;
use qrcode_generator::QrCodeEcc;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::collections::HashMap;
use std::fmt::Display;
use std::net;

use crate::graph::*;
use crate::laada::LaadaConfig;
use rust_embed::RustEmbed;

#[derive(RustEmbed)]
#[folder = "static/templates"]
struct Templates;

#[derive(RustEmbed)]
#[folder = "static/dist"]
struct Dist;

#[derive(Debug)]
pub struct CryptoError;
impl Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Crypto Error")
    }
}
impl error::ResponseError for CryptoError {}

#[derive(Debug)]
pub struct UnauthorizedError;
impl Display for UnauthorizedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("You're not authorized")
    }
}
impl error::ResponseError for UnauthorizedError {
    fn error_response(&self) -> HttpResponse {
        HttpResponse::TemporaryRedirect()
            .append_header(("Location", "/login"))
            .finish()
    }
}

pub struct AuthenticatedUser {
    access_token: AccessToken,
}

#[derive(Serialize, Deserialize)]
pub struct CallbackQuery {
    pub code: String,
}

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

impl FromRequest for AuthenticatedUser {
    type Error = UnauthorizedError;

    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(
        req: &actix_web::HttpRequest,
        _payload: &mut actix_web::dev::Payload,
    ) -> Self::Future {
        let h = req.head().headers().get("Cookie");
        if let Some(c) = h {
            if let Ok(cs) = c.to_str() {
                if let Some(c) = cs
                    .to_string()
                    .split(';')
                    .filter_map(|x| Cookie::parse(x).ok())
                    .find(|c| c.name() == "token")
                {
                    let token = AccessToken::new("Bearer", 3600, "", c.value());
                    if !token.is_expired() {
                        return ok(AuthenticatedUser {
                            access_token: AccessToken::new("Bearer", 3600, "", c.value()),
                        });
                    }
                }
            }
        }
        err(UnauthorizedError)
    }
}
#[get("/")]
async fn get_index(hb: web::Data<Handlebars<'_>>) -> HttpResponse {
    let rendered = hb
        .render("index.html.hbs", &())
        .expect("resource bundling error");
    HttpResponse::Ok().body(rendered)
}

#[get("/manage")]
async fn get_manage(hb: web::Data<Handlebars<'_>>, user: AuthenticatedUser) -> HttpResponse {
    let cl: Graph<AsyncHttpClient> = Graph::from(&user.access_token);
    let resp: GraphResult<GraphResponse<LaadaExtension>> =
        cl.v1().me().get_extensions(EXTENSION_NAME).json().await;
    // TODO: there has to be a better way
    let claims: HashMap<String, String> = user
        .access_token
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
    let rendered = hb
        .render("manage.html.hbs", &data)
        .expect("correct rendering");
    HttpResponse::Ok().body(rendered)
}

#[get("/login")]
pub async fn get_login(cfg: web::Data<LaadaConfig>, info: ConnectionInfo) -> HttpResponse {
    let url =
        cfg.oauth_request(format!("{}://{}/login/callback", info.scheme(), info.host()).as_str());
    HttpResponse::TemporaryRedirect()
        .append_header(("Location", url.as_str()))
        .finish()
}
#[get("/login/callback")]
pub async fn get_callback(
    cfg: web::Data<LaadaConfig>,
    info: ConnectionInfo,
    q: web::Query<CallbackQuery>,
) -> HttpResponse {
    let code = &q.code;
    trace!("Access Code {:?}", code);
    let mut req = cfg
        .oauth_client()
        .access_code(code.as_str())
        .redirect_uri(format!("{}://{}/login/callback", info.scheme(), info.host()).as_str())
        .build_async()
        .code_flow();

    trace!("req {:?}", req);
    let token = req.access_token().send().await.unwrap();
    trace!("Claims {:?}", token.jwt().unwrap().claims());

    HttpResponse::TemporaryRedirect()
        .append_header(("Location", "/manage"))
        .cookie(
            Cookie::build("token", token.bearer_token())
                .path("/")
                .http_only(true)
                .finish(),
        )
        .finish()
}
#[post("/manage/register")]
pub async fn post_register(
    hb: web::Data<Handlebars<'_>>,
    user: AuthenticatedUser,
    cfg: web::Data<LaadaConfig>,
) -> Result<HttpResponse, CryptoError> {
    let cl: Graph<AsyncHttpClient> = Graph::from(&user.access_token);
    let mut token = [0u8; 128];
    let mut nonce = [0u8; 12];
    getrandom::getrandom(&mut token).map_err(|_| CryptoError {})?;
    getrandom::getrandom(&mut nonce).map_err(|_| CryptoError {})?;
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
    let rendered = hb
        .render("register.html.hbs", &data)
        .expect("correct rendering");
    Ok(HttpResponse::Ok().body(rendered))
}

#[get("/dist/{path:.*}")]
async fn handle_embedded_file(path: web::Path<String>) -> HttpResponse {
    trace!("fetching static asset {:?}", path);
    match Dist::get(path.as_str()) {
        Some(content) => {
            let body: Vec<u8> = match content.data {
                Cow::Borrowed(bytes) => bytes.into(),
                Cow::Owned(bytes) => bytes,
            };
            HttpResponse::Ok()
                .content_type(from_path(path.as_str()).first_or_octet_stream().as_ref())
                .body(body)
        }
        None => HttpResponse::NotFound().body("404 Not Found"),
    }
}
pub fn serve(cfg: LaadaConfig) -> actix_web::dev::Server {
    let webcfg = cfg.clone().web.unwrap_or_default();
    let addr: net::SocketAddr = format!("{}:{}", webcfg.host, webcfg.port).parse().unwrap();

    let mut hb = Handlebars::new();
    if cfg!(debug_assertions) {
        debug!("using templates from directory");
        hb.set_dev_mode(true);
        hb.register_templates_directory("", "static/templates/")
            .expect("failed to load assets from dir");
    } else {
        debug!("using embedded templates");
        hb.register_embed_templates::<Templates>()
            .expect("failed to bundle static assets");
    }

    let hb_ref = web::Data::new(hb);
    info!("started http listener on {:?}", addr);
    HttpServer::new(move || {
        App::new()
            .service(get_index)
            .service(get_manage)
            .service(get_login)
            .service(get_callback)
            .service(post_register)
            .service(handle_embedded_file)
            .app_data(hb_ref.clone())
            .app_data(web::Data::new(cfg.clone()))
    })
    .bind(addr)
    .unwrap()
    .run()
}
