use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, Request, Response, Server, StatusCode};
use std::net;
use std::str::FromStr;

use futures::lock::Mutex;
use std::sync::Arc;

use crate::laada::LaadaServer;

pub async fn handle_http(
    srv: Arc<Mutex<LaadaServer>>,
    req: Request<Body>,
) -> Result<Response<Body>, hyper::Error> {
    match (req.method(), req.uri().path()) {
        // Serve some instructions at /
        (&Method::GET, "/") => Ok(Response::new(Body::from("Welcome to laada"))),
        (&Method::POST, "/register") => Ok(Response::new(Body::from("Welcome to laada"))),

        // Return the 404 Not Found for other routes.
        _ => {
            let mut not_found = Response::default();
            *not_found.status_mut() = StatusCode::NOT_FOUND;
            Ok(not_found)
        }
    }
}

pub async fn serve(srv: Arc<Mutex<LaadaServer>>) {
    let web_addr = net::SocketAddr::from_str("127.0.0.1:8080").unwrap();
    let web_svc = make_service_fn(move |_conn| {
        let s1 = Arc::clone(&srv);
        async move {
            Ok::<_, hyper::Error>(service_fn(move |req| {
                let s = Arc::clone(&s1);
                handle_http(s, req)
            }))
        }
    });
    Server::bind(&web_addr).serve(web_svc).await;
}
