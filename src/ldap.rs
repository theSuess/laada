use futures::lock::Mutex;
use futures::{SinkExt, StreamExt};
use graph_rs_sdk::error::GraphResult;
use graph_rs_sdk::prelude::GraphResponse;
use ldap3_proto::simple::*;
use ldap3_proto::LdapCodec;
use libreauth::oath::TOTPBuilder;
use std::net;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tokio_util::codec::{FramedRead, FramedWrite};

use crate::graph::*;
use crate::laada::LaadaServer;

pub struct LdapSession {
    dn: String,
    srv: Arc<Mutex<LaadaServer>>,
}

impl LdapSession {
    pub async fn do_bind(&mut self, sbr: &SimpleBindRequest) -> LdapMsg {
        if sbr.dn == "" && sbr.pw == "" {
            self.dn = "Anonymous".to_string();
            return sbr.gen_success();
        }
        let mut srv = self.srv.lock().await;
        let client = &srv.graph_client().await;
        let id = id_from_dn(&sbr.dn);
        if id.is_none() {
            error!("Invalid user dn {:?}", sbr.dn);
            return sbr.gen_invalid_cred();
        }
        trace!("User ID: {:?}", id);
        let resp: GraphResult<GraphResponse<LaadaExtension>> = client
            .v1()
            .user(id.unwrap())
            .get_extensions(EXTENSION_NAME)
            .json()
            .await;
        if resp.is_err() {
            error!("Failed to get user {:?}", resp);
            return sbr.gen_invalid_cred();
        }
        let ext = resp.unwrap();
        debug!("Extension: {:?}", ext);

        let token = srv.cfg.decrypt_token(&ext.body().token, &ext.body().nonce);
        let totp = TOTPBuilder::new()
            .key(token.as_slice())
            .tolerance(1)
            .finalize()
            .unwrap();
        if totp.is_valid(sbr.pw.as_str()) {
            self.dn = sbr.dn.to_string();
            sbr.gen_success()
        } else {
            sbr.gen_invalid_cred()
        }
    }

    pub async fn do_search(&mut self, lsr: &SearchRequest) -> Vec<LdapMsg> {
        let mut srv = self.srv.lock().await;
        let client = &srv.graph_client().await;
        let cfg = srv.cfg.ldap.clone().unwrap_or_default();

        if lsr.base != "" && lsr.base != cfg.basedn {
            return vec![lsr.gen_error(LdapResultCode::NoSuchObject, String::from("Not found"))];
        }
        let raw_resp = client.v1().users().list_user().send().await;
        trace!("Graph api response: {:?}", raw_resp);
        let user_resp: GraphResult<GraphResponse<ListUserResponse>> =
            client.v1().users().list_user().json().await;
        debug!("Graph api response: {:?}", user_resp);
        let mut resp: Vec<LdapMsg> = user_resp
            .unwrap()
            .body()
            .value
            .iter()
            .map(|u| {
                debug!("user: {:?}", u);
                let mut attributes: Vec<LdapPartialAttribute> = vec![
                    LdapPartialAttribute {
                        atype: "objectClass".to_string(),
                        vals: vec![
                            "inetOrgPerson".to_string(),
                            "person".to_string(),
                            "top".to_string(),
                        ],
                    },
                    LdapPartialAttribute {
                        atype: "userPrincipalName".to_string(),
                        vals: vec![u.upn.clone()],
                    },
                    LdapPartialAttribute {
                        atype: "displayName".to_string(),
                        vals: vec![u.display_name.clone()],
                    },
                    LdapPartialAttribute {
                        atype: "uid".to_string(),
                        vals: vec![u.id.clone()],
                    },
                ];
                match &u.given_name {
                    Some(n) => {
                        attributes.push(LdapPartialAttribute {
                            atype: "givenName".to_string(),
                            vals: vec![n.to_string()],
                        });
                        attributes.push(LdapPartialAttribute {
                            atype: "cn".to_string(),
                            vals: vec![n.to_string()],
                        });
                    }
                    _ => {
                        attributes.push(LdapPartialAttribute {
                            atype: "cn".to_string(),
                            vals: vec![u.display_name.clone()],
                        });
                    }
                }
                match &u.surname {
                    Some(n) => attributes.push(LdapPartialAttribute {
                        atype: "sn".to_string(),
                        vals: vec![n.to_string()],
                    }),
                    _ => {}
                }
                lsr.gen_result_entry(LdapSearchResultEntry {
                    dn: format!("userPrincipalName={},{}", u.upn, cfg.basedn),
                    attributes,
                })
            })
            .collect();
        resp.push(lsr.gen_success());
        resp
    }

    pub fn do_whoami(&mut self, wr: &WhoamiRequest) -> LdapMsg {
        wr.gen_success(format!("dn: {}", self.dn).as_str())
    }
}

fn id_from_dn(dn: &String) -> Option<&str> {
    let mut it = dn.split(['=', ',']);
    let selector = it.next()?;
    if selector == "userPrincipalName" || selector == "id" {
        return Some(it.next()?);
    }
    None
}

pub async fn serve(srv: Arc<Mutex<LaadaServer>>) {
    let cfg = srv.lock().await.cfg.clone().ldap.unwrap_or_default();
    let addr: net::SocketAddr = format!("{}:{}", cfg.host, cfg.port).parse().unwrap();
    let listener = Box::new(TcpListener::bind(&addr).await.unwrap());
    info!("started ldap listener on {:?}", addr);
    loop {
        match listener.accept().await {
            Ok((socket, _paddr)) => {
                tokio::spawn(handle_client(socket, srv.clone()));
            }
            Err(_e) => {
                //pass
            }
        }
    }
}

async fn handle_client(socket: TcpStream, srv: Arc<Mutex<LaadaServer>>) {
    // Configure the codec etc.
    let (r, w) = tokio::io::split(socket);
    let mut reqs = FramedRead::new(r, LdapCodec);
    let mut resp = FramedWrite::new(w, LdapCodec);

    let mut session = LdapSession {
        dn: "Anonymous".to_string(),
        srv,
    };

    while let Some(msg) = reqs.next().await {
        debug!("ldap message");
        let server_op = match msg
            .map_err(|_e| ())
            .and_then(|msg| ServerOps::try_from(msg))
        {
            Ok(v) => v,
            Err(_) => {
                let _err = resp
                    .send(DisconnectionNotice::gen(
                        LdapResultCode::Other,
                        "Internal Server Error",
                    ))
                    .await;
                let _err = resp.flush().await;
                return;
            }
        };

        let result = match server_op {
            ServerOps::SimpleBind(sbr) => vec![session.do_bind(&sbr).await],
            ServerOps::Search(sr) => session.do_search(&sr).await,
            ServerOps::Unbind(_) => {
                // No need to notify on unbind (per rfc4511)
                return;
            }
            ServerOps::Whoami(wr) => vec![session.do_whoami(&wr)],
        };

        for rmsg in result.into_iter() {
            if let Err(_) = resp.send(rmsg).await {
                return;
            }
        }

        if let Err(_) = resp.flush().await {
            return;
        }
    }
    // Client disconnected
}
