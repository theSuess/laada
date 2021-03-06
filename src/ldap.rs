use argon2::{PasswordHash, PasswordVerifier};
use futures::lock::Mutex;
use futures::{SinkExt, StreamExt};
use graph_rs_sdk::error::GraphResult;
use graph_rs_sdk::header::HeaderValue;
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
        if sbr.dn.is_empty() && sbr.pw.is_empty() {
            self.dn = "Anonymous".to_string();
            return sbr.gen_success();
        }
        let mut srv = self.srv.lock().await;
        let client = &srv.graph_client().await;
        let raw_id = id_from_dn(&sbr.dn, &srv.cfg.upn_domains, &srv.cfg.external_issuer);
        if raw_id.is_none() {
            error!("Invalid user dn {:?}", sbr.dn);
            return sbr.gen_invalid_cred();
        }
        let id = raw_id.unwrap();
        trace!("User ID: {:?}", id);
        let resp: GraphResult<GraphResponse<LaadaExtension>> = client
            .v1()
            .user(id)
            .get_extensions(EXTENSION_NAME)
            .json()
            .await;
        if resp.is_err() {
            error!("Failed to get user {:?}", resp);
            return sbr.gen_invalid_cred();
        }
        let ext = resp.unwrap();
        trace!("ext: {:?}", ext);
        let token = srv.cfg.decrypt(&ext.body().token, &ext.body().nonce);

        if !ext.body().pin.is_empty() {
            trace!("user has pin set");
            let ph = srv.cfg.decrypt(&ext.body().pin, &ext.body().nonce);
            if argon2::Argon2::default()
                .verify_password(
                    sbr.pw.split(':').next().unwrap().as_bytes(),
                    &PasswordHash::new(std::str::from_utf8(&ph).unwrap()).unwrap(),
                )
                .is_err()
            {
                return sbr.gen_invalid_cred();
            }
        }

        let totp = TOTPBuilder::new()
            .key(token.as_slice())
            .tolerance(1)
            .finalize()
            .unwrap();
        let totp_input = sbr.pw.split(':').last().unwrap();
        if totp.is_valid(totp_input) {
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

        if !lsr.base.is_empty() && !lsr.base.ends_with(cfg.basedn.as_str()) {
            return vec![lsr.gen_error(LdapResultCode::NoSuchObject, String::from("Not found"))];
        }

        let group = group_from_dn(lsr.base.as_str(), cfg.basedn.as_str());
        trace!("group: {:?}", group);
        let filter = build_filter(&lsr.filter, &srv.cfg.upn_domains);
        trace!("graph search filter: {}", filter);

        let user_resp: GraphResult<GraphResponse<ListUserResponse>> = match group {
            Some(gid) => {
                client
                    .v1()
                    .group(&gid)
                    .list_members()
                    .cast("microsoft.graph.user")
                    .filter(&[filter.as_str()])
                    .expand(&["memberOf"])
                    .header("ConsistencyLevel", HeaderValue::from_static("eventual"))
                    .json()
                    .await
            }
            None => {
                client
                    .v1()
                    .users()
                    .list_user()
                    .expand(&["memberOf"])
                    .filter(&[filter.as_str()])
                    .json()
                    .await
            }
        };
        if let Err(e) = user_resp {
            error!("invalid graph api response: {:?}", e);
            return vec![lsr.gen_error(
                LdapResultCode::Unavailable,
                String::from("graph api exception"),
            )];
        }
        let mut resp: Vec<LdapMsg> = user_resp
            .unwrap()
            .body()
            .value
            .iter()
            .map(|u| {
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
                    LdapPartialAttribute {
                        atype: "memberOf".to_string(),
                        vals: u
                            .member_of
                            .iter()
                            .map(|g| g.display_name.clone().unwrap_or_else(|| g.id.clone()))
                            .collect(),
                    },
                ];
                if let Some(n) = &u.given_name {
                    attributes.push(LdapPartialAttribute {
                        atype: "givenName".to_string(),
                        vals: vec![n.to_string()],
                    });
                    attributes.push(LdapPartialAttribute {
                        atype: "cn".to_string(),
                        vals: vec![n.to_string()],
                    });
                } else {
                    attributes.push(LdapPartialAttribute {
                        atype: "cn".to_string(),
                        vals: vec![u.display_name.clone()],
                    });
                }
                if let Some(n) = &u.surname {
                    attributes.push(LdapPartialAttribute {
                        atype: "sn".to_string(),
                        vals: vec![n.to_string()],
                    });
                }
                lsr.gen_result_entry(LdapSearchResultEntry {
                    dn: format!("userPrincipalName={},{}", u.dn(), cfg.basedn),
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

fn build_filter(l: &LdapFilter, upn_domains: &Option<Vec<String>>) -> String {
    match l {
        LdapFilter::Present(k) => {
            if k == "objectclass" {
                return String::from("");
            }
            format!("{} ne null", k)
        }
        LdapFilter::Equality(k, v) => {
            match k.to_lowercase().as_str() {
                "userprincipalname" => {
                    if let Some(d) = upn_domains {
                        if !d.iter().any(|x| v.ends_with(x)) {
                            return format!("mail eq '{}'", v);
                        }
                    }
                }
                "memberof" => return format!("memberOf/any(g:g/displayName eq '{}')", v),
                _ => {}
            }
            format!("{} eq '{}'", k, v)
        }
        LdapFilter::And(fs) => fs
            .iter()
            .map(|f| format!("({})", build_filter(f, upn_domains)))
            .collect::<Vec<String>>()
            .join(" and "),
        _ => todo!(),
    }
}

fn id_from_dn(
    dn: &str,
    upn_domains: &Option<Vec<String>>,
    external_issuer: &Option<String>,
) -> Option<String> {
    let mut it = dn.split(['=', ',']);
    let selector = it.next()?;
    let id = if selector.to_lowercase() == "userprincipalname" || selector == "id" {
        it.next()
    } else {
        None
    }?;
    if let Some(domains) = upn_domains {
        if !domains.iter().any(|d| id.ends_with(d)) {
            if let Some(i) = external_issuer {
                return Some(external_upn(id, i.as_str()));
            }
        }
    }
    Some(id.to_string())
}

fn group_from_dn(dn: &str, base_dn: &str) -> Option<String> {
    if dn.is_empty() || dn == base_dn {
        return None;
    }
    let mut it = dn.split(['=', ',']);
    let selector = it.next()?;
    if selector.to_lowercase() == "ou" {
        return it.next().map(|x| x.to_string());
    }
    None
}

fn external_upn(email: &str, issuer: &str) -> String {
    format!("{}#EXT#@{}", email.replace('@', "_"), issuer)
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
        let server_op = match msg.map_err(|_e| ()).and_then(ServerOps::try_from) {
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
        trace!("LDAP Operation: {:?}", server_op);
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
            if let Err(e) = resp.send(rmsg).await {
                error!("sending response: {:?}", e);
                return;
            }
        }

        if let Err(e) = resp.flush().await {
            error!("flushing response: {:?}", e);
            return;
        }
    }
    // Client disconnected
}
