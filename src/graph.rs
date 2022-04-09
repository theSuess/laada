use chrono::prelude::*;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

pub static EXTENSION_NAME: &str = "wtf.suess.laada";

#[derive(Debug, Serialize, Deserialize)]
pub struct ADUser {
    #[serde(rename = "userPrincipalName")]
    pub upn: String,
    #[serde(rename = "displayName")]
    pub display_name: String,
    #[serde(rename = "givenName")]
    pub given_name: Option<String>,
    pub surname: Option<String>,
    pub mail: Option<String>,
    #[serde(rename = "memberOf")]
    pub member_of: Vec<ADGroup>,
    pub id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ADGroup {
    pub id: String,
    #[serde(rename = "displayName")]
    pub display_name: Option<String>,
}

impl ADUser {
    pub fn dn(&self) -> String {
        if self.upn.contains("#EXT#") {
            if let Some(m) = &self.mail {
                m.to_owned()
            } else {
                self.upn.split("#EXT#").next().unwrap().replace('_', "@")
            }
        } else {
            self.upn.clone()
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ListUserResponse {
    pub value: Vec<ADUser>,
}

#[serde_as]
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LaadaExtension {
    #[serde(rename = "extensionName")]
    pub extension_name: Option<String>,
    #[serde_as(as = "serde_with::base64::Base64")]
    pub token: Vec<u8>,
    #[serde_as(as = "serde_with::base64::Base64")]
    pub nonce: Vec<u8>,
    #[serde_as(as = "serde_with::base64::Base64")]
    #[serde(default = "pin_default")]
    pub pin: Vec<u8>,
    pub created_at: DateTime<Utc>,
}

fn pin_default() -> Vec<u8> {
    vec![]
}

impl LaadaExtension {
    pub fn new(token: Vec<u8>, nonce: Vec<u8>) -> Self {
        LaadaExtension {
            extension_name: Some(EXTENSION_NAME.to_string()),
            created_at: Utc::now(),
            pin: vec![],
            token,
            nonce,
        }
    }
}
