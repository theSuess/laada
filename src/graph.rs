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
    pub given_name: String,
    #[serde(rename = "surname")]
    pub surname: String,
    pub id: String,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct ListUserResponse {
    pub value: Vec<ADUser>,
}

#[serde_as]
#[derive(Debug, Serialize, Deserialize)]
pub struct LaadaExtension {
    #[serde(rename = "extensionName")]
    pub extension_name: String,
    #[serde_as(as = "serde_with::base64::Base64")]
    pub token: Vec<u8>,
    #[serde_as(as = "serde_with::base64::Base64")]
    pub nonce: Vec<u8>,
}

impl LaadaExtension {
    pub fn new(token: Vec<u8>, nonce: Vec<u8>) -> Self {
        LaadaExtension {
            extension_name: EXTENSION_NAME.to_string(),
            token,
            nonce,
        }
    }
}
