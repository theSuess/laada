use serde::{Deserialize, Serialize};

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

#[derive(Debug, Serialize, Deserialize)]
pub struct LaadaExtension {
    #[serde(rename = "extensionName")]
    pub extension_name: String,
    pub token: String,
}

impl LaadaExtension {
    pub fn new(token: String) -> Self {
        LaadaExtension {
            extension_name: EXTENSION_NAME.to_string(),
            token,
        }
    }
}
