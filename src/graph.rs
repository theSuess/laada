use serde::{Deserialize, Serialize};
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
}
#[derive(Debug, Serialize, Deserialize)]
pub struct ListUserResponse {
    pub value: Vec<ADUser>,
}
