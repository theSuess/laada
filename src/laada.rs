use chacha20poly1305::aead::{Aead, NewAead};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce}; // Or `XChaCha20Poly1305`
use graph_rs_sdk::http::AsyncHttpClient;
use graph_rs_sdk::oauth::OAuth;
use graph_rs_sdk::{client::Graph, oauth::AccessToken};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LaadaConfig {
    tenant_id: String,
    client_id: String,
    client_secret: String,
    pub upn_domains: Option<Vec<String>>,
    pub external_issuer: Option<String>,
    pub ldap: Option<LDAPConfig>,
    pub web: Option<WebConfig>,
}
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LDAPConfig {
    #[serde(default = "default_ldap_host")]
    pub host: String,
    #[serde(default = "default_ldap_port")]
    pub port: u16,
    #[serde(default = "default_ldap_basedn")]
    pub basedn: String,
}

impl Default for LDAPConfig {
    fn default() -> Self {
        LDAPConfig {
            host: default_ldap_host(),
            port: default_ldap_port(),
            basedn: default_ldap_basedn(),
        }
    }
}

fn default_ldap_host() -> String {
    "0.0.0.0".to_string()
}

fn default_ldap_port() -> u16 {
    3389
}
fn default_ldap_basedn() -> String {
    "dc=laada,dc=suess,dc=wtf".to_string()
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WebConfig {
    #[serde(default = "default_web_host")]
    pub host: String,
    #[serde(default = "default_web_port")]
    pub port: u16,
}
fn default_web_host() -> String {
    "0.0.0.0".to_string()
}
fn default_web_port() -> u16 {
    8080
}

impl Default for WebConfig {
    fn default() -> Self {
        WebConfig {
            host: String::from("0.0.0.0"),
            port: 8080,
        }
    }
}

pub struct LaadaServer {
    pub cfg: LaadaConfig,
    access_token: AccessToken,
}

impl LaadaServer {
    pub async fn new(cfg: LaadaConfig) -> Self {
        let access_token = cfg.new_access_token().await;
        LaadaServer { cfg, access_token }
    }
    pub async fn graph_client(&mut self) -> Graph<AsyncHttpClient> {
        if self.access_token.is_expired() {
            self.access_token = self.cfg.new_access_token().await;
        }
        Graph::from(&self.access_token)
    }
}

impl LaadaConfig {
    pub fn oauth_client(&self) -> OAuth {
        let mut oauth = OAuth::new();
        oauth
            .client_id(self.client_id.as_str())
            .client_secret(self.client_secret.as_str())
            .add_scope("offline_access")
            .access_token_url("https://login.microsoftonline.com/common/oauth2/v2.0/token")
            .tenant_id(self.tenant_id.as_str())
            .response_type("code")
            .add_scope("https://graph.microsoft.com/.default");
        oauth
    }
    async fn new_access_token(&self) -> AccessToken {
        let mut oauth = self.oauth_client();
        let token = oauth
            .build_async()
            .client_credentials()
            .access_token()
            .send()
            .await
            .unwrap();
        trace!("Access Token: {:?}", token);
        token
    }
    pub fn oauth_request(&self, redirect_uri: &str) -> String {
        let mut oauth = self.oauth_client();
        oauth
            .redirect_uri(redirect_uri)
            .build()
            .code_flow()
            .authorization_url()
            .to_string()
    }
    pub fn encrypt_token(&self, token: &[u8], nonce: &[u8]) -> Vec<u8> {
        let rk = self.get_key();
        let key = Key::from_slice(rk.as_slice());
        let cipher = ChaCha20Poly1305::new(key);
        let nonce = Nonce::from_slice(nonce); // 12-bytes; unique per message
        cipher.encrypt(nonce, token).expect("crypto error")
    }
    pub fn decrypt_token(&self, enc: &[u8], nonce: &[u8]) -> Vec<u8> {
        let rk = self.get_key();
        let key = Key::from_slice(rk.as_slice());
        let cipher = ChaCha20Poly1305::new(key);
        let nonce = Nonce::from_slice(nonce); // 12-bytes; unique per message
        cipher.decrypt(nonce, enc).expect("invalid ciphertext")
    }
    fn get_key(&self) -> Vec<u8> {
        let kdf = argon2::Argon2::default();
        let mut key = [0u8; 32];
        kdf.hash_password_into(
            self.client_secret.as_bytes(),
            self.tenant_id.as_bytes(),
            &mut key,
        )
        .expect("key deriviation error");
        key.to_vec()
    }
}
