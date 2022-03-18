use graph_rs_sdk::http::AsyncHttpClient;
use graph_rs_sdk::oauth::OAuth;
use graph_rs_sdk::{client::Graph, oauth::AccessToken};
use serde::{Deserialize, Serialize};

#[derive(Default, Debug, Serialize, Deserialize)]
pub struct LaadaConfig {
    tenant_id: String,
    client_id: String,
    client_secret: String,
}
pub struct LaadaServer {
    cfg: LaadaConfig,
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
    async fn new_access_token(&self) -> AccessToken {
        let mut oauth = OAuth::new();
        oauth
            .client_id(self.client_id.as_str())
            .client_secret(self.client_secret.as_str())
            .access_token_url("https://login.microsoftonline.com/common/oauth2/v2.0/token")
            .tenant_id(self.tenant_id.as_str())
            .add_scope("https://graph.microsoft.com/.default");
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
}
