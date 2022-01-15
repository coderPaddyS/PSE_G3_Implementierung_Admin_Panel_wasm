/// SPDX-License-Identifier: MIT
/// SPDX-License-Identifier: APACHE
/// 
/// 2022, Patrick Schneider <patrick@itermori.de>

use wasm_bindgen::prelude::*;
use oauth2::{
    ClientId,
    AuthUrl,
    RedirectUrl,
    TokenUrl
};
use oauth2::basic::BasicClient;
use super::auth_error::AuthError;

/// The ClientData struct stores the relevant authentication provider data used in the authentication process.
/// 
#[wasm_bindgen]
pub struct ClientData {

    /// The URL to redirect to.
    /// Must be known to the authentication provider
    redirect_url: RedirectUrl,

    /// The URL of the authentication provider.
    auth_url: AuthUrl,

    // The URL to fetch the token of the authentication provider.
    token_url: TokenUrl,

    /// The client id registered at the authentication provider.
    client_id: ClientId
}

#[wasm_bindgen]
impl ClientData {

    /// Create a new ClientData instance with the given values
    /// 
    /// # Arguments
    /// 
    /// * `auth_url` - The endpoint of the used authentication provider
    /// * `token_url` - The endpoint used to fetch tokens on
    /// * `client_id` - The at the authentication provider registered client id
    /// * `redirect_url`- The at the authentication provider registered redirection url
    /// 
    /// # Example
    /// ```rust
    /// let auth_url = String::from("https://auth_provider.org/auth");
    /// let token_url = String::from("https://auth_provider.org/token");
    /// let client_id = String::from("my-client-id");
    /// let redirect_url = String::from("https://my.site");
    /// let client: ClientData = ClientData::new(auth_url, token_url, client_id, redirect_url);
    /// ```
    pub fn from(
        auth_url: String, 
        token_url: String,
        client_id: String, 
        redirect_url: String) -> Result<ClientData, JsValue> {
        
        match (
            AuthUrl::new(auth_url),
            TokenUrl::new(token_url),
            ClientId::new(client_id),
            RedirectUrl::new(redirect_url)
        ) {
            (Ok(auth_url), Ok(token_url), client_id, Ok(redirect_url)) => Ok(
                ClientData::new(
                    auth_url,
                    token_url,
                    client_id,
                    redirect_url
                )
            ),
            _ => Err(JsValue::from(AuthError::from("The provided data is not correct!")))
        }
    }
}

impl ClientData {

    /// Create a new ClientData instance with the given values
    /// 
    /// # Arguments
    /// 
    /// * `auth_url` - The endpoint of the used authentication provider
    /// * `client_id` - The at the authentication provider registered client id
    /// * `redirect_url`- The at the authentication provider registered redirection url
    /// 
    /// # Example
    /// ```rust
    /// let auth_url = AuthUrl::new(String::from("https://auth_provider.org/auth"));
    /// let client_id = ClientId::new(String::from("my-client-id"));
    /// let redirect_url = RedirectUrl::new(String::from("https://my.site"));
    /// let client: ClientData = ClientData::new(auth_url, client_id, redirect_url);
    /// ```
    pub fn new(
        auth_url: AuthUrl, 
        token_url: TokenUrl,
        client_id: ClientId, 
        redirect_url: RedirectUrl) -> Self {
        
        ClientData {
            auth_url,
            token_url,
            client_id,
            redirect_url
        }
    }

    /// Create the client represented by the data of this instance.
    /// Consumes this instance!
    /// 
    /// # Returns
    /// [`BasicClient`](oauth2::basic::BasicClient)
    /// 
    /// # Example
    /// ```rust
    /// let data = BasicClient::new(/** */)
    /// let client: BasicClient = data.create();
    /// // data cannot be used anymore!
    /// // do stuff with client
    /// ```
    pub fn create(self) -> BasicClient {
        
        BasicClient::new(
            self.client_id,
            None,
            self.auth_url,
            Some(self.token_url)
        ).set_redirect_uri(self.redirect_url)
    }
}

// ********************** Unit Tests *************************

#[cfg(test)]
mod tests {

    use super::*;
}