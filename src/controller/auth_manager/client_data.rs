/// SPDX-License-Identifier: MIT
/// SPDX-License-Identifier: APACHE
/// 
/// 2022, Patrick Schneider <patrick@itermori.de>

use wasm_bindgen::prelude::*;
use oauth2::{
    ClientId,
    AuthUrl,
    RedirectUrl
};
use oauth2::basic::BasicClient;

/// The ClientData struct stores the relevant authentication provider data used in the authentication process.
/// 
#[wasm_bindgen]
pub struct ClientData {

    /// The URL to redirect to.
    /// Must be known to the authentication provider
    redirect_url: RedirectUrl,

    /// The URL of the authentication provider.
    auth_url: AuthUrl,

    /// The client id registered at the authentication provider.
    client_id: ClientId
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
    pub fn new(auth_url: AuthUrl, client_id: ClientId, redirect_url: RedirectUrl) -> Self {
        
        ClientData {
            auth_url: auth_url,
            client_id: client_id,
            redirect_url: redirect_url,
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
            None
        ).set_redirect_uri(self.redirect_url)
    }
}

// ********************** Unit Tests *************************

#[cfg(test)]
mod tests {

    use super::*;
}