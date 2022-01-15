/// SPDX-License-Identifier: MIT
/// SPDX-License-Identifier: APACHE
/// 
/// 2022, Patrick Schneider <patrick@itermori.de>

use wasm_bindgen::prelude::*;
use wasm_bindgen::throw_str;
use web_sys::Storage;
use super::AuthManager;
use super::auth_manager::{
    ClientData,
};

use oauth2::url::Url;

#[wasm_bindgen]
pub struct Framework {

    session: Storage,
    auth: AuthManager
}

#[wasm_bindgen]
impl Framework {

    /// Create the framework by supplying the necessary client data and a storage
    /// 
    /// # Arguments
    /// 
    /// * `client_data` - See [`ClientData`](ClientData)
    /// * `storage` - A [`Storage`](Storage)
    /// 
    /// # Returns
    /// 
    /// * `Framework`
    /// 
    /// # Example
    /// ```rust
    /// let client_data = ClientData::from(/* */);
    /// let storage: Storage = /* */;
    /// let framework: Framework = Framework::new(client_data, storage);
    /// ```
    pub fn new(
        client_data: ClientData,
        storage: Storage
    ) -> Framework {
        Framework {
            auth: AuthManager::new(client_data),
            session: storage
        }
    }

    /// Initiate the authentication process and retrieve the URL to authenticate on
    /// 
    /// # Returns
    /// 
    /// * `String` - `String` representing the URL the user needs to authenticate on
    /// 
    /// # Throws
    /// Throws if an error occurred during initiation containing a description of the error
    /// 
    /// # Example
    /// ```rust
    /// let framework: Framework;
    /// let authentication_url: String = framework.initiate_authentication();
    /// ```
    pub fn initiate_authentication(&mut self) -> String {

        match self.auth.init_authentication(&self.session) {
            Ok(url) => url.to_string(),
            Err(err) => throw_str(format!("{:?}", err))
        }
    }

    /// Authenticate the user by providing the url the user got redirected to.
    /// This URL `has` to contain a parameter `state` and `code`.
    /// 
    /// # Arguments
    /// 
    /// * `response` - The response in form of the redirection url after authentication of the user.
    /// 
    /// # Throws
    /// If an error occurred, an error containing the cause is thrown.
    /// 
    /// # Example
    /// ```rust
    /// let framework: Framewok = 
    /// let response: String = String::from("https://example.com/?state=abc123&code=qwert12345");
    /// framework.authenticate(response);
    /// // The user is now authenticated, if nothing was thrown.
    /// ```
    pub async fn authenticate(mut self, response: String) -> Self {

        let url = match Url::parse(&response) {
            Ok(url) => url,
            _ => throw_str(&format!("{} is not a valid url.", response))
        };

        let (code, state) = match AuthManager::get_response(url) {
            Ok(values) => values,
            Err(err) => throw_str(&format!("{}", err))
        };
        let (auth, result) = self.auth.exchange_token(code, state, Some(&self.session)).await;
        self.auth = auth;
        if let Err(err) = result {
            throw_str(&format!("{}", err))
        }

        self
    }
}