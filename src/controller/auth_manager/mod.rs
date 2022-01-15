/// SPDX-License-Identifier: MIT
/// SPDX-License-Identifier: APACHE
/// 
/// 2022, Patrick Schneider <patrick@itermori.de>

mod pkce;
pub use pkce::PKCE;

mod client_data;
pub use client_data::ClientData;

mod auth_error;
pub use auth_error::AuthError;

use wasm_bindgen::prelude::*;
use web_sys::Storage;
use oauth2::{
    PkceCodeChallenge,
    CsrfToken,
    AuthorizationCode,
    StandardTokenResponse,
    EmptyExtraTokenFields,
    TokenResponse
};
use oauth2::basic::{
    BasicClient,
    BasicTokenType
};
use oauth2::url::Url;
use oauth2::reqwest::async_http_client;

use std::collections::HashMap;

pub struct AuthManager {
    pkce: Option<PKCE>,
    client: BasicClient,
    tokens: Option<StandardTokenResponse<EmptyExtraTokenFields, BasicTokenType>>
}

impl AuthManager {
    
    const URL_AUTH_CODE: &'static str = "code";
    const URL_STATE: &'static str = "state";

    /// Create a new AuthManager instance with default values
    /// 
    /// # Example
    /// ```rust
    /// let client_data = ClientData::new(/** */);
    /// let auth: AuthManager = AuthManager::new(client);
    /// ```
    pub fn new(client_data: ClientData) -> Self {
        AuthManager {
            pkce: None,
            client: client_data.create(),
            tokens: None
        }
    }

    /// Store the state of the AuthManager in the provided storage.
    /// Only set state will be stored.
    /// 
    /// # Arguments
    /// 
    /// * `storage` - A [`Storage`](web_sys::Storage) to store the content
    /// 
    /// # Returns
    /// 
    /// * `Ok(())` - State could be stored
    /// * `Err(JsValue)` - State could not be stored
    /// 
    /// # Example
    /// 
    /// ```rust
    /// // The storage is provided elsewhere
    /// let storage: Storage;
    /// let auth = AuthManager::new()
    /// if let Err(err) = auth.store(storage) {
    ///     // handle error
    /// }
    /// ```
    pub fn store(&self, storage: Storage) -> Result<(), JsValue> {
        if let Some(pkce) = &self.pkce {
            pkce.store(storage)?
        }

        Ok(())
    }

    /// Load the state of the AuthManager from the provided storage.
    /// Only set state will be loaded.
    /// 
    /// # Arguments
    /// 
    /// * `storage` - A [`Storage`](web_sys::Storage) to store the content
    /// 
    /// # Returns
    /// 
    /// * `Ok(())` - State could be loaded
    /// * `Err(JsValue)` - State could not be loaded
    /// 
    /// # Example
    /// 
    /// ```rust
    /// // The storage is provided elsewhere
    /// let storage: Storage;
    /// let auth = AuthManager::new()
    /// if let Err(err) = auth.load(storage) {
    ///     // handle error
    /// }
    /// ```
    pub fn load(&mut self, storage: Storage) -> Result<(), JsValue> {
        if let Some(pkce) = &mut self.pkce {
            pkce.load(storage)?
        }

        Ok(())
    }

    /// Initialize the authentication process and 
    /// return the URL the user needs to authenticate on.
    /// Saves the state of the auth_manager to support different authentication methods.
    /// 
    /// # Arguments
    /// 
    /// * `storage` - A [`Storage`](web_sys::Storage) to store the information of the authentication process
    /// 
    /// # Returns
    /// 
    /// * `Ok(String)` - The URL the user can authenticate on
    /// * `Err(JsValue)` - If an error occurred during the initialization
    /// 
    /// # Example
    /// 
    /// ```rust
    /// // The storage is provided elsewhere
    /// let storage: Storage;
    /// let auth = AuthManager::new();
    /// match auth.init_authentication() {
    ///     Ok(url) => {
    ///         // do something
    ///     },
    ///     Err(err) => {
    ///         // handle the error
    ///     }
    /// }
    /// ```
    pub fn init_authentication(&mut self, storage: Storage) -> Result<Url, JsValue>{
    
        // Generate a PKCE challenge.
        let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
    
        // Generate the full authorization URL and the csrf token
        let (redirect, csrf) = self.client
            .authorize_url(CsrfToken::new_random)
            // Set the desired scopes.
            // .add_scope(Scope::new("read".to_string()))
            // .add_scope(Scope::new("write".to_string()))
            // Set the PKCE code challenge.
            .set_pkce_challenge(challenge)
            .url();

        // Store the verifier and the csrf token to verify server response
        self.pkce = Some(PKCE::new(verifier, csrf));
        self.store(storage)?;

        Ok(redirect)
    }

    /// Exchange the given authorization code for the tokens at the authentication provider.
    /// Check for security issues (Cross-Site Request Forgery) by providing the state answer.
    /// 
    /// # Params
    /// 
    /// * `code`  - The authorization code of the response. See [`AuthorizationCode`](oauth2::AuthorizationCode)
    /// * `state` - The state code of the response. See [`CsrfToken`](oauth2::CsrfToken)
    /// 
    /// # Returns
    /// 
    /// * `(Self, Result<(), [AuthError]` 
    ///     - The instance itself and an [`AuthError`] if something fails.
    /// 
    /// # Example
    /// ```rust
    /// let auth = AuthManager::new(/** */);
    /// let redirect = auth.init_authentication(/** */);
    /// /* Authenticate and retreive code and state */
    /// let (auth, result) = auth.exchange_token(code, state);
    /// if let Err(err) = result {
    ///     // Handle Error
    /// }
    /// // You now can access the tokens
    /// ```
    pub async fn exchange_token(mut self, code: AuthorizationCode, state: CsrfToken) -> (Self, Result<(), AuthError>) {
        
        let (verifier, csrf) = match self.pkce {
            Some(pkce) => {
                self.pkce = None;
                pkce.destructure()
            },
            None => {
                return (
                    self, 
                    Err(AuthError::new(String::from("No authentication process was initiated!")))
                );
            }
        };
        
        if csrf.secret() != state.secret() {
            return (
                self,
                Err(
                    AuthError::new(
                        String::from("Cross-Site Request Forgery detected! The returned state did not match!")
                    )
                )
            );
        }
        let token_result = self.client
            .exchange_code(code)
            .set_pkce_verifier(verifier)
            .request_async(async_http_client)
            .await;

        self.tokens = match token_result {
            Ok(tokens) => Some(tokens),
            Err(err) => {
                return (
                    self,
                    Err(AuthError::new(err.to_string()))
                )
            }
        };
        
        (self, Ok(()))
    }

    /// This function is used to retrieve the authorization code and the state token from the authorization response.
    /// 
    /// # Arguments
    /// 
    /// * `url` - A [`oauth2::url::Url`] containing the response of the authorization provider
    /// 
    /// # Returns
    /// 
    /// * `Ok((AuthorizationCode, CsrfToken))` - Iff the authorization code and the state were present
    ///                                          and could be retrieved.
    /// * `Err(AuthError)` - Otherwise
    /// 
    /// # Example
    /// ```rust
    /// let url = Url::from_str("https://example.com/?state=abc123&code=qwert12345");
    /// let (code, state) = AuthManager::get_response(url);
    /// assert!(code, AuthorizationCode::new(String::from(abc123)));
    /// assert!(state, CsrfToken::new(String::from(qwert12345)));
    /// ```
    pub fn get_response(url: Url) -> Result<(AuthorizationCode, CsrfToken), AuthError> {

        let queries: HashMap<String, String> = 
            url.query_pairs()
            .map(|(key, value)| (key.to_string(), value.to_string()))
            .collect();
        if queries.is_empty() {
            return Err(AuthError::new(String::from("No response is present in the given url!")))
        }
        
        let auth_code: AuthorizationCode = match queries.get(Self::URL_AUTH_CODE) {

            Some(code) => AuthorizationCode::new(String::from(code)),
            None => {
                return Err(AuthError::new(String::from("There was no authorization code present in the provided url!")))
            }
        };

        let state: CsrfToken = match queries.get(Self::URL_STATE) {

            Some(token) => CsrfToken::new(String::from(token)),
            None => {
                return Err(AuthError::new(String::from("There was no state present in the provided url!")))
            }
        };

        Ok((auth_code, state))
    }

    // TODO: Remove this function since it is disabling any security regarding the access token
    //       Debugging only!
    // 
    // pub fn access_token(&self) -> Result<&String, AuthError> {
    //     match &self.tokens {
    //         Some(tokens) => {
    //             Ok(tokens.access_token().secret())
    //         }
    //         None => {
    //             Err(AuthError::new(String::from("No access token available!")))
    //         }
    //     }
    // }

}

// ********************** Unit Tests *************************

#[cfg(test)]
mod tests {


}