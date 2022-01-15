/// SPDX-License-Identifier: MIT
/// SPDX-License-Identifier: APACHE
/// 
/// 2022, Patrick Schneider <patrick@itermori.de>

// use crate::console_log;

mod pkce;
pub use pkce::PKCE;

mod client_data;
pub use client_data::OIDCClientData;

mod auth_error;
pub use auth_error::AuthError;

use wasm_bindgen::prelude::*;
use web_sys::Storage;
use openidconnect::{
    PkceCodeChallenge,
    CsrfToken,
    Nonce,
    AuthorizationCode,
    TokenResponse,
    IdToken,
    IdTokenClaims,
    AccessToken,
    RefreshToken,
    EmptyAdditionalClaims,
    AccessTokenHash,
    OAuth2TokenResponse
};
use openidconnect::core::{
    CoreAuthenticationFlow,
    CoreClient,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJwsSigningAlgorithm,
    CoreJsonWebKeyType,
};
use openidconnect::url::Url;
use openidconnect::reqwest::async_http_client;

use std::collections::HashMap;

pub struct AuthManager {
    pkce: Option<PKCE>,
    client: Option<CoreClient>,
    id_token: Option<IdToken<
        EmptyAdditionalClaims, 
        CoreGenderClaim, 
        CoreJweContentEncryptionAlgorithm, 
        CoreJwsSigningAlgorithm, 
        CoreJsonWebKeyType
        >>,
    access_token: Option<AccessToken>,
    refresh_token: Option<RefreshToken>,
    claims: Option<IdTokenClaims<EmptyAdditionalClaims, CoreGenderClaim>>
}

impl AuthManager {
    
    const URL_AUTH_CODE: &'static str = "code";
    const URL_STATE: &'static str = "state";

    /// Create a new AuthManager instance with default values
    /// 
    /// # Example
    /// ```rust
    /// let client_data: OIDCClientData // Already elsewhere provided;
    /// let auth: AuthManager = AuthManager::new(client);
    /// ```
    pub fn new(client_data: OIDCClientData) -> Self {
        AuthManager {
            pkce: None,
            client: Some(client_data.create()),
            id_token: None,
            access_token: None,
            refresh_token: None,
            claims: None
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
    pub fn store(&self, storage: &Storage) -> Result<(), JsValue> {
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
    pub fn load(&mut self, storage: &Storage) -> Result<(), JsValue> {
        self.pkce = Some(PKCE::load_from(storage)?);

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
    pub fn init_authentication(&mut self, storage: &Storage) -> Result<Url, JsValue>{
    
        // Generate a PKCE challenge.
        let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
    
        // Generate the full authorization URL and the csrf token
        let (redirect, csrf, nonce) = match &self.client {
            Some(client) => client.authorize_url(
                                CoreAuthenticationFlow::AuthorizationCode,
                                CsrfToken::new_random,
                                Nonce::new_random
                            )
                            .set_pkce_challenge(challenge)
                            .url(),
            None => return Err(JsValue::from(AuthError::from("No client was setup!")))
        };

        // Store the verifier, csrf token and nonce to verify server response
        self.pkce = Some(PKCE::new(verifier, csrf, nonce));
        self.store(storage)?;

        Ok(redirect)
    }

    /// Exchange the given authorization code for the tokens at the authentication provider.
    /// Check for security issues (Cross-Site Request Forgery) by providing the state answer.
    /// After this method returned successfully, the user was successfully authorized and the claims are available.
    /// 
    /// # Params
    /// 
    /// * `code`  - The authorization code of the response. See [`AuthorizationCode`](oauth2::AuthorizationCode)
    /// * `state` - The state code of the response. See [`CsrfToken`](oauth2::CsrfToken)
    /// * `storage` - The storage to read the previously generated authorization data from. [`Some(&Storage)](Storage)
    /// 
    /// # Returns
    /// 
    /// * `(Self, Result<(), [AuthError]` 
    ///     - The instance itself and an [`AuthError`] if something fails.
    /// 
    /// # Example
    /// ```rust
    /// let auth: AuthManager; // Already elsewhere provided
    /// let redirect: Url; // Already elsewhere provided
    /// let storage: Storage; // already provided elsewhere
    /// // Authenticate and retreive code and state
    /// let (auth, result) = auth.exchange_token(code, state, Some(&storage));
    /// if let Err(err) = result {
    ///     // Handle Error
    /// }
    /// // You now can access the tokens
    /// ```
    pub async fn exchange_token(
        mut self, 
        code: AuthorizationCode, 
        state: CsrfToken,
        storage: Option<&Storage>
    ) -> (Self, Result<(), AuthError>) {
        
        // If no pkce data is present, try to load the data from the provided storage
        if let None = self.pkce {
            if let Some(store) = storage {
                if let Err(_) = self.load(&store) {
                    return (
                        self, 
                        Err(AuthError::from("Could not load data from given store!"))
                    )
                }
            } else {
                return (
                    self, 
                    Err(AuthError::from("No authentication process was initiated!"))
                );
            }
        }

        let client = match self.client {
            Some(client) => {
                self.client = None;
                client
            },
            None => return (
                self,
                Err(AuthError::from("No client was setup to authenticate!"))
            )
        };
        
        let (verifier, csrf, nonce) = self.pkce.unwrap().destructure();
        self.pkce = None;
        
        // check for csrf errors
        if csrf.secret() != state.secret() {
            return (
                self,
                Err(
                    AuthError::from("Cross-Site Request Forgery detected! The returned state did not match!")
                )
            );
        }

        // retrieve the tokens
        let token_result = client
            .exchange_code(code)
            .set_pkce_verifier(verifier)
            .request_async(async_http_client)
            .await;

        let tokens = match token_result {
            Ok(tokens) => tokens,
            Err(err) => {
                return (
                    self,
                    Err(AuthError::from(err.to_string()))
                )
            }
        };

        // Extract the id_token and the claims containing the user information
        let id_token = match tokens.id_token() {
            Some(id) => id,
            None => return (
                self,
                Err(AuthError::from("The server did not respond with an id token!"))
            )
        };

        let claims = match id_token.claims(&client.id_token_verifier(), &nonce) {
            Ok(claims) => claims,
            Err(err) => return (
                self,
                Err(AuthError::from(err.to_string()))
            )
        };

        // Check if the access_token got tampered and signed differently
        // and throw errors if anything does not line up.
        if let Some(expected_hash_algorithm) = claims.access_token_hash() {
            
            let siging_alg = match id_token.signing_alg() {
                Ok(alg) => alg,
                Err(err) => return (
                    self,
                    Err(AuthError::from(err.to_string()))
                )
            };
            let actual_hash_algorithm = match 
                AccessTokenHash::from_token(
                    tokens.access_token(),
                    &siging_alg
                ) {
                Ok(alg) => alg,
                Err(err) => return (
                    self,
                    Err(AuthError::from(err.to_string()))
                )
            };
            if *expected_hash_algorithm != actual_hash_algorithm {
                return (
                    self,
                    Err(AuthError::from("The used and expected hash algorithms are not the same!"))
                )
            }
        }

        // save the extracted id, access and refresh tokens as well as the claims for later usage
        self.id_token = Some(id_token.clone());
        self.access_token = Some(tokens.access_token().clone());
        self.refresh_token = match tokens.refresh_token() {
            Some(refresh) => Some(refresh.clone()),
            None => None
        };
        self.claims = Some(claims.clone());

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
            return Err(AuthError::from("No response is present in the given url!"))
        }
        
        let auth_code: AuthorizationCode = match queries.get(Self::URL_AUTH_CODE) {

            Some(code) => AuthorizationCode::new(String::from(code)),
            None => {
                return Err(AuthError::from("There was no authorization code present in the provided url!"))
            }
        };

        let state: CsrfToken = match queries.get(Self::URL_STATE) {

            Some(token) => CsrfToken::new(String::from(token)),
            None => {
                return Err(AuthError::from("There was no state present in the provided url!"))
            }
        };

        Ok((auth_code, state))
    }

}

// ********************** Unit Tests *************************

#[cfg(test)]
mod tests {


}