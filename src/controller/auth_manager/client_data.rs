/// SPDX-License-Identifier: MIT
/// SPDX-License-Identifier: APACHE
/// 
/// 2022, Patrick Schneider <patrick@itermori.de>

use wasm_bindgen::prelude::*;
use wasm_bindgen::throw_str;
use openidconnect::{
    ClientId,
    IssuerUrl,
    RedirectUrl
};
use openidconnect::core::{
    CoreClient,
    CoreProviderMetadata
};
use openidconnect::reqwest::async_http_client;

use super::auth_error::AuthError;

/// The OIDCClientData struct stores the relevant authentication provider data used in the authentication process.
/// 
#[wasm_bindgen]
pub struct OIDCClientData {

    /// The URL to redirect to.
    /// Must be known to the authentication provider
    redirect_url: RedirectUrl,

    /// The client id registered at the authentication provider.
    client_id: ClientId,

    metadata: CoreProviderMetadata
}

#[wasm_bindgen]
impl OIDCClientData {

    /// Create a new OIDCClientData instance with the given values.
    /// 
    /// # Arguments
    /// 
    /// * `issuer_url` - The url of the used authentication provider
    /// * `client_id` - The at the authentication provider registered client id
    /// * `redirect_url`- The at the authentication provider registered redirection url
    /// 
    /// # Returns
    /// 
    /// * `OIDCClientData`
    /// 
    /// # Throws
    /// If any of the given values are not valid, e.g not a url provided
    /// 
    /// # Example
    /// ```rust
    /// let issuer_url = String::from("https://auth_provider.org/");
    /// let client_id = String::from("my-client-id");
    /// let redirect_url = String::from("https://my.site");
    /// let client: OIDCClientData = OIDCClientData::new(auth_url, token_url, client_id, redirect_url);
    /// ```
    pub async fn from(
        issuer_url: String, 
        token_url: String,
        client_id: String, 
        redirect_url: String) -> OIDCClientData {
        
        let (issuer, client, redirect) = match (
            IssuerUrl::new(issuer_url),
            ClientId::new(client_id),
            RedirectUrl::new(redirect_url)
        ) {
            (Ok(issuer_url), client_id, Ok(redirect_url)) => (issuer_url, client_id, redirect_url),
            (Err(err), _, _) |
            (_, _, Err(err)) => throw_str(&format!("{}", err))
        };

        match OIDCClientData::new(issuer, client, redirect).await {
            Ok(client_data) => client_data,
            Err(err) => throw_str(&format!("{}", err))
        }
    }
}

impl OIDCClientData {

    /// Create a new OIDCClientData instance with the given values.
    /// The relevant endpoints are discovered through the provided issuer url.
    /// 
    /// # Arguments
    /// 
    /// * `issuer_url` - The The url of the used authentication provider
    /// * `client_id` - The at the authentication provider registered client id
    /// * `redirect_url`- The at the authentication provider registered redirection url
    /// 
    /// # Returns
    /// `Ok(OIDCClientData)` - If the issuer url could be accessed
    /// `Err(AuthErr)` - If the issuer url could not be accessed
    /// 
    /// # Example
    /// ```rust
    /// let issuer = IssuerUrl::new(String::from("https://auth_provider.org/"));
    /// let client_id = ClientId::new(String::from("my-client-id"));
    /// let redirect_url = RedirectUrl::new(String::from("https://my.site"));
    /// let client: OIDCClientData = OIDCClientData::new(auth_url, client_id, redirect_url);
    /// ```
    pub async fn new(
        issuer_url: IssuerUrl, 
        client_id: ClientId, 
        redirect_url: RedirectUrl) -> Result<Self, AuthError> {
        
        let metadata = match CoreProviderMetadata::discover_async(issuer_url, async_http_client).await {
            Ok(metadata) => metadata,
            Err(err) => return Err(AuthError::from(err.to_string()))
        };

        Ok(OIDCClientData {
            client_id,
            redirect_url,
            metadata
        })
    }

    /// Create the client represented by the data of this instance.
    /// Consumes this instance!
    /// 
    /// # Returns
    /// [`CoreClient`](openidconnect::core::CoreClient)
    /// 
    /// # Example
    /// ```rust
    /// let data: OIDCClientData; // Provided elsewhere
    /// let client: CoreClient = data.create();
    /// // data cannot be used anymore!
    /// // do stuff with client
    /// ```
    pub fn create(self) -> CoreClient {
        
        CoreClient::from_provider_metadata(
            self.metadata,
            self.client_id,
            None,
        ).set_redirect_uri(self.redirect_url)
    }
}

// ********************** Unit Tests *************************

#[cfg(test)]
mod tests {

    use super::*;
}