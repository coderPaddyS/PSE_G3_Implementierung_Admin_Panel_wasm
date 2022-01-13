/// SPDX-License-Identifier: MIT
/// SPDX-License-Identifier: APACHE
/// 
/// 2022, Patrick Schneider <patrick@itermori.de>

use wasm_bindgen::prelude::*;
use web_sys::Storage;
use oauth2::{
    CsrfToken,
    PkceCodeVerifier
};

/// The PKCE structs holds the data involved in the authentication process
/// 
#[wasm_bindgen]
#[derive(Default)]
pub struct PKCE {

    /// The verifier used to verify the response of the authentication process
    verifier: Option<PkceCodeVerifier>,

    /// The csrf token involved in the authentication process
    csrf: Option<CsrfToken>
}

impl PKCE {
    const ID_VERIFIER: &'static str = "verifier";
    const ID_CSRF: &'static str = "csrf";
}

#[wasm_bindgen]
impl PKCE {

    /// Create a new pkce instance with default values
    /// 
    /// # Example
    /// ```rust
    /// let pkce: PKCE = PKCE::new()
    /// ```
    pub fn new() -> Self {
        PKCE::default()
    }

    /// Store the state of the pkce in the provided storage.
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
    /// let pkce = PKCE::new()
    /// if let Err(err) = pkce.store(storage) {
    ///     // handle error
    /// }
    /// ```
    pub fn store(&self, storage: Storage) -> Result<(), JsValue> {

        if let Some(verifier) = &self.verifier {
            storage.set(PKCE::ID_VERIFIER, &verifier.secret())?;
        }
        if let Some(csrf) = &self.csrf {
            storage.set(PKCE::ID_CSRF, &csrf.secret())?;
        }
        Ok(())
    }

    /// Loads the state of the pkce from the provided storage.
    /// Only set state will be loaded.
    /// 
    /// # Arguments
    /// 
    /// * `storage` - A [`Storage`](web_sys::Storage) to load the content
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
    /// // and contains some stored values from pkce
    /// let storage: Storage;
    /// let pkce = PKCE::new()
    /// if let Err(err) = pkce.store(storage) {
    ///     // handle error
    /// }
    /// ```
    pub fn load(&mut self, storage: Storage) -> Result<(), JsValue> {

        match storage.get(PKCE::ID_VERIFIER) {
            Ok(Some(verifier)) => {
                self.verifier = Some(PkceCodeVerifier::new(verifier));
            },
            Ok(None) => (),
            Err(e) => return Err(e)
        }
        match storage.get(PKCE::ID_CSRF) {
            Ok(Some(csrf)) => {
                self.csrf = Some(CsrfToken::new(csrf));
            },
            Ok(None) => (),
            Err(e) => return Err(e)
        }
        Ok(())
    }
}

// ********************** Unit Tests *************************

#[cfg(test)]
mod tests {

    use super::*;
}