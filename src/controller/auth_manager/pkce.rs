/// SPDX-License-Identifier: MIT
/// SPDX-License-Identifier: APACHE
/// 
/// 2022, Patrick Schneider <patrick@itermori.de>

use wasm_bindgen::prelude::*;
use web_sys::Storage;
use openidconnect::{
    CsrfToken,
    PkceCodeVerifier,
    Nonce
};

use super::AuthError;

/// The PKCE structs holds the data involved in the authentication process
/// 
pub struct PKCE {

    /// The verifier used to verify the response of the authentication process
    verifier: PkceCodeVerifier,

    /// The csrf token involved in the authentication process
    csrf: CsrfToken,

    /// The nonce involved to verify the response of the authentication process
    nonce: Nonce
}

impl PKCE {
    const ID_VERIFIER: &'static str = "verifier";
    const ID_CSRF: &'static str = "csrf";
    const ID_NONCE: &'static str = "nonce";
}

impl PKCE {

    /// Create a new pkce instance with the given pkce verifier, csrf token and nonce
    /// 
    /// # Arguments
    /// 
    /// * `verifier` - The [`PkceCodeVerifier`](PkceCodeVerifier) used to verify the response
    /// * `csrf` - The [`CsrfToken`](CsrfToken) used to validate CSRF
    /// * `nonce` - The created [`Nonce`](Nonce)
    /// 
    /// # Example
    /// ```rust
    /// let pkce: PKCE = PKCE::new()
    /// ```
    pub fn new(verifier: PkceCodeVerifier, csrf: CsrfToken, nonce: Nonce) -> Self {
        PKCE {
            verifier,
            csrf,
            nonce
        }
    }

    /// Store the state of the pkce in the provided storage.
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
    pub fn store(&self, storage: &Storage) -> Result<(), JsValue> {

        storage.set(PKCE::ID_VERIFIER, &self.verifier.secret())?;
        storage.set(PKCE::ID_CSRF, &self.csrf.secret())?;
        storage.set(PKCE::ID_NONCE, &self.nonce.secret())?;
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
    pub fn load_from(storage: &Storage) -> Result<PKCE, JsValue> {

        let (verifier, csrf, nonce) = match (
            storage.get(PKCE::ID_VERIFIER),
            storage.get(PKCE::ID_CSRF),
            storage.get(PKCE::ID_NONCE)
        ) {
            (Ok(Some(verifier)), Ok(Some(csrf)), Ok(Some(nonce))) => {
                (PkceCodeVerifier::new(verifier), CsrfToken::new(csrf), Nonce::new(nonce))
            },
            (Ok(None), _, _) | 
            (_, Ok(None), _) | 
            (_, _, Ok(None)) => return Err(JsValue::from(AuthError::from("No authentication data in storage found!"))),
            (Err(e), _, _) | 
            (_, Err(e), _) |
            (_, _, Err(e)) => return Err(e)
        };
        Ok(PKCE::new(verifier, csrf, nonce))
    }

    /// Destructure this pkce data into its components to use.
    /// The data is moved out of the data, therefore consumes this instance.
    /// 
    /// # Returns
    /// 
    /// * `(PkceCodeVerifier, CsrfToken, Nonce)` - The used verifier, csrf token and nonce.
    /// 
    /// # Example 
    /// ```rust
    /// let pkce = PKCE::new(verifier, csrf, nonce);
    /// 
    /// // Cannot use verifier, csrf, nonce here due to move
    /// 
    /// let (verifier, csrf, nonce) = pkce.destructure;
    /// 
    /// // Can use verifer, csrf, nonce here, but not pkce anymore
    /// ```
    pub fn destructure(self) -> (PkceCodeVerifier, CsrfToken, Nonce) {
        (self.verifier, self.csrf, self.nonce)
    }
}

// ********************** Unit Tests *************************

#[cfg(test)]
mod tests {

    use super::*;
}