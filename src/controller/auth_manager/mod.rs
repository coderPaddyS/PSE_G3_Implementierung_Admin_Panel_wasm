/// SPDX-License-Identifier: MIT
/// SPDX-License-Identifier: APACHE
/// 
/// 2022, Patrick Schneider <patrick@itermori.de>

mod pkce;
pub use pkce::PKCE;

use wasm_bindgen::prelude::*;
use web_sys::Storage;

#[wasm_bindgen]
#[derive(Default)]
pub struct AuthManager {
    pkce: PKCE
}

#[wasm_bindgen]
impl AuthManager {
    
    /// Create a new AuthManager instance with default values
    /// 
    /// # Example
    /// ```rust
    /// let auth: AuthManager = AuthManager::new()
    /// ```
    pub fn new() -> Self {
        AuthManager::default()
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
        self.pkce.store(storage)
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
        self.pkce.load(storage)
    }

    pub fn init_authentication(&self) -> Result<String, JsValue>{

        let redirect: String = String::from("");
        Ok(redirect)
    }
}

// ********************** Unit Tests *************************

#[cfg(test)]
mod tests {


}