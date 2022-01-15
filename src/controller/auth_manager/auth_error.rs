/// SPDX-License-Identifier: MIT
/// SPDX-License-Identifier: APACHE
/// 
/// 2022, Patrick Schneider <patrick@itermori.de>

use wasm_bindgen::prelude::*;
use std::fmt;

/// The AuthError represents an error which occurs during the authorization process 
#[wasm_bindgen]
pub struct AuthError {

    /// The URL to redirect to.
    /// Must be known to the authentication provider
    cause: String
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Error, cannot authenticate: {}", self.cause)
    }
}

impl fmt::Debug for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{{ file: {}, line: {}, message: {} }}", file!(), line!(), self.cause)
    }
}

impl AuthError {

    /// Create an AuthError with a cause
    /// 
    /// # Variables
    /// 
    /// * `cause` - An error message describing the cause
    /// 
    /// # Example
    /// ```rust
    /// // An error occured
    /// return Err(AuthError::new(String::from("Something went wrong")))
    /// ```
    pub fn new(cause: String) -> Self {
        AuthError {
            cause
        }
    }
}

// ********************** Unit Tests *************************

#[cfg(test)]
mod tests {

    use super::*;
}