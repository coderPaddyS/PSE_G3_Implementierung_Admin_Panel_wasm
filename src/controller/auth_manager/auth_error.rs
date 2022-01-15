/// SPDX-License-Identifier: MIT
/// SPDX-License-Identifier: APACHE
/// 
/// 2022, Patrick Schneider <patrick@itermori.de>

use wasm_bindgen::prelude::*;
use std::fmt;
use std::convert::From;

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

impl From<String> for AuthError {
    fn from(cause: String) -> AuthError{
        AuthError {
            cause
        }
    }
}

impl From<&str> for AuthError {
    fn from(cause: &str) -> AuthError{
        AuthError::from(String::from(cause))
    }
}

// ********************** Unit Tests *************************

#[cfg(test)]
mod tests {

    use super::*;
}