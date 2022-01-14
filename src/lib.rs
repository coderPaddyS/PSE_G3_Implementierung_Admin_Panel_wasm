//! SPDX-License-Identifier: MIT
//! SPDX-License-Identifier: APACHE
//! 
//! 2022, Patrick Schneider <patrick@itermori.de>

mod utils;
mod controller;
pub use controller::AuthManager;

use wasm_bindgen::prelude::*;

// When the `wee_alloc` feature is enabled, use `wee_alloc` as the global
// allocator.
#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;


#[wasm_bindgen]
extern {
    fn alert(s: &str);

    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
}

macro_rules! log {
    ($($t:tt)*) => (log(&format_args!($($t)*).to_string()))
}

#[wasm_bindgen]
pub struct Greeter {
    name: String
}

#[wasm_bindgen]
impl Greeter {

    pub fn new(name: String) -> Self {
        Greeter {
            name
        }
    }

    pub fn greet(self){
        let mut greeting: String = "Hello, ".to_owned();
        greeting.push_str(&self.name);
        alert(&greeting);
    }
}