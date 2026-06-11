//! # TLS Key Exchange Interceptor
//!
//! This module intercepts TLS key exchange group negotiation to log the selected group.
//! Note: This is a temporary workaround for Quinn 0.11. Quinn 0.12 is expected to provide 
//! cleaner access to session parameters via redesigned crypto traits.

use rustls::crypto::{ActiveKeyExchange, SupportedKxGroup};
use rustls::NamedGroup;
use tracing::info;

#[derive(Debug)]
struct InterceptingKxGroup {
    inner: &'static dyn SupportedKxGroup,
}

impl SupportedKxGroup for InterceptingKxGroup {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange + 'static>, rustls::Error> {
        let group_name = self.inner.name();

        info!("TLS Key Exchange Group negotiated: {:?}", group_name);

        self.inner.start()
    }

    fn name(&self) -> NamedGroup {
        self.inner.name()
    }
}

pub fn install_intercept_provider() {
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();

    let mut wrapped_groups: Vec<&'static dyn SupportedKxGroup> = Vec::new();

    for group in provider.kx_groups {
        let wrapped = InterceptingKxGroup { inner: group };
        let leaked: &'static dyn SupportedKxGroup = Box::leak(Box::new(wrapped));
        wrapped_groups.push(leaked);
    }

    provider.kx_groups = wrapped_groups;

    match rustls::crypto::CryptoProvider::install_default(provider) {
        Ok(_) => {
            eprintln!("[TLS Intercept] Custom CryptoProvider installed successfully.");
        }
        Err(_) => {
            eprintln!("[TLS Intercept] ERROR: Failed to install custom CryptoProvider because a default was already installed!");
            eprintln!("[TLS Intercept] Hint: Call `install_intercept_provider()` at the absolute beginning of your `main` function (before any Quinn config or endpoints are touched).");
        }
    }
}