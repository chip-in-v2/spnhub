//! # TLS Key Exchange Interceptor
//!
//! This module intercepts TLS key exchange group negotiation to log the selected group.
//! Note: This is a temporary workaround for Quinn 0.11. Quinn 0.12 is expected to provide 
//! cleaner access to session parameters via redesigned crypto traits.

use rustls::crypto::{ActiveKeyExchange, SupportedKxGroup};
use rustls::NamedGroup;
use tracing::info;

/// Wrapper to hook key exchange and log the result.
#[derive(Debug)]
struct InterceptingKxGroup {
    inner: &'static dyn SupportedKxGroup,
}

impl SupportedKxGroup for InterceptingKxGroup {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange + 'static>, rustls::Error> {
        // Log the negotiated group immediately upon selection.
        info!("TLS Key Exchange Group negotiated: {:?}", self.inner.name());
        self.inner.start()
    }

    fn name(&self) -> NamedGroup {
        self.inner.name()
    }
}

/// Installs a provider that wraps all default KX groups. Call once during initialization.
pub fn install_intercept_provider() {
    let mut provider = rustls::crypto::ring::default_provider();
    
    let mut wrapped_groups: Vec<&'static dyn SupportedKxGroup> = Vec::new();
    
    // Wrap existing KX groups and leak them to satisfy 'static lifetime.
    for group in provider.kx_groups {
        let wrapped = InterceptingKxGroup { inner: group };
        let leaked: &'static dyn SupportedKxGroup = Box::leak(Box::new(wrapped));
        wrapped_groups.push(leaked);
    }
    
    provider.kx_groups = wrapped_groups;
    
    // Register as the default crypto provider.
    let _ = rustls::crypto::CryptoProvider::install_default(provider);
}