/// The backend model
pub mod model;

/// Contains a backend for performing operations on curve points. Uses libsecp256k1.
#[cfg(all(feature = "libsecp", not(feature = "rust-secp")))]
pub mod libsecp;

/// Contains a backend for performing operations on curve points. Uses rust secp256k1.
#[cfg(all(feature = "rust-secp", not(feature = "libsecp")))]
pub mod rust_secp;

pub use model::*;

#[cfg(all(feature = "rust-secp", not(feature = "libsecp")))]
pub use rust_secp as backend;

#[cfg(all(feature = "libsecp", not(feature = "rust-secp")))]
pub use libsecp as backend;

#[cfg(any(feature = "libsecp", feature = "rust-secp"))]
pub use backend::*;
