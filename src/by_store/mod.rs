/*!
# By-Store Credential Module

This module implements a keyring store where each store instance has its own dedicated vault
(backed by SharedPreferences and encrypted via Android KeyStore). It supports creating,
configuring, and managing credentials in each vault.

## Key Features
- **Isolated Stores**: Each store uses a unique filename for SharedPreferences.
- **Encryption**: Secrets are encrypted using AES/GCM/NoPadding with keys from Android KeyStore.
- **Thread-Safety**: Uses `Arc<Mutex<Vault>>` for concurrent access.
- **Configuration**: Customizable via `StoreConfig` (name, filename, divider).

## Usage
To create a new store:
```rust
use android_native_keyring_store::by_store::Store;
let store = Store::new().unwrap();
```

See individual type documentation for more details.
 */
mod vault;

pub mod store;
pub use store::Store;

pub mod cred;
pub use cred::Cred;
