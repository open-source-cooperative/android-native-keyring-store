/*!
# By-Store Credential Module

This module implements independent, named keyring credential stores. Each credential store
uses a SharedPreferences file for storage, encrypting the secret data stored in that file
via a key kept in the Android KeyStore.

## Storage Conventions

Clients provide a name for each credential store using the `name` configuration key (value
`default` if not provided). The name of the store's SharedPreferences file (and the alias
for that store's Keystore entry) are derived from the store name by prefixing it with
`keyring-`. Clients can override this by specifying the filename directly with the
`filename` configuration key.

Inside the store's SharedPreferences file, an entry's credential is identified by the
concatenation of the entry's user and service names with a store-specific divider string.
Clients can specify the divider string---which must contain at least one
non-alphanumeric character---using the `divider` configuration key. The divider string defaults to
`\u{feff}@\u{feff}` (that's an @-sign with a BOM character on both sides).

The store's name, filename, and divider string are kept in the store in a
SharedPreferences entry named by the key `vaultConfig`. Since dividers must contain non-alphanumeric
characters, and every credential's key contains the divider, there is no way the `vaultConfig`
entry can be confused with an entry's credential key.

## Ambiguity

Stores do not allow either user or service names to contain the
store's divider string. This means that ambiguity is not possible.

## Attributes

Credentials do not have any attributes.

## Search

Users can search for credentials using regular expressions matched
against the credential's ID, its service value, and/or its user value.
The search matches anywhere in the respective strings, so use string
start and end anchors to match the entire string. A search with
no specification will return all the credentials in the store.

## Usage
To use the `default` store:
```rust
let store = Store::new().unwrap();
```

See individual type documentation for more details.
 */
mod vault;
#[cfg(feature = "compile_tests")]
pub use vault::clear_vault_list;

pub mod store;
pub use store::Store;

pub mod cred;
pub use cred::Cred;
