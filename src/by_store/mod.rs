/*!
# Named Credential Stores

This module implements independent, named keyring credential stores. Each credential store
uses a SharedPreferences file for storage, encrypting the secret data stored in that file
via a key kept in the Android KeyStore.

## Storage Conventions

Clients provide a store name using the `name` configuration key, which defaults to `default`, and a SharedPreferences filename using `filename`, which defaults to `keyring-{name}`.

Store names are unique within an application storage domain, even when callers supply different application-context objects for that domain.

A store's filename is also its Keystore alias in both credential-protected and device-protected storage, so one filename names one store per application. Creating a store whose filename is already taken in the other storage domain fails with [BadStoreFormat](keyring_core::Error::BadStoreFormat).

Inside the store's SharedPreferences file, an entry's credential is identified by the
concatenation of the entry's user and service names with a store-specific divider string.
Clients can specify the divider string---which must contain at least one
non-alphanumeric character---using the `divider` configuration key. The divider string defaults to
`\u{feff}@\u{feff}` (that's an @-sign with a BOM character on both sides).

The store's name, filename, and divider string are kept in the store in a
SharedPreferences entry named by the key `vaultConfig`. Since dividers must contain non-alphanumeric
characters, and every credential's key contains the divider, there is no way the `vaultConfig`
entry can be confused with an entry's credential key.

Accessing a store's SharedPreference file directly is not recommended. To avoid
interactions with third-party software that might do so, store operations are careful to
ignore entries that don't look like they are credential IDs.

Creating a store whose file holds credentials but whose Keystore key is gone fails with
[BadStoreFormat](keyring_core::Error::BadStoreFormat), and deleting it removes the file.

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

Searches do not return entries in the SharedPreferences file
that don't conform to the credential naming conventions. These can
only have been added by third parties, so they are assumed
not to be valid credentials.

## User Authentication

With `user-auth-required` set to `true`, a store opens for `user-auth-timeout` seconds after the
user authenticates with a strong biometric or the device credential, and otherwise fails with
[NoStorageAccess](keyring_core::Error::NoStorageAccess). It needs a non-default `name`,
Android 11 and a secure lock screen, whose removal destroys its key.
 */
mod vault;
#[cfg(feature = "compile-tests")]
pub use vault::clear_vault_list;

/// The named store's [`Store`] type and its `StoreConfig`.
pub mod store;
pub use store::Store;

/// The named store's [`Cred`] credential type.
pub mod cred;
pub use cred::Cred;
