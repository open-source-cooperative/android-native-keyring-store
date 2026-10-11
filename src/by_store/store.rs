use std::{collections::HashMap, sync::Arc};

use keyring_core::{Entry, Error, Result, api::CredentialStoreApi, attributes::parse_attributes};
use regex::{Error as RegexError, Regex};
use serde::{Deserialize, Serialize};

use super::Cred;
use super::vault::{AtomicVault, delete, exists, lookup};

/// The configurable parts of a Store.
///
/// It's serializable so that it can be kept
/// in the store's SharedPreferences file as a JSON string.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct StoreConfig {
    pub name: String,
    pub filename: String,
    pub divider: String,
    /// Seconds that one user authentication opens the store's key for, if it needs one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_auth_timeout: Option<u32>,
}

impl Default for StoreConfig {
    fn default() -> Self {
        StoreConfig {
            name: "default".to_string(),
            filename: "keyring-default".to_string(),
            divider: "\u{FEFF}@\u{FEFF}".to_string(),
            user_auth_timeout: None,
        }
    }
}

impl StoreConfig {
    /// Diff this config against another.
    ///
    /// If any fields differ, return an error naming one of the differences.
    pub fn diff(&self, other: &Self) -> Result<()> {
        if self.name != other.name {
            let msg = format!("doesn't match existing name {:?}", other.name);
            return Err(Error::Invalid("name".to_string(), msg));
        }
        if self.filename != other.filename {
            let msg = format!("doesn't match existing filename {:?}", other.filename);
            return Err(Error::Invalid("filename".to_string(), msg));
        }
        if self.divider != other.divider {
            let msg = format!("doesn't match existing divider {:?}", other.divider);
            return Err(Error::Invalid("divider".to_string(), msg));
        }
        if self.user_auth_timeout != other.user_auth_timeout {
            let msg = format!(
                "doesn't match existing user-auth-timeout {:?}",
                other.user_auth_timeout
            );
            return Err(Error::Invalid("user-auth-timeout".to_string(), msg));
        }
        Ok(())
    }

    /// Create a StoreConfig from a configuration HashMap
    pub fn from_configuration(configuration: &HashMap<&str, &str>) -> Result<Self> {
        let mods = parse_attributes(
            &[
                "+name",
                "+filename",
                "+divider",
                "*user-auth-required",
                "+user-auth-timeout",
            ],
            Some(configuration),
        )?;
        let mut config = StoreConfig::default();
        if let Some(name) = mods.get("name") {
            config.name = name.to_string();
        }
        if let Some(filename) = mods.get("filename") {
            config.filename = filename.to_string();
        } else {
            config.filename = format!("keyring-{}", config.name);
        }
        if let Some(divider) = mods.get("divider") {
            // Vault dividers must have a non-alphabetic character so that the
            // vault's config key is guaranteed not to match any credential's key.
            if config.divider.chars().all(char::is_alphanumeric) {
                let err = "must contain a non-alphabetic character".to_string();
                return Err(Error::Invalid("divider".to_string(), err));
            }
            config.divider = divider.to_string();
        }
        let required = mods.get("user-auth-required").is_some_and(|v| v == "true");
        let timeout_err = |msg: &str| Error::Invalid("user-auth-timeout".to_string(), msg.into());
        config.user_auth_timeout = match (required, mods.get("user-auth-timeout")) {
            (true, Some(timeout)) => Some(
                timeout
                    .parse::<u32>()
                    .ok()
                    .filter(|seconds| (1..=i32::MAX.unsigned_abs()).contains(seconds))
                    .ok_or_else(|| timeout_err("must be from 1 to 2147483647 seconds"))?,
            ),
            (true, None) => return Err(timeout_err("is required with user-auth-required")),
            (false, Some(_)) => return Err(timeout_err("requires user-auth-required")),
            (false, None) => None,
        };
        if required && config.name == "default" {
            let err = "must not be the default when user authentication is required";
            return Err(Error::Invalid("name".to_string(), err.to_string()));
        }
        Ok(config)
    }
}

/// A Store is a wrapper around a Vault
/// that keeps its configuration handy.
pub struct Store {
    pub id: String,
    pub config: StoreConfig,
    vault: AtomicVault,
}

impl std::fmt::Debug for Store {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Store")
            .field("vendor", &self.vendor())
            .field("id", &self.id)
            .field("config", &self.config)
            .finish()
    }
}

impl Store {
    /// Returns a store with the default configuration,
    /// creating one if necessary.
    pub fn new() -> Result<Arc<Self>> {
        let config = StoreConfig::default();
        Store::new_with_store_config(config)
    }

    /// Returns a store with the specified configuration,
    /// creating one if necessary.
    ///
    /// Allowed configuration keys are `name`, `filename`, `divider`, `user-auth-required`,
    /// and `user-auth-timeout`. None are required, but any that are supplied must be non-empty,
    /// and `user-auth-required` must be `true` or `false`.
    ///
    /// The value of `name` defaults to `default`. Stores names are unique, so you can't
    /// create two stores with the same name (even if they use different configurations).
    ///
    /// The value of `filename` defaults to `keyring-{name}`. Store filenames are unique,
    /// so you can't create two differently named stores with the same filename.
    ///
    /// The value of `divider` defaults to `\u{feff}@\u{feff}` which,
    /// when printed as part of a string, looks like `@` because
    /// the BOM character is considered a non-spacing word-joining
    /// character. The divider _must_ contain a non-alphabetic character.
    ///
    /// For `user-auth-required` and `user-auth-timeout`, see
    /// [the module docs](super#user-authentication).
    pub fn new_with_configuration(configuration: &HashMap<&str, &str>) -> Result<Arc<Self>> {
        let config = StoreConfig::from_configuration(configuration)?;
        Store::new_with_store_config(config)
    }

    /// Returns a store with the specified [StoreConfig],
    /// creating one if necessary.
    pub fn new_with_store_config(config: StoreConfig) -> Result<Arc<Self>> {
        let vault = lookup(&config)?;
        let id = generate_instance_id();
        Ok(Arc::new(Store { id, config, vault }))
    }

    /// Attempts to delete the store with the specified configuration.
    ///
    /// Physically deletes the underlying vault file and key, which
    /// in turn deletes all the contained credential information.
    ///
    /// Once a store is deleted, it cannot be recovered.
    ///
    /// A store whose Keystore key is gone can still be deleted.
    ///
    /// Vaults can't be deleted by a process that has previously
    /// used them to back a store. This would leave any existing
    /// credentials with no vault to back them.
    pub fn delete(configuration: &HashMap<&str, &str>) -> Result<bool> {
        let config = StoreConfig::from_configuration(configuration)?;
        delete(&config)
    }

    /// Reports whether a store with the specified configuration exists, without creating it or
    /// needing its Keystore key.
    ///
    /// `true` means the store is open or its file holds this configuration. Its Keystore key may
    /// still be gone, in which case opening it fails with [BadStoreFormat](Error::BadStoreFormat).
    ///
    /// `false` means there is no store file, or one without credentials whose key is gone.
    ///
    /// [BadStoreFormat](Error::BadStoreFormat) means the file at the configuration's filename is
    /// not a store, and [Invalid](Error::Invalid) means the store with this name has a different
    /// configuration.
    pub fn exists(configuration: &HashMap<&str, &str>) -> Result<bool> {
        let config = StoreConfig::from_configuration(configuration)?;
        exists(&config)
    }

    #[cfg(feature = "compile-tests")]
    pub fn change_key(&self) -> Result<()> {
        let vault = self
            .vault
            .lock()
            .expect("Vault lock poisoned: report a bug!");
        vault.change_key()
    }

    #[cfg(feature = "compile-tests")]
    pub fn remove_key(&self) -> Result<()> {
        let vault = self
            .vault
            .lock()
            .expect("Vault lock poisoned: report a bug!");
        vault.remove_key()
    }
}

impl CredentialStoreApi for Store {
    fn vendor(&self) -> String {
        "Android SharedPreferences/KeyStore, https://github.com/open-source-cooperative/android-native-keyring-store".to_string()
    }

    fn id(&self) -> String {
        self.id.clone()
    }

    /// See the API documentation for [CredentialStoreApi::build].
    ///
    /// No modifiers are allowed.
    ///
    /// The matching credential is identified by the string `{user}{divider}{service}`.
    /// The user and service values are not allowed to
    /// contain the divider string, so entries are never ambiguous.
    fn build(
        &self,
        service: &str,
        user: &str,
        modifiers: Option<&HashMap<&str, &str>>,
    ) -> Result<Entry> {
        let divider = &self.config.divider;
        if modifiers.is_some_and(|mods| !mods.is_empty()) {
            return Err(Error::NotSupportedByStore(
                "The Android native store doesn't allow entry modifiers".to_string(),
            ));
        }
        if service.contains(divider) {
            return Err(Error::Invalid(
                "service".to_string(),
                "cannot contain the divider".to_string(),
            ));
        }
        if user.contains(divider) {
            return Err(Error::Invalid(
                "user".to_string(),
                "cannot contain the divider".to_string(),
            ));
        }
        let id = format!("{user}{divider}{service}");
        log::debug!("Building entry {id:?} for ({service:?}, {user:?})");
        let credential = Cred::new_specifier(self.vault.clone(), &id, service, user);
        Ok(Entry::new_with_credential(Arc::new(credential)))
    }

    /// See the API documentation for [CredentialStoreApi::search].
    ///
    /// Allowed specifiers are `id`, `service`, and `user`, and their
    /// values must be valid regular expressions. The `user` and `service`
    /// expressions are matched against the user and service parts,
    /// respectively, of each credential's identifier. The `id` expression
    /// is matched against the entire credential identifier.
    ///
    /// The match used is a match-anywhere, case-sensitive, Unicode-aware match.
    /// Expressions must be in the syntax of the `regex` crate, documented
    /// [here](https://docs.rs/regex/latest/regex/#syntax), and can use sub-expressions to
    /// modify the case-sensitiviy or anchors to force a match of the entire string.
    ///
    /// If third parties have introduced entries into the store's
    /// SharedPreferences file that don't conform to credential ID
    /// conventions, they are ignored, as is the special entry
    /// used to hold the store's configuration.
    ///
    /// The wrappers returned by searches are all specifiers, so they
    /// can be queried for their user and service values.
    fn search(&self, spec: &HashMap<&str, &str>) -> Result<Vec<Entry>> {
        let spec_err = |key: &str, e: RegexError| {
            let msg = format!("invalid regexp: {}", e);
            Error::Invalid(key.to_string(), msg)
        };
        let spec = parse_attributes(&["id", "service", "user"], Some(spec))?;
        let id_spec = spec.get("id").cloned().unwrap_or_default();
        let id_exp = Regex::new(&id_spec).map_err(|e| spec_err("id", e))?;
        let service_spec = spec.get("service").cloned().unwrap_or_default();
        let service_exp = Regex::new(&service_spec).map_err(|e| spec_err("service", e))?;
        let user_spec = spec.get("user").cloned().unwrap_or_default();
        let user_exp = Regex::new(&user_spec).map_err(|e| spec_err("user", e))?;
        let vault = self
            .vault
            .lock()
            .expect("Vault lock poisoned: report a bug!");
        let mut results = Vec::new();
        let triples = vault.get_ids(&id_exp)?;
        for (id, service, user) in triples.iter() {
            if user_exp.is_match(user) && service_exp.is_match(service) {
                let credential = Cred::new_specifier(self.vault.clone(), id, service, user);
                results.push(Entry::new_with_credential(Arc::new(credential)));
            }
        }
        Ok(results)
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn debug_fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

fn generate_instance_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    let now = SystemTime::now();
    let elapsed = if now.lt(&UNIX_EPOCH) {
        UNIX_EPOCH.duration_since(now).unwrap()
    } else {
        now.duration_since(UNIX_EPOCH).unwrap()
    };

    format!(
        "One File per Store storage, Crate version {}, Instantiated at {}",
        env!("CARGO_PKG_VERSION"),
        elapsed.as_secs_f64()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(pairs: &[(&str, &str)]) -> Result<StoreConfig> {
        StoreConfig::from_configuration(&pairs.iter().copied().collect())
    }

    const NAME: (&str, &str) = ("name", "vault");
    const REQUIRED: (&str, &str) = ("user-auth-required", "true");

    fn assert_invalid(pairs: &[(&str, &str)], expected_key: &str) {
        match parse(pairs) {
            Err(Error::Invalid(key, _)) => assert_eq!(key, expected_key, "{pairs:?}"),
            other => panic!("{pairs:?}: expected Invalid({expected_key:?}), got {other:?}"),
        }
    }

    #[test]
    fn user_auth_timeout_needs_both_keys() {
        let config = parse(&[NAME, REQUIRED, ("user-auth-timeout", "30")]).unwrap();
        assert_eq!(config.user_auth_timeout, Some(30));
        let config = parse(&[NAME, ("user-auth-required", "false")]).unwrap();
        assert_eq!(config.user_auth_timeout, None);
        assert_invalid(&[NAME, REQUIRED], "user-auth-timeout");
        assert_invalid(&[NAME, ("user-auth-timeout", "30")], "user-auth-timeout");
        assert_invalid(&[REQUIRED, ("user-auth-timeout", "30")], "name");
    }

    #[test]
    fn user_auth_timeout_must_fit_the_keystore_range() {
        for timeout in ["0", "-1", "2147483648", "soon"] {
            assert_invalid(
                &[NAME, REQUIRED, ("user-auth-timeout", timeout)],
                "user-auth-timeout",
            );
        }
        let config = parse(&[NAME, REQUIRED, ("user-auth-timeout", "2147483647")]).unwrap();
        assert_eq!(config.user_auth_timeout, Some(2147483647));
    }

    #[test]
    fn stored_config_without_user_auth_keeps_its_earlier_format() {
        let stored = r#"{"name":"vault","filename":"keyring-vault","divider":"@"}"#;
        let config: StoreConfig = serde_json::from_str(stored).unwrap();
        assert_eq!(config.user_auth_timeout, None);
        assert_eq!(serde_json::to_string(&config).unwrap(), stored);
    }
}
