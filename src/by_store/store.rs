use super::Cred;
use keyring_core::{Entry, Error, Result, api::CredentialStoreApi, attributes::parse_attributes};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Arc};

use super::vault::{AtomicVault, delete, lookup};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoreConfig {
    pub name: String,
    pub filename: String,
    pub divider: String,
}

impl Default for StoreConfig {
    fn default() -> Self {
        StoreConfig {
            name: "default".to_string(),
            filename: "keyring-default".to_string(),
            divider: "\u{FEFF}@\u{FEFF}".to_string(),
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
        Ok(())
    }

    pub fn from_configuration(configuration: &HashMap<&str, &str>) -> Result<Self> {
        let mods = parse_attributes(&["+name", "+filename", "+divider"], Some(configuration))?;
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
            if config.divider.chars().all(char::is_alphabetic) {
                let err = "must contain a non-alphabetic character".to_string();
                return Err(Error::Invalid("divider".to_string(), err));
            }
            config.divider = divider.to_string();
        }
        Ok(config)
    }
}

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
    pub fn new() -> Result<Arc<Self>> {
        let config = StoreConfig::default();
        Store::new_with_store_config(config)
    }

    pub fn new_with_configuration(configuration: &HashMap<&str, &str>) -> Result<Arc<Self>> {
        let config = StoreConfig::from_configuration(configuration)?;
        Store::new_with_store_config(config)
    }

    pub fn new_with_store_config(config: StoreConfig) -> Result<Arc<Self>> {
        let vault = lookup(&config)?;
        let id = generate_instance_id();
        Ok(Arc::new(Store { id, config, vault }))
    }

    pub fn delete(configuration: &HashMap<&str, &str>) -> Result<bool> {
        let config = StoreConfig::from_configuration(configuration)?;
        delete(&config)
    }

    #[cfg(feature = "compile_tests")]
    pub fn change_key(&self) -> Result<()> {
        let vault = self
            .vault
            .lock()
            .expect("Vault lock poisoned: report a bug!");
        vault.change_key()
    }
}

impl CredentialStoreApi for Store {
    fn vendor(&self) -> String {
        "Android SharedPreferences/KeyStore, https://github.com/open-source-cooperative/android-native-keyring-store".to_string()
    }

    fn id(&self) -> String {
        self.id.clone()
    }

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
        let credential = Cred::new_specifier(self.vault.clone(), id, service, user);
        Ok(Entry::new_with_credential(Arc::new(credential)))
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
