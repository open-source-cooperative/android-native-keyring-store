use std::sync::{Arc, Mutex};

use jni::{JNIEnv, JavaVM, objects::GlobalRef};
use keyring_core::{Error, Result};
use regex::Regex;

use crate::{
    error::AndroidKeyringResult,
    keystore::{
        BLOCK_MODE_GCM, ENCRYPTION_PADDING_NONE, KEY_ALGORITHM_AES, Key,
        KeyGenParameterSpecBuilder, KeyGenerator, KeyStore, PROVIDER, PURPOSE_DECRYPT,
        PURPOSE_ENCRYPT,
    },
    shared_preferences::{Context, MODE_PRIVATE, SharedPreferences},
};

use super::store::StoreConfig;

/// An AtomicVault is a [Vault] protected by a mutex.
///
/// Because vaults can be modified from multiple threads, they are
/// protected by a mutex. This mutex also serves to serialize access to the
/// credentials held in the vault. All accesses to the vault must be
/// performed through the mutex.
pub type AtomicVault = Arc<Mutex<Vault>>;

// Because multiple stores can access the same [AtomicVault], we keep a list
// of all the known vaults so we can look up the one a user is requesting.
static VAULTS: Mutex<Vec<AtomicVault>> = Mutex::new(Vec::new());

/// Look up a vault by name, creating it if it doesn't exist.
///
/// If an existing vault with that name has a different config, return
/// an error naming one of the differences.
pub fn lookup(config: &StoreConfig) -> Result<AtomicVault> {
    log::debug!("Looking up vault with config: {:?}", config);
    let mut vaults = VAULTS
        .lock()
        .expect("Vaults list lock poisoned: report a bug!");
    // first check the list of instantiated vaults for a matching name
    if let Some(vault) = in_use(&vaults, config)? {
        log::debug!("Found already-in-use vault {:?}", config.name);
        return Ok(vault.clone());
    }
    // next look for or create a matching vault with the same filename
    let vault = match Vault::find(config)? {
        (Found::Present, vault) => {
            log::debug!("Found existing-but-not-in-use vault {:?}", config.name);
            vault
        }
        (Found::KeyLost, _) => {
            return Err(Error::BadStoreFormat(format!(
                "Keystore key {:?} is missing",
                config.filename
            )));
        }
        (Found::Absent, _) => {
            log::debug!("Creating new vault {:?}", config.name);
            Vault::new(config)?
        }
    };
    let atomic_vault = Arc::new(Mutex::new(vault));
    vaults.push(atomic_vault.clone());
    Ok(atomic_vault)
}

/// Delete a vault by name. Returns whether any vault was actually deleted.
///
/// If there is a vault with a matching name but a different config, return an error.
///
/// If the matching vault is in use, return an error.
pub fn delete(config: &StoreConfig) -> Result<bool> {
    log::debug!("Deleting vault with config: {:?}", config);
    let vaults = VAULTS
        .lock()
        .expect("Vaults list lock poisoned: report a bug!");
    if in_use(&vaults, config)?.is_some() {
        log::debug!("Found already-in-use vault for {}", config.name);
        return Err(Error::NotSupportedByStore("Store is in use".to_string()));
    }
    match Vault::find(config)? {
        (Found::Present, vault) => {
            log::debug!("Found existing vault to delete for {}", config.name);
            vault.delete()?;
            Ok(true)
        }
        (Found::KeyLost, vault) => {
            log::debug!("Deleting file of vault {} whose key is gone", config.name);
            if !vault.with_env(|env| vault.delete_file(env))? {
                log::warn!("Failed to find file {:?}", config.filename);
            }
            Ok(true)
        }
        (Found::Absent, _) => {
            log::debug!("No existing vault found to delete");
            Ok(false)
        }
    }
}

/// Whether a vault exists, without creating it or needing its key.
pub fn exists(config: &StoreConfig) -> Result<bool> {
    let vaults = VAULTS
        .lock()
        .expect("Vaults list lock poisoned: report a bug!");
    if in_use(&vaults, config)?.is_some() {
        return Ok(true);
    }
    let (found, _) = Vault::find(config)?;
    Ok(!matches!(found, Found::Absent))
}

/// The instantiated vault with this config's name, which must have the same config.
fn in_use<'a>(vaults: &'a [AtomicVault], config: &StoreConfig) -> Result<Option<&'a AtomicVault>> {
    for vault in vaults {
        let guard = vault.lock().expect("Vault lock poisoned: report a bug!");
        if config.name == guard.config.name {
            config.diff(&guard.config)?;
            return Ok(Some(vault));
        }
    }
    Ok(None)
}

#[cfg(feature = "compile-tests")]
pub fn clear_vault_list() {
    VAULTS
        .lock()
        .expect("Vaults list lock poisoned: report a bug!")
        .clear();
}

/// A Vault holds credentials securely in a single SharedPreferences file.
///
/// There is an associated key in the Android Keystore that encrypts credential secrets.
pub struct Vault {
    vm: Arc<JavaVM>,
    context: GlobalRef,
    config: StoreConfig,
}

impl std::fmt::Debug for Vault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vault")
            .field("config", &self.config)
            .finish()
    }
}

const CONFIG_KEY: &str = "vaultConfig";

/// The result of [Vault::find].
#[derive(Clone, Copy)]
enum Found {
    Absent,
    Present,
    /// The file holds credentials but the Keystore key is gone.
    KeyLost,
}

impl Vault {
    // Find an existing vault with the same name and config
    fn find(config: &StoreConfig) -> Result<(Found, Self)> {
        let (vm, context) = crate::android_context()?;
        let vault = Self {
            vm,
            context,
            config: config.clone(),
        };
        let found = vault.with_env(|env| {
            let file = vault.get_file(env)?;
            let Some(config_val) = file.get_string(env, CONFIG_KEY)? else {
                return Ok(Found::Absent);
            };
            let existing = serde_json::from_str::<StoreConfig>(&config_val)
                .map_err(|_| Error::BadStoreFormat("Invalid configuration".to_string()))?;
            config.diff(&existing)?;
            if vault.find_key(env)?.is_none() {
                // A keyless file without credentials loses nothing, so it counts as absent.
                let keys = file.get_all(env)?.get_keys(env)?;
                return Ok(if keys.iter().any(|key| vault.split_id(key).is_some()) {
                    Found::KeyLost
                } else {
                    Found::Absent
                });
            }
            Ok(Found::Present)
        })?;
        Ok((found, vault))
    }

    fn new(config: &StoreConfig) -> Result<Self> {
        // Vault dividers must have a non-alphabetic character so that the
        // vault's config key is guaranteed not to match any credential's key.
        if config.divider.chars().all(char::is_alphanumeric) {
            let err = "must contain a non-alphabetic character".to_string();
            return Err(Error::Invalid("divider".to_string(), err));
        }
        log::debug!("Creating new vault with config {config:?}");
        let (vm, context) = crate::android_context()?;
        let mut vault = Self {
            vm,
            context,
            config: config.clone(),
        };
        vault.initialize_config()?;
        vault.initialize_key()?;
        Ok(vault)
    }

    fn initialize_config(&mut self) -> Result<()> {
        // Vaults contain a special unencrypted value whose key
        // is guaranteed not to match any encrypted credential's key
        // (because it's alphabetic and thus can't contain a delimiter).
        let config_value = serde_json::to_string(&self.config).unwrap();
        self.with_env(|env| {
            let file = self.get_file(env)?;
            let editor = file.edit(env)?;
            editor.put_string(env, CONFIG_KEY, &config_value)?;
            editor.commit(env)?;
            Ok(())
        })?;
        Ok(())
    }

    fn initialize_key(&mut self) -> Result<()> {
        self.with_env(|env| {
            self.create_key(env)?;
            Ok(())
        })?;
        Ok(())
    }

    /// Deletes the vault, which better not be in use!
    fn delete(&self) -> Result<()> {
        log::debug!("Deleting vault with config {:?}", self.config);
        self.with_env(|env| {
            self.delete_key(env)?;
            if !self.delete_file(env)? {
                log::warn!("Failed to find file {:?}", self.config.filename);
            }
            Ok(())
        })?;
        Ok(())
    }

    /// Find all credentials whose ids match a given regular expression, returning
    /// the triple (id, service, user) for each matching credential.
    pub fn get_ids(&self, re: &Regex) -> Result<Vec<(String, String, String)>> {
        let mut ids = Vec::new();
        self.with_env(|env| {
            let file = self.get_file(env)?;
            let keys = file.get_all(env)?.get_keys(env)?;
            for key in keys {
                if let Some((user, service)) = self.split_id(&key)
                    && re.is_match(&key)
                {
                    ids.push((key.clone(), service.to_string(), user.to_string()));
                }
            }
            Ok(())
        })?;
        Ok(ids)
    }

    /// The (user, service) of a credential ID, which has exactly one divider.
    fn split_id<'a>(&self, id: &'a str) -> Option<(&'a str, &'a str)> {
        let divider = &self.config.divider;
        id.split_once(divider)
            .filter(|(_, service)| !service.contains(divider))
    }

    #[cfg(feature = "compile-tests")]
    pub fn change_key(&self) -> Result<()> {
        self.with_env(|env| {
            self.delete_key(env)?;
            self.create_key(env)?;
            Ok(())
        })?;
        Ok(())
    }

    #[cfg(feature = "compile-tests")]
    pub fn remove_key(&self) -> Result<()> {
        self.with_env(|env| self.delete_key(env))?;
        Ok(())
    }
}

static KEY_SERVICE_LOCK: Mutex<()> = Mutex::new(());

impl Vault {
    pub fn with_env<T, F>(&self, f: F) -> AndroidKeyringResult<T>
    where
        F: FnOnce(&mut JNIEnv) -> AndroidKeyringResult<T>,
    {
        let mut env = self.vm.attach_current_thread()?;
        let result = f(&mut env);
        if env.exception_check()? {
            log::error!("Exception in vault {:?}: see console", self.config.name);
            env.exception_describe()?;
            env.exception_clear()?;
        }
        result
    }

    pub fn with_key_and_file<T, F>(&self, f: F) -> AndroidKeyringResult<T>
    where
        F: FnOnce(&mut JNIEnv, Key, SharedPreferences) -> AndroidKeyringResult<T>,
    {
        let wrapper = |env: &mut JNIEnv| -> AndroidKeyringResult<T> {
            let key = self.get_key(env)?;
            let file = self.get_file(env)?;
            f(env, key, file)
        };
        self.with_env(wrapper)
    }

    fn create_key(&self, env: &mut JNIEnv) -> AndroidKeyringResult<Key> {
        let _lock = KEY_SERVICE_LOCK
            .lock()
            .expect("Key service lock poisoned: report a bug!");
        let keystore = KeyStore::get_instance(env, PROVIDER)?;
        keystore.load(env)?;
        if keystore.contains_alias(env, &self.config.filename)? {
            let err = "Encryption key already exists";
            return Err(Error::BadStoreFormat(err.to_string()).into());
        }
        let key_generator_spec = KeyGenParameterSpecBuilder::new(
            env,
            &self.config.filename,
            PURPOSE_DECRYPT | PURPOSE_ENCRYPT,
        )?
        .set_block_modes(env, &[BLOCK_MODE_GCM])?
        .set_encryption_paddings(env, &[ENCRYPTION_PADDING_NONE])?
        .set_user_authentication_required(env, false)?
        .build(env)?;
        let key_generator = KeyGenerator::get_instance(env, KEY_ALGORITHM_AES, PROVIDER)?;
        key_generator.init(env, key_generator_spec.into())?;
        let key = key_generator.generate_key(env)?;
        Ok(key.into())
    }

    fn get_key(&self, env: &mut JNIEnv) -> AndroidKeyringResult<Key> {
        self.find_key(env)?
            .ok_or_else(|| Error::BadStoreFormat("Encryption key not found".to_string()).into())
    }

    fn find_key(&self, env: &mut JNIEnv) -> AndroidKeyringResult<Option<Key>> {
        let _lock = KEY_SERVICE_LOCK
            .lock()
            .expect("Key service lock poisoned: report a bug!");
        let keystore = KeyStore::get_instance(env, PROVIDER)?;
        keystore.load(env)?;
        Ok(keystore.get_key(env, &self.config.filename)?)
    }

    fn delete_key(&self, env: &mut JNIEnv) -> AndroidKeyringResult<()> {
        log::debug!("Deleting key for {:?}", self.config.filename);
        let _lock = KEY_SERVICE_LOCK
            .lock()
            .expect("Key service lock poisoned: report a bug!");
        let keystore = KeyStore::get_instance(env, PROVIDER)?;
        keystore.load(env)?;
        keystore.delete_entry(env, &self.config.filename)?;
        Ok(())
    }

    pub fn get_file(&self, env: &mut JNIEnv) -> AndroidKeyringResult<SharedPreferences> {
        let ctx = Context::from_raw(self.context.clone());
        Ok(ctx.get_shared_preferences(env, &self.config.filename, MODE_PRIVATE)?)
    }

    pub fn delete_file(&self, env: &mut JNIEnv) -> AndroidKeyringResult<bool> {
        log::debug!("Deleting file for {:?}", self.config.filename);
        let ctx = Context::from_raw(self.context.clone());
        Ok(ctx.delete_shared_preferences(env, &self.config.filename)?)
    }
}
