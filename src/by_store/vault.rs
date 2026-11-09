use std::sync::{Arc, Mutex};

use jni::{
    JNIEnv,
    objects::{GlobalRef, JObject},
};
use keyring_core::{Error, Result};
use regex::Regex;

use crate::{
    AndroidContext,
    cipher::Cipher,
    crypto::{decryption_cipher, encryption_cipher, seal, unseal},
    error::{AndroidKeyringError, AndroidKeyringResult},
    keystore::{
        AUTH_BIOMETRIC_STRONG, AUTH_DEVICE_CREDENTIAL, BLOCK_MODE_GCM, ENCRYPTION_PADDING_NONE,
        KEY_ALGORITHM_AES, Key, KeyGenParameterSpecBuilder, KeyGenerator, KeyStore, PROVIDER,
        PURPOSE_DECRYPT, PURPOSE_ENCRYPT, SecretKeySpec, is_expired_timeout,
    },
    methods::ClassDecl,
    shared_preferences::{
        MODE_PRIVATE, SharedPreferences, delete_shared_preferences, get_shared_preferences,
    },
    throwable::Throwable,
};

use super::store::StoreConfig;

/// An AtomicVault is a [Vault] protected by a mutex.
///
/// Because vaults can be modified from multiple threads, they are
/// protected by a mutex. This mutex also serves to serialize access to the
/// credentials held in the vault. All accesses to the vault must be
/// performed through the mutex.
pub(crate) type AtomicVault = Arc<Mutex<Vault>>;

// Because multiple stores can access the same [AtomicVault], we keep a list
// of all the known vaults so we can look up the one a user is requesting.
static VAULTS: Mutex<Vec<AtomicVault>> = Mutex::new(Vec::new());

/// Look up a vault by name, creating it if it doesn't exist.
///
/// If an existing vault with that name has a different config, return
/// an error naming one of the differences.
pub(crate) fn lookup(context: AndroidContext, config: &StoreConfig) -> Result<AtomicVault> {
    log::debug!("Looking up vault with config: {:?}", config);
    let mut vaults = VAULTS
        .lock()
        .expect("Vaults list lock poisoned: report a bug!");
    // first check the list of instantiated vaults for a matching name
    if let Some(vault) = in_use(&vaults, &context, config)? {
        log::debug!("Found already-in-use vault {:?}", config.name);
        return Ok(vault.clone());
    }
    // next look for or create a matching vault with the same filename
    match find(&context, config)? {
        Found::Present => {
            log::debug!("Found existing-but-not-in-use vault {:?}", config.name);
        }
        Found::KeyLost => {
            return Err(Error::BadStoreFormat(format!(
                "Keystore key {:?} is missing",
                config.filename
            )));
        }
        Found::Absent => {
            log::debug!("Creating new vault {:?}", config.name);
            initialize(&context, config)?;
        }
    };
    let atomic_vault = Arc::new(Mutex::new(Vault {
        context,
        config: config.clone(),
        unlock: Unlock::Locked,
    }));
    vaults.push(atomic_vault.clone());
    Ok(atomic_vault)
}

/// Delete a vault by name. Returns whether any vault was actually deleted.
///
/// If there is a vault with a matching name but a different config, return an error.
///
/// If the matching vault is in use, return an error.
pub(crate) fn delete(context: &AndroidContext, config: &StoreConfig) -> Result<bool> {
    log::debug!("Deleting vault with config: {:?}", config);
    let vaults = VAULTS
        .lock()
        .expect("Vaults list lock poisoned: report a bug!");
    if in_use(&vaults, context, config)?.is_some() {
        log::debug!("Found already-in-use vault for {}", config.name);
        return Err(Error::NotSupportedByStore("Store is in use".to_string()));
    }
    let found = find(context, config)?;
    if matches!(found, Found::Absent) {
        log::debug!("No existing vault found to delete");
        return Ok(false);
    }
    with_env(context, config, |env| {
        if matches!(found, Found::Present) {
            delete_key(env, &config.filename)?;
        }
        if !delete_file(env, context, &config.filename)? {
            log::warn!("Failed to find file {:?}", config.filename);
        }
        Ok(())
    })?;
    Ok(true)
}

/// Whether a vault exists, without creating it or needing its key.
pub(crate) fn exists(context: &AndroidContext, config: &StoreConfig) -> Result<bool> {
    let vaults = VAULTS
        .lock()
        .expect("Vaults list lock poisoned: report a bug!");
    if in_use(&vaults, context, config)?.is_some() {
        return Ok(true);
    }
    Ok(!matches!(find(context, config)?, Found::Absent))
}

/// The instantiated vault with this config's name, which must have the same config.
fn in_use<'a>(
    vaults: &'a [AtomicVault],
    context: &AndroidContext,
    config: &StoreConfig,
) -> Result<Option<&'a AtomicVault>> {
    for vault in vaults {
        let guard = vault.lock().expect("Vault lock poisoned: report a bug!");
        if context.same_storage(&guard.context) && config.name == guard.config.name {
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
/// There is an associated key in the Android Keystore that encrypts credential secrets,
/// or, when that key needs an approval per use, wraps a data key that encrypts them.
pub struct Vault {
    context: AndroidContext,
    config: StoreConfig,
    unlock: Unlock,
}

/// How far a vault whose key needs an approval per use is unlocked.
enum Unlock {
    Locked,
    /// `cipher` unwraps `sealed` once approved, or wraps a new data key when that's `None`.
    Pending {
        cipher: Cipher,
        sealed: Option<Vec<u8>>,
    },
    Unlocked(Key),
}

impl std::fmt::Debug for Vault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vault")
            .field("config", &self.config)
            .finish()
    }
}

const CONFIG_KEY: &str = "vaultConfig";
const USER_NOT_AUTHENTICATED: ClassDecl =
    ClassDecl("Landroid/security/keystore/UserNotAuthenticatedException;");
const AEAD_BAD_TAG: ClassDecl = ClassDecl("Ljavax/crypto/AEADBadTagException;");
// Alphabetic like CONFIG_KEY, so it never matches a credential's key.
const DATA_KEY_KEY: &str = "vaultDataKey";
const DATA_KEY_BITS: i32 = 256;

/// The result of [find].
#[derive(Clone, Copy)]
enum Found {
    Absent,
    Present,
    /// The file holds credentials but the Keystore key is gone.
    KeyLost,
}

fn find(context: &AndroidContext, config: &StoreConfig) -> Result<Found> {
    Ok(with_env(context, config, |env| {
        let file = get_file(env, context, &config.filename)?;
        let Some(config_val) = file.get_string(env, CONFIG_KEY)? else {
            return Ok(Found::Absent);
        };
        let existing = serde_json::from_str::<StoreConfig>(&config_val)
            .map_err(|_| Error::BadStoreFormat("Invalid configuration".to_string()))?;
        config.diff(&existing)?;
        if find_key(env, &config.filename)?.is_none() {
            // A keyless file without credentials loses nothing, so it counts as absent.
            let keys = file.get_all(env)?.get_keys(env)?;
            return Ok(if keys.iter().any(|key| split_id(config, key).is_some()) {
                Found::KeyLost
            } else {
                Found::Absent
            });
        }
        Ok(Found::Present)
    })?)
}

fn initialize(context: &AndroidContext, config: &StoreConfig) -> Result<()> {
    // A non-alphanumeric divider separates credential keys from the config key.
    if config.divider.chars().all(char::is_alphanumeric) {
        let err = "must contain a non-alphanumeric character".to_string();
        return Err(Error::Invalid("divider".to_string(), err));
    }
    let config_value = serde_json::to_string(config).unwrap();
    with_env(context, config, |env| {
        // Refuse before writing, because both storage domains share Keystore key names.
        if find_key(env, &config.filename)?.is_some() {
            let err = "Encryption key already exists";
            return Err(Error::BadStoreFormat(err.to_string()).into());
        }
        let file = get_file(env, context, &config.filename)?;
        let editor = file.edit(env)?;
        editor.put_string(env, CONFIG_KEY, &config_value)?;
        editor.commit(env)?;
        Ok(())
    })?;
    with_env(context, config, |env| {
        create_key(env, context, config)?;
        Ok(())
    })?;
    Ok(())
}

fn split_id<'a>(config: &StoreConfig, id: &'a str) -> Option<(&'a str, &'a str)> {
    let divider = &config.divider;
    id.split_once(divider)
        .filter(|(_, service)| !service.contains(divider))
}

impl Vault {
    /// Find all credentials whose ids match a given regular expression, returning
    /// the triple (id, service, user) for each matching credential.
    pub fn get_ids(&self, re: &Regex) -> Result<Vec<(String, String, String)>> {
        let mut ids = Vec::new();
        self.with_env(|env| {
            let file = self.get_file(env)?;
            let keys = file.get_all(env)?.get_keys(env)?;
            for key in keys {
                if let Some((user, service)) = split_id(&self.config, &key)
                    && re.is_match(&key)
                {
                    ids.push((key.clone(), service.to_string(), user.to_string()));
                }
            }
            Ok(())
        })?;
        Ok(ids)
    }

    /// Fails while a vault whose key needs an approval per use is not unlocked.
    fn check_unlocked(&self) -> AndroidKeyringResult<()> {
        if self.config.user_auth_timeout == Some(0) && !matches!(self.unlock, Unlock::Unlocked(_)) {
            return Err(AndroidKeyringError::UserNotAuthenticated);
        }
        Ok(())
    }

    /// Locks the vault and returns a cipher for the user to approve and [Vault::finish_unlock].
    pub fn begin_unlock(&mut self) -> Result<GlobalRef> {
        self.check_zero_timeout()?;
        self.unlock = Unlock::Locked;
        let (cipher, sealed) = self.with_env(|env| {
            let key = self.get_key(env)?;
            match self.get_file(env)?.get_binary(env, DATA_KEY_KEY)? {
                Some(sealed) => Ok((decryption_cipher(env, &key, &sealed)?, Some(sealed))),
                None => Ok((encryption_cipher(env, &key)?, None)),
            }
        })?;
        let object = cipher.object().clone();
        self.unlock = Unlock::Pending { cipher, sealed };
        Ok(object)
    }

    /// Unlocks the vault with the approved cipher from the latest [Vault::begin_unlock].
    pub fn finish_unlock(&mut self, approved: &JObject) -> Result<()> {
        self.check_zero_timeout()?;
        let not_latest = || {
            let err = "is not the one from the latest unlock".to_string();
            Error::Invalid("cipher".to_string(), err)
        };
        let Unlock::Pending { cipher, sealed } =
            std::mem::replace(&mut self.unlock, Unlock::Locked)
        else {
            return Err(not_latest());
        };
        let data_key = self.with_env(|env| {
            if !env.is_same_object(cipher.object(), approved)? {
                return Err(not_latest().into());
            }
            let Some(sealed) = sealed else {
                let generator = KeyGenerator::get_default_instance(env, KEY_ALGORITHM_AES)?;
                generator.init_key_size(env, DATA_KEY_BITS)?;
                let data_key = generator.generate_key(env)?;
                let bytes = data_key.get_encoded(env)?;
                let sealed = seal(env, &cipher, &bytes)
                    .map_err(|_| AndroidKeyringError::UserNotAuthenticated)?;
                let editor = self.get_file(env)?.edit(env)?;
                editor.put_binary(env, DATA_KEY_KEY, &sealed)?.commit(env)?;
                return Ok(data_key.into());
            };
            let bytes = match unseal(env, &cipher, sealed) {
                Ok(bytes) => bytes,
                // A tag mismatch means corrupt data, any other failure an unapproved cipher.
                Err(e) => match Throwable::take_pending(env)? {
                    Some(exception) if exception.is_instance_of(env, AEAD_BAD_TAG)? => {
                        return Err(e);
                    }
                    _ => return Err(AndroidKeyringError::UserNotAuthenticated),
                },
            };
            Ok(SecretKeySpec::new(env, &bytes, KEY_ALGORITHM_AES)?.into())
        })?;
        self.unlock = Unlock::Unlocked(data_key);
        Ok(())
    }

    /// Locks the vault until the next [Vault::finish_unlock].
    pub fn lock(&mut self) -> Result<()> {
        self.check_zero_timeout()?;
        self.unlock = Unlock::Locked;
        Ok(())
    }

    fn check_zero_timeout(&self) -> Result<()> {
        if self.config.user_auth_timeout != Some(0) {
            let err = "Only stores with a user-auth-timeout of 0 are unlocked and locked";
            return Err(Error::NotSupportedByStore(err.to_string()));
        }
        Ok(())
    }

    #[cfg(feature = "compile-tests")]
    pub fn change_key(&self) -> Result<()> {
        self.with_env(|env| {
            delete_key(env, &self.config.filename)?;
            create_key(env, &self.context, &self.config)?;
            Ok(())
        })?;
        Ok(())
    }

    #[cfg(feature = "compile-tests")]
    pub fn remove_key(&self) -> Result<()> {
        self.with_env(|env| delete_key(env, &self.config.filename))?;
        Ok(())
    }
}

static KEY_SERVICE_LOCK: Mutex<()> = Mutex::new(());

impl Vault {
    pub fn with_env<T, F>(&self, f: F) -> AndroidKeyringResult<T>
    where
        F: FnOnce(&mut JNIEnv) -> AndroidKeyringResult<T>,
    {
        with_env(&self.context, &self.config, f)
    }

    pub fn with_key_and_file<T, F>(&self, f: F) -> AndroidKeyringResult<T>
    where
        F: FnOnce(&mut JNIEnv, Key, SharedPreferences) -> AndroidKeyringResult<T>,
    {
        let wrapper = |env: &mut JNIEnv| -> AndroidKeyringResult<T> {
            self.check_unlocked()?;
            let key = match &self.unlock {
                Unlock::Unlocked(data_key) => data_key.clone(),
                _ => self.get_key(env)?,
            };
            let file = self.get_file(env)?;
            f(env, key, file)
        };
        self.with_env(wrapper)
    }

    fn get_key(&self, env: &mut JNIEnv) -> AndroidKeyringResult<Key> {
        find_key(env, &self.config.filename)?
            .ok_or_else(|| Error::BadStoreFormat("Encryption key not found".to_string()).into())
    }

    pub fn get_file(&self, env: &mut JNIEnv) -> AndroidKeyringResult<SharedPreferences> {
        get_file(env, &self.context, &self.config.filename)
    }
}

fn with_env<T>(
    context: &AndroidContext,
    config: &StoreConfig,
    f: impl FnOnce(&mut JNIEnv) -> AndroidKeyringResult<T>,
) -> AndroidKeyringResult<T> {
    let mut env = context.inner.vm.attach_current_thread()?;
    let result = f(&mut env);
    if let Some(exception) = Throwable::take_pending(&mut env)? {
        log::error!("Exception in vault {:?}: see console", config.name);
        if exception.is_instance_of(&mut env, USER_NOT_AUTHENTICATED)?
            || (config.user_auth_timeout.is_some() && is_expired_timeout(&mut env, &exception))
        {
            return Err(AndroidKeyringError::UserNotAuthenticated);
        }
    }
    result
}

fn create_key(
    env: &mut JNIEnv,
    context: &AndroidContext,
    config: &StoreConfig,
) -> AndroidKeyringResult<Key> {
    let alias = &config.filename;
    let _lock = KEY_SERVICE_LOCK
        .lock()
        .expect("Key service lock poisoned: report a bug!");
    let keystore = KeyStore::get_instance(env, PROVIDER)?;
    keystore.load(env)?;
    if keystore.contains_alias(env, alias)? {
        let err = "Encryption key already exists";
        return Err(Error::BadStoreFormat(err.to_string()).into());
    }
    let mut builder =
        KeyGenParameterSpecBuilder::new(env, alias, PURPOSE_DECRYPT | PURPOSE_ENCRYPT)?
            .set_block_modes(env, &[BLOCK_MODE_GCM])?
            .set_encryption_paddings(env, &[ENCRYPTION_PADDING_NONE])?
            .set_user_authentication_required(env, config.user_auth_timeout.is_some())?;
    if let Some(seconds) = config.user_auth_timeout {
        let seconds = i32::try_from(seconds).map_err(|_| {
            Error::Invalid("user-auth-timeout".to_string(), "is too large".to_string())
        })?;
        // Device credentials keep the key valid when fingerprints are re-enrolled.
        let authenticators = AUTH_BIOMETRIC_STRONG | AUTH_DEVICE_CREDENTIAL;
        builder = builder.set_user_authentication_parameters(env, seconds, authenticators)?;
    }
    let key_generator_spec = builder.build(env)?;
    let key_generator = KeyGenerator::get_instance(env, KEY_ALGORITHM_AES, PROVIDER)?;
    key_generator.init(env, key_generator_spec.into())?;
    let key = key_generator.generate_key(env)?;
    // A data key sealed by an earlier Keystore key can never be unsealed again.
    let editor = get_file(env, context, &config.filename)?.edit(env)?;
    editor.remove(env, DATA_KEY_KEY)?.commit(env)?;
    Ok(key.into())
}

fn find_key(env: &mut JNIEnv, alias: &str) -> AndroidKeyringResult<Option<Key>> {
    let _lock = KEY_SERVICE_LOCK
        .lock()
        .expect("Key service lock poisoned: report a bug!");
    let keystore = KeyStore::get_instance(env, PROVIDER)?;
    keystore.load(env)?;
    Ok(keystore.get_key(env, alias)?)
}

fn delete_key(env: &mut JNIEnv, alias: &str) -> AndroidKeyringResult<()> {
    log::debug!("Deleting key for {:?}", alias);
    let _lock = KEY_SERVICE_LOCK
        .lock()
        .expect("Key service lock poisoned: report a bug!");
    let keystore = KeyStore::get_instance(env, PROVIDER)?;
    keystore.load(env)?;
    keystore.delete_entry(env, alias)?;
    Ok(())
}

fn get_file(
    env: &mut JNIEnv,
    context: &AndroidContext,
    filename: &str,
) -> AndroidKeyringResult<SharedPreferences> {
    Ok(get_shared_preferences(
        context.inner.reference.as_obj(),
        env,
        filename,
        MODE_PRIVATE,
    )?)
}

fn delete_file(
    env: &mut JNIEnv,
    context: &AndroidContext,
    filename: &str,
) -> AndroidKeyringResult<bool> {
    log::debug!("Deleting file for {:?}", filename);
    Ok(delete_shared_preferences(
        context.inner.reference.as_obj(),
        env,
        filename,
    )?)
}
