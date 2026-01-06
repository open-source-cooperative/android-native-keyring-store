use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
use std::time::{SystemTime, UNIX_EPOCH};

use jni::{JNIEnv, JavaVM};
use keyring_core::{
    Credential, Entry,
    api::{CredentialApi, CredentialStoreApi},
};

use crate::{
    cipher::{Cipher, GCMParameterSpec},
    keystore::{Key, KeyGenParameterSpecBuilder, KeyGenerator, KeyStore},
    shared_preferences::{Context, SharedPreferences},
};

pub const KEY_ALGORITHM_AES: &str = "AES";
pub const PROVIDER: &str = "AndroidKeyStore";
pub const PURPOSE_ENCRYPT: i32 = 1;
pub const PURPOSE_DECRYPT: i32 = 2;
pub const BLOCK_MODE_GCM: &str = "GCM";
pub const ENCRYPTION_PADDING_NONE: &str = "NoPadding";
pub const MODE_PRIVATE: i32 = 0;
pub const ENCRYPT_MODE: i32 = 1;
pub const DECRYPT_MODE: i32 = 2;
pub const CIPHER_TRANSFORMATION: &str = "AES/GCM/NoPadding";
pub const IV_LEN: usize = 12;

pub struct AndroidStore {
    java_vm: Arc<JavaVM>,
    context: Context,
}

impl std::fmt::Debug for AndroidStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AndroidStore")
            .field("vendor", &self.vendor())
            .field("id", &self.id())
            .field("context", &self.context.id())
            .finish()
    }
}

impl AndroidStore {
    /// Initializes AndroidBuilder using the JNI context available
    /// on the `ndk-context` crate.
    pub fn from_ndk_context() -> AndroidKeyringResult<Arc<Self>> {
        let ctx = ndk_context::android_context();
        let vm = ctx.vm().cast();
        let activity = ctx.context();

        let java_vm = unsafe { JavaVM::from_raw(vm)? };
        let env = java_vm.attach_current_thread()?;

        let j_context = unsafe { jni::objects::JObject::from_raw(activity as jni::sys::jobject) };
        let context = Context::new(&env, j_context)?;
        let java_vm = Arc::new(env.get_java_vm()?);
        Ok(Arc::new(Self { java_vm, context }))
    }
}

impl CredentialStoreApi for AndroidStore {
    fn vendor(&self) -> String {
        "SharedPreferences/KeyStore, https://github.com/open-source-cooperative/android-native-keyring-store".to_string()
    }

    fn id(&self) -> String {
        let now = SystemTime::now();
        let elapsed = if now.lt(&UNIX_EPOCH) {
            UNIX_EPOCH.duration_since(now).unwrap()
        } else {
            now.duration_since(UNIX_EPOCH).unwrap()
        };
        format!(
            "KCrate version {}, Instantiated at {}",
            env!("CARGO_PKG_VERSION"),
            elapsed.as_secs_f64()
        )
    }

    fn build(
        &self,
        service: &str,
        user: &str,
        _modifiers: Option<&HashMap<&str, &str>>,
    ) -> keyring_core::Result<Entry> {
        let credential =
            AndroidCredential::new(self.java_vm.clone(), self.context.clone(), service, user);

        Ok(Entry::new_with_credential(Arc::new(credential)))
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn debug_fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

pub struct AndroidCredential {
    java_vm: Arc<JavaVM>,
    context: Context,
    service: String,
    user: String,
}

impl std::fmt::Debug for AndroidCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AndroidCredential")
            .field("service", &self.service)
            .field("user", &self.user)
            .finish()
    }
}

impl AndroidCredential {
    pub fn new(java_vm: Arc<JavaVM>, context: Context, service: &str, user: &str) -> Self {
        Self {
            java_vm,
            context,
            service: service.to_owned(),
            user: user.to_owned(),
        }
    }

    fn get_key(env: &mut JNIEnv, service: &str) -> AndroidKeyringResult<Key> {
        static SERVICE_LOCK: Mutex<()> = Mutex::new(());
        let _lock = SERVICE_LOCK.lock().unwrap();

        let keystore = KeyStore::get_instance(env, PROVIDER)?;
        keystore.load(env)?;

        Ok(match keystore.get_key(env, service)? {
            Some(key) => key,
            None => {
                let key_generator_spec = KeyGenParameterSpecBuilder::new(
                    env,
                    service,
                    PURPOSE_DECRYPT | PURPOSE_ENCRYPT,
                )?
                .set_block_modes(env, &[BLOCK_MODE_GCM])?
                .set_encryption_paddings(env, &[ENCRYPTION_PADDING_NONE])?
                .set_user_authentication_required(env, false)?
                .build(env)?;
                let key_generator = KeyGenerator::get_instance(env, KEY_ALGORITHM_AES, PROVIDER)?;
                key_generator.init(env, key_generator_spec.into())?;
                let key = key_generator.generate_key(env)?;
                key.into()
            }
        })
    }

    fn get_file(
        env: &mut JNIEnv,
        context: &Context,
        service: &str,
    ) -> AndroidKeyringResult<SharedPreferences> {
        Ok(context.get_shared_preferences(env, service, MODE_PRIVATE)?)
    }
}

impl CredentialApi for AndroidCredential {
    fn set_secret(&self, secret: &[u8]) -> keyring_core::Result<()> {
        self.check_for_exception(|env| {
            let file = Self::get_file(env, &self.context, &self.service)?;
            let key = Self::get_key(env, &self.service)?;

            let cipher = Cipher::get_instance(env, CIPHER_TRANSFORMATION)?;
            cipher.init(env, ENCRYPT_MODE, &key)?;
            let iv = cipher.get_iv(env)?;
            assert_eq!(
                iv.len(),
                IV_LEN,
                "IV should always be 12 bytes, please file a bug report"
            );
            let ciphertext = cipher.do_final(env, secret)?;

            let iv_len = iv.len() as u8;

            let edit = file.edit(env)?;
            let mut value = vec![iv_len];
            value.extend_from_slice(&iv);
            value.extend_from_slice(&ciphertext);
            edit.put_binary(env, &self.user, &value)?;
            edit.commit(env)?;

            Ok(())
        })?;

        Ok(())
    }

    fn get_secret(&self) -> keyring_core::Result<Vec<u8>> {
        let r = self.check_for_exception(|env| {
            let file = Self::get_file(env, &self.context, &self.service)?;
            let key = Self::get_key(env, &self.service)?;
            let ciphertext = file.get_binary(env, &self.user)?;

            Ok(match ciphertext {
                Some(data) => {
                    if data.is_empty() {
                        return Err(AndroidKeyringError::CorruptedData(
                            data,
                            CorruptedData::MissingIvLen,
                        ));
                    }

                    let iv_len = data[0] as usize;

                    if iv_len != IV_LEN {
                        return Err(AndroidKeyringError::CorruptedData(
                            data,
                            CorruptedData::InvalidIvLen(iv_len),
                        ));
                    }

                    let ciphertext = &data[1..];
                    let ciphertext_len = ciphertext.len();
                    if ciphertext_len <= iv_len {
                        return Err(AndroidKeyringError::CorruptedData(
                            data,
                            CorruptedData::DataTooSmall(ciphertext_len),
                        ));
                    }

                    let iv = &ciphertext[..iv_len];
                    let iv = &iv[..iv_len];
                    let ciphertext = &ciphertext[iv_len..];

                    let spec = GCMParameterSpec::new(env, 128, iv)?;
                    let cipher = Cipher::get_instance(env, CIPHER_TRANSFORMATION)?;
                    cipher.init2(env, DECRYPT_MODE, &key, spec.into())?;
                    let plaintext = cipher.do_final(env, ciphertext).map_err(move |_| {
                        AndroidKeyringError::CorruptedData(data, CorruptedData::DecryptionFailure)
                    })?;

                    Some(plaintext)
                }
                None => None,
            })
        })?;

        match r {
            Some(r) => Ok(r),
            None => Err(keyring_core::Error::NoEntry),
        }
    }

    fn delete_credential(&self) -> keyring_core::Result<()> {
        self.check_for_exception(|env| {
            let file = Self::get_file(env, &self.context, &self.service)?;
            let edit = file.edit(env)?;
            edit.remove(env, &self.user)?.commit(env)?;
            edit.commit(env)?;
            Ok(())
        })?;

        Ok(())
    }

    fn get_credential(&self) -> keyring_core::Result<Option<Arc<Credential>>> {
        self.get_secret()?;
        Ok(None)
    }

    fn get_specifiers(&self) -> Option<(String, String)> {
        Some((self.service.clone(), self.user.clone()))
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn debug_fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

pub trait HasJavaVm {
    fn java_vm(&self) -> &JavaVM;
    fn check_for_exception<T, F>(&self, f: F) -> AndroidKeyringResult<T>
    where
        F: FnOnce(&mut JNIEnv) -> AndroidKeyringResult<T>,
    {
        let vm = self.java_vm();
        let mut env = vm.attach_current_thread()?;
        let t_result = f(&mut env);
        if env.exception_check()? {
            env.exception_describe()?;
            env.exception_clear()?;

            if t_result.is_ok() {
                return Err(AndroidKeyringError::JavaExceptionThrow);
            }
        }

        t_result
    }
}
impl HasJavaVm for AndroidStore {
    fn java_vm(&self) -> &JavaVM {
        &self.java_vm
    }
}
impl HasJavaVm for AndroidCredential {
    fn java_vm(&self) -> &JavaVM {
        &self.java_vm
    }
}

#[derive(thiserror::Error, Debug)]
pub enum AndroidKeyringError {
    #[error(transparent)]
    JniError(#[from] jni::errors::Error),
    #[error("Java exception was thrown")]
    JavaExceptionThrow,
    #[error("{1}")]
    CorruptedData(Vec<u8>, CorruptedData),
}
impl From<AndroidKeyringError> for keyring_core::Error {
    fn from(value: AndroidKeyringError) -> Self {
        match value {
            AndroidKeyringError::JniError(error) => {
                keyring_core::Error::PlatformFailure(Box::new(error))
            }
            e @ AndroidKeyringError::JavaExceptionThrow => {
                keyring_core::Error::PlatformFailure(Box::new(e))
            }
            AndroidKeyringError::CorruptedData(data, error) => {
                keyring_core::Error::BadDataFormat(data, Box::new(error))
            }
        }
    }
}
type AndroidKeyringResult<T> = Result<T, AndroidKeyringError>;

#[derive(thiserror::Error, Debug)]
pub enum CorruptedData {
    #[error("IV length not specified on entry")]
    MissingIvLen,
    #[error("IV length in data is {0}, but should be {expected}", expected=IV_LEN)]
    InvalidIvLen(usize),
    #[error("Data is too small to contain IV and ciphertext, length = {0}")]
    DataTooSmall(usize),
    #[error("Verification of data signature/MAC failed")]
    DecryptionFailure,
}
