use crate::{
    cipher::{Cipher, GCMParameterSpec},
    keystore::{Key, KeyGenParameterSpecBuilder, KeyGenerator, KeyStore},
    shared_preferences::{Context, SharedPreferences},
};
use jni::{JNIEnv, JavaVM};
use keyring::{
    Credential,
    credential::{CredentialApi, CredentialBuilderApi},
};
use std::sync::Mutex;

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

pub struct AndroidBuilder {
    java_vm: JavaVM,
    context: Context,
}
impl AndroidBuilder {
    /// Initializes AndroidBuilder using the JNI context available
    /// on the `ndk-context` crate.
    #[cfg(feature = "ndk-context")]
    pub fn from_ndk_context() -> AndroidKeyringResult<Self> {
        let ctx = ndk_context::android_context();
        let vm = ctx.vm().cast();
        let activity = ctx.context();

        let java_vm = unsafe { jni::JavaVM::from_raw(vm)? };
        let env = java_vm.attach_current_thread()?;

        let context = unsafe { jni::objects::JObject::from_raw(activity as jni::sys::jobject) };
        let context = Context::new(&env, context)?;

        Self::new(&env, context)
    }

    pub fn new(env: &JNIEnv, context: Context) -> AndroidKeyringResult<Self> {
        let java_vm = env.get_java_vm()?;
        Ok(Self { java_vm, context })
    }
}
impl CredentialBuilderApi for AndroidBuilder {
    fn build(
        &self,
        _target: Option<&str>,
        service: &str,
        user: &str,
    ) -> keyring::Result<Box<Credential>> {
        let credential = self
            .check_for_exception(|env| AndroidCredential::new(env, &self.context, service, user))?;

        Ok(Box::new(credential))
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

pub struct AndroidCredential {
    java_vm: JavaVM,
    key: Key,
    file: SharedPreferences,
    user: String,
}
impl AndroidCredential {
    pub fn new(
        env: &mut JNIEnv,
        context: &Context,
        service: &str,
        user: &str,
    ) -> AndroidKeyringResult<Self> {
        let java_vm = env.get_java_vm()?;
        let key = {
            static SERVICE_LOCK: Mutex<()> = Mutex::new(());
            let _lock = SERVICE_LOCK.lock().unwrap();
            Self::get_key(env, service)?
        };
        let file = Self::get_file(env, context, service)?;

        Ok(Self {
            java_vm,
            key,
            file,
            user: user.to_owned(),
        })
    }

    fn get_key(env: &mut JNIEnv, service: &str) -> AndroidKeyringResult<Key> {
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
    fn set_password(&self, password: &str) -> keyring::Result<()> {
        self.set_secret(password.as_bytes())
    }

    fn set_secret(&self, password: &[u8]) -> keyring::Result<()> {
        self.check_for_exception(|env| {
            let cipher = Cipher::get_instance(env, CIPHER_TRANSFORMATION)?;
            cipher.init(env, ENCRYPT_MODE, &self.key)?;
            let iv = cipher.get_iv(env)?;
            let ciphertext = cipher.do_final(env, password)?;

            let iv_len = iv.len() as u8;

            let edit = self.file.edit(env)?;
            let mut value = vec![iv_len];
            value.extend_from_slice(&iv);
            value.extend_from_slice(&ciphertext);
            edit.put_binary(env, &self.user, &value)?;
            edit.commit(env)?;

            Ok(())
        })?;

        Ok(())
    }

    fn get_password(&self) -> keyring::Result<String> {
        let secret = self.get_secret()?;
        match String::from_utf8(secret) {
            Ok(str) => Ok(str),
            Err(e) => Err(keyring::Error::BadEncoding(e.into_bytes())),
        }
    }

    fn get_secret(&self) -> keyring::Result<Vec<u8>> {
        let r = self.check_for_exception(|env| {
            let ciphertext = self.file.get_binary(env, &self.user)?;
            Ok(match ciphertext {
                Some(ciphertext) => {
                    if ciphertext.is_empty() {
                        return Err(AndroidKeyringError::CorruptedData);
                    }

                    let iv_len = ciphertext[0] as usize;
                    let ciphertext = &ciphertext[1..];
                    if ciphertext.len() < iv_len {
                        return Err(AndroidKeyringError::CorruptedData);
                    }

                    let iv = &ciphertext[..iv_len];
                    let ciphertext = &ciphertext[iv_len..];

                    let spec = GCMParameterSpec::new(env, 128, iv)?;
                    let cipher = Cipher::get_instance(env, CIPHER_TRANSFORMATION)?;
                    cipher.init2(env, DECRYPT_MODE, &self.key, spec.into())?;
                    let plaintext = cipher.do_final(env, ciphertext)?;

                    Some(plaintext)
                }
                None => None,
            })
        })?;

        match r {
            Some(r) => Ok(r),
            None => Err(keyring::Error::NoEntry),
        }
    }

    fn delete_credential(&self) -> keyring::Result<()> {
        self.check_for_exception(|env| {
            let edit = self.file.edit(env)?;
            edit.remove(env, &self.user)?.commit(env)?;
            Ok(())
        })?;

        Ok(())
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
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
            if let Err(e) = t_result {
                tracing::warn!(%e, "Result::Err being converted into JavaExceptionThrown");
                tracing::debug!(?e);
            }
            return Err(AndroidKeyringError::JavaExceptionThrow);
        }

        t_result
    }
}
impl HasJavaVm for AndroidBuilder {
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
    #[error("Corrupted data in SharedPreferences")]
    CorruptedData,
}
impl From<AndroidKeyringError> for keyring::Error {
    fn from(value: AndroidKeyringError) -> Self {
        Self::PlatformFailure(Box::new(value))
    }
}
type AndroidKeyringResult<T> = Result<T, AndroidKeyringError>;
