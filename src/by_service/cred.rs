use std::sync::{Arc, Mutex};

use jni::{JNIEnv, JavaVM};
use keyring_core::{Credential, api::CredentialApi};

use crate::crypto::{decrypt, encrypt};
use crate::{
    error::{AndroidKeyringResult, HasJavaVm},
    keystore::{
        BLOCK_MODE_GCM, ENCRYPTION_PADDING_NONE, KEY_ALGORITHM_AES, Key,
        KeyGenParameterSpecBuilder, KeyGenerator, KeyStore, PROVIDER, PURPOSE_DECRYPT,
        PURPOSE_ENCRYPT,
    },
    shared_preferences::{Context, MODE_PRIVATE, SharedPreferences},
};

pub struct Cred {
    java_vm: Arc<JavaVM>,
    context: Context,
    service: String,
    user: String,
}

impl std::fmt::Debug for Cred {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AndroidCredential")
            .field("service", &self.service)
            .field("user", &self.user)
            .finish()
    }
}

impl Cred {
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

impl CredentialApi for Cred {
    fn set_secret(&self, secret: &[u8]) -> keyring_core::Result<()> {
        self.check_for_exception(|env| {
            let file = Self::get_file(env, &self.context, &self.service)?;
            let key = Self::get_key(env, &self.service)?;
            let ciphertext = encrypt(env, key, secret)?;
            let edit = file.edit(env)?;
            edit.put_binary(env, &self.user, &ciphertext)?.commit(env)?;
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
                    let plaintext = decrypt(env, key, data)?;
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

impl HasJavaVm for Cred {
    fn java_vm(&self) -> &JavaVM {
        &self.java_vm
    }
}
