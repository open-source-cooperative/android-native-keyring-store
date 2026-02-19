use std::sync::{Arc, Mutex};

use jni::{JNIEnv, JavaVM};
use keyring_core::{Credential, api::CredentialApi};

use crate::{
    cipher::{Cipher, GCMParameterSpec},
    keystore::{Key, KeyGenParameterSpecBuilder, KeyGenerator, KeyStore},
    shared_preferences::{Context, SharedPreferences},
};

use super::{AndroidKeyringError, AndroidKeyringResult, CorruptedData};
use super::{
    BLOCK_MODE_GCM, CIPHER_TRANSFORMATION, DECRYPT_MODE, ENCRYPT_MODE, ENCRYPTION_PADDING_NONE,
    HasJavaVm, IV_LEN, KEY_ALGORITHM_AES, MODE_PRIVATE, PROVIDER, PURPOSE_DECRYPT, PURPOSE_ENCRYPT,
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

impl HasJavaVm for Cred {
    fn java_vm(&self) -> &JavaVM {
        &self.java_vm
    }
}
