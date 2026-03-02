use std::sync::Arc;

use keyring_core::{Credential, api::CredentialApi};

use crate::{
    cipher::{Cipher, GCMParameterSpec},
    consts::AndroidConstants,
    error::{AndroidKeyringError, CorruptedData},
};

use super::vault::AtomicVault;

pub struct Cred {
    vault: AtomicVault,
    pub id: String,
    pub specifiers: Option<(String, String)>,
}

impl std::fmt::Debug for Cred {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AndroidCredential")
            .field("vault", &self.vault)
            .field("key", &self.id)
            .field("specifiers", &self.specifiers)
            .finish()
    }
}

impl Cred {
    pub fn new_specifier(vault: AtomicVault, id: String, service: &str, user: &str) -> Self {
        Self {
            vault,
            id,
            specifiers: Some((service.to_owned(), user.to_owned())),
        }
    }

    pub fn new_wrapper(vault: AtomicVault, key: String) -> Self {
        Self {
            vault,
            id: key,
            specifiers: None,
        }
    }
}

impl AndroidConstants for Cred {}

impl CredentialApi for Cred {
    fn set_secret(&self, secret: &[u8]) -> keyring_core::Result<()> {
        let vault = self
            .vault
            .lock()
            .expect("Vault lock poisoned: report a bug!");
        vault.with_key_and_file(|env, key, file| {
            let cipher = Cipher::get_instance(env, Cred::CIPHER_TRANSFORMATION)?;
            cipher.init(env, Cred::ENCRYPT_MODE, &key)?;
            let iv = cipher.get_iv(env)?;
            assert_eq!(
                iv.len(),
                Cred::IV_LEN,
                "IV len is wrong, please file a bug report"
            );
            let ciphertext = cipher.do_final(env, secret)?;
            let iv_len = iv.len() as u8;
            let edit = file.edit(env)?;
            let mut value = vec![iv_len];
            value.extend_from_slice(&iv);
            value.extend_from_slice(&ciphertext);
            edit.put_binary(env, &self.id, &value)?;
            edit.commit(env)?;
            Ok(())
        })?;
        Ok(())
    }

    fn get_secret(&self) -> keyring_core::Result<Vec<u8>> {
        let vault = self
            .vault
            .lock()
            .expect("Vault lock poisoned: report a bug!");
        let result = vault.with_key_and_file(|env, key, file| {
            let ciphertext = file.get_binary(env, &self.id)?;
            if let Some(data) = ciphertext {
                log::debug!("Found secret for id {:?}", self.id);
                if data.is_empty() {
                    let err = CorruptedData::MissingIvLen;
                    return Err(AndroidKeyringError::CorruptedData(data, err));
                }
                let iv_len = data[0] as usize;
                if iv_len != Cred::IV_LEN {
                    let err = CorruptedData::InvalidIvLen {
                        actual: iv_len,
                        expected: Cred::IV_LEN,
                    };
                    return Err(AndroidKeyringError::CorruptedData(data, err));
                }
                let ciphertext = &data[1..];
                let ciphertext_len = ciphertext.len();
                if ciphertext_len <= iv_len {
                    let err = CorruptedData::DataTooSmall(ciphertext_len);
                    return Err(AndroidKeyringError::CorruptedData(data, err));
                }
                let iv = &ciphertext[..iv_len];
                let iv = &iv[..iv_len];
                let ciphertext = &ciphertext[iv_len..];
                let spec = GCMParameterSpec::new(env, 128, iv)?;
                let cipher = Cipher::get_instance(env, Cred::CIPHER_TRANSFORMATION)?;
                cipher.init2(env, Cred::DECRYPT_MODE, &key, spec.into())?;
                let plaintext = cipher.do_final(env, ciphertext).map_err(move |_| {
                    AndroidKeyringError::CorruptedData(data, CorruptedData::DecryptionFailure)
                })?;
                Ok(Some(plaintext))
            } else {
                log::debug!("No secret found for id {:?}", self.id);
                Ok(None)
            }
        })?;
        match result {
            Some(secret) => Ok(secret),
            None => Err(keyring_core::Error::NoEntry),
        }
    }

    fn delete_credential(&self) -> keyring_core::Result<()> {
        let vault = self
            .vault
            .lock()
            .expect("Vault lock poisoned: report a bug!");
        vault.with_env(|env| {
            let file = vault.get_file(env)?;
            if !file.contains(env, &self.id)? {
                log::debug!("No credential to delete for id {:?}", self.id);
                return Err(keyring_core::Error::NoEntry.into());
            }
            log::debug!("Deleting credential for id {:?}", self.id);
            let editor = file.edit(env)?;
            editor.remove(env, &self.id)?.commit(env)?;
            Ok(())
        })?;
        Ok(())
    }

    fn get_credential(&self) -> keyring_core::Result<Option<Arc<Credential>>> {
        let vault = self
            .vault
            .lock()
            .expect("Vault lock poisoned: report a bug!");
        vault.with_env(|env| {
            let file = vault.get_file(env)?;
            if !file.contains(env, &self.id)? {
                log::debug!("No credential for id {:?}", self.id);
                Err(keyring_core::Error::NoEntry)?;
            }
            log::debug!("Found credential for id {:?}", self.id);
            Ok(())
        })?;
        Ok(None)
    }

    fn get_specifiers(&self) -> Option<(String, String)> {
        self.specifiers.clone()
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn debug_fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}
