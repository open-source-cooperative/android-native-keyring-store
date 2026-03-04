use std::sync::Arc;

use keyring_core::{Credential, api::CredentialApi};

use crate::crypto::{decrypt, encrypt};

use super::vault::AtomicVault;

pub struct Cred {
    vault: AtomicVault,
    pub id: String,
    pub specifiers: (String, String),
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
    pub fn new_specifier(vault: AtomicVault, id: &str, service: &str, user: &str) -> Self {
        Self {
            vault,
            id: id.to_owned(),
            specifiers: (service.to_owned(), user.to_owned()),
        }
    }
}

impl CredentialApi for Cred {
    fn set_secret(&self, secret: &[u8]) -> keyring_core::Result<()> {
        let vault = self
            .vault
            .lock()
            .expect("Vault lock poisoned: report a bug!");
        vault.with_key_and_file(|env, key, file| {
            let ciphertext = encrypt(env, key, secret)?;
            let edit = file.edit(env)?;
            edit.put_binary(env, &self.id, &ciphertext)?.commit(env)?;
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
                let plaintext = decrypt(env, key, data)?;
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
        Some(self.specifiers.clone())
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn debug_fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}
