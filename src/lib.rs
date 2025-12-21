#[cfg(feature = "android-log")]
pub mod android_log;
pub mod cipher;
pub mod credential;
pub mod keystore;
pub mod methods;
pub mod shared_preferences;
#[cfg(feature = "compile_tests")]
pub mod tests;

use jni::{JNIEnv, objects::JObject};
use shared_preferences::Context;
use std::collections::HashMap;
use std::sync::Arc;

use keyring_core::{Error, Result};

pub type Store = credential::AndroidStore;
pub type Cred = credential::AndroidCredential;

//noinspection SpellCheckingInspection
// package io.crates.keyring
// import android.content.Context
// class Keyring {
//     companion object {
//         init {
//             System.loadLibrary("android_keyring")
//         }
//         external fun setAndroidKeyringCredentialBuilder(context: Context);
//     }
// }
#[allow(non_snake_case)]
#[unsafe(no_mangle)]
pub extern "system" fn Java_io_crates_keyring_Keyring_00024Companion_setAndroidKeyringCredentialBuilder(
    env: JNIEnv,
    _class: JObject,
    context: JObject,
) {
    let context = match Context::new(&env, context) {
        Ok(context) => context,
        Err(e) => {
            tracing::error!(%e, "error converting context JObject into Context");
            tracing::debug!(?e);
            return;
        }
    };

    let builder = match credential::AndroidStore::from_activity_context(&env, context) {
        Ok(builder) => builder,
        Err(e) => {
            tracing::error!(%e, "error initialized AndroidBuilder credential builder");
            tracing::debug!(?e);
            return;
        }
    };

    keyring_core::set_default_store(builder);
}

/// Standard Store creation signature.
/// Requires the `ndk-context` feature.
#[cfg(feature = "ndk-context")]
impl Store {
    pub fn new() -> Result<Arc<Self>> {
        match credential::AndroidStore::from_ndk_context() {
            Ok(store) => Ok(store),
            Err(e) => Err(e.into()),
        }
    }

    pub fn new_with_configuration(configuration: &HashMap<&str, &str>) -> Result<Arc<Self>> {
        if (!configuration.is_empty()) {
            return Err(Error::NotSupportedByStore(
                "The Android Keyring Store does not support configuration options".to_string(),
            ));
        }
        Self::new()
    }
}
