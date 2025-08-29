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

pub use credential::AndroidStore;

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
#[unsafe(no_mangle)]
pub extern "system" fn Java_io_crates_keyring_Keyring_00024Companion_setAndroidKeyringCredentialBuilder(
    env: JNIEnv,
    _class: JObject,
    context: JObject,
) {
    let context = match Context::new(&env, context) {
        Ok(context) => context,
        Err(e) => {
            tracing::error!(%e, "error converting context jobject into Context");
            tracing::debug!(?e);
            return;
        }
    };

    let builder = match AndroidStore::new(&env, context) {
        Ok(builder) => builder,
        Err(e) => {
            tracing::error!(%e, "error initialized AndroidBuilder credential builder");
            tracing::debug!(?e);
            return;
        }
    };

    keyring_core::set_default_store(builder);
}

/// Initializes the android-keyring from pure Rust (no Java call needed).
/// Requires the `ndk-context` feature.
#[cfg(feature = "ndk-context")]
pub fn set_android_keyring_credential_builder() -> Result<(), credential::AndroidKeyringError> {
    keyring_core::set_default_store(AndroidStore::from_ndk_context()?);

    Ok(())
}
