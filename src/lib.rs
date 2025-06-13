use jni::{JNIEnv, objects::JObject};
use shared_preferences::Context;

#[cfg(feature = "rust-init")]
use crate::credential::AndroidKeyringError;

#[cfg(feature = "android-log")]
pub mod android_log;
pub mod cipher;
pub mod credential;
pub mod keystore;
pub mod methods;
pub mod shared_preferences;
#[cfg(feature = "compile_tests")]
pub mod tests;

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

    let builder = match credential::AndroidBuilder::new(&env, context) {
        Ok(builder) => builder,
        Err(e) => {
            tracing::error!(%e, "error initialized AndroidBuilder credential builder");
            tracing::debug!(?e);
            return;
        }
    };

    keyring::set_default_credential_builder(Box::new(builder));
}

/// Initializes the android-keyring from pure Rust (no Java call needed).
/// Requires the `rust-init` feature.
#[cfg(feature = "rust-init")]
pub fn set_android_keyring_credential_builder() -> Result<(), AndroidKeyringError> {
    use crate::credential::AndroidBuilder;

    let ctx = ndk_context::android_context();
    let vm = ctx.vm().cast();
    let activity = ctx.context();

    let java_vm = unsafe { jni::JavaVM::from_raw(vm)? };
    let env = java_vm.attach_current_thread()?;
    let context = unsafe { JObject::from_raw(activity as jni::sys::jobject) };

    let android_ctx = Context::new(&env, context)?;
    let builder = AndroidBuilder::new(&env, android_ctx)?;

    keyring::set_default_credential_builder(Box::new(builder));

    Ok(())
}
