use std::ffi::c_void;
use std::sync::OnceLock;

use jni::{
    JNIEnv,
    objects::{GlobalRef, JObject},
};

pub mod by_store;
pub use by_store::Cred;
pub use by_store::Store;

pub mod by_service;
pub use by_service::Cred as LegacyCred;
pub use by_service::Store as LegacyStore;

#[cfg(feature = "android-log")]
mod android_log;
mod cipher;
mod consts;
mod error;
mod keystore;
mod methods;
mod shared_preferences;

#[cfg(feature = "compile_tests")]
pub mod by_service_tests;
#[cfg(feature = "compile_tests")]
pub mod by_store_tests;

/// Initialize the NDK context.
///
/// This JNI function can be called from your application's Java
/// code to prepare the NDK context for use by this crate.
/// (Some Android application frameworks do this for you.)
///
/// You can invoke this function automatically by defining it as
/// a companion object's `init` function, as shown in the example
/// below.
/// ```java
/// package io.crates.keyring
/// import android.content.Context
/// class Keyring {
///     companion object {
///         init {
///             System.loadLibrary("android_native_keyring_store")
///         }
///         external fun initializeNdkContext(context: Context);
///     }
/// }
/// ```
#[allow(non_snake_case)]
#[unsafe(no_mangle)]
pub extern "system" fn Java_io_crates_keyring_Keyring_00024Companion_initializeNdkContext(
    env: JNIEnv,
    _class: JObject,
    context: JObject,
) {
    static REF: OnceLock<Option<GlobalRef>> = OnceLock::new();
    REF.get_or_init(|| match env.new_global_ref(&context) {
        Ok(ref_) => {
            let vm = env.get_java_vm().unwrap();
            let vm = vm.get_java_vm_pointer() as *mut c_void;
            unsafe {
                ndk_context::initialize_android_context(vm, ref_.as_obj().as_raw() as _);
            }
            Some(ref_)
        }
        Err(e) => {
            tracing::error!(%e, "error creating global reference for context");
            tracing::debug!(?e);
            None
        }
    });
}
