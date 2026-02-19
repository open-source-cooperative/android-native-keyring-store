use std::collections::HashMap;
use std::ffi::c_void;
use std::sync::{Arc, OnceLock};

use jni::{
    JNIEnv,
    objects::{GlobalRef, JObject},
};
use keyring_core::{Error, Result};

#[cfg(feature = "android-log")]
pub mod android_log;
pub mod by_service;
pub mod by_store;
pub mod cipher;
pub mod error;
pub mod keystore;
pub mod methods;
pub mod shared_preferences;
#[cfg(feature = "compile_tests")]
pub mod tests;

pub type Store = by_service::Store;
pub type Cred = by_service::Cred;

// package io.crates.keyring
// import android.content.Context
// class Keyring {
//     companion object {
//         init {
//             System.loadLibrary("android_native_keyring_store")
//         }
//         external fun initializeNdkContext(context: Context);
//     }
// }
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

/// Standard Store creation signature.
impl Store {
    pub fn new() -> Result<Arc<Self>> {
        match by_service::Store::from_ndk_context() {
            Ok(store) => Ok(store),
            Err(e) => Err(e.into()),
        }
    }

    pub fn new_with_configuration(configuration: &HashMap<&str, &str>) -> Result<Arc<Self>> {
        if !configuration.is_empty() {
            return Err(Error::NotSupportedByStore(
                "The Android Keyring Store does not support configuration options".to_string(),
            ));
        }
        Self::new()
    }
}
