/*!
# Keyring-compatible Android-native credential store

This crate uses two Android-native features---SharedPreferences and the
Keystore---to provide secure storage of passwords and other sensitive data
for the
[keyring ecosystem](https://github.com/open-source-cooperative/keyring-rs/wiki/Keyring).

# Named Credential Stores

This crate supports multiple, named credential stores, each
backed by a dedicated SharedPreferences file and a dedicated Android
Keystore entry. The implementation, found in
the [by_store] module, supports search and doesn't allow for ambiguity
or provide any attributes on credentials.

# Legacy Credential Store

Earlier versions of this crate provided a single store that used one SharedPreferences
file and Keystore entry _per service name_, rather than _per store name_. This
legacy implementation, found in the [by_service] module, does not support search and leaves
keys behind even when all of their associated credentials are deleted. It is still
available under the `legacy` feature flag via the [LegacyStore::from_ndk_context]
constructor, but it is deprecated and may be removed in future versions of the crate. All
client applications are advised to migrate any existing credentials from legacy storage to
a named store. See the [Migration Guide](by_service#migration-guide) for details.

## Application Requirements

This crate compiles to produce a native library that can be loaded into an Android
application. Because this crate gets its Android application context from the
[ndk-context crate](https://crates.io/crates/ndk-context), applications that use
this crate must initialize the `application-context` object provided by the `ndk-context`
crate before they can create credential stores. The
[README](https://github.com/open-source-cooperative/android-native-keyring-store) for this
crate provides detailed instructions for how to do this.

 */

use std::ffi::c_void;
use std::sync::OnceLock;

use jni::{
    JNIEnv,
    objects::{GlobalRef, JObject},
};

pub mod by_store;
pub use by_store::Cred;
pub use by_store::Store;

#[cfg(feature = "legacy")]
pub mod by_service;
#[cfg(feature = "legacy")]
pub use by_service::Cred as LegacyCred;
#[cfg(feature = "legacy")]
pub use by_service::Store as LegacyStore;

#[cfg(feature = "android-log")]
mod android_log;
mod cipher;
mod crypto;
mod error;
mod keystore;
mod methods;
mod shared_preferences;

#[cfg(feature = "compile-tests")]
pub mod tests;

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
