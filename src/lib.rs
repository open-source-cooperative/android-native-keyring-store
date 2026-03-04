/*!
# Keyring-compatible Android-native credential store

This crate uses two Android-native features---SharedPreferences and the
Keystore---to provide secure storage of passwords and other sensitive data
for the
[keyring ecosystem](https://github.com/open-source-cooperative/keyring-rs/wiki/Keyring).

The current implementation supports multiple, named credential stores, each
backed by a dedicated SharedPreferences file and a dedicated Android
Keystore entry. This implementation, the details of which are described in
the [by-store] module, supports search and doesn't allow for ambiguity
or provide any attributes on credentials.
Calling [Store::new] provides access to the `default` credential store, and
is the recommended usage pattern.

Earlier versions of this crate used one SharedPreferences file and Keystore
file per _service_, rather than per (named) _store_. This implementation, the
details of which are described in the [by-service] module, does not support
search and leaves keys behind even when all of their associated credentials
are deleted. It is still available under the `legacy` feature flag via the
[LegacyStore::from_ndk_context] constructor, but it is deprecated and may
be removed in future versions of the crate. All client applications are
advised to migrate any existing credentials from legacy storage to a single
store in the new format.

## Application Requirements

This crate gets its Android application context from the
[ndk-context crate](https://crates.io/crates/ndk-context).
Thus, applications that use this crate initalize the `ndk-context` crate by
calling its `initialize_android_context` function, as documented
[here](https://docs.rs/ndk-context/latest/ndk_context/fn.initialize_android_context.html).

There are a number of application frameworks that do this initialization for you,
such as [ndk-glue](https://github.com/rust-windowing/ndk-glue) and
[Tauri](https://v2.tauri.app/). Also, this crate
includes a JNI function that you can make a companion object's `init` function
to automatically initialize the NDK context. To do the initialization, this way,
include this Kotlin class to load the native library:
```kotlin
package io.crates.keyring
import android.content.Context
class Keyring {
    companion object {
        init {
            System.loadLibrary("android_native_keyring_store")
        }
        external fun initializeNdkContext(context: Context);
    }
}
```
and then call the `Keyring.initializeNdkContext` function from your `MainActivity`'s
`onCreate` method. You can see this method demonstrated in the `KeyringTester`
application found in this crate's
[source repository](https://github.com/open-source-cooperative/android-native-keyring-store).

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

pub mod by_service;
pub use by_service::Cred as LegacyCred;
pub use by_service::Store as LegacyStore;

#[cfg(feature = "android-log")]
mod android_log;
mod cipher;
mod crypto;
mod error;
mod keystore;
mod methods;
mod shared_preferences;

#[cfg(feature = "compile_tests")]
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
