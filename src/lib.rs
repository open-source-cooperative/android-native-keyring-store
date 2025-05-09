use android_log_sys::{__android_log_write, LogPriority};
use jni::{JNIEnv, objects::JObject};
use shared_preferences::Context;
use std::ffi::{CStr, CString};

pub mod cipher;
pub mod credential;
pub mod keystore;
pub mod methods;
pub mod shared_preferences;
#[cfg(feature = "compile_tests")]
pub mod tests;

fn log<T: ToString>(data: T) {
    static TAG: &CStr = c"hello";
    let msg = CString::new(data.to_string()).unwrap();

    unsafe {
        __android_log_write(LogPriority::DEBUG as i32, TAG.as_ptr(), msg.as_ptr());
    }
}

fn logd<T: std::fmt::Debug>(data: T) {
    log(format!("{data:?}"));
}

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
            log("error creating context");
            logd(e);
            return;
        }
    };

    let builder = match credential::AndroidBuilder::new(env, context) {
        Ok(builder) => builder,
        Err(e) => {
            log("error creating builder");
            logd(e);
            return;
        }
    };

    keyring::set_default_credential_builder(Box::new(builder));
}
