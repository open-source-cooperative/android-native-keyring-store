use android_log_sys::{__android_log_write, LogPriority};
use jni::{JNIEnv, objects::JObject};
use std::ffi::CString;

use keyring_core::Result;

use crate::{by_store::clear_vault_list, shared_preferences::Context};

mod crypto_tests;
pub mod legacy_tests;
pub mod store_tests;

// package io.crates.keyring
// import android.content.Context
// class KeyringTests {
//     companion object {
//         external fun runAllTests(context: android.content.Context);
//     }
// }
#[allow(non_snake_case)]
#[unsafe(no_mangle)]
pub extern "system" fn Java_io_crates_keyring_KeyringTests_00024Companion_runAllTests(
    env: JNIEnv,
    _class: JObject,
    context: JObject,
) {
    let context = Context::new(&env, context).unwrap();
    let (ls, lf) = legacy_tests::run_tests();
    let (ss, sf) = store_tests::run_tests();
    let (cs, cf) = crypto_tests::run_tests(env, context);
    let successes = ls + ss + cs;
    let failures = lf + sf + cf;
    let msg = CString::new(format!(
        "Overall: {} successes, {} failures",
        successes, failures
    ))
    .unwrap();
    let tag = c"unit-test";
    let level = LogPriority::INFO as i32;
    unsafe {
        __android_log_write(level, tag.as_ptr(), msg.as_ptr());
    }
    match cleanup() {
        Ok(()) => log::info!("Successfully cleaned up tests"),
        Err(e) => {
            let msg = CString::new(format!("Failed to clean up tests: {e}")).unwrap();
            let tag = c"unit-test";
            let level = LogPriority::ERROR as i32;
            unsafe {
                __android_log_write(level, tag.as_ptr(), msg.as_ptr());
            }
        }
    }
}

pub fn cleanup() -> Result<()> {
    legacy_tests::setup()?;
    legacy_tests::teardown()?;
    clear_vault_list();
    store_tests::cleanup()?;
    crypto_tests::cleanup()?;
    Ok(())
}
