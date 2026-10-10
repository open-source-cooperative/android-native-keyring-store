use android_log_sys::LogPriority;
use jni::{JNIEnv, objects::JObject};
use std::ffi::CString;

use keyring_core::Result;

use crate::{by_store::clear_vault_list, shared_preferences::Context};

mod crypto_tests;
#[cfg(feature = "legacy")]
pub mod legacy_tests;
pub mod store_tests;
mod unlock_tests;

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
    #[cfg(feature = "legacy")]
    let (ls, lf) = legacy_tests::run_tests();
    let (ss, sf) = store_tests::run_tests();
    let (cs, cf) = crypto_tests::run_tests(env, context);
    #[cfg(feature = "legacy")]
    let successes = ls + ss + cs;
    #[cfg(not(feature = "legacy"))]
    let successes = ss + cs;
    #[cfg(feature = "legacy")]
    let failures = lf + sf + cf;
    #[cfg(not(feature = "legacy"))]
    let failures = sf + cf;
    report(
        LogPriority::INFO,
        &format!("Overall: {} successes, {} failures", successes, failures),
    );
    match cleanup() {
        Ok(()) => log::info!("Successfully cleaned up tests"),
        Err(e) => {
            report(
                LogPriority::ERROR,
                &format!("Failed to clean up tests: {e}"),
            );
        }
    }
}

/// Logs `message` under the `unit-test` tag.
pub fn report(priority: LogPriority, message: &str) {
    let message = CString::new(message).unwrap();
    crate::logcat::write(priority, c"unit-test", &message);
}

/// The failure of `op`, which should have returned `msg`.
pub fn bad_result(op: &str, msg: &str) -> Result<()> {
    Err(keyring_core::Error::Invalid(
        op.to_string(),
        format!("should have returned {msg}"),
    ))
}

pub fn cleanup() -> Result<()> {
    #[cfg(feature = "legacy")]
    legacy_tests::setup()?;
    #[cfg(feature = "legacy")]
    legacy_tests::teardown()?;
    clear_vault_list();
    store_tests::cleanup()?;
    crypto_tests::cleanup()?;
    unlock_tests::cleanup()?;
    Ok(())
}
