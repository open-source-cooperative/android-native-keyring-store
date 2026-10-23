use android_log_sys::LogPriority;
use jni::{JNIEnv, objects::JObject};
use std::ffi::CString;

use keyring_core::Result;

use crate::{by_store::clear_vault_list, shared_preferences::Context};

mod crypto_tests;
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
    let (ss, sf) = store_tests::run_tests();
    let (cs, cf) = crypto_tests::run_tests(env, context);
    let successes = ss + cs;
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
    #[cfg(keyring_coverage)]
    write_coverage_profile();
}

/// Writes the coverage profile, since Android kills the app before the runtime would.
#[cfg(keyring_coverage)]
fn write_coverage_profile() {
    unsafe extern "C" {
        fn __llvm_profile_write_file() -> std::ffi::c_int;
    }
    // SAFETY: `-C instrument-coverage` links the runtime defining this no-argument function,
    // and no test is still running to update the counters it reads.
    let status = unsafe { __llvm_profile_write_file() };
    let priority = if status == 0 {
        LogPriority::INFO
    } else {
        LogPriority::ERROR
    };
    report(
        priority,
        &format!("Coverage profile written with status {status}"),
    );
}

/// Logs `message` under the `unit-test` tag.
pub fn report(priority: LogPriority, message: &str) {
    let message = CString::new(message).unwrap();
    crate::logcat::write(priority, c"unit-test", &message);
}

pub fn cleanup() -> Result<()> {
    clear_vault_list();
    store_tests::cleanup()?;
    crypto_tests::cleanup()?;
    Ok(())
}
