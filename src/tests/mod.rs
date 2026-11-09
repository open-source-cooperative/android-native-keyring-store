use android_log_sys::LogPriority;
use jni::{JNIEnv, objects::JObject};
use std::ffi::CString;
use std::panic::{UnwindSafe, catch_unwind};

use keyring_core::Result;

use crate::{by_store::clear_vault_list, shared_preferences::Context};

mod context_tests;
mod crypto_tests;
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

/// The failure of `op`, which should have returned `msg`.
pub fn bad_result(op: &str, msg: &str) -> Result<()> {
    Err(keyring_core::Error::Invalid(
        op.to_string(),
        format!("should have returned {msg}"),
    ))
}

/// Runs each named test, counting a panic as a failure, and reports the results under `suite`.
fn run_suite<'a, F>(suite: &str, tests: impl IntoIterator<Item = (&'a str, F)>) -> (usize, usize)
where
    F: FnOnce() -> Result<()> + UnwindSafe,
{
    report(LogPriority::INFO, &format!("Running {suite} tests..."));
    let mut successes = 0;
    let mut failures = 0;
    for (name, test) in tests {
        let result = catch_unwind(test).unwrap_or_else(|e| {
            log::error!("Test {name} panicked: {e:?}");
            bad_result(name, "panicked")
        });
        match result {
            Ok(()) => {
                report(LogPriority::INFO, &format!("{name} success"));
                successes += 1;
            }
            Err(e) => {
                report(LogPriority::ERROR, &format!("{name} error: {e:?}"));
                failures += 1;
            }
        }
    }
    report(
        LogPriority::INFO,
        &format!("{suite}: {successes} successes, {failures} failures"),
    );
    (successes, failures)
}

pub fn cleanup() -> Result<()> {
    clear_vault_list();
    store_tests::cleanup()?;
    context_tests::cleanup()?;
    crypto_tests::cleanup()?;
    unlock_tests::cleanup()?;
    Ok(())
}
