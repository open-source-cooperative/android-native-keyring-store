use std::ffi::CString;

use android_log_sys::{__android_log_write, LogPriority};
use jni::{JNIEnv, JavaVM, objects::JObject};

use keyring_core::Entry;

use crate::shared_preferences::Context;

// package io.crates.keyring
// import android.content.Context
// class KeyringTests {
//     companion object {
//         external fun runTests(context: android.content.Context);
//     }
// }
#[allow(non_snake_case)]
#[unsafe(no_mangle)]
pub extern "system" fn Java_io_crates_keyring_KeyringTests_00024Companion_runByStoreTests(
    env: JNIEnv,
    _class: JObject,
    context: JObject,
) {
    let context = Context::new(&env, context).unwrap();
    match crate::Store::new() {
        Ok(store) => {
            keyring_core::set_default_store(store);
            let msg = c"Successfully created Modern (by-store) store";
            let tag = c"unit-test";
            let level = LogPriority::INFO as i32;
            unsafe {
                __android_log_write(level, tag.as_ptr(), msg.as_ptr());
            }
        }
        Err(e) => {
            let message = format!("Failed to create Legacy (by-service) store: {e}");
            let msg = CString::new(message).unwrap();
            let tag = c"unit-test";
            let level = LogPriority::ERROR as i32;
            unsafe {
                __android_log_write(level, tag.as_ptr(), msg.as_ptr());
            }
            return;
        }
    }
    run_store_tests(env, context);
    keyring_core::unset_default_store();
}

fn run_store_tests(env: JNIEnv, context: Context) {
    let testing = [
        (
            "golden_path",
            golden_path as fn(JavaVM, Context) -> keyring_core::Result<()>,
        ),
        ("delete_credential", delete_credential),
        ("concurrent_access", concurrent_access),
    ]
    .iter()
    .map(|(name, entry)| {
        let java_vm = env.get_java_vm().unwrap();
        let context = context.clone();
        (name, move || -> keyring_core::Result<()> {
            entry(java_vm, context)
        })
    })
    .collect::<Vec<_>>();

    let mut successes = 0;
    let mut failures = 0;
    if cleanup().is_ok() {
        for (name, testing) in testing {
            let level;
            let msg;
            match testing() {
                Ok(()) => {
                    level = LogPriority::INFO as i32;
                    msg = format!("{name} success");
                    successes += 1;
                }
                Err(e) => {
                    level = LogPriority::ERROR as i32;
                    msg = format!("{name} error: {e:?}");
                    failures += 1;
                }
            }

            let msg = CString::new(msg).unwrap();
            let tag = c"unit-test";
            unsafe {
                __android_log_write(level, tag.as_ptr(), msg.as_ptr());
            }
        }
    } else {
        failures += 1;
    }
    let msg = CString::new(format!("{} successes, {} failures", successes, failures)).unwrap();
    let tag = c"unit-test";
    let level = LogPriority::INFO as i32;
    unsafe {
        __android_log_write(level, tag.as_ptr(), msg.as_ptr());
    }
}

fn bad_result(op: &str, msg: &str) -> keyring_core::Result<()> {
    Err(keyring_core::Error::Invalid(
        op.to_string(),
        format!("should have returned {msg}"),
    ))
}

fn cleanup() -> keyring_core::Result<()> {
    // make sure there's nothing left from prior runs
    // golden_path:
    let entry1 = Entry::new("my-service", "my-user")?;
    let entry2 = Entry::new("my-service", "my-user2")?;
    let entry3 = Entry::new("my-service2", "my-user")?;
    _ = entry1.delete_credential();
    _ = entry2.delete_credential();
    _ = entry3.delete_credential();
    // delete_credential:
    let entry1 = Entry::new("my-service", "delete-test")?;
    _ = entry1.delete_credential();
    // concurrent_access:
    let entry1 = Entry::new("concurrent", "user")?;
    _ = entry1.delete_credential();
    Ok(())
}

fn golden_path(_vm: JavaVM, _ctx: Context) -> keyring_core::Result<()> {
    let entry1 = Entry::new("my-service", "my-user")?;
    let entry2 = Entry::new("my-service", "my-user2")?;
    let entry3 = Entry::new("my-service2", "my-user")?;
    match entry1.get_credential() {
        Ok(e) => return bad_result("get_credential", &format!("NoEntry, but got {e:?}")),
        Err(keyring_core::Error::NoEntry) => {}
        Err(e) => return bad_result("get_credential", &format!("NoEntry, but got {e:?}")),
    }
    entry1.set_password("test")?;
    match entry1.get_password() {
        Ok(p) if p.eq("test") => {}
        Ok(p) => return bad_result("get_password", &format!("'test', got '{p}'")),
        Err(e) => return bad_result("get_password", &format!("'test', got {e:?}")),
    }
    match entry2.get_password() {
        Ok(_) => return bad_result("get_credential", "NoEntry, but got password"),
        Err(keyring_core::Error::NoEntry) => {}
        Err(e) => return bad_result("get_credential", &format!("NoEntry, but got {e:?}")),
    }
    entry2.set_password("test2")?;
    match entry2.get_password() {
        Ok(p) if p.eq("test2") => {}
        Ok(p) => return bad_result("get_password", &format!("'test2', got '{p}'")),
        Err(e) => return bad_result("get_password", &format!("'test2', got {e:?}")),
    }
    entry3.set_password("test3")?;
    match entry2.get_password() {
        Ok(p) if p.eq("test3") => {}
        Ok(p) => return bad_result("get_password", &format!("'test3', got '{p}'")),
        Err(e) => return bad_result("get_password", &format!("'test3', got {e:?}")),
    }
    entry1.delete_credential()?;
    entry2.delete_credential()?;
    entry3.delete_credential()?;
    Ok(())
}

fn delete_credential(_vm: JavaVM, _ctx: Context) -> keyring_core::Result<()> {
    let entry1 = Entry::new("my-service", "delete-test")?;
    entry1.set_password("test")?;
    match entry1.get_password() {
        Ok(p) if p.eq("test") => {}
        Ok(p) => return bad_result("get_password", &format!("'test', got '{p}'")),
        Err(e) => return bad_result("get_password", &format!("'test', got {e:?}")),
    }

    entry1.delete_credential()?;
    match entry1.get_password() {
        Ok(_) => bad_result("get_credential", "NoEntry, but got password"),
        Err(keyring_core::Error::NoEntry) => Ok(()),
        Err(e) => bad_result("get_credential", &format!("NoEntry, but got {e:?}")),
    }
}

fn concurrent_access(_vm: JavaVM, _ctx: Context) -> keyring_core::Result<()> {
    let all = (0..64)
        .map(|_| {
            std::thread::spawn(|| {
                let entry = Entry::new("concurrent", "user").unwrap();
                entry.set_password("same").unwrap();
            })
        })
        .collect::<Vec<_>>();

    for t in all {
        t.join()
            .map_err(|_| keyring_core::Error::Invalid("join".to_string(), "failed".to_string()))?;
    }

    let entry = Entry::new("concurrent", "user")?;
    match entry.get_password() {
        Ok(p) if p.eq("same") => {}
        Ok(p) => return bad_result("get_password", &format!("'test2', got '{p}'")),
        Err(e) => return bad_result("get_password", &format!("'test2', got {e:?}")),
    }
    Ok(())
}
