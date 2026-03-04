use std::collections::HashMap;
use std::ffi::CString;
use std::panic::catch_unwind;

use android_log_sys::{__android_log_write, LogPriority};
use jni::{JNIEnv, JavaVM};

use keyring_core::{Entry, get_default_store};

use crate::{
    error::CorruptedData,
    shared_preferences::{Context, MODE_PRIVATE},
};

pub fn run_tests(env: JNIEnv, context: Context) -> (usize, usize) {
    let testing = [
        (
            "setup",
            setup as fn(JavaVM, Context) -> keyring_core::Result<()>,
        ),
        ("missing_iv_len", missing_iv_len),
        ("data_too_small", data_too_small),
        ("invalid_iv", invalid_iv),
        ("decryption_failure", decryption_failure),
        ("teardown", teardown),
    ]
    .iter()
    .map(|(name, entry)| {
        let java_vm = env.get_java_vm().unwrap();
        let context = context.clone();
        (name, move || -> keyring_core::Result<()> {
            catch_unwind(move || entry(java_vm, context))
                .map_err(|e| {
                    log::error!("Test {name} panicked: {e:?}");
                    bad_result(name, "panicked")
                })
                .unwrap_or_else(|e| e)
        })
    })
    .collect::<Vec<_>>();

    let msg = c"Running shared crypto tests...";
    let tag = c"unit-test";
    let level = LogPriority::INFO as i32;
    unsafe {
        __android_log_write(level, tag.as_ptr(), msg.as_ptr());
    }
    let mut successes = 0;
    let mut failures = 0;
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
    let msg = CString::new(format!(
        "Crypto: {} successes, {} failures",
        successes, failures
    ))
    .unwrap();
    let tag = c"unit-test";
    let level = LogPriority::INFO as i32;
    unsafe {
        __android_log_write(level, tag.as_ptr(), msg.as_ptr());
    }
    (successes, failures)
}

fn bad_result(op: &str, msg: &str) -> keyring_core::Result<()> {
    Err(keyring_core::Error::Invalid(
        op.to_string(),
        format!("should have returned {msg}"),
    ))
}

const STORE_CONFIG: [(&str, &str); 3] = [
    ("name", "crypto-test"),
    ("filename", "crypto-test"),
    ("divider", "@"),
];

fn setup(_vm: JavaVM, _context: Context) -> keyring_core::Result<()> {
    cleanup()?;
    let store_config = HashMap::from(STORE_CONFIG);
    let store = crate::Store::new_with_configuration(&store_config)?;
    log::info!("Store initialized with config: {:?}", store_config);
    keyring_core::set_default_store(store);
    Ok(())
}

fn teardown(_vm: JavaVM, _context: Context) -> keyring_core::Result<()> {
    keyring_core::unset_default_store();
    Ok(())
}

pub fn cleanup() -> keyring_core::Result<()> {
    // make sure there's nothing left from prior runs, and test store deletion
    // let store_config = HashMap::from([("name", "crypto-test"), ("filename", "crypto-test")]);
    let store_config = HashMap::from(STORE_CONFIG);
    if crate::Store::delete(&store_config)? {
        log::info!("crypto-test store successfully deleted");
    } else {
        log::info!("No crypto-test store found to delete");
    }
    Ok(())
}

fn missing_iv_len(vm: JavaVM, ctx: Context) -> keyring_core::Result<()> {
    let entry1 = Entry::new("missing-iv-len", "user")?;
    entry1.set_password("test")?;
    // Force setting entry to empty data
    {
        let mut env = vm.attach_current_thread().unwrap();
        let shared = ctx
            .get_shared_preferences(&mut env, "crypto-test", MODE_PRIVATE)
            .unwrap();
        let editor = shared.edit(&mut env).unwrap();
        editor
            .put_binary(&mut env, "user@missing-iv-len", &[])
            .unwrap();
        editor.commit(&mut env).unwrap();
    }
    match entry1.get_password() {
        Err(keyring_core::Error::BadDataFormat(_, error)) => {
            match error.downcast::<CorruptedData>().as_deref() {
                Ok(&CorruptedData::MissingIvLen) => {}
                x => return bad_result("missing_iv_len", &format!("CorruptedData, got {x:?}")),
            }
        }
        x => return bad_result("missing_iv_len", &format!("CorruptedData, got {x:?}")),
    };
    Ok(())
}

fn data_too_small(vm: JavaVM, ctx: Context) -> keyring_core::Result<()> {
    let entry1 = Entry::new("iv-too-big", "user")?;
    entry1.set_password("test")?;
    // Force setting entry to empty data
    {
        let mut env = vm.attach_current_thread().expect("attach_current_thread");
        let shared = ctx
            .get_shared_preferences(&mut env, "crypto-test", MODE_PRIVATE)
            .unwrap();
        let mut original = shared
            .get_binary(&mut env, "user@iv-too-big")
            .unwrap()
            .unwrap();
        original.truncate(13);
        let editor = shared.edit(&mut env).unwrap();
        editor
            .put_binary(&mut env, "user@iv-too-big", &original)
            .unwrap();
        editor.commit(&mut env).unwrap();
    }
    match entry1.get_password() {
        Err(keyring_core::Error::BadDataFormat(_, error)) => {
            match error.downcast::<CorruptedData>().as_deref() {
                Ok(&CorruptedData::DataTooSmall(12)) => (),
                x => return bad_result("data_too_small", &format!("CorruptedData, got {x:?}")),
            }
        }
        x => return bad_result("data_too_small", &format!("CorruptedData, got {x:?}")),
    }
    entry1.delete_credential()?;
    Ok(())
}

fn invalid_iv(vm: JavaVM, ctx: Context) -> keyring_core::Result<()> {
    let entry1 = Entry::new("invalid-iv", "user")?;
    entry1.set_password("test")?;
    const CIPHERTEXT_LEN: usize = "test".len() + 12 + 16;
    // Force setting entry to empty data
    {
        let mut env = vm.attach_current_thread().unwrap();
        let shared = ctx
            .get_shared_preferences(&mut env, "crypto-test", MODE_PRIVATE)
            .unwrap();
        let mut original = shared
            .get_binary(&mut env, "user@invalid-iv")
            .unwrap()
            .unwrap();
        original[0] = (CIPHERTEXT_LEN - 1) as u8;
        let editor = shared.edit(&mut env).unwrap();
        editor
            .put_binary(&mut env, "user@invalid-iv", &original)
            .unwrap();
        editor.commit(&mut env).unwrap();
    }
    match entry1.get_password() {
        Err(keyring_core::Error::BadDataFormat(_, error)) => {
            match error.downcast::<CorruptedData>().as_deref() {
                Ok(&CorruptedData::InvalidIvLen {
                    actual: 31,
                    expected: 12,
                }) => (),
                x => return bad_result("invalid_iv", &format!("CorruptedData, got {x:?}")),
            }
        }
        x => return bad_result("invalid_iv", &format!("CorruptedData, got {x:?}")),
    }
    entry1.delete_credential()?;
    Ok(())
}

fn decryption_failure(_vm: JavaVM, _ctx: Context) -> keyring_core::Result<()> {
    // create secret on entry with existing key
    let entry1 = Entry::new("corrupted", "my-user")?;
    entry1.set_password("test")?;
    // change the vault key
    {
        let cred_store = get_default_store().unwrap();
        let store = cred_store.as_any().downcast_ref::<crate::Store>().unwrap();
        store.change_key()?;
    }
    // try to read old-key secret with new key
    match entry1.get_password() {
        Err(keyring_core::Error::BadDataFormat(_, error)) => {
            match error.downcast::<CorruptedData>().as_deref() {
                Ok(&CorruptedData::DecryptionFailure) => (),
                x => return bad_result("decryption_failure", &format!("CorruptedData, got {x:?}")),
            }
        }
        x => return bad_result("decryption_failure", &format!("CorruptedData, got {x:?}")),
    }
    // now set and get entry with new key
    entry1.set_password("reset")?;
    match entry1.get_password() {
        Ok(p) if p.eq("reset") => {}
        Ok(p) => return bad_result("get_password", &format!("'reset', got '{p}'")),
        Err(e) => return bad_result("get_password", &format!("'reset', got {e:?}")),
    }
    entry1.delete_credential()?;
    Ok(())
}
