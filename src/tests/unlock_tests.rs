use std::collections::HashMap;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Arc, Mutex};

use android_log_sys::LogPriority;
use jni::{JNIEnv, objects::JObject, sys::jobject};
use keyring_core::{Entry, Error, Result, api::CredentialStoreApi};

use super::{bad_result, report};
use crate::Store;

// The app approves each Cipher these return in a BiometricPrompt and passes it to the next one.

const CONFIG: [(&str, &str); 4] = [
    ("name", "unlock-test"),
    ("divider", "@"),
    ("user-auth-required", "true"),
    ("user-auth-timeout", "0"),
];

static TALLY: Mutex<(usize, usize)> = Mutex::new((0, 0));

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_crates_keyring_KeyringTests_00024Companion_unlockTestsStart(
    env: JNIEnv,
    _class: JObject,
) -> jobject {
    if !cfg!(feature = "user-auth-tests") {
        return std::ptr::null_mut();
    }
    *TALLY.lock().unwrap() = (0, 0);
    run("unlock_setup", cleanup);
    run("locked_store_refuses_secrets", locked_store_refuses_secrets);
    run(
        "unapproved_cipher_does_not_unlock",
        unapproved_cipher_does_not_unlock,
    );
    run(
        "only_the_latest_cipher_unlocks",
        only_the_latest_cipher_unlocks,
    );
    next_cipher(env)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_crates_keyring_KeyringTests_00024Companion_unlockTestsFirst(
    env: JNIEnv,
    _class: JObject,
    cipher: JObject,
) -> jobject {
    run("first_unlock_opens_every_instance", || {
        store()?.finish_unlock(&cipher)?;
        entry(&store()?)?.set_password("secret")?;
        expect_password(&store()?)
    });
    run("lock_closes_every_instance", || {
        store()?.lock()?;
        expect_no_access(entry(&store()?)?.get_password())
    });
    run("locked_store_finds_entries", || {
        let store = store()?;
        entry(&store)?.get_credential()?;
        match store.search(&HashMap::new())?.len() {
            1 => Ok(()),
            n => bad_result("search", &format!("1 entry, got {n:?}")),
        }
    });
    next_cipher(env)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_crates_keyring_KeyringTests_00024Companion_unlockTestsSecond(
    env: JNIEnv,
    _class: JObject,
    cipher: JObject,
) -> jobject {
    run("second_unlock_reads_earlier_secrets", || {
        store()?.finish_unlock(&cipher)?;
        expect_password(&store()?)
    });
    run("locked_store_deletes_entries", || {
        let store = store()?;
        store.lock()?;
        entry(&store)?.delete_credential()?;
        match entry(&store)?.get_credential() {
            Err(Error::NoEntry) => Ok(()),
            r => bad_result("get_credential", &format!("NoEntry, got {r:?}")),
        }
    });
    run("replace_key", || store()?.change_key());
    next_cipher(env)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_crates_keyring_KeyringTests_00024Companion_unlockTestsThird(
    _env: JNIEnv,
    _class: JObject,
    cipher: JObject,
) {
    run("new_key_unlocks_afresh", || {
        store()?.finish_unlock(&cipher)?;
        entry(&store()?)?.set_password("secret")?;
        expect_password(&store()?)
    });
    run("unlock_teardown", cleanup);
    let (successes, failures) = *TALLY.lock().unwrap();
    report(
        LogPriority::INFO,
        &format!("Unlock: {successes} successes, {failures} failures"),
    );
}

pub fn cleanup() -> Result<()> {
    crate::by_store::clear_vault_list();
    Store::delete(&HashMap::from(CONFIG))?;
    Ok(())
}

fn store() -> Result<Arc<Store>> {
    Store::new_with_configuration(&HashMap::from(CONFIG))
}

fn entry(store: &Arc<Store>) -> Result<Entry> {
    store.build("unlock-service", "unlock-user", None)
}

fn locked_store_refuses_secrets() -> Result<()> {
    let entry = entry(&store()?)?;
    expect_no_access(entry.set_password("secret"))?;
    expect_no_access(entry.get_password())
}

fn unapproved_cipher_does_not_unlock() -> Result<()> {
    let store = store()?;
    let cipher = store.begin_unlock()?;
    expect_no_access(store.finish_unlock(&cipher))?;
    expect_no_access(entry(&store)?.get_password())
}

fn only_the_latest_cipher_unlocks() -> Result<()> {
    let store = store()?;
    let first = store.begin_unlock()?;
    store.begin_unlock()?;
    match store.finish_unlock(&first) {
        Err(Error::Invalid(key, _)) if key == "cipher" => Ok(()),
        r => bad_result("finish_unlock", &format!("Invalid(cipher), got {r:?}")),
    }
}

fn expect_password(store: &Arc<Store>) -> Result<()> {
    match entry(store)?.get_password() {
        Ok(p) if p == "secret" => Ok(()),
        r => bad_result("get_password", &format!("'secret', got {r:?}")),
    }
}

fn expect_no_access<T: std::fmt::Debug>(result: Result<T>) -> Result<()> {
    match result {
        Err(Error::NoStorageAccess(_)) => Ok(()),
        r => bad_result("operation", &format!("NoStorageAccess, got {r:?}")),
    }
}

fn next_cipher(env: JNIEnv) -> jobject {
    let cipher = catch_unwind(|| store()?.begin_unlock());
    match cipher {
        Ok(Ok(cipher)) => env
            .new_local_ref(&cipher)
            .map_or(std::ptr::null_mut(), JObject::into_raw),
        _ => {
            record(
                "begin_unlock",
                Err(Error::Invalid("begin_unlock".into(), "failed".into())),
            );
            std::ptr::null_mut()
        }
    }
}

fn run(name: &str, test: impl FnOnce() -> Result<()>) {
    let result = catch_unwind(AssertUnwindSafe(test))
        .unwrap_or_else(|_| Err(Error::Invalid(name.to_string(), "panicked".to_string())));
    record(name, result);
}

fn record(name: &str, result: Result<()>) {
    let mut tally = TALLY.lock().unwrap();
    match result {
        Ok(()) => {
            tally.0 += 1;
            report(LogPriority::INFO, &format!("{name} success"));
        }
        Err(e) => {
            tally.1 += 1;
            report(LogPriority::ERROR, &format!("{name} error: {e:?}"));
        }
    }
}
