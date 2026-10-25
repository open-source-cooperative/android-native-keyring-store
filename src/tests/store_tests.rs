use std::collections::HashMap;
use std::panic::catch_unwind;

use android_log_sys::LogPriority;

use keyring_core::{Entry, api::CredentialStoreApi};

pub fn run_tests() -> (usize, usize) {
    let testing = [
        ("setup", setup as fn() -> keyring_core::Result<()>),
        ("golden_path", golden_path),
        ("delete_credential", delete_credential),
        ("concurrent_access", concurrent_access),
        ("search", search),
        ("entry_validation", entry_validation),
        ("existing_credential", existing_credential),
        ("teardown", teardown),
        ("user_auth_timeout", user_auth_timeout),
        ("lost_key", lost_key),
        ("exists", exists),
        ("configuration_mismatch", configuration_mismatch),
        ("default_store", default_store),
    ]
    .iter()
    // user_auth_timeout needs a secure lock screen and a device unlocked in the last 300 seconds.
    .filter(|(name, _)| cfg!(feature = "user-auth-tests") || *name != "user_auth_timeout")
    .map(|(name, entry)| {
        (name, move || -> keyring_core::Result<()> {
            catch_unwind(entry)
                .map_err(|e| {
                    log::error!("Test {name} panicked: {e:?}");
                    bad_result(name, "panicked")
                })
                .unwrap_or_else(|e| e)
        })
    })
    .collect::<Vec<_>>();

    super::report(LogPriority::INFO, "Running Store tests...");
    let mut successes = 0;
    let mut failures = 0;
    for (name, testing) in testing {
        let level;
        let msg;
        match testing() {
            Ok(()) => {
                level = LogPriority::INFO;
                msg = format!("{name} success");
                successes += 1;
            }
            Err(e) => {
                level = LogPriority::ERROR;
                msg = format!("{name} error: {e:?}");
                failures += 1;
            }
        }

        super::report(level, &msg);
    }
    super::report(
        LogPriority::INFO,
        &format!("Store: {} successes, {} failures", successes, failures),
    );
    (successes, failures)
}

fn bad_result(op: &str, msg: &str) -> keyring_core::Result<()> {
    Err(keyring_core::Error::Invalid(
        op.to_string(),
        format!("should have returned {msg}"),
    ))
}

const STORE_CONFIG: [(&str, &str); 2] = [("name", "test"), ("divider", "@")];

fn setup() -> keyring_core::Result<()> {
    cleanup()?;
    let store_config = HashMap::from(STORE_CONFIG);
    let store = crate::Store::new_with_configuration(&store_config)?;
    log::info!("Store initialized with config: {:?}", store_config);
    keyring_core::set_default_store(store);
    Ok(())
}

fn teardown() -> keyring_core::Result<()> {
    keyring_core::unset_default_store();
    let store_config = HashMap::from(STORE_CONFIG);
    match crate::Store::delete(&store_config) {
        Err(keyring_core::Error::NotSupportedByStore(_)) => (),
        r => return bad_result("delete", &format!("NotSupported, got {r:?}")),
    }
    Ok(())
}

pub fn cleanup() -> keyring_core::Result<()> {
    // make sure there's nothing left from prior runs, and test store deletion
    crate::Store::delete(&HashMap::from(AUTH_OPEN_CONFIG))?;
    crate::Store::delete(&HashMap::from(AUTH_EXPIRED_CONFIG))?;
    let store_config = HashMap::from(STORE_CONFIG);
    if crate::Store::delete(&store_config)? {
        log::info!("Test store successfully deleted");
    } else {
        log::info!("No test store found to delete");
    }
    Ok(())
}

fn golden_path() -> keyring_core::Result<()> {
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
    match entry3.get_password() {
        Ok(p) if p.eq("test3") => {}
        Ok(p) => return bad_result("get_password", &format!("'test3', got '{p}'")),
        Err(e) => return bad_result("get_password", &format!("'test3', got {e:?}")),
    }
    Ok(())
}

fn delete_credential() -> keyring_core::Result<()> {
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

fn concurrent_access() -> keyring_core::Result<()> {
    let all = (0..64)
        .map(|i| {
            let i_string = i.to_string();
            std::thread::spawn(move || {
                let entry = Entry::new("concurrent", "user").unwrap();
                entry.set_password(&i_string).unwrap();
                match entry.get_password() {
                    Ok(s) => {
                        if !i_string.eq(&s) {
                            log::info!("thread {i_string} got interleaved with thread {s}")
                        } else {
                            log::info!("thread {i_string} didn't get interleaved")
                        }
                    }
                    Err(e) => panic!("thread {i_string} failed: {e:?}"),
                };
            })
        })
        .collect::<Vec<_>>();
    for t in all {
        t.join().map_err(|e| {
            if e.is::<String>() {
                log::error!(
                    "Failed thread panic message: {}",
                    e.downcast::<String>().unwrap()
                );
            }
            keyring_core::Error::Invalid("join".to_string(), "failed".to_string())
        })?;
    }
    let entry = Entry::new("concurrent", "user")?;
    let s = entry.get_password()?;
    log::debug!("thread {s} finished last");
    Ok(())
}

fn search() -> keyring_core::Result<()> {
    Entry::new("search-service-only", "search-user-as-well")?.set_password("p")?;
    Entry::new("search-service-as-well", "search-user-only")?.set_password("p")?;
    let all = Entry::search(&HashMap::new())?;
    let all_specifiers: Vec<(String, String)> =
        all.iter().map(|e| e.get_specifiers().unwrap()).collect();
    log::info!("There are {} entries:\n{all_specifiers:?}", all.len());
    let user_only = Entry::search(&HashMap::from([("user", "only")]))?;
    if user_only.len() != 1 {
        return bad_result("user-only", &format!("1, got {}", user_only.len()));
    }
    let service = user_only[0].get_specifiers().unwrap().0;
    if service != "search-service-as-well" {
        let msg = format!("search-service-as-well, got {}", service);
        return bad_result("user-only service", &msg);
    }
    let service_only = Entry::search(&HashMap::from([("service", "only")]))?;
    if service_only.len() != 1 {
        return bad_result("service-only", &format!("1, got {}", service_only.len()));
    }
    let user = service_only[0].get_specifiers().unwrap().1;
    if user != "search-user-as-well" {
        let msg = format!("search-user-as-well, got {}", user);
        return bad_result("service-only user", &msg);
    }
    let both = Entry::search(&HashMap::from([("id", "only")]))?;
    if both.len() != 2 {
        return bad_result("both", &format!("2, got {}", both.len()));
    }
    Ok(())
}

fn entry_validation() -> keyring_core::Result<()> {
    for (service, user, key) in [("a@b", "user", "service"), ("service", "u@x", "user")] {
        match Entry::new(service, user) {
            Err(keyring_core::Error::Invalid(k, _)) if k == key => {}
            r => return bad_result("new", &format!("Invalid({key}), got {r:?}")),
        }
    }
    let modifiers = HashMap::from([("color", "blue")]);
    match Entry::new_with_modifiers("service", "user", &modifiers) {
        Err(keyring_core::Error::NotSupportedByStore(_)) => {}
        r => return bad_result("new_with_modifiers", &format!("NotSupported, got {r:?}")),
    }
    for key in ["id", "service", "user"] {
        match Entry::search(&HashMap::from([(key, "(")])) {
            Err(keyring_core::Error::Invalid(k, _)) if k == key => {}
            r => return bad_result("search", &format!("Invalid({key}), got {r:?}")),
        }
    }
    match Entry::new("my-service", "never-set")?.delete_credential() {
        Err(keyring_core::Error::NoEntry) => Ok(()),
        r => bad_result("delete_credential", &format!("NoEntry, got {r:?}")),
    }
}

fn existing_credential() -> keyring_core::Result<()> {
    let entry = Entry::new("my-service", "existing-test")?;
    entry.set_password("existing")?;
    match entry.get_credential()?.get_password() {
        Ok(p) if p == "existing" => {}
        r => return bad_result("get_credential", &format!("'existing', got {r:?}")),
    }
    entry.delete_credential()
}

const AUTH_OPEN_CONFIG: [(&str, &str); 4] = [
    ("name", "auth-open-test"),
    ("divider", "@"),
    ("user-auth-required", "true"),
    ("user-auth-timeout", "300"),
];
const AUTH_EXPIRED_CONFIG: [(&str, &str); 4] = [
    ("name", "auth-expired-test"),
    ("divider", "@"),
    ("user-auth-required", "true"),
    ("user-auth-timeout", "1"),
];

fn user_auth_timeout() -> keyring_core::Result<()> {
    let store = crate::Store::new_with_configuration(&HashMap::from(AUTH_OPEN_CONFIG))?;
    let entry = store.build("auth", "user", None)?;
    entry.set_password("open")?;
    match entry.get_password() {
        Ok(p) if p == "open" => {}
        r => return bad_result("get_password", &format!("'open', got {r:?}")),
    }
    let store = crate::Store::new_with_configuration(&HashMap::from(AUTH_EXPIRED_CONFIG))?;
    let entry = store.build("auth", "user", None)?;
    std::thread::sleep(std::time::Duration::from_secs(2));
    match entry.set_password("expired") {
        Err(keyring_core::Error::NoStorageAccess(_)) => Ok(()),
        r => bad_result("set_password", &format!("NoStorageAccess, got {r:?}")),
    }
}

const LOST_KEY_CONFIG: [(&str, &str); 2] = [("name", "lost-key-test"), ("divider", "@")];

fn lost_key() -> keyring_core::Result<()> {
    let config = HashMap::from(LOST_KEY_CONFIG);
    crate::Store::delete(&config)?;
    let store = crate::Store::new_with_configuration(&config)?;
    store
        .build("lost-service", "lost-user", None)?
        .set_password("p")?;
    store.remove_key()?;
    drop(store);
    crate::by_store::clear_vault_list();
    match crate::Store::new_with_configuration(&config) {
        Err(keyring_core::Error::BadStoreFormat(_)) => {}
        r => {
            return bad_result(
                "new_with_configuration",
                &format!("BadStoreFormat, got {r:?}"),
            );
        }
    }
    // A different config is refused even without the key, and removes nothing.
    let other = HashMap::from([("name", "lost-key-test"), ("divider", "#")]);
    match crate::Store::delete(&other) {
        Err(keyring_core::Error::Invalid(key, _)) if key == "divider" => {}
        r => return bad_result("delete", &format!("Invalid(divider), got {r:?}")),
    }
    if !crate::Store::delete(&config)? {
        return bad_result("delete", "true for a store whose key is gone");
    }
    let store = crate::Store::new_with_configuration(&config)?;
    match store
        .build("lost-service", "lost-user", None)?
        .get_password()
    {
        Err(keyring_core::Error::NoEntry) => {}
        r => {
            return bad_result(
                "get_password",
                &format!("NoEntry after the wipe, got {r:?}"),
            );
        }
    }
    // A keyless store without credentials is recreated.
    store.remove_key()?;
    drop(store);
    crate::by_store::clear_vault_list();
    crate::Store::new_with_configuration(&config)?;
    crate::by_store::clear_vault_list();
    crate::Store::delete(&config)?;
    Ok(())
}

const EXISTS_CONFIG: [(&str, &str); 2] = [("name", "exists-test"), ("divider", "@")];

fn exists() -> keyring_core::Result<()> {
    let config = HashMap::from(EXISTS_CONFIG);
    crate::Store::delete(&config)?;
    let expect = |op: &str, expected: bool| -> keyring_core::Result<()> {
        match crate::Store::exists(&config) {
            Ok(found) if found == expected => Ok(()),
            r => bad_result(op, &format!("{expected}, got {r:?}")),
        }
    };
    expect("exists before creation", false)?;
    // Checking creates nothing that delete could find.
    if crate::Store::delete(&config)? {
        return bad_result("delete", "false after exists on a missing store");
    }
    let store = crate::Store::new_with_configuration(&config)?;
    expect("exists while open", true)?;
    store
        .build("exists-service", "exists-user", None)?
        .set_password("p")?;
    store.remove_key()?;
    drop(store);
    crate::by_store::clear_vault_list();
    expect("exists with credentials and no key", true)?;
    let other = HashMap::from([("name", "exists-test"), ("divider", "#")]);
    match crate::Store::exists(&other) {
        Err(keyring_core::Error::Invalid(key, _)) if key == "divider" => {}
        r => return bad_result("exists", &format!("Invalid(divider), got {r:?}")),
    }
    crate::Store::delete(&config)?;
    expect("exists after delete", false)?;
    // A keyless file without credentials loses nothing, so it counts as absent.
    let store = crate::Store::new_with_configuration(&config)?;
    store.remove_key()?;
    drop(store);
    crate::by_store::clear_vault_list();
    expect("exists without key or credentials", false)?;
    crate::Store::new_with_configuration(&config)?;
    crate::by_store::clear_vault_list();
    crate::Store::delete(&config)?;
    Ok(())
}

const MISMATCH_CONFIG: [(&str, &str); 2] = [("name", "mismatch-test"), ("divider", "@")];

fn configuration_mismatch() -> keyring_core::Result<()> {
    let config = HashMap::from(MISMATCH_CONFIG);
    crate::Store::delete(&config)?;
    let expect_invalid = |attempt: &[(&str, &str)], expected: &str| -> keyring_core::Result<()> {
        let attempt = attempt.iter().copied().collect::<HashMap<_, _>>();
        match crate::Store::new_with_configuration(&attempt) {
            Err(keyring_core::Error::Invalid(key, _)) if key == expected => Ok(()),
            r => bad_result(
                "new_with_configuration",
                &format!("Invalid({expected}), got {r:?}"),
            ),
        }
    };
    let store = crate::Store::new_with_configuration(&config)?;
    expect_invalid(
        &[
            ("name", "mismatch-test"),
            ("filename", "keyring-other"),
            ("divider", "@"),
        ],
        "filename",
    )?;
    expect_invalid(
        &[
            ("name", "mismatch-test"),
            ("divider", "@"),
            ("user-auth-required", "true"),
            ("user-auth-timeout", "30"),
        ],
        "user-auth-timeout",
    )?;
    drop(store);
    crate::by_store::clear_vault_list();
    expect_invalid(
        &[
            ("name", "other-name"),
            ("filename", "keyring-mismatch-test"),
            ("divider", "@"),
        ],
        "name",
    )?;
    crate::Store::delete(&config)?;
    Ok(())
}

fn default_store() -> keyring_core::Result<()> {
    let default = HashMap::new();
    crate::Store::delete(&default)?;
    let store = crate::Store::new()?;
    let entry = store.build("default-service", "default-user", None)?;
    entry.set_password("default")?;
    match entry.get_password() {
        Ok(p) if p == "default" => {}
        r => return bad_result("get_password", &format!("'default', got {r:?}")),
    }
    drop(entry);
    drop(store);
    crate::by_store::clear_vault_list();
    if !crate::Store::delete(&default)? {
        return bad_result("delete", "true for the default store");
    }
    Ok(())
}
