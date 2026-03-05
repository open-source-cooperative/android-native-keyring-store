use std::ffi::CString;
use std::panic::catch_unwind;

use android_log_sys::{__android_log_write, LogPriority};

use keyring_core::Entry;

pub fn run_tests() -> (usize, usize) {
    let testing = [
        ("setup", setup as fn() -> keyring_core::Result<()>),
        ("golden_path", golden_path),
        ("delete_credential", delete_credential),
        ("concurrent_access", concurrent_access),
        ("teardown", teardown),
    ]
    .iter()
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

    let msg = c"Running LegacyStore tests...";
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
        "Legacy: {} successes, {} failures",
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

pub(crate) fn setup() -> keyring_core::Result<()> {
    let store = crate::LegacyStore::from_ndk_context()?;
    log::info!("Successfully created LegacyStore");
    keyring_core::set_default_store(store);
    cleanup()?;
    Ok(())
}

pub(crate) fn teardown() -> keyring_core::Result<()> {
    keyring_core::unset_default_store();
    Ok(())
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
    match entry.get_password() {
        Ok(s) => log::debug!("thread {s} finished last"),
        Err(e) => return Err(e),
    }
    Ok(())
}
