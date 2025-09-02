use crate::{
    credential::{
        BLOCK_MODE_GCM, CorruptedData, ENCRYPTION_PADDING_NONE, KEY_ALGORITHM_AES, MODE_PRIVATE,
        PROVIDER, PURPOSE_DECRYPT, PURPOSE_ENCRYPT,
    },
    keystore::{KeyGenParameterSpecBuilder, KeyGenerator},
    shared_preferences::Context,
};
use android_log_sys::{__android_log_write, LogPriority};
use jni::{JNIEnv, JavaVM, objects::JObject};
use keyring_core::Entry;
use std::ffi::CString;

// package io.crates.keyring
// import android.content.Context
// class KeyringTests {
//     companion object {
//         external fun runTests(context: android.content.Context);
//     }
// }
#[unsafe(no_mangle)]
pub extern "system" fn Java_io_crates_keyring_KeyringTests_00024Companion_runTests(
    env: JNIEnv,
    _class: JObject,
    context: JObject,
) {
    let context = Context::new(&env, context).unwrap();
    let testing = [
        ("golden_path", golden_path as fn(JavaVM, Context)),
        ("delete_credential", delete_credential),
        ("missing_iv_len", missing_iv_len),
        ("data_too_small", data_too_small),
        ("invalid_iv", invalid_iv),
        ("decryption_failure", decryption_failure),
        ("concurrent_access", concurrent_access),
    ]
    .iter()
    .map(|(name, entry)| {
        let java_vm = env.get_java_vm().unwrap();
        let context = context.clone();
        (name, std::thread::spawn(move || entry(java_vm, context)))
    })
    .collect::<Vec<_>>();

    for (name, testing) in testing {
        let level;
        let msg;
        match testing.join() {
            Ok(()) => {
                level = LogPriority::INFO as i32;
                msg = format!("{name} success");
            }
            Err(e) => {
                let error = e.downcast_ref::<String>();
                level = LogPriority::ERROR as i32;
                msg = format!("{name} error: {error:?}");
            }
        }

        let msg = CString::new(msg).unwrap();
        let tag = c"unit-test";
        unsafe {
            __android_log_write(level, tag.as_ptr(), msg.as_ptr());
        }
    }
}

fn golden_path(_vm: JavaVM, _ctx: Context) {
    let entry1 = Entry::new("myservice", "myuser").unwrap();
    let entry2 = Entry::new("myservice", "myuser2").unwrap();
    let entry3 = Entry::new("myservice2", "myuser").unwrap();
    entry1.delete_credential().unwrap();
    entry2.delete_credential().unwrap();
    entry3.delete_credential().unwrap();

    entry1.set_password("test").unwrap();
    assert_eq!(entry1.get_password().unwrap(), "test");
    match entry2.get_password() {
        Err(keyring_core::Error::NoEntry) => {}
        x => panic!("unexpected result on entry2 get_password(): {x:?}"),
    };
    match entry3.get_password() {
        Err(keyring_core::Error::NoEntry) => {}
        x => panic!("unexpected result on entry3 get_password(): {x:?}"),
    };

    entry2.set_password("test2").unwrap();
    assert_eq!(entry2.get_password().unwrap(), "test2");

    entry3.set_password("test3").unwrap();
    assert_eq!(entry3.get_password().unwrap(), "test3");
}

fn delete_credential(_vm: JavaVM, _ctx: Context) {
    let entry1 = Entry::new("myservice", "delete-test").unwrap();

    entry1.set_password("test").unwrap();
    assert_eq!(entry1.get_password().unwrap(), "test");

    entry1.delete_credential().unwrap();
    match entry1.get_password() {
        Err(keyring_core::Error::NoEntry) => {}
        x => panic!("unexpected result on entry1 get_password(): {x:?}"),
    };
}

fn missing_iv_len(vm: JavaVM, ctx: Context) {
    let entry1 = Entry::new("missing-iv-len", "user").expect("Entry::new");
    entry1.set_password("test").expect("set_password");

    // Force setting entry to empty data
    {
        let mut env = vm.attach_current_thread().expect("attach_current_thread");
        let shared = ctx
            .get_shared_preferences(&mut env, "missing-iv-len", MODE_PRIVATE)
            .unwrap();
        let editor = shared.edit(&mut env).unwrap();
        editor.put_binary(&mut env, "user", &[]).unwrap();
        editor.commit(&mut env).unwrap();
    }

    match entry1.get_password() {
        Err(keyring_core::Error::BadDataFormat(_, error)) => {
            match error.downcast::<CorruptedData>().as_deref() {
                Ok(&CorruptedData::MissingIvLen) => (),
                x => panic!("unexpected result on corrupted get_password(): {x:?}"),
            }
        }
        x => panic!("unexpected result on corrupted get_password(): {x:?}"),
    }
}

fn data_too_small(vm: JavaVM, ctx: Context) {
    let entry1 = Entry::new("iv-too-big", "user").expect("Entry::new");
    entry1.set_password("test").expect("set_password");

    // Force setting entry to empty data
    {
        let mut env = vm.attach_current_thread().expect("attach_current_thread");
        let shared = ctx
            .get_shared_preferences(&mut env, "iv-too-big", MODE_PRIVATE)
            .unwrap();

        let mut original = shared.get_binary(&mut env, "user").unwrap().unwrap();
        original.truncate(13);
        let editor = shared.edit(&mut env).unwrap();
        editor.put_binary(&mut env, "user", &original).unwrap();
        editor.commit(&mut env).unwrap();
    }

    match entry1.get_password() {
        Err(keyring_core::Error::BadDataFormat(_, error)) => {
            match error.downcast::<CorruptedData>().as_deref() {
                Ok(&CorruptedData::DataTooSmall(12)) => (),
                x => panic!("unexpected result on corrupted get_password(): {x:?}"),
            }
        }
        x => panic!("unexpected result on corrupted get_password(): {x:?}"),
    }
}

fn invalid_iv(vm: JavaVM, ctx: Context) {
    let entry1 = Entry::new("invalid-iv", "user").expect("Entry::new");
    entry1.set_password("test").expect("set_password");

    const CIPHERTEXT_LEN: usize = "test".len() + 12 + 16;

    // Force setting entry to empty data
    {
        let mut env = vm.attach_current_thread().expect("attach_current_thread");
        let shared = ctx
            .get_shared_preferences(&mut env, "invalid-iv", MODE_PRIVATE)
            .unwrap();

        let mut original = shared.get_binary(&mut env, "user").unwrap().unwrap();
        original[0] = (CIPHERTEXT_LEN - 1) as u8;
        let editor = shared.edit(&mut env).unwrap();
        editor.put_binary(&mut env, "user", &original).unwrap();
        editor.commit(&mut env).unwrap();
    }

    match entry1.get_password() {
        Err(keyring_core::Error::BadDataFormat(_, error)) => {
            match error.downcast::<CorruptedData>().as_deref() {
                Ok(&CorruptedData::InvalidIvLen(31)) => (),
                x => panic!("unexpected result on corrupted get_password(): {x:?}"),
            }
        }
        x => panic!("unexpected result on corrupted get_password(): {x:?}"),
    }
}

fn decryption_failure(vm: JavaVM, _ctx: Context) {
    let entry1 = Entry::new("corrupted", "myuser").expect("Entry::new");
    entry1.set_password("test").expect("set_password");

    // Force generating new key in order to corrupt entry
    {
        let mut env = vm.attach_current_thread().expect("attach_current_thread");
        let env = &mut env;

        let key_generator_spec =
            KeyGenParameterSpecBuilder::new(env, "corrupted", PURPOSE_DECRYPT | PURPOSE_ENCRYPT)
                .expect("KeyGenParameterSpecBuilder::new")
                .set_block_modes(env, &[BLOCK_MODE_GCM])
                .expect("set_block_modes")
                .set_encryption_paddings(env, &[ENCRYPTION_PADDING_NONE])
                .expect("set_encryption_paddings")
                .set_user_authentication_required(env, false)
                .expect("set_user_authentication_required")
                .build(env)
                .expect("build");
        let key_generator =
            KeyGenerator::get_instance(env, KEY_ALGORITHM_AES, PROVIDER).expect("get_instance");
        key_generator
            .init(env, key_generator_spec.into())
            .expect("init");
        key_generator.generate_key(env).expect("generate_key");
    }

    match entry1.get_password() {
        Err(keyring_core::Error::BadDataFormat(_, error)) => {
            match error.downcast::<CorruptedData>().as_deref() {
                Ok(&CorruptedData::DecryptionFailure) => (),
                x => panic!("unexpected result on corrupted get_password(): {x:?}"),
            }
        }
        x => panic!("unexpected result on corrupted get_password(): {x:?}"),
    }

    entry1.set_password("reset").unwrap();
    assert_eq!(entry1.get_password().unwrap(), "reset");
}

fn concurrent_access(_vm: JavaVM, _ctx: Context) {
    let all = (0..64)
        .map(|_| {
            std::thread::spawn(|| {
                let entry = Entry::new("concurrent", "user").unwrap();
                entry.set_password("same").unwrap();
            })
        })
        .collect::<Vec<_>>();

    for t in all {
        t.join().unwrap();
    }

    let entry = Entry::new("concurrent", "user").unwrap();
    assert_eq!(entry.get_password().unwrap(), "same");
}
