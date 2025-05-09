use android_log_sys::{__android_log_write, LogPriority};
use cipher::{Cipher, GCMParameterSpec};
use jni::{JNIEnv, objects::JObject};
use keystore::{KeyGenParameterSpecBuilder, KeyGenerator, KeyStore};
use shared_preferences::Context;
use std::ffi::{CStr, CString};

pub mod cipher;
pub mod keystore;
pub mod methods;
pub mod shared_preferences;

const KEY_ALGORITHM_AES: &str = "AES";
const PROVIDER: &str = "AndroidKeyStore";
const PURPOSE_ENCRYPT: i32 = 1;
const PURPOSE_DECRYPT: i32 = 2;
const BLOCK_MODE_GCM: &str = "GCM";
const ENCRYPTION_PADDING_NONE: &str = "NoPadding";
const MODE_PRIVATE: i32 = 0;
const ENCRYPT_MODE: i32 = 1;
const DECRYPT_MODE: i32 = 2;
const CIPHER_TRANSFORMATION: &str = "AES/GCM/NoPadding";

fn log<T: ToString>(data: T) {
    static TAG: &CStr = c"hello";
    let msg = CString::new(data.to_string()).unwrap();

    unsafe {
        __android_log_write(LogPriority::DEBUG as i32, TAG.as_ptr(), msg.as_ptr());
    }
}

fn logd<T: std::fmt::Debug>(data: T) {
    log(format!("{data:?}"));
}

// package com.example.myapplication
// class JniBridge {
//     external fun nativeInit(context: Context);
// }
//

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_example_myapplication_JniBridge_nativeInit<'local>(
    env: JNIEnv<'local>,
    _class: JObject<'local>,
    context: JObject<'local>,
) {
    if let Err(e) = run(env, context) {
        log("error");
        log(e.to_string());
        logd(e);
    }
}

fn run(mut env: JNIEnv<'_>, context: JObject) -> JResult<()> {
    log("hello from jni");
    let keystore = KeyStore::get_instance(&mut env, PROVIDER)?;
    log("got key store instance");
    keystore.load(&mut env)?;
    log("loaded keystore");

    let context = Context::new(&env, context)?;

    let alias = "keyring.key";

    let key = match keystore.get_key(&mut env, alias)? {
        Some(key) => {
            log("key present");
            key
        }
        None => {
            log("key absent, generating");
            let key_generator_spec = KeyGenParameterSpecBuilder::new(
                &mut env,
                alias,
                PURPOSE_DECRYPT | PURPOSE_ENCRYPT,
            )?
            .set_block_modes(&mut env, &[BLOCK_MODE_GCM])?
            .set_encryption_paddings(&mut env, &[ENCRYPTION_PADDING_NONE])?
            .set_user_authentication_required(&mut env, false)?
            .build(&mut env)?;
            log("generated key generator spec");
            let key_generator = KeyGenerator::get_instance(&mut env, KEY_ALGORITHM_AES, PROVIDER)?;
            key_generator.init(&mut env, key_generator_spec.into())?;
            let key = key_generator.generate_key(&mut env)?;
            log("generated key");
            key.into()
        }
    };

    let preferences = context.get_shared_preferences(&mut env, alias, MODE_PRIVATE)?;
    log("got preferences");

    let user = "test.user";

    let ciphertext = preferences.get_binary(&mut env, user)?;
    match ciphertext {
        Some(ciphertext) => {
            if ciphertext.is_empty() {
                return Err(jni::errors::Error::NullPtr("Bad length"));
            }

            let iv_len = ciphertext[0] as usize;
            let ciphertext = &ciphertext[1..];
            if ciphertext.len() < iv_len {
                return Err(jni::errors::Error::NullPtr("Bad length"));
            }

            log("ciphertext present, decrypting");

            let iv = &ciphertext[..iv_len];
            let ciphertext = &ciphertext[iv_len..];

            let spec = GCMParameterSpec::new(&mut env, 128, iv)?;
            let cipher = Cipher::get_instance(&mut env, CIPHER_TRANSFORMATION)?;
            cipher.init2(&mut env, DECRYPT_MODE, key, spec.into())?;
            let plaintext = cipher.do_final(&mut env, ciphertext)?;
            let plaintext = String::from_utf8_lossy(&plaintext);
            log(format!("plaintext decrypted: {plaintext:?}"));
        }
        None => {
            log("ciphertext absent, encrypting");

            let cipher = Cipher::get_instance(&mut env, CIPHER_TRANSFORMATION)?;
            cipher.init(&mut env, ENCRYPT_MODE, key)?;
            let iv = cipher.get_iv(&mut env)?;
            let ciphertext = cipher.do_final(&mut env, b"my secret password")?;

            let iv_len = iv.len() as u8;

            let edit = preferences.edit(&mut env)?;
            let mut value = vec![iv_len];
            value.extend_from_slice(&iv);
            value.extend_from_slice(&ciphertext);
            edit.put_binary(&mut env, user, &value)?;
            edit.commit(&mut env)?;
            log("encrypted password and saved to shared preferences");
        },
    }

    Ok(())
}

type JResult<T> = Result<T, jni::errors::Error>;
