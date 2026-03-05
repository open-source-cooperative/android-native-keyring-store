use jni::JNIEnv;

use crate::{
    cipher::{Cipher, GCMParameterSpec},
    error::{AndroidKeyringError, AndroidKeyringResult, CorruptedData},
    keystore::Key,
};

const ENCRYPT_MODE: i32 = 1;
const DECRYPT_MODE: i32 = 2;
const CIPHER_TRANSFORMATION: &str = "AES/GCM/NoPadding";
const IV_LEN: usize = 12;

pub fn encrypt(env: &mut JNIEnv, key: Key, data: &[u8]) -> AndroidKeyringResult<Vec<u8>> {
    let cipher = Cipher::get_instance(env, CIPHER_TRANSFORMATION)?;
    cipher.init(env, ENCRYPT_MODE, &key)?;
    let iv = cipher.get_iv(env)?;
    assert_eq!(iv.len(), IV_LEN, "IV len is wrong, please file a bug!");
    let ciphertext = cipher.do_final(env, data)?;
    let iv_len = iv.len() as u8;
    let mut value = vec![iv_len];
    value.extend_from_slice(&iv);
    value.extend_from_slice(&ciphertext);
    Ok(value)
}

pub fn decrypt(env: &mut JNIEnv, key: Key, data: Vec<u8>) -> AndroidKeyringResult<Vec<u8>> {
    if data.is_empty() {
        let err = CorruptedData::MissingIvLen;
        return Err(AndroidKeyringError::CorruptedData(data, err));
    }
    let iv_len = data[0] as usize;
    if iv_len != IV_LEN {
        let err = CorruptedData::InvalidIvLen {
            actual: iv_len,
            expected: IV_LEN,
        };
        return Err(AndroidKeyringError::CorruptedData(data, err));
    }
    let ciphertext = &data[1..];
    let ciphertext_len = ciphertext.len();
    if ciphertext_len <= iv_len {
        let err = CorruptedData::DataTooSmall(ciphertext_len);
        return Err(AndroidKeyringError::CorruptedData(data, err));
    }
    let iv = &ciphertext[..iv_len];
    let iv = &iv[..iv_len];
    let ciphertext = &ciphertext[iv_len..];
    let spec = GCMParameterSpec::new(env, 128, iv)?;
    let cipher = Cipher::get_instance(env, CIPHER_TRANSFORMATION)?;
    cipher.init2(env, DECRYPT_MODE, &key, spec.into())?;
    let plaintext = cipher.do_final(env, ciphertext).map_err(move |_| {
        AndroidKeyringError::CorruptedData(data, CorruptedData::DecryptionFailure)
    })?;
    Ok(plaintext)
}
