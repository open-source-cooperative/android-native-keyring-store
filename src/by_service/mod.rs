use jni::{JNIEnv, JavaVM};

pub mod store;
pub use store::Store;

pub mod cred;
pub use cred::Cred;

pub const KEY_ALGORITHM_AES: &str = "AES";
pub const PROVIDER: &str = "AndroidKeyStore";
pub const PURPOSE_ENCRYPT: i32 = 1;
pub const PURPOSE_DECRYPT: i32 = 2;
pub const BLOCK_MODE_GCM: &str = "GCM";
pub const ENCRYPTION_PADDING_NONE: &str = "NoPadding";
pub const MODE_PRIVATE: i32 = 0;
pub const ENCRYPT_MODE: i32 = 1;
pub const DECRYPT_MODE: i32 = 2;
pub const CIPHER_TRANSFORMATION: &str = "AES/GCM/NoPadding";
pub const IV_LEN: usize = 12;

#[derive(thiserror::Error, Debug)]
pub enum AndroidKeyringError {
    #[error(transparent)]
    JniError(#[from] jni::errors::Error),
    #[error("Java exception was thrown")]
    JavaExceptionThrow,
    #[error("{1}")]
    CorruptedData(Vec<u8>, CorruptedData),
}

impl From<AndroidKeyringError> for keyring_core::Error {
    fn from(value: AndroidKeyringError) -> Self {
        match value {
            AndroidKeyringError::JniError(error) => {
                keyring_core::Error::PlatformFailure(Box::new(error))
            }
            e @ AndroidKeyringError::JavaExceptionThrow => {
                keyring_core::Error::PlatformFailure(Box::new(e))
            }
            AndroidKeyringError::CorruptedData(data, error) => {
                keyring_core::Error::BadDataFormat(data, Box::new(error))
            }
        }
    }
}

pub type AndroidKeyringResult<T> = Result<T, AndroidKeyringError>;

#[derive(thiserror::Error, Debug)]
pub enum CorruptedData {
    #[error("IV length not specified on entry")]
    MissingIvLen,
    #[error("IV length in data is {0}, but should be {expected}", expected=IV_LEN)]
    InvalidIvLen(usize),
    #[error("Data is too small to contain IV and ciphertext, length = {0}")]
    DataTooSmall(usize),
    #[error("Verification of data signature/MAC failed")]
    DecryptionFailure,
}

pub trait HasJavaVm {
    fn java_vm(&self) -> &JavaVM;

    fn check_for_exception<T, F>(&self, f: F) -> AndroidKeyringResult<T>
    where
        F: FnOnce(&mut JNIEnv) -> AndroidKeyringResult<T>,
    {
        let vm = self.java_vm();
        let mut env = vm.attach_current_thread()?;
        let t_result = f(&mut env);
        if env.exception_check()? {
            env.exception_describe()?;
            env.exception_clear()?;

            if t_result.is_ok() {
                return Err(AndroidKeyringError::JavaExceptionThrow);
            }
        }

        t_result
    }
}
