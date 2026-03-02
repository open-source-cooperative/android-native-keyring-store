pub trait AndroidConstants {
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
    const IV_LEN: usize = 12;
}
