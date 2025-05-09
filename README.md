# Android Keyring

Pure Rust integration of Android's `KeyStore` and Android's `SharedPreferences`
with crate [keyring](https://crates.io/crates/keyring).

The Java API is called by using JNI, so no actual Java code needs to be inserted
in the end project. Only the initialization function as an instance of
`android.content.Context` is needed in order to fetch a `SharedPreferences`
instance.

## Experimental

This project should not be deemed mature enough for production level or
sensitive applications.

# Activating Android Keyring

Insert the following Kotlin code into your Android project:

    package io.crates.keyring;
    import android.content.Context
    class Keyring {
        companion object {
            init {
                // See Note 1
                System.loadLibrary("android_keyring")
            }

            external fun setAndroidKeyringCredentialBuilder(context: Context);
        }
    }

From your main activity, initialize the credential builder, e.g:

    class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        Keyring.setAndroidKeyringCredentialBuilder(this);

Note 1: This code expects that a library file `libandroid_keyring.so` was
compiled with the contents of this package. Depending on how the project is
managed, the library loading may need to be adjusted or not needed at all.
