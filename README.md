# Android Keyring

Pure Rust integration of Android's `KeyStore` and Android's `SharedPreferences`
with crate [keyring](https://crates.io/crates/keyring).

The Java API is called by using JNI, so no actual Java code needs to be inserted
in the project.

## Experimental

This project should not be deemed mature enough for production level or
sensitive applications.

# Initialization

There are two options for setting Android Keyring as the default entry builder
for `keyring-rs`.

## `ndk-context` (Recommended)

This option is the recommended option and works out of box for projects that do
setup `ndk-context`, (e.g., Dioxus Mobile, Tauri Mobile and android-activity).

Invoke the initialization function once on the startup of the project:

```rust
android_keyring::set_android_keyring_credential_builder().unwrap();
```

# Manual initialization through Java/Kotlin Code

If the project does not support `ndk-context` (e.g. Flutter/FRB), then
Java/Kotlin code must be inserted into the project so that the Andorid Keyring
application has access to the JNI context and the Android's Activity context.

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
