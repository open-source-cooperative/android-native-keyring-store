# Android Credential Store

This crate provides management of Keyring credentials in Android's native `KeyStore` and `SharedPreferences` stores. Once this library has been loaded and initialized (as described below) by your application, other Rust code in your application can use this credential store.

## Usage

As usual for Keyring credential stores, you create a credential store by invoking `Store::new` (or `Store::new_with_configuration`). But in order for this to work, your application must first have initialized the `application_context` object provided by the [ndk-context crate](https://crates.io/crates/ndk-context) and also loaded this library.

A number of Android/Rust application frameworks, such as Dioxus Mobile, Tauri Mobile and the [android-activity crate](https://crates.io/crates/android-activity), already provide this initialization for you. If your framework does not, then this crate also provides an initialization function that you can invoke at your application's startup. To do this, you add a Java/Kotlin class `io.crates.keyring.Keyring` to your main application with the following content:

```kotlin
package io.crates.keyring;

import android.content.Context

class Keyring {
    companion object {
        init {
          	// see Note 1, below
            System.loadLibrary("android_native_keyring_store")
        }

        external fun initializeNdkContext(context: Context);
    }
}
```

Then, from your main activity, you have your app load the library and initialize the ndk-context:

```kotlin
    class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        Keyring.initializeNdkContext(this.applicationContext);
```

Note 1: This code expects that a library file `libandroid_native_keyring_store.so` was compiled with the contents of this package and attached to your application. See the next section for details on how to do that. It’s possible that your application framework may already provide a way to attach and pre-load external libraries. If so, you won’t need the `init` section above that loads the library.

## Building for Android

Because the Android/Rust ecosystem is still relatively new, there is a lot of conflicting and outdated information about how to build Rust code for Android. At the time of this writing, there are quite a few Gradle plugins that try to automate this process, as well as a number of Rust crates that try to make the process easier. But if you are new to Android programming or are having trouble getting these solutions to work, here is a bare-bones guide that shows how to build and attach this crate’s library manually to your application.

1. Start by getting the released sources of the version of this crate you want to use. In what follows, we’ll assume they’re in the folder named `~/src/android-native-keyring-store`.

2. Rust libraries for use in Android applications are invoked from the application via JNI. This means they must be compiled as dynamic libraries (`.so` files) that can be loaded by the Android runtime. This crate is already setup to build a `.so` library as well as a (Rust-only) `rlib`.

3. One way to attach `.so` files to an Android application is to add an `app/src/main/jniLibs` folder to your source tree, with subfolders for each of the Android API targets you wish to support (e.g., `arm64-v8a` and/or `x86-64`). Do this unless your application framework specifies some other way.

4. Now you need to build this crate specifying the appropriate `--target` for each of the Android API targets you are supporting.  For example, if you want to support the `arm64-v8a` Android target, you would specify the command:

   ```shell
   cargo build --target aarch64-linux-android --release
   ```

   There is a lot of consistent documentation on the web about which Android targets correspond to which cargo targets, so I won’t give more examples here.

5. Note that step (4) is likely to be a cross-compilation, because your dev machine is probably not an Android machine. This means that you will need both the appropriate rust standard libraries for that target and a linker for that target to be available:

   - The libaries are provided by the Rust team and can be installed via `rustup`. For example, to add the libraries needed in the example of step (4), you would invoke:

     ```shell
     rustup target add aarch64-linux-android
     ```

     Once you’ve installed the appropriate target libraries, Rust will know to use them.

   - The linker is provided by the Android NDK. In your NDK root folder you will find a folder called `toolchains` containing a folder called `llvm` containing a folder called `prebuilt` that finally contains a folder named for your development platform (e.g., mine starts with `darwin`). Inside that is a folder named `bin` that contains all the relevant linkers. Each of the linkers is named `<target-architecture><sdk-version>-clang`, where `target-architecture` is the Rust triple you build and `sdk-version` is the Android SDK generation you are building for. You will want to use the appropriate `clang` linker for the target architecture and sdk.

   - Now you have to tell Rust which linker to use for each target. To do this, create a `.cargo` subdirectory of your source directory `~/src/android_native_keyring_store`, and create a `config.toml` file in that directory. To this new file, add a pair of lines for each target you will be building. They each will look something like this (but with a path and target of your choosing):
     ```toml 
     [target.aarch64-linux-android]
     linker = "$NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64/bin/aarch64-linux-android29-clang"
     ```

     (You can also create these entries in your global `~/.cargo/config.toml` directory, in which case these linkers will be known to all projects on your machine. But since this entry has an SDK-version-specific value in it, you might not want to do that.)

6. Now that you’ve built for each of your desired Android targets, you need to copy the built `.so` files into the appropriate `jniLibs` subdirectory of your Android project. To avoid having to repeat this step every time you do a new build, it may be easier (if your dev platform supports it) to just place symbolic links in the `jniLibs` subdirectories.  For example, you could change into the `jniLibs/arm64-v8a` folder and give the command:

   ```shell
   ln -s ~/android_native_keyring_store/target/aarch64-linux-android/release/libandroid_native_keyring_store.so libandroid_native_keyring_store.so
   ```

   (Note that this symlink is to the release build of the library, which is probably the one you want to use in your application.)

## Changelog

See the [release history on GitHub](https://github.com/open-source-cooperative/android-native-keyring-store/releases).

## License

Licensed under either of

* Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
* MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you shall be dual licensed as above, without any additional terms or conditions.

