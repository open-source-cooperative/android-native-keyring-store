package io.crates.keyring

import android.content.Context

class Keyring {
    companion object {
        init {
            System.loadLibrary("android_native_keyring_store")
        }

        external fun initializeNdkContext(context: Context);
    }
}
