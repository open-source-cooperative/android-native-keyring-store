package io.crates.keyring

 import android.content.Context

 class KeyringTests {
     companion object {
         external fun runByServiceTests(context: Context);
         external fun runByStoreTests(context: Context);
     }
 }
