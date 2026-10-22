package io.crates.keyring

 import android.content.Context

 class KeyringTests {
     companion object {
         external fun runContextTests(context: Context): Boolean
         external fun runAllTests(context: Context);
     }
 }
