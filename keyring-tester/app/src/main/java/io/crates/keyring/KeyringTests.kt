package io.crates.keyring

 import android.content.Context
 import javax.crypto.Cipher

 class KeyringTests {
     companion object {
         external fun runAllTests(context: Context);
         external fun unlockTestsStart(): Cipher?;
         external fun unlockTestsFirst(cipher: Cipher): Cipher?;
         external fun unlockTestsSecond(cipher: Cipher): Cipher?;
         external fun unlockTestsThird(cipher: Cipher);
     }
 }
