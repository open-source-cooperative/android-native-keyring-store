package io.crates.keyring

import android.content.Context
import android.content.ContextWrapper
import java.io.File
import javax.crypto.Cipher

class KeyringTests {
    companion object {
        fun runContextTests(context: Context): Boolean {
            val missingApplication = object : ContextWrapper(context) {
                override fun getApplicationContext(): Context? = null
            }
            val mismatchedStorage = object : ContextWrapper(context) {
                override fun getDataDir(): File = File(context.dataDir, "different-storage")
            }
            return runContextTestsWithInvalidContexts(context, missingApplication, mismatchedStorage)
        }

        private external fun runContextTestsWithInvalidContexts(
            context: Context,
            missingApplication: Context,
            mismatchedStorage: Context,
        ): Boolean

        external fun runAllTests(context: Context)
        external fun unlockTestsStart(): Cipher?
        external fun unlockTestsFirst(cipher: Cipher): Cipher?
        external fun unlockTestsSecond(cipher: Cipher): Cipher?
        external fun unlockTestsThird(cipher: Cipher)
    }
}
