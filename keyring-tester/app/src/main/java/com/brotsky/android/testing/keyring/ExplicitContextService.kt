package com.brotsky.android.testing.keyring

import android.app.Service
import android.content.Intent
import android.os.IBinder
import android.system.Os
import android.util.Log
import io.crates.keyring.KeyringTests

class ExplicitContextService : Service() {
    override fun onBind(intent: Intent): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val run = intent?.getStringExtra(EXTRA_RUN) ?: "interactive"
        // Read by a coverage build of the library when it loads.
        Os.setenv("LLVM_PROFILE_FILE", "${applicationContext.filesDir}/keyring.profraw", true)
        System.loadLibrary("android_native_keyring_store")
        Log.i(LOG_TAG, "Explicit prepare start run=$run")
        val ok = runCatching { KeyringTests.runContextTests(applicationContext) }
            .getOrElse {
                Log.e(LOG_TAG, "Explicit prepare error run=$run $it")
                false
            }
        Log.i(LOG_TAG, if (ok) "Explicit prepare done run=$run" else "Explicit prepare failed run=$run")
        stopSelf(startId)
        return START_NOT_STICKY
    }

    companion object {
        private const val LOG_TAG = "unit-test"
        const val EXTRA_RUN = "run"
    }
}
