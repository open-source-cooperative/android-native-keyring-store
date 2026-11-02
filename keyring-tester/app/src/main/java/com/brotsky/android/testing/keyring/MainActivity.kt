package com.brotsky.android.testing.keyring

import android.os.Bundle
import android.system.Os
import android.util.Log
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import io.crates.keyring.Keyring
import io.crates.keyring.KeyringLog
import io.crates.keyring.KeyringTests

class MainActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // Read by a coverage build of the library when it loads.
        Os.setenv("LLVM_PROFILE_FILE", "$filesDir/keyring.profraw", true)
        if (!intent.getBooleanExtra("context-tested", false)) {
            System.loadLibrary("android_native_keyring_store")
            check(KeyringTests.runContextTests(applicationContext))
        }
        Keyring.initializeNdkContext(applicationContext)
        enableEdgeToEdge()
        setContentView(R.layout.start_tests)
        ViewCompat.setOnApplyWindowInsetsListener(findViewById(R.id.main)) { v, insets ->
            val systemBars = insets.getInsets(WindowInsetsCompat.Type.systemBars())
            v.setPadding(systemBars.left, systemBars.top, systemBars.right, systemBars.bottom)
            insets
        }
        KeyringLog.setLog("android_native_keyring_store=trace")
        KeyringTests.runAllTests(applicationContext)
        val run = intent.getStringExtra("run") ?: "interactive"
        Log.i("unit-test", "Explicit foreground done run=$run")
        setContentView(R.layout.finish_tests)
        ViewCompat.setOnApplyWindowInsetsListener(findViewById(R.id.main)) { v, insets ->
            val systemBars = insets.getInsets(WindowInsetsCompat.Type.systemBars())
            v.setPadding(systemBars.left, systemBars.top, systemBars.right, systemBars.bottom)
            insets
        }
    }
}