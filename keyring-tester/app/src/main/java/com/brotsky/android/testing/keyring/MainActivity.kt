package com.brotsky.android.testing.keyring

import android.hardware.biometrics.BiometricManager.Authenticators
import android.hardware.biometrics.BiometricPrompt
import android.os.Bundle
import android.os.CancellationSignal
import android.util.Log
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import io.crates.keyring.Keyring
import io.crates.keyring.KeyringLog
import io.crates.keyring.KeyringTests
import javax.crypto.Cipher

class MainActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
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
        setContentView(R.layout.finish_tests)
        ViewCompat.setOnApplyWindowInsetsListener(findViewById(R.id.main)) { v, insets ->
            val systemBars = insets.getInsets(WindowInsetsCompat.Type.systemBars())
            v.setPadding(systemBars.left, systemBars.top, systemBars.right, systemBars.bottom)
            insets
        }
        runUnlockTests()
    }

    private fun runUnlockTests() {
        val first = KeyringTests.unlockTestsStart() ?: return
        approve(first, "Unlock the test store") { approved ->
            val second = KeyringTests.unlockTestsFirst(approved) ?: return@approve
            approve(second, "Unlock the test store again") { reapproved ->
                val third = KeyringTests.unlockTestsSecond(reapproved) ?: return@approve
                approve(third, "Unlock the test store with its new key") { renewed ->
                    Thread { KeyringTests.unlockTestsThird(renewed) }.start()
                }
            }
        }
    }

    private fun approve(cipher: Cipher, title: String, onApproved: (Cipher) -> Unit) {
        val prompt = BiometricPrompt.Builder(this)
            .setTitle(title)
            .setAllowedAuthenticators(Authenticators.BIOMETRIC_STRONG or Authenticators.DEVICE_CREDENTIAL)
            .build()
        val callback = object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                onApproved(result.cryptoObject.cipher!!)
            }

            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                Log.e("unit-test", "gated prompt error $errorCode: $errString")
            }
        }
        prompt.authenticate(BiometricPrompt.CryptoObject(cipher), CancellationSignal(), mainExecutor, callback)
    }
}