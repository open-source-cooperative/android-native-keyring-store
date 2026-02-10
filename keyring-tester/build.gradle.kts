// Top-level build file where you can add configuration options common to all sub-projects/modules.
plugins {
    alias(libs.plugins.android.application) apply false
    alias(libs.plugins.kotlin.android) apply false
}

val adb: String = providers.environmentVariable("ANDROID_HOME")
    .orElse(providers.systemProperty("android.home"))
    .map { "$it/platform-tools/adb" }
    .getOrElse("adb")

val appId = "com.brotsky.android.testing.keyring"
val pin = "1234"

tasks.register<Exec>("ensurePin") {
    description = "Ensures the emulator has a PIN lock screen configured"
    commandLine(adb, "shell", "locksettings", "set-pin", "--old", pin, pin)
    isIgnoreExitValue = true
}

tasks.register("unlockDevice") {
    description = "Locks then unlocks the device with PIN to refresh auth timeout"
    dependsOn("ensurePin")
    doLast {
        exec { commandLine(adb, "shell", "input", "keyevent", "KEYCODE_SLEEP") }
        Thread.sleep(1000)
        exec { commandLine(adb, "shell", "input", "keyevent", "KEYCODE_WAKEUP") }
        Thread.sleep(1000)
        exec { commandLine(adb, "shell", "input", "swipe", "540", "1800", "540", "400") }
        Thread.sleep(1000)
        exec { commandLine(adb, "shell", "input", "text", pin) }
        Thread.sleep(500)
        exec { commandLine(adb, "shell", "input", "keyevent", "KEYCODE_ENTER") }
        Thread.sleep(2000)
    }
}

tasks.register("runTests") {
    description = "Builds, installs, and runs the keyring test app on the connected device"
    dependsOn(":app:installDebug", "unlockDevice")
    doLast {
        exec { commandLine(adb, "logcat", "-c") }
        exec { commandLine(adb, "shell", "am", "force-stop", appId) }
        Thread.sleep(500)
        exec {
            commandLine(adb, "shell", "am", "start", "-n", "$appId/.MainActivity")
        }
        Thread.sleep(8000)
        val output = java.io.ByteArrayOutputStream()
        exec {
            commandLine(adb, "logcat", "-d", "-s", "unit-test")
            standardOutput = output
        }
        val results = output.toString()
        println(results)
        if (results.contains(" E unit-test:")) {
            throw GradleException("One or more tests failed. See logcat output above.")
        }
        if (!results.contains("All tests complete")) {
            throw GradleException("Tests did not complete. App may have crashed.")
        }
    }
}
