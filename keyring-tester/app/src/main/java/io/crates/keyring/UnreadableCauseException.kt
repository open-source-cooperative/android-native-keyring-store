package io.crates.keyring

import java.security.InvalidKeyException

/** An `InvalidKeyException` whose cause cannot be read, so inspecting it fails. */
class UnreadableCauseException : InvalidKeyException() {
    override val cause: Throwable?
        get() = throw IllegalStateException("unreadable cause")
}
