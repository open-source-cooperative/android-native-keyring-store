package io.crates.keyring

import android.content.Context

class KeyringLog {
    companion object {
        external fun setLog(filter: String)
    }
}
