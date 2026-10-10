use std::ffi::CStr;

use android_log_sys::{__android_log_write, LogPriority};

/// Writes `message` to logcat under `tag`.
pub fn write(priority: LogPriority, tag: &CStr, message: &CStr) {
    // SAFETY: both pointers come from live `CStr`s.
    unsafe {
        __android_log_write(priority as i32, tag.as_ptr(), message.as_ptr());
    }
}
