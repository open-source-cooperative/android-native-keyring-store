use std::{
    process::Command,
    thread::sleep,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use keyring_core::{Error, Result};

use super::bad_result;
use crate::android_log::set_log;

const TARGET: &str = module_path!();

/// Routes a repeated `setLog` call, spans and events through the logcat layer and reads them back.
pub(super) fn logcat_routing() -> Result<()> {
    let marker = format!(
        "{:x}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    set_log("android_native_keyring_store=trace");
    {
        let outer = tracing::info_span!("outer", store = "check");
        let _outer = outer.enter();
        let inner = tracing::info_span!("inner", attempt = tracing::field::Empty);
        let _inner = inner.enter();
        inner.record("attempt", 2);
        let _bare = tracing::info_span!("bare").entered();
        tracing::warn!("routed {marker}");
        tracing::trace!("traced {marker}");
    }

    let expected = [
        format!(
            "W/{TARGET}: outer{{store=check}}:inner{{attempt=2}}:bare: {TARGET}: routed {marker}"
        ),
        format!(
            "V/{TARGET}: outer{{store=check}}:inner{{attempt=2}}:bare: {TARGET}: traced {marker}"
        ),
        "W/android_native_keyring_store::android_log: android_native_keyring_store::android_log: \
         Trying to initialize logger twice e=a global default trace dispatcher has already been set"
            .to_string(),
    ];
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let lines = own_logcat()?;
        let missing = expected
            .iter()
            .filter(|line| !lines.iter().any(|l| l == *line))
            .collect::<Vec<_>>();
        if missing.is_empty() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            log::error!("logcat lacks {missing:?}, has {lines:?}");
            return bad_result("logcat_routing", "the routed lines");
        }
        sleep(Duration::from_millis(100));
    }
}

/// The logcat lines this process wrote, in `tag` format.
fn own_logcat() -> Result<Vec<String>> {
    let output = Command::new("logcat")
        .args(["-d", "-v", "tag", "--pid", &std::process::id().to_string()])
        .output()
        .map_err(|e| Error::PlatformFailure(Box::new(e)))?;
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::to_string)
        .collect())
}
