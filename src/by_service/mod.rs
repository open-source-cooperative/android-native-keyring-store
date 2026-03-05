/*!
# Legacy Implementation

This module implements a single credential store that uses one SharedPreferences
file and Keystore entry _per service name_, rather than _per store name_.
This was the only implementation available in versions 0.5 and earlier of this
crate, but it is deprecated and may be removed in future versions.

# Migration Guide

If your application was built against the legacy implementation, it will continue to work
with the current implementation, but you should migrate your credentials from the legacy
store to a named store of your choosing.

The legacy store does not interact with named stores in any way, except in the unlikely event
that the named store's filename is the same as a legacy credential's service name.
So, to migrate a credential from the legacy store to a named store, an application
can simply

- Open both the legacy store and the target named store.
- Create an entry with the same service and username in both stores.
- Read the legacy credential's secret and write it to the named store.
- If desired, delete the legacy credential.

Since the legacy store doesn't support search, an application doing the migration
must know in advance which credentials are to be migrated. Here's some sample code
for how that might be done (targeting the default named store):

```rust
#[cfg(feature = "legacy")]
use android_native_keyring_store::{Store, LegacyStore};
fn main() -> keyring_core::Result<()> {
    let legacy_credentials = vec![("example.com", "user1"), ("example.com", "user2")];
    let legacy_store = LegacyStore::from_ndk_context()?;
    let named_store = Store::new()?;
    for (service, username) in legacy_credentials {
        let legacy_entry = legacy_store.build(service, username)?;
        let named_entry = named_store.build(service, username)?;
        named_entry.set_secret(&legacy_entry.get_secret()?);
        legacy_entry.delete_credential()?;
    }
    Ok(())
}
```

 */

pub mod store;
pub use store::Store;

pub mod cred;
use crate::error::{AndroidKeyringError, AndroidKeyringResult};
pub use cred::Cred;
use jni::{JNIEnv, JavaVM};

trait HasJavaVm {
    fn java_vm(&self) -> &JavaVM;

    fn check_for_exception<T, F>(&self, f: F) -> AndroidKeyringResult<T>
    where
        F: FnOnce(&mut JNIEnv) -> AndroidKeyringResult<T>,
    {
        let vm = self.java_vm();
        let mut env = vm.attach_current_thread()?;
        let t_result = f(&mut env);
        if env.exception_check()? {
            env.exception_describe()?;
            env.exception_clear()?;

            if t_result.is_ok() {
                return Err(AndroidKeyringError::JavaExceptionThrow);
            }
        }

        t_result
    }
}
