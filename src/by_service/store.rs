use std::{collections::HashMap, sync::Arc};

use jni::JavaVM;
use keyring_core::{Entry, api::CredentialStoreApi};

use crate::{error::AndroidKeyringResult, shared_preferences::Context};

use super::{Cred, HasJavaVm};

pub struct Store {
    java_vm: Arc<JavaVM>,
    context: Context,
    instance_id: String,
}

impl std::fmt::Debug for Store {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Store")
            .field("vendor", &self.vendor())
            .field("id", &self.id())
            .field("context", &self.context.id())
            .finish()
    }
}

impl Store {
    /// Initializes the store using the AndroidContext available
    /// on the `ndk-context` crate.
    pub fn from_ndk_context() -> AndroidKeyringResult<Arc<Self>> {
        let (java_vm, context) = crate::android_context()?;
        let context = Context::from_raw(context);
        let instance_id = generate_instance_id();
        Ok(Arc::new(Self {
            java_vm,
            context,
            instance_id,
        }))
    }
}

impl CredentialStoreApi for Store {
    fn vendor(&self) -> String {
        "Android SharedPreferences/KeyStore (Legacy), https://github.com/open-source-cooperative/android-native-keyring-store".to_string()
    }

    fn id(&self) -> String {
        self.instance_id.clone()
    }

    fn build(
        &self,
        service: &str,
        user: &str,
        _modifiers: Option<&HashMap<&str, &str>>,
    ) -> keyring_core::Result<Entry> {
        let credential = Cred::new(self.java_vm.clone(), self.context.clone(), service, user);

        Ok(Entry::new_with_credential(Arc::new(credential)))
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn debug_fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

impl HasJavaVm for Store {
    fn java_vm(&self) -> &JavaVM {
        &self.java_vm
    }
}

fn generate_instance_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    let now = SystemTime::now();
    let elapsed = if now.lt(&UNIX_EPOCH) {
        UNIX_EPOCH.duration_since(now).unwrap()
    } else {
        now.duration_since(UNIX_EPOCH).unwrap()
    };

    format!(
        "One File per Service storage, Crate version {}, Instantiated at {}",
        env!("CARGO_PKG_VERSION"),
        elapsed.as_secs_f64()
    )
}
