use std::{collections::HashMap, sync::Arc};

use jni::JavaVM;
use keyring_core::{Entry, api::CredentialStoreApi};

use crate::shared_preferences::Context;

use super::Cred;
use super::{AndroidKeyringResult, HasJavaVm};

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
    /// Initializes AndroidBuilder using the JNI context available
    /// on the `ndk-context` crate.
    pub fn from_ndk_context() -> AndroidKeyringResult<Arc<Self>> {
        let ctx = ndk_context::android_context();
        let vm = ctx.vm().cast();
        let activity = ctx.context();

        let java_vm = unsafe { JavaVM::from_raw(vm)? };
        let env = java_vm.attach_current_thread()?;

        let j_context = unsafe { jni::objects::JObject::from_raw(activity as jni::sys::jobject) };
        let context = Context::new(&env, j_context)?;
        let java_vm = Arc::new(env.get_java_vm()?);
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
        "Crate version {}, Instantiated at {}",
        env!("CARGO_PKG_VERSION"),
        elapsed.as_secs_f64()
    )
}
