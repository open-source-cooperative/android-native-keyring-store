use std::sync::Arc;

use jni::{
    JNIEnv, JavaVM,
    objects::{GlobalRef, JObject, JString},
};
use keyring_core::{Error, Result};

use crate::{error::AndroidKeyringResult, throwable::Throwable};

/// An owned application context and its Android storage domain, independent of `ndk-context`.
#[derive(Clone)]
pub struct AndroidContext {
    pub(crate) inner: Arc<ContextData>,
}

pub(crate) struct ContextData {
    pub(crate) vm: JavaVM,
    pub(crate) reference: GlobalRef,
    storage_id: String,
}
struct LocalFrame<'env, 'local>(&'env mut JNIEnv<'local>);

impl Drop for LocalFrame<'_, '_> {
    fn drop(&mut self) {
        // SAFETY: The constructor pushed this frame and retains only global references outside it.
        let _ = unsafe { self.0.pop_local_frame(&JObject::null()) };
    }
}

impl AndroidContext {
    /// Retains the application context and storage domain of a callback's context.
    pub fn new(env: &mut JNIEnv, context: &JObject) -> Result<Self> {
        let result = (|| -> AndroidKeyringResult<Self> {
            if env.exception_check()? {
                return Err(jni::errors::Error::JavaException.into());
            }
            env.push_local_frame(16)?;
            let frame = LocalFrame(env);
            let env = &mut *frame.0;
            if context.is_null() || !env.is_instance_of(context, "android/content/Context")? {
                return Err(
                    Error::Invalid("context".into(), "must be an Android context".into()).into(),
                );
            }
            let sdk = env
                .get_static_field("android/os/Build$VERSION", "SDK_INT", "I")?
                .i()?;
            let device_protected = sdk >= 24
                && env
                    .call_method(context, "isDeviceProtectedStorage", "()Z", &[])?
                    .z()?;
            let application = env
                .call_method(
                    context,
                    "getApplicationContext",
                    "()Landroid/content/Context;",
                    &[],
                )?
                .l()?;
            if application.is_null() {
                return Err(
                    Error::Invalid("context".into(), "has no application context".into()).into(),
                );
            }
            let application = if sdk >= 24 {
                let method = if device_protected {
                    "createDeviceProtectedStorageContext"
                } else {
                    "createCredentialProtectedStorageContext"
                };
                env.call_method(&application, method, "()Landroid/content/Context;", &[])?
                    .l()?
            } else {
                application
            };
            let storage_id = data_directory(env, &application, sdk)?;
            if storage_id != data_directory(env, context, sdk)? {
                return Err(Error::Invalid(
                    "context".into(),
                    "does not use its application's storage domain".into(),
                )
                .into());
            }
            Ok(Self {
                inner: Arc::new(ContextData {
                    vm: env.get_java_vm()?,
                    reference: env.new_global_ref(application)?,
                    storage_id,
                }),
            })
        })();
        Throwable::take_pending(env).map_err(crate::error::AndroidKeyringError::from)?;
        result.map_err(Into::into)
    }

    pub(crate) fn same_storage(&self, other: &Self) -> bool {
        self.inner.vm.get_java_vm_pointer() == other.inner.vm.get_java_vm_pointer()
            && self.inner.storage_id == other.inner.storage_id
    }
}

fn data_directory(env: &mut JNIEnv, context: &JObject, sdk: i32) -> AndroidKeyringResult<String> {
    let directory = if sdk >= 24 {
        env.call_method(context, "getDataDir", "()Ljava/io/File;", &[])?
            .l()?
    } else {
        let info = env
            .call_method(
                context,
                "getApplicationInfo",
                "()Landroid/content/pm/ApplicationInfo;",
                &[],
            )?
            .l()?;
        let path = env.get_field(info, "dataDir", "Ljava/lang/String;")?.l()?;
        env.new_object("java/io/File", "(Ljava/lang/String;)V", &[(&path).into()])?
    };
    let path = JString::from(
        env.call_method(directory, "getCanonicalPath", "()Ljava/lang/String;", &[])?
            .l()?,
    );
    Ok(env.get_string(&path)?.into())
}
