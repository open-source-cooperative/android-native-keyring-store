use std::{
    collections::HashMap,
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{Arc, mpsc},
    time::Duration,
};

use android_log_sys::LogPriority;
use jni::{JNIEnv, objects::JObject, sys::jboolean};
use keyring_core::{Entry, Error, Result, api::CredentialStoreApi};

use crate::{
    AndroidContext, Store,
    by_store::{clear_vault_list, store::StoreConfig},
    error::AndroidKeyringResult,
    keystore::{KeyStore, PROVIDER},
};

const CONFIG: [(&str, &str); 1] = [("name", "explicit-context-test")];
const DEVICE_CONFIG: [(&str, &str); 1] = [("name", "explicit-device-test")];

#[allow(non_snake_case)]
#[unsafe(no_mangle)]
pub extern "system" fn Java_io_crates_keyring_KeyringTests_00024Companion_runContextTestsWithInvalidContexts(
    mut env: JNIEnv,
    _class: JObject,
    context: JObject,
    missing_application: JObject,
    mismatched_storage: JObject,
) -> jboolean {
    match catch_unwind(AssertUnwindSafe(|| {
        before_activity(
            &mut env,
            &context,
            [&missing_application, &mismatched_storage],
        )
    })) {
        Ok(Ok(())) => true.into(),
        failure => {
            super::report(
                LogPriority::ERROR,
                &format!("Explicit context failed {failure:?}"),
            );
            false.into()
        }
    }
}

fn store(context: AndroidContext) -> Result<Arc<Store>> {
    Store::new_with_context(
        context,
        StoreConfig::from_configuration(&HashMap::from(CONFIG))?,
    )
}

fn credential(store: &Arc<Store>) -> Result<Entry> {
    store.build("notification", "callback", None)
}

fn before_activity(
    env: &mut JNIEnv,
    context: &JObject,
    invalid_contexts: [&JObject; 2],
) -> AndroidKeyringResult<()> {
    assert!(
        matches!(AndroidContext::new(env, &JObject::null()), Err(Error::Invalid(key, _)) if key == "context")
    );
    let wrong = env.new_string("not a context")?;
    assert!(
        matches!(AndroidContext::new(env, wrong.as_ref()), Err(Error::Invalid(key, _)) if key == "context")
    );
    env.throw_new(
        "java/lang/IllegalStateException",
        "pending context exception",
    )?;
    assert!(matches!(
        AndroidContext::new(env, context),
        Err(Error::PlatformFailure(_))
    ));
    assert!(!env.exception_check()?);
    let global = env.new_global_ref(context)?;
    let android = AndroidContext::new(env, global.as_obj())?;
    drop(global);
    let device = env
        .call_method(
            context,
            "createDeviceProtectedStorageContext",
            "()Landroid/content/Context;",
            &[],
        )?
        .l()?;
    let device = AndroidContext::new(env, &device)?;
    let configuration = HashMap::from(CONFIG);
    let device_configuration = HashMap::from(DEVICE_CONFIG);
    clear_vault_list();
    Store::delete_with_context(&android, &configuration)?;
    Store::delete_with_context(&device, &configuration)?;
    Store::delete_with_context(&device, &device_configuration)?;
    assert!(!Store::exists_with_context(&android, &configuration)?);
    assert!(!Store::delete_with_context(&android, &configuration)?);
    for invalid in invalid_contexts {
        assert!(
            matches!(AndroidContext::new(env, invalid), Err(Error::Invalid(key, _)) if key == "context")
        );
        assert!(!env.exception_check()?);
        let recovered = store(AndroidContext::new(env, context)?)?;
        let entry = credential(&recovered)?;
        entry.set_password("callback-key")?;
        assert_eq!(entry.get_password()?, "callback-key");
    }
    {
        let retained = android.clone();
        let (sender, receiver) = mpsc::channel();
        std::thread::spawn(move || {
            let result = (|| -> Result<_> {
                let store = store(retained)?;
                credential(&store)?.set_password("callback-key")?;
                Ok(store)
            })();
            let _ = sender.send(("context-lifetime", result));
        });
        let (id, result) = receiver
            .recv_timeout(Duration::from_secs(30))
            .map_err(|e| Error::Invalid("context-lifetime".into(), e.to_string()))?;
        assert_eq!(id, "context-lifetime");
        let retained = result?;
        let entry = credential(&retained)?;
        assert_eq!(entry.get_password()?, "callback-key");
        assert!(Store::exists_with_context(&android, &configuration)?);
        assert!(matches!(
            Store::delete_with_context(&android, &configuration),
            Err(Error::NotSupportedByStore(_))
        ));
        let another = AndroidContext::new(env, context)?;
        assert_eq!(
            credential(&store(another.clone())?)?.get_password()?,
            "callback-key"
        );
        let mut conflicting = configuration.clone();
        conflicting.insert("divider", "#");
        assert!(
            matches!(Store::new_with_context(another.clone(), StoreConfig::from_configuration(&conflicting)?), Err(Error::Invalid(key, _)) if key == "divider")
        );
        assert!(
            matches!(Store::exists_with_context(&another, &conflicting), Err(Error::Invalid(key, _)) if key == "divider")
        );
        assert!(!Store::exists_with_context(&device, &configuration)?);
        assert!(!Store::delete_with_context(&device, &configuration)?);
        // Keystore keys are named by filename in both storage domains, so the name is taken.
        assert!(matches!(
            Store::new_with_context(
                device.clone(),
                StoreConfig::from_configuration(&configuration)?
            ),
            Err(Error::BadStoreFormat(_))
        ));
        assert!(!Store::exists_with_context(&device, &configuration)?);
        let isolated = Store::new_with_context(
            device.clone(),
            StoreConfig::from_configuration(&device_configuration)?,
        )?;
        credential(&isolated)?.set_password("device-key")?;
        assert_eq!(entry.get_password()?, "callback-key");
        assert_eq!(credential(&isolated)?.get_password()?, "device-key");
        let keystore = KeyStore::get_instance(env, PROVIDER)?;
        keystore.load(env)?;
        assert!(keystore.contains_alias(env, "keyring-explicit-device-test")?);
    }
    clear_vault_list();
    assert!(Store::delete_with_context(&device, &device_configuration)?);
    assert!(!Store::exists_with_context(&device, &device_configuration)?);
    assert_eq!(
        credential(&store(android.clone())?)?.get_password()?,
        "callback-key"
    );
    #[cfg(feature = "user-auth-tests")]
    authentication(&android)?;
    Ok(())
}

#[cfg(feature = "user-auth-tests")]
fn authentication(context: &AndroidContext) -> Result<()> {
    let configuration = HashMap::from([
        ("name", "explicit-auth-test"),
        ("user-auth-required", "true"),
        ("user-auth-timeout", "1"),
    ]);
    Store::delete_with_context(context, &configuration)?;
    {
        let gated = Store::new_with_context(
            context.clone(),
            StoreConfig::from_configuration(&configuration)?,
        )?;
        std::thread::sleep(Duration::from_secs(2));
        assert!(matches!(
            gated
                .build("service", "user", None)?
                .set_password("expired"),
            Err(Error::NoStorageAccess(_))
        ));
        assert_eq!(
            credential(&store(context.clone())?)?.get_password()?,
            "callback-key"
        );
    }
    clear_vault_list();
    Store::delete_with_context(context, &configuration)?;
    assert_eq!(
        credential(&store(context.clone())?)?.get_password()?,
        "callback-key"
    );
    Ok(())
}

pub fn after_activity() -> Result<()> {
    {
        let global = Store::new_with_configuration(&HashMap::from(CONFIG))?;
        let explicit = store(crate::android_context()?)?;
        let entry = credential(&global)?;
        assert_eq!(entry.get_password()?, "callback-key");
        entry.set_password("foreground-key")?;
        assert_eq!(credential(&explicit)?.get_password()?, "foreground-key");
    }
    clear_vault_list();
    assert!(Store::delete_with_context(
        &crate::android_context()?,
        &HashMap::from(CONFIG)
    )?);
    assert!(!Store::exists(&HashMap::from(CONFIG))?);
    Ok(())
}

pub fn cleanup() -> Result<()> {
    Store::delete(&HashMap::from(CONFIG)).map(|_| ())
}
