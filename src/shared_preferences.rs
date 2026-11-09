use crate::methods::{ClassDecl, FromValue, JResult, Method, NoParam, SignatureComp, ToValue};
use base64::{Engine, prelude::BASE64_STANDARD};
use jni::{
    JNIEnv,
    objects::{AutoLocal, GlobalRef, JMap, JObject, JString, JValueGen},
};
use std::marker::PhantomData;

pub(crate) const MODE_PRIVATE: i32 = 0;

#[cfg(feature = "compile-tests")]
#[derive(Clone)]
pub(crate) struct Context {
    self_: GlobalRef,
}

#[cfg(feature = "compile-tests")]
impl Context {
    pub(crate) fn new(env: &JNIEnv, obj: JObject) -> JResult<Self> {
        Ok(Self {
            self_: env.new_global_ref(obj)?,
        })
    }

    pub(crate) fn get_shared_preferences(
        &self,
        env: &mut JNIEnv,
        name: &str,
        mode: i32,
    ) -> JResult<SharedPreferences> {
        get_shared_preferences(self.self_.as_obj(), env, name, mode)
    }
}

pub(crate) fn get_shared_preferences(
    context: &JObject,
    env: &mut JNIEnv,
    name: &str,
    mode: i32,
) -> JResult<SharedPreferences> {
    struct ThisMethod<'a>(PhantomData<&'a ()>);
    impl<'a> Method for ThisMethod<'a> {
        type Param = (&'a str, i32);
        type Return = SharedPreferences;

        const NAME: &'static str = "getSharedPreferences";
    }

    ThisMethod::call(context, env, (name, mode))
}

pub(crate) fn delete_shared_preferences(
    context: &JObject,
    env: &mut JNIEnv,
    name: &str,
) -> JResult<bool> {
    struct ThisMethod<'a>(PhantomData<&'a ()>);
    impl<'a> Method for ThisMethod<'a> {
        type Param = &'a str;
        type Return = bool;

        const NAME: &'static str = "deleteSharedPreferences";
    }

    ThisMethod::call(context, env, name)
}

pub(crate) struct SharedPreferences {
    self_: GlobalRef,
}

impl FromValue for SharedPreferences {
    fn signature() -> SignatureComp {
        Self::class().into()
    }

    fn from_object(self_: GlobalRef, _env: &mut JNIEnv) -> JResult<Self> {
        Ok(Self { self_ })
    }
}

impl SharedPreferences {
    fn class() -> ClassDecl {
        ClassDecl("Landroid/content/SharedPreferences;")
    }

    pub(crate) fn get_all(&self, env: &mut JNIEnv) -> JResult<SharedPreferencesKeys> {
        struct ThisMethod;
        impl Method for ThisMethod {
            type Param = NoParam;
            type Return = SharedPreferencesKeys;

            const NAME: &str = "getAll";
        }
        ThisMethod::call(&self.self_, env, NoParam)
    }

    pub(crate) fn contains(&self, env: &mut JNIEnv, key: &str) -> JResult<bool> {
        struct ThisMethod<'a>(PhantomData<&'a ()>);
        impl<'a> Method for ThisMethod<'a> {
            type Param = &'a str;
            type Return = bool;

            const NAME: &'static str = "contains";
        }
        ThisMethod::call(&self.self_, env, key)
    }

    pub(crate) fn get_string(&self, env: &mut JNIEnv, key: &str) -> JResult<Option<String>> {
        /// The `null` default `getString` returns for a missing key.
        struct NoDefault;
        impl ToValue for NoDefault {
            fn signature() -> SignatureComp {
                <&str as ToValue>::signature()
            }

            fn to_value<'a>(&self, _env: &mut JNIEnv<'a>) -> JResult<JValueGen<JObject<'a>>> {
                Ok(JObject::null().into())
            }
        }

        struct ThisMethod<'a>(PhantomData<&'a ()>);
        impl<'a> Method for ThisMethod<'a> {
            type Param = (&'a str, NoDefault);
            type Return = Option<String>;

            const NAME: &'static str = "getString";
        }
        ThisMethod::call(&self.self_, env, (key, NoDefault))
    }

    pub(crate) fn get_binary(&self, env: &mut JNIEnv, key: &str) -> JResult<Option<Vec<u8>>> {
        let Some(b64) = self.get_string(env, key)? else {
            return Ok(None);
        };

        Ok(match BASE64_STANDARD.decode(&b64) {
            Ok(data) => Some(data),
            Err(e) => {
                tracing::error!(%e, "Error decoding base64 data, ignoring value");
                tracing::debug!(?e, ?b64);
                None
            }
        })
    }

    pub(crate) fn edit(&self, env: &mut JNIEnv) -> JResult<SharedPreferencesEditor> {
        struct ThisMethod;
        impl Method for ThisMethod {
            type Param = NoParam;
            type Return = SharedPreferencesEditor;

            const NAME: &str = "edit";
        }
        ThisMethod::call(&self.self_, env, NoParam)
    }
}

pub(crate) struct SharedPreferencesEditor {
    self_: GlobalRef,
}
impl FromValue for SharedPreferencesEditor {
    fn signature() -> SignatureComp {
        Self::class().into()
    }

    fn from_object(self_: GlobalRef, _env: &mut JNIEnv) -> JResult<Self> {
        Ok(Self { self_ })
    }
}
impl SharedPreferencesEditor {
    fn class() -> ClassDecl {
        ClassDecl("Landroid/content/SharedPreferences$Editor;")
    }

    pub(crate) fn put_string(&self, env: &mut JNIEnv, key: &str, value: &str) -> JResult<Self> {
        struct ThisMethod<'a>(PhantomData<&'a ()>);
        impl<'a> Method for ThisMethod<'a> {
            type Param = (&'a str, &'a str);
            type Return = SharedPreferencesEditor;

            const NAME: &'static str = "putString";
        }
        ThisMethod::call(&self.self_, env, (key, value))
    }

    pub(crate) fn put_binary(&self, env: &mut JNIEnv, key: &str, value: &[u8]) -> JResult<Self> {
        let value = BASE64_STANDARD.encode(value);
        self.put_string(env, key, &value)
    }

    pub(crate) fn remove(&self, env: &mut JNIEnv, key: &str) -> JResult<Self> {
        struct ThisMethod<'a>(PhantomData<&'a ()>);
        impl<'a> Method for ThisMethod<'a> {
            type Param = &'a str;
            type Return = SharedPreferencesEditor;

            const NAME: &'static str = "remove";
        }
        ThisMethod::call(&self.self_, env, key)
    }

    pub(crate) fn commit(&self, env: &mut JNIEnv) -> JResult<bool> {
        struct ThisMethod;
        impl Method for ThisMethod {
            type Param = NoParam;
            type Return = bool;

            const NAME: &str = "commit";
        }
        ThisMethod::call(&self.self_, env, NoParam)
    }
}

pub(crate) struct SharedPreferencesKeys {
    self_: GlobalRef,
}
impl FromValue for SharedPreferencesKeys {
    fn signature() -> SignatureComp {
        Self::class().into()
    }
    fn from_object(self_: GlobalRef, _env: &mut JNIEnv) -> JResult<Self> {
        Ok(Self { self_ })
    }
}
impl SharedPreferencesKeys {
    fn class() -> ClassDecl {
        ClassDecl("Ljava/util/Map;")
    }

    pub(crate) fn get_keys(&self, env: &mut JNIEnv) -> JResult<Vec<String>> {
        let mut result = Vec::new();
        let j_map = JMap::from_env(env, self.self_.as_obj())?;
        let mut iterator = j_map.iter(env)?;
        while let Some((j_key, _)) = iterator.next(env)? {
            let j_key: AutoLocal<JString> = env.auto_local(j_key.into());
            let key_str = env.get_string(&j_key)?;
            result.push(key_str.into());
        }
        Ok(result)
    }
}
