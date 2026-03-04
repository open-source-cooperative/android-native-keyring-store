use crate::methods::{ClassDecl, FromValue, JResult, Method, NoParam, SignatureComp};
use base64::{Engine, prelude::BASE64_STANDARD};
use jni::objects::{AutoLocal, JMap, JString};
use jni::{
    JNIEnv,
    objects::{GlobalRef, JObject},
};
use std::marker::PhantomData;

pub const MODE_PRIVATE: i32 = 0;

#[derive(Clone)]
pub struct Context {
    self_: GlobalRef,
}

impl Context {
    pub fn new(env: &JNIEnv, obj: JObject) -> JResult<Self> {
        Ok(Self {
            self_: env.new_global_ref(obj)?,
        })
    }

    pub fn from_raw(self_: GlobalRef) -> Self {
        Self { self_ }
    }

    pub fn get_shared_preferences(
        &self,
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

        ThisMethod::call(&self.self_, env, (name, mode))
    }

    pub fn delete_shared_preferences(&self, env: &mut JNIEnv, name: &str) -> JResult<bool> {
        struct ThisMethod<'a>(PhantomData<&'a ()>);
        impl<'a> Method for ThisMethod<'a> {
            type Param = &'a str;
            type Return = bool;

            const NAME: &'static str = "deleteSharedPreferences";
        }

        ThisMethod::call(&self.self_, env, name)
    }

    pub fn id(&self) -> usize {
        self.self_.as_raw() as usize
    }
}

pub struct SharedPreferences {
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

    pub fn get_all(&self, env: &mut JNIEnv) -> JResult<SharedPreferencesKeys> {
        struct ThisMethod;
        impl Method for ThisMethod {
            type Param = NoParam;
            type Return = SharedPreferencesKeys;

            const NAME: &str = "getAll";
        }
        ThisMethod::call(&self.self_, env, NoParam)
    }

    pub fn contains(&self, env: &mut JNIEnv, key: &str) -> JResult<bool> {
        struct ThisMethod<'a>(PhantomData<&'a ()>);
        impl<'a> Method for ThisMethod<'a> {
            type Param = &'a str;
            type Return = bool;

            const NAME: &'static str = "contains";
        }
        ThisMethod::call(&self.self_, env, key)
    }

    pub fn get_string(&self, env: &mut JNIEnv, key: &str) -> JResult<Option<String>> {
        struct ThisMethod<'a>(PhantomData<&'a ()>);
        impl<'a> Method for ThisMethod<'a> {
            type Param = (&'a str, Option<&'a str>);
            type Return = Option<String>;

            const NAME: &'static str = "getString";
        }
        ThisMethod::call(&self.self_, env, (key, None))
    }

    pub fn get_binary(&self, env: &mut JNIEnv, key: &str) -> JResult<Option<Vec<u8>>> {
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

    pub fn edit(&self, env: &mut JNIEnv) -> JResult<SharedPreferencesEditor> {
        struct ThisMethod;
        impl Method for ThisMethod {
            type Param = NoParam;
            type Return = SharedPreferencesEditor;

            const NAME: &str = "edit";
        }
        ThisMethod::call(&self.self_, env, NoParam)
    }
}

pub struct SharedPreferencesEditor {
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

    pub fn put_string(&self, env: &mut JNIEnv, key: &str, value: &str) -> JResult<Self> {
        struct ThisMethod<'a>(PhantomData<&'a ()>);
        impl<'a> Method for ThisMethod<'a> {
            type Param = (&'a str, &'a str);
            type Return = SharedPreferencesEditor;

            const NAME: &'static str = "putString";
        }
        ThisMethod::call(&self.self_, env, (key, value))
    }

    pub fn put_binary(&self, env: &mut JNIEnv, key: &str, value: &[u8]) -> JResult<Self> {
        let value = BASE64_STANDARD.encode(value);
        self.put_string(env, key, &value)
    }

    pub fn remove(&self, env: &mut JNIEnv, key: &str) -> JResult<Self> {
        struct ThisMethod<'a>(PhantomData<&'a ()>);
        impl<'a> Method for ThisMethod<'a> {
            type Param = &'a str;
            type Return = SharedPreferencesEditor;

            const NAME: &'static str = "remove";
        }
        ThisMethod::call(&self.self_, env, key)
    }

    pub fn commit(&self, env: &mut JNIEnv) -> JResult<bool> {
        struct ThisMethod;
        impl Method for ThisMethod {
            type Param = NoParam;
            type Return = bool;

            const NAME: &str = "commit";
        }
        ThisMethod::call(&self.self_, env, NoParam)
    }
}

pub struct SharedPreferencesKeys {
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

    pub fn get_keys(&self, env: &mut JNIEnv) -> JResult<Vec<String>> {
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
