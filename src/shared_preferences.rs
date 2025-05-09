use crate::{
    JResult, log, logd,
    methods::{ClassDecl, FromValue, Method, NoParam, SignatureComp},
};
use base64::{Engine, prelude::BASE64_STANDARD};
use jni::{
    JNIEnv,
    objects::{GlobalRef, JObject},
};
use std::marker::PhantomData;

pub struct Context {
    self_: GlobalRef,
}
impl Context {
    pub fn new(env: &JNIEnv, obj: JObject) -> JResult<Self> {
        Ok(Self {
            self_: env.new_global_ref(obj)?,
        })
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
                log(format!("bad base64 on key {key:?}, ignoring"));
                logd(e);
                logd(b64);
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
