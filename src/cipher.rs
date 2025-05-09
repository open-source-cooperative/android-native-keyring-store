use crate::{
    JResult,
    keystore::Key,
    methods::{
        ClassDecl, Constructible, FromValue, Method, NoParam, SignatureComp, StaticMethod, ToValue,
    },
};
use jni::{
    JNIEnv,
    objects::{GlobalRef, JObject, JValueGen},
};
use std::marker::PhantomData;

pub struct Cipher {
    self_: GlobalRef,
}
impl FromValue for Cipher {
    fn signature() -> SignatureComp {
        Self::class().into()
    }

    fn from_object(self_: GlobalRef, _env: &mut JNIEnv) -> JResult<Self> {
        Ok(Self { self_ })
    }
}
impl Cipher {
    fn class() -> ClassDecl {
        ClassDecl("Ljavax/crypto/Cipher;")
    }

    pub fn get_instance(env: &mut JNIEnv, transformation: &str) -> JResult<Self> {
        struct ThisMethod<'a>(PhantomData<&'a ()>);
        impl<'a> StaticMethod for ThisMethod<'a> {
            type Param = &'a str;
            type Return = Cipher;

            const NAME: &'static str = "getInstance";
        }
        ThisMethod::call(Self::class(), env, transformation)
    }

    pub fn init(&self, env: &mut JNIEnv, mode: i32, key: Key) -> JResult<()> {
        struct ThisMethod;
        impl Method for ThisMethod {
            type Param = (i32, Key);
            type Return = ();

            const NAME: &str = "init";
        }

        ThisMethod::call(&self.self_, env, (mode, key))
    }

    pub fn init2(
        &self,
        env: &mut JNIEnv,
        mode: i32,
        key: Key,
        spec: AlgorithmParameterSpec,
    ) -> JResult<()> {
        struct ThisMethod;
        impl Method for ThisMethod {
            type Param = (i32, Key, AlgorithmParameterSpec);
            type Return = ();

            const NAME: &str = "init";
        }
        ThisMethod::call(&self.self_, env, (mode, key, spec))
    }

    pub fn get_iv(&self, env: &mut JNIEnv) -> JResult<Vec<u8>> {
        struct ThisMethod;
        impl Method for ThisMethod {
            type Param = NoParam;
            type Return = Vec<u8>;

            const NAME: &str = "getIV";
        }
        ThisMethod::call(&self.self_, env, NoParam)
    }

    pub fn do_final(&self, env: &mut JNIEnv, input: &[u8]) -> JResult<Vec<u8>> {
        struct ThisMethod<'a>(PhantomData<&'a ()>);
        impl<'a> Method for ThisMethod<'a> {
            type Param = &'a [u8];
            type Return = Vec<u8>;

            const NAME: &'static str = "doFinal";
        }
        ThisMethod::call(&self.self_, env, input)
    }
}

pub struct AlgorithmParameterSpec {
    self_: GlobalRef,
}
impl ToValue for AlgorithmParameterSpec {
    fn signature() -> SignatureComp {
        Self::class().into()
    }

    fn to_value<'a>(&self, env: &mut JNIEnv<'a>) -> JResult<JValueGen<JObject<'a>>> {
        Ok(env.new_local_ref(self.self_.as_obj())?.into())
    }
}
impl AlgorithmParameterSpec {
    fn class() -> ClassDecl {
        ClassDecl("Ljava/security/spec/AlgorithmParameterSpec;")
    }
}

pub struct GCMParameterSpec {
    self_: GlobalRef,
}
impl FromValue for GCMParameterSpec {
    fn signature() -> SignatureComp {
        Self::class().into()
    }

    fn from_object(self_: GlobalRef, _env: &mut JNIEnv) -> JResult<Self> {
        Ok(Self { self_ })
    }
}
impl ToValue for GCMParameterSpec {
    fn signature() -> SignatureComp {
        Self::class().into()
    }

    fn to_value<'a>(&self, env: &mut JNIEnv<'a>) -> JResult<JValueGen<JObject<'a>>> {
        Ok(env.new_local_ref(self.self_.as_obj())?.into())
    }
}
impl GCMParameterSpec {
    fn class() -> ClassDecl {
        ClassDecl("Ljavax/crypto/spec/GCMParameterSpec;")
    }

    pub fn new(env: &mut JNIEnv, tag_len: i32, iv: &[u8]) -> JResult<GCMParameterSpec> {
        struct ThisMethod<'a>(PhantomData<&'a ()>);
        impl<'a> Constructible for ThisMethod<'a> {
            type Param = (i32, &'a [u8]);
            type Return = GCMParameterSpec;
        }
        ThisMethod::call_new(Self::class(), env, (tag_len, iv))
    }
}
impl From<GCMParameterSpec> for AlgorithmParameterSpec {
    fn from(value: GCMParameterSpec) -> Self {
        Self { self_: value.self_ }
    }
}
