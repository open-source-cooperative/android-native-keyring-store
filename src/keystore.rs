use crate::methods::{
    ClassDecl, Constructible, FromValue, JResult, Method, NoParam, SignatureComp, StaticMethod,
    ToValue,
};
use jni::{
    JNIEnv,
    objects::{GlobalRef, JObject, JValueGen},
};
use std::marker::PhantomData;

pub struct KeyStore {
    self_: GlobalRef,
}
impl FromValue for KeyStore {
    fn signature() -> SignatureComp {
        Self::class().into()
    }

    fn from_object(self_: GlobalRef, _env: &mut JNIEnv) -> JResult<Self> {
        Ok(Self { self_ })
    }
}
impl KeyStore {
    fn class() -> ClassDecl {
        ClassDecl("Ljava/security/KeyStore;")
    }

    pub fn get_instance(env: &mut JNIEnv<'_>, store: &str) -> JResult<KeyStore> {
        struct ThisMethod<'a>(PhantomData<&'a ()>);
        impl<'a> StaticMethod for ThisMethod<'a> {
            type Param = &'a str;
            type Return = KeyStore;

            const NAME: &'static str = "getInstance";
        }

        ThisMethod::call(Self::class(), env, store)
    }

    pub fn load(&self, env: &mut JNIEnv<'_>) -> JResult<()> {
        struct LoadStoreParameter;
        impl ToValue for LoadStoreParameter {
            fn signature() -> SignatureComp {
                ClassDecl("Ljava/security/KeyStore$LoadStoreParameter;").into()
            }

            fn to_value<'a>(
                &self,
                _env: &mut JNIEnv<'a>,
            ) -> JResult<JValueGen<JObject<'a>>> {
                Ok(JObject::null().into())
            }
        }

        struct ThisMethod;
        impl Method for ThisMethod {
            type Param = LoadStoreParameter;
            type Return = ();

            const NAME: &str = "load";
        }

        ThisMethod::call(&self.self_, env, LoadStoreParameter)
    }

    pub fn contains_alias(&self, env: &mut JNIEnv<'_>, alias: &str) -> JResult<bool> {
        struct ThisMethod<'a>(PhantomData<&'a ()>);
        impl<'a> Method for ThisMethod<'a> {
            type Param = &'a str;
            type Return = bool;

            const NAME: &'static str = "containsAlias";
        }

        ThisMethod::call(&self.self_, env, alias)
    }

    pub fn get_key(&self, env: &mut JNIEnv<'_>, alias: &str) -> JResult<Option<Key>> {
        struct ThisMethod<'a>(PhantomData<&'a ()>);
        impl<'a> Method for ThisMethod<'a> {
            type Param = (&'a str, Option<Vec<u16>>);
            type Return = Option<Key>;

            const NAME: &'static str = "getKey";
        }

        ThisMethod::call(&self.self_, env, (alias, None))
    }
}

#[derive(Debug)]
pub struct Key {
    self_: GlobalRef,
}
impl FromValue for Key {
    fn signature() -> SignatureComp {
        Self::class().into()
    }

    fn from_object(self_: GlobalRef, _env: &mut JNIEnv) -> JResult<Self> {
        Ok(Self { self_ })
    }
}
impl ToValue for Key {
    fn signature() -> SignatureComp {
        Self::class().into()
    }

    fn to_value<'a>(&self, env: &mut JNIEnv<'a>) -> JResult<JValueGen<JObject<'a>>> {
        Ok(env.new_local_ref(&self.self_)?.into())
    }
}
impl Key {
    fn class() -> ClassDecl {
        ClassDecl("Ljava/security/Key;")
    }
}

pub struct SecretKey {
    self_: GlobalRef,
}
impl FromValue for SecretKey {
    fn signature() -> SignatureComp {
        Self::class().into()
    }

    fn from_object(self_: GlobalRef, _env: &mut JNIEnv) -> JResult<Self> {
        Ok(Self { self_ })
    }
}
impl SecretKey {
    fn class() -> ClassDecl {
        ClassDecl("Ljavax/crypto/SecretKey;")
    }
}
impl From<SecretKey> for Key {
    fn from(value: SecretKey) -> Self {
        Key { self_: value.self_ }
    }
}

pub struct KeyGenerator {
    self_: GlobalRef,
}
impl FromValue for KeyGenerator {
    fn signature() -> SignatureComp {
        Self::class().into()
    }

    fn from_object(self_: GlobalRef, _env: &mut JNIEnv) -> JResult<Self> {
        Ok(Self { self_ })
    }
}
impl KeyGenerator {
    fn class() -> ClassDecl {
        ClassDecl("Ljavax/crypto/KeyGenerator;")
    }

    pub fn get_instance(env: &mut JNIEnv, algorithm: &str, provider: &str) -> JResult<Self> {
        struct ThisMethod<'a>(PhantomData<&'a ()>);
        impl<'a> StaticMethod for ThisMethod<'a> {
            type Param = (&'a str, &'a str);
            type Return = KeyGenerator;

            const NAME: &'static str = "getInstance";
        }

        ThisMethod::call(Self::class(), env, (algorithm, provider))
    }

    pub fn init(&self, env: &mut JNIEnv, spec: AlgorithmParameterSpec) -> JResult<()> {
        struct ThisMethod;
        impl Method for ThisMethod {
            type Param = AlgorithmParameterSpec;
            type Return = ();

            const NAME: &str = "init";
        }

        ThisMethod::call(&self.self_, env, spec)
    }

    pub fn generate_key(&self, env: &mut JNIEnv) -> JResult<SecretKey> {
        struct ThisMethod;
        impl Method for ThisMethod {
            type Param = NoParam;
            type Return = SecretKey;

            const NAME: &str = "generateKey";
        }

        ThisMethod::call(&self.self_, env, NoParam)
    }
}

pub struct KeyGenParameterSpecBuilder {
    self_: GlobalRef,
}
impl FromValue for KeyGenParameterSpecBuilder {
    fn signature() -> SignatureComp {
        Self::class().into()
    }

    fn from_object(self_: GlobalRef, _env: &mut JNIEnv) -> JResult<Self> {
        Ok(Self { self_ })
    }
}
impl KeyGenParameterSpecBuilder {
    fn class() -> ClassDecl {
        ClassDecl("Landroid/security/keystore/KeyGenParameterSpec$Builder;")
    }
}
impl KeyGenParameterSpecBuilder {
    pub fn new(env: &mut JNIEnv, alias: &str, purpose: i32) -> JResult<Self> {
        struct ThisMethod<'a>(PhantomData<&'a ()>);
        impl<'a> Constructible for ThisMethod<'a> {
            type Param = (&'a str, i32);
            type Return = KeyGenParameterSpecBuilder;
        }

        ThisMethod::call_new(Self::class(), env, (alias, purpose))
    }

    pub fn set_block_modes(
        &self,
        env: &mut JNIEnv,
        modes: &[&str],
    ) -> JResult<KeyGenParameterSpecBuilder> {
        struct ThisMethod<'a>(PhantomData<&'a ()>);
        impl<'a> Method for ThisMethod<'a> {
            type Param = &'a [&'a str];
            type Return = KeyGenParameterSpecBuilder;

            const NAME: &'static str = "setBlockModes";
        }

        ThisMethod::call(&self.self_, env, modes)
    }

    pub fn set_encryption_paddings(
        &self,
        env: &mut JNIEnv,
        modes: &[&str],
    ) -> JResult<KeyGenParameterSpecBuilder> {
        struct ThisMethod<'a>(PhantomData<&'a ()>);
        impl<'a> Method for ThisMethod<'a> {
            type Param = &'a [&'a str];
            type Return = KeyGenParameterSpecBuilder;

            const NAME: &'static str = "setEncryptionPaddings";
        }

        ThisMethod::call(&self.self_, env, modes)
    }

    pub fn set_user_authentication_required(
        &self,
        env: &mut JNIEnv,
        required: bool,
    ) -> JResult<KeyGenParameterSpecBuilder> {
        struct ThisMethod;
        impl Method for ThisMethod {
            type Param = bool;
            type Return = KeyGenParameterSpecBuilder;

            const NAME: &str = "setUserAuthenticationRequired";
        }

        ThisMethod::call(&self.self_, env, required)
    }

    /// Set the validity duration (in seconds) after user authentication.
    ///
    /// Available on API 24+. When `seconds` > 0 the key is usable for that
    /// many seconds after the user authenticates; when 0, auth is required
    /// for every use.
    pub fn set_user_authentication_validity_duration_seconds(
        &self,
        env: &mut JNIEnv,
        seconds: i32,
    ) -> JResult<KeyGenParameterSpecBuilder> {
        struct ThisMethod;
        impl Method for ThisMethod {
            type Param = i32;
            type Return = KeyGenParameterSpecBuilder;

            const NAME: &str = "setUserAuthenticationValidityDurationSeconds";
        }

        ThisMethod::call(&self.self_, env, seconds)
    }

    /// Set user authentication parameters with explicit auth type bitmask.
    ///
    /// Available on API 30+. `auth_type` is a combination of
    /// `BiometricManager.Authenticators` flags (e.g. `BIOMETRIC_STRONG | DEVICE_CREDENTIAL`).
    pub fn set_user_authentication_parameters(
        &self,
        env: &mut JNIEnv,
        timeout_seconds: i32,
        auth_type: i32,
    ) -> JResult<KeyGenParameterSpecBuilder> {
        struct ThisMethod;
        impl Method for ThisMethod {
            type Param = (i32, i32);
            type Return = KeyGenParameterSpecBuilder;

            const NAME: &str = "setUserAuthenticationParameters";
        }

        ThisMethod::call(&self.self_, env, (timeout_seconds, auth_type))
    }

    pub fn build(&self, env: &mut JNIEnv) -> JResult<KeyGenParameterSpec> {
        struct ThisMethod;
        impl Method for ThisMethod {
            type Param = NoParam;
            type Return = KeyGenParameterSpec;

            const NAME: &str = "build";
        }

        ThisMethod::call(&self.self_, env, NoParam)
    }
}

pub struct KeyGenParameterSpec {
    self_: GlobalRef,
}
impl FromValue for KeyGenParameterSpec {
    fn signature() -> SignatureComp {
        Self::class().into()
    }

    fn from_object(self_: GlobalRef, _env: &mut JNIEnv) -> JResult<Self> {
        Ok(Self { self_ })
    }
}
impl KeyGenParameterSpec {
    fn class() -> ClassDecl {
        ClassDecl("Landroid/security/keystore/KeyGenParameterSpec;")
    }
}

pub struct AlgorithmParameterSpec {
    self_: GlobalRef,
}
impl From<KeyGenParameterSpec> for AlgorithmParameterSpec {
    fn from(value: KeyGenParameterSpec) -> Self {
        Self { self_: value.self_ }
    }
}
impl ToValue for AlgorithmParameterSpec {
    fn signature() -> SignatureComp {
        Self::class().into()
    }

    fn to_value<'a>(&self, env: &mut JNIEnv<'a>) -> JResult<JValueGen<JObject<'a>>> {
        Ok(env.new_local_ref(&self.self_)?.into())
    }
}
impl AlgorithmParameterSpec {
    fn class() -> ClassDecl {
        ClassDecl("Ljava/security/spec/AlgorithmParameterSpec;")
    }
}
