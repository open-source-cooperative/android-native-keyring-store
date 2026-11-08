use jni::{JNIEnv, objects::GlobalRef};

use crate::methods::{ClassDecl, FromValue, JResult, Method, NoParam, SignatureComp};

/// A Java exception taken from the JNI environment.
pub struct Throwable {
    self_: GlobalRef,
}

impl FromValue for Throwable {
    fn signature() -> SignatureComp {
        Self::class().into()
    }

    fn from_object(self_: GlobalRef, _env: &mut JNIEnv) -> JResult<Self> {
        Ok(Self { self_ })
    }
}

impl Throwable {
    fn class() -> ClassDecl {
        ClassDecl("Ljava/lang/Throwable;")
    }

    /// Describes and clears the pending exception, if any, and returns it.
    pub fn take_pending(env: &mut JNIEnv) -> JResult<Option<Self>> {
        if !env.exception_check()? {
            return Ok(None);
        }
        let exception = env.exception_occurred()?;
        env.exception_describe()?;
        env.exception_clear()?;
        Ok(Some(Self {
            self_: env.new_global_ref(exception)?,
        }))
    }

    pub fn is_instance_of(&self, env: &mut JNIEnv, class: ClassDecl) -> JResult<bool> {
        env.is_instance_of(&self.self_, class.for_finding())
    }

    pub fn get_cause(&self, env: &mut JNIEnv) -> JResult<Option<Throwable>> {
        struct ThisMethod;
        impl Method for ThisMethod {
            type Param = NoParam;
            type Return = Option<Throwable>;

            const NAME: &str = "getCause";
        }

        ThisMethod::call(&self.self_, env, NoParam)
    }

    pub fn get_message(&self, env: &mut JNIEnv) -> JResult<Option<String>> {
        struct ThisMethod;
        impl Method for ThisMethod {
            type Param = NoParam;
            type Return = Option<String>;

            const NAME: &str = "getMessage";
        }

        ThisMethod::call(&self.self_, env, NoParam)
    }
}
