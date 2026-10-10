use jni::{JNIEnv, objects::GlobalRef};

use crate::methods::{ClassDecl, JResult};

/// A Java exception taken from the JNI environment.
pub struct Throwable {
    self_: GlobalRef,
}

impl Throwable {
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
}
