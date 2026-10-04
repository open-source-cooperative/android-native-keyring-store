use jni::{JNIEnv, objects::GlobalRef};

use crate::methods::{ClassDecl, FromValue, JResult, Method, NoParam, SignatureComp};

pub struct KeyguardManager {
    self_: GlobalRef,
}

impl FromValue for KeyguardManager {
    // Context.getSystemService declares Object as its return type.
    fn signature() -> SignatureComp {
        ClassDecl("Ljava/lang/Object;").into()
    }

    fn from_object(self_: GlobalRef, _env: &mut JNIEnv) -> JResult<Self> {
        Ok(Self { self_ })
    }
}

impl KeyguardManager {
    /// Whether the device has a secure lock screen, which keys requiring user authentication need.
    pub fn is_device_secure(&self, env: &mut JNIEnv) -> JResult<bool> {
        struct ThisMethod;
        impl Method for ThisMethod {
            type Param = NoParam;
            type Return = bool;

            const NAME: &str = "isDeviceSecure";
        }

        ThisMethod::call(&self.self_, env, NoParam)
    }
}
