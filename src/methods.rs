use jni::{
    JNIEnv,
    objects::{GlobalRef, JByteArray, JObject, JValue, JValueGen, ReleaseMode},
    signature::{Primitive, ReturnType},
};

#[derive(Clone, Copy)]
pub enum SignatureComp {
    Class(ClassDecl),
    Boolean,
    Byte,
    Char,
    Short,
    Int,
    Long,
    Float,
    Double,
    Void,
    ArrayBoolean,
    ArrayByte,
    ArrayChar,
    ArrayShort,
    ArrayInt,
    ArrayLong,
    ArrayFloat,
    ArrayDouble,
}
impl From<ClassDecl> for SignatureComp {
    fn from(value: ClassDecl) -> Self {
        Self::Class(value)
    }
}
impl From<SignatureComp> for ReturnType {
    fn from(value: SignatureComp) -> Self {
        match value {
            SignatureComp::Class(class_decl) if class_decl.0.starts_with('[') => ReturnType::Array,
            SignatureComp::Class(_) => ReturnType::Object,
            SignatureComp::Boolean => ReturnType::Primitive(Primitive::Boolean),
            SignatureComp::Byte => ReturnType::Primitive(Primitive::Byte),
            SignatureComp::Char => ReturnType::Primitive(Primitive::Char),
            SignatureComp::Short => ReturnType::Primitive(Primitive::Short),
            SignatureComp::Int => ReturnType::Primitive(Primitive::Int),
            SignatureComp::Long => ReturnType::Primitive(Primitive::Long),
            SignatureComp::Float => ReturnType::Primitive(Primitive::Float),
            SignatureComp::Double => ReturnType::Primitive(Primitive::Double),
            SignatureComp::Void => ReturnType::Primitive(Primitive::Void),
            SignatureComp::ArrayBoolean => ReturnType::Array,
            SignatureComp::ArrayByte => ReturnType::Array,
            SignatureComp::ArrayChar => ReturnType::Array,
            SignatureComp::ArrayShort => ReturnType::Array,
            SignatureComp::ArrayInt => ReturnType::Array,
            SignatureComp::ArrayLong => ReturnType::Array,
            SignatureComp::ArrayFloat => ReturnType::Array,
            SignatureComp::ArrayDouble => ReturnType::Array,
        }
    }
}
impl SignatureComp {
    fn for_finding(self) -> &'static str {
        match self {
            SignatureComp::Class(class_decl) => class_decl.for_finding(),
            other => other.as_str(),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            SignatureComp::Class(ClassDecl(class_decl)) => class_decl,
            SignatureComp::Boolean => "Z",
            SignatureComp::Byte => "B",
            SignatureComp::Char => "C",
            SignatureComp::Short => "S",
            SignatureComp::Int => "I",
            SignatureComp::Long => "J",
            SignatureComp::Float => "F",
            SignatureComp::Double => "D",
            SignatureComp::Void => "V",
            SignatureComp::ArrayBoolean => "[Z",
            SignatureComp::ArrayByte => "[B",
            SignatureComp::ArrayChar => "[C",
            SignatureComp::ArrayShort => "[S",
            SignatureComp::ArrayInt => "[I",
            SignatureComp::ArrayLong => "[J",
            SignatureComp::ArrayFloat => "[F",
            SignatureComp::ArrayDouble => "[D",
        }
    }
}

#[derive(Clone, Copy)]
pub struct ClassDecl(pub &'static str);
impl ClassDecl {
    fn for_finding(self) -> &'static str {
        if !self.0.is_empty() && &self.0[0..1] == "[" {
            return self.0;
        }

        &self.0[..(self.0.len() - 1)][1..]
    }
}

pub trait Method {
    type Param: AsParam;
    type Return: FromValue;

    const NAME: &str;

    fn call(self_: &JObject, env: &mut JNIEnv, params: Self::Param) -> JResult<Self::Return> {
        let signature = make_signature(&Self::Param::signature(), Self::Return::signature());
        let param = params.as_param(env)?;
        let param = borrow_params(&param);
        let r = env.call_method(self_, Self::NAME, &signature, param.as_slice())?;

        match r {
            JValueGen::Object(obj) if obj.is_null() => Ok(FromValue::from_null()?),
            JValueGen::Object(obj) => Ok(FromValue::from_object(env.new_global_ref(obj)?, env)?),
            JValueGen::Byte(value) => Ok(FromValue::from_value(JValueGen::Byte(value))?),
            JValueGen::Char(value) => Ok(FromValue::from_value(JValueGen::Char(value))?),
            JValueGen::Short(value) => Ok(FromValue::from_value(JValueGen::Short(value))?),
            JValueGen::Int(value) => Ok(FromValue::from_value(JValueGen::Int(value))?),
            JValueGen::Long(value) => Ok(FromValue::from_value(JValueGen::Long(value))?),
            JValueGen::Bool(value) => Ok(FromValue::from_value(JValueGen::Bool(value))?),
            JValueGen::Float(value) => Ok(FromValue::from_value(JValueGen::Float(value))?),
            JValueGen::Double(value) => Ok(FromValue::from_value(JValueGen::Double(value))?),
            JValueGen::Void => Ok(FromValue::from_value(JValueGen::Void)?),
        }
    }
}

pub trait StaticMethod {
    type Param: AsParam;
    type Return: FromValue;

    const NAME: &str;

    fn call(self_: ClassDecl, env: &mut JNIEnv, params: Self::Param) -> JResult<Self::Return> {
        let signature = make_signature(&Self::Param::signature(), Self::Return::signature());
        let param = params.as_param(env)?;
        let param = borrow_params(&param);
        let r = env.call_static_method(
            self_.for_finding(),
            Self::NAME,
            &signature,
            param.as_slice(),
        )?;

        match r {
            JValueGen::Object(obj) if obj.is_null() => Ok(FromValue::from_null()?),
            JValueGen::Object(obj) => Ok(FromValue::from_object(env.new_global_ref(obj)?, env)?),
            JValueGen::Byte(value) => Ok(FromValue::from_value(JValueGen::Byte(value))?),
            JValueGen::Char(value) => Ok(FromValue::from_value(JValueGen::Char(value))?),
            JValueGen::Short(value) => Ok(FromValue::from_value(JValueGen::Short(value))?),
            JValueGen::Int(value) => Ok(FromValue::from_value(JValueGen::Int(value))?),
            JValueGen::Long(value) => Ok(FromValue::from_value(JValueGen::Long(value))?),
            JValueGen::Bool(value) => Ok(FromValue::from_value(JValueGen::Bool(value))?),
            JValueGen::Float(value) => Ok(FromValue::from_value(JValueGen::Float(value))?),
            JValueGen::Double(value) => Ok(FromValue::from_value(JValueGen::Double(value))?),
            JValueGen::Void => Ok(FromValue::from_value(JValueGen::Void)?),
        }
    }
}

pub trait Constructible {
    type Param: AsParam;
    type Return: FromValue;

    fn call_new(self_: ClassDecl, env: &mut JNIEnv, params: Self::Param) -> JResult<Self::Return> {
        let signature = make_signature(&Self::Param::signature(), <() as FromValue>::signature());
        let param = params.as_param(env)?;
        let param = borrow_params(&param);
        let obj = env.new_object(self_.for_finding(), &signature, param.as_slice())?;

        FromValue::from_object(env.new_global_ref(obj)?, env)
    }
}

pub trait AsParam {
    fn signature() -> Vec<SignatureComp>;
    fn as_param<'a>(&self, env: &mut JNIEnv<'a>) -> JResult<Vec<JValueGen<JObject<'a>>>>;
}
impl<T1> AsParam for T1
where
    T1: ToValue,
{
    fn signature() -> Vec<SignatureComp> {
        vec![T1::signature()]
    }

    fn as_param<'a>(&self, env: &mut JNIEnv<'a>) -> JResult<Vec<JValueGen<JObject<'a>>>> {
        Ok(vec![self.to_value(env)?])
    }
}
impl<T1, T2> AsParam for (T1, T2)
where
    T1: ToValue,
    T2: ToValue,
{
    fn signature() -> Vec<SignatureComp> {
        vec![T1::signature(), T2::signature()]
    }

    fn as_param<'a>(&self, env: &mut JNIEnv<'a>) -> JResult<Vec<JValueGen<JObject<'a>>>> {
        Ok(vec![self.0.to_value(env)?, self.1.to_value(env)?])
    }
}
impl<T1, T2, T3> AsParam for (T1, T2, T3)
where
    T1: ToValue,
    T2: ToValue,
    T3: ToValue,
{
    fn signature() -> Vec<SignatureComp> {
        vec![T1::signature(), T2::signature(), T3::signature()]
    }

    fn as_param<'a>(&self, env: &mut JNIEnv<'a>) -> JResult<Vec<JValueGen<JObject<'a>>>> {
        Ok(vec![
            self.0.to_value(env)?,
            self.1.to_value(env)?,
            self.2.to_value(env)?,
        ])
    }
}

pub struct NoParam;
impl AsParam for NoParam {
    fn signature() -> Vec<SignatureComp> {
        vec![]
    }

    fn as_param<'a>(&self, _env: &mut JNIEnv<'a>) -> JResult<Vec<JValueGen<JObject<'a>>>> {
        Ok(vec![])
    }
}

pub trait ToValue: Sized {
    fn signature() -> SignatureComp;
    fn to_value<'a>(&self, env: &mut JNIEnv<'a>) -> JResult<JValueGen<JObject<'a>>>;
}
impl<T: ToValue> ToValue for &T {
    fn signature() -> SignatureComp {
        T::signature()
    }

    fn to_value<'a>(&self, env: &mut JNIEnv<'a>) -> JResult<JValueGen<JObject<'a>>> {
        T::to_value(self, env)
    }
}
impl<T: ToValue> ToValue for Option<T> {
    fn signature() -> SignatureComp {
        T::signature()
    }

    fn to_value<'a>(&self, env: &mut JNIEnv<'a>) -> JResult<JValueGen<JObject<'a>>> {
        Ok(match self {
            Some(self_) => self_.to_value(env)?,
            None => JObject::null().into(),
        })
    }
}
impl ToValue for &str {
    fn signature() -> SignatureComp {
        <String as FromValue>::signature()
    }

    fn to_value<'a>(&self, env: &mut JNIEnv<'a>) -> JResult<JValueGen<JObject<'a>>> {
        Ok(JValueGen::Object(env.new_string(self)?.into()))
    }
}
impl ToValue for &[&str] {
    fn signature() -> SignatureComp {
        ClassDecl("[Ljava/lang/String;").into()
    }

    fn to_value<'a>(&self, env: &mut JNIEnv<'a>) -> JResult<JValueGen<JObject<'a>>> {
        let array = env.new_object_array(
            self.len() as i32,
            <&str as ToValue>::signature().for_finding(),
            JObject::null(),
        )?;

        for (index, value) in self.iter().enumerate() {
            env.set_object_array_element(&array, index as i32, env.new_string(*value)?)?;
        }

        let array: JObject = array.into();
        Ok(array.into())
    }
}
impl ToValue for &[u8] {
    fn signature() -> SignatureComp {
        SignatureComp::ArrayByte
    }

    fn to_value<'a>(&self, env: &mut JNIEnv<'a>) -> JResult<JValueGen<JObject<'a>>> {
        let bytes: JObject = env.byte_array_from_slice(self)?.into();
        Ok(bytes.into())
    }
}
impl ToValue for Vec<u16> {
    fn signature() -> SignatureComp {
        SignatureComp::ArrayChar
    }

    fn to_value<'a>(&self, env: &mut JNIEnv<'a>) -> JResult<JValueGen<JObject<'a>>> {
        let chars = env.new_char_array(self.len() as i32)?;
        unsafe {
            let mut chars_write = env.get_array_elements(&chars, ReleaseMode::CopyBack)?;
            chars_write.copy_from_slice(self);
        }
        let chars: JObject = chars.into();
        Ok(chars.into())
    }
}
impl ToValue for i32 {
    fn signature() -> SignatureComp {
        SignatureComp::Int
    }

    fn to_value<'a>(&self, _env: &mut JNIEnv<'a>) -> JResult<JValueGen<JObject<'a>>> {
        Ok((*self).into())
    }
}
impl ToValue for bool {
    fn signature() -> SignatureComp {
        SignatureComp::Boolean
    }

    fn to_value<'a>(&self, _env: &mut JNIEnv<'a>) -> JResult<JValueGen<JObject<'a>>> {
        Ok((*self).into())
    }
}

pub trait FromValue: Sized {
    fn signature() -> SignatureComp;

    fn from_object(value: GlobalRef, env: &mut JNIEnv) -> JResult<Self> {
        let _ = (value, env);
        Err(jni::errors::Error::WrongJValueType("primitive", "object"))
    }

    fn from_value(value: JValue) -> JResult<Self> {
        Err(jni::errors::Error::WrongJValueType(
            "object",
            value.type_name(),
        ))
    }

    fn from_null() -> JResult<Self> {
        Err(jni::errors::Error::WrongJValueType("object", "null"))
    }
}
impl<T: FromValue> FromValue for Option<T> {
    fn signature() -> SignatureComp {
        T::signature()
    }

    fn from_null() -> JResult<Self> {
        Ok(Self::None)
    }

    fn from_object(value: GlobalRef, env: &mut JNIEnv) -> JResult<Self> {
        Ok(Some(T::from_object(value, env)?))
    }

    fn from_value(value: JValue) -> JResult<Self> {
        Ok(Some(T::from_value(value)?))
    }
}
impl FromValue for () {
    fn signature() -> SignatureComp {
        SignatureComp::Void
    }

    fn from_value(value: JValue) -> JResult<Self> {
        value.v()
    }

    fn from_null() -> JResult<Self> {
        Ok(())
    }
}
impl FromValue for bool {
    fn signature() -> SignatureComp {
        SignatureComp::Boolean
    }

    fn from_value(value: JValue) -> JResult<Self> {
        value.z()
    }
}
impl FromValue for String {
    fn signature() -> SignatureComp {
        ClassDecl("Ljava/lang/String;").into()
    }

    fn from_object(value: GlobalRef, env: &mut JNIEnv) -> JResult<Self> {
        let string = env.get_string((&value as &JObject).into())?;
        Ok(string.to_string_lossy().into_owned())
    }
}
impl FromValue for Vec<u8> {
    fn signature() -> SignatureComp {
        SignatureComp::ArrayByte
    }

    fn from_object(value: GlobalRef, env: &mut JNIEnv) -> JResult<Self> {
        let value: &JByteArray = value.as_obj().into();
        let len = env.get_array_length(value)? as usize;
        let mut buf = vec![0; len];
        env.get_byte_array_region(value, 0, &mut buf)?;

        Ok(buf.into_iter().map(|x| x as u8).collect())
    }
}

fn make_signature(params: &[SignatureComp], result: SignatureComp) -> String {
    use std::fmt::Write;
    let mut w = String::new();
    write!(w, "(").unwrap();
    for param in params {
        write!(w, "{}", param.as_str()).unwrap();
    }
    write!(w, "){}", result.as_str()).unwrap();
    w
}

fn borrow_params<'a, 'b>(
    params: &'a Vec<JValueGen<JObject<'b>>>,
) -> Vec<JValueGen<&'a JObject<'b>>> {
    params
        .iter()
        .map(|value| match value {
            JValueGen::Object(value) => JValueGen::Object(value),
            JValueGen::Byte(value) => JValueGen::Byte(*value),
            JValueGen::Char(value) => JValueGen::Char(*value),
            JValueGen::Short(value) => JValueGen::Short(*value),
            JValueGen::Int(value) => JValueGen::Int(*value),
            JValueGen::Long(value) => JValueGen::Long(*value),
            JValueGen::Bool(value) => JValueGen::Bool(*value),
            JValueGen::Float(value) => JValueGen::Float(*value),
            JValueGen::Double(value) => JValueGen::Double(*value),
            JValueGen::Void => JValueGen::Void,
        })
        .collect()
}

pub type JResult<T> = Result<T, jni::errors::Error>;
