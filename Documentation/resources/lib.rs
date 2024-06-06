use robusta_jni::bridge;
#[bridge]
pub mod jni {
    use robusta_jni::{
        convert::{IntoJavaValue, Signature, TryFromJavaValue, TryIntoJavaValue},
        jni::{
            JNIEnv,
            objects::AutoLocal,
        },
    };
    #[allow(unused_imports)] //the bridge import is marked as unused, but if removed the compiler throws an error
    use robusta_jni::bridge;
    #[derive(Signature, TryIntoJavaValue, IntoJavaValue, TryFromJavaValue)]
    #[package(com.example.test_1inst_1guide)] //the 1 is an escape character for the underscore
    pub struct RustDef<'env: 'borrow, 'borrow> {
        #[instance]
        pub raw: AutoLocal<'env, 'borrow>,
    }

    #[allow(non_snake_case)]
    impl<'env: 'borrow, 'borrow> RustDef<'env, 'borrow> {

        pub extern "jni" fn callRust(environment: &JNIEnv) -> String { String::from("Hello from Rust!") }
    }
}