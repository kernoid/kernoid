// SPDX-License-Identifier: MIT
//! The core for Android's DocumentsProvider: `dev.kernoid.kernoid.ProviderCore` in Kotlin
//! (`android/app/src/main/kotlin/dev/kernoid/kernoid/ProviderCore.kt`) declares the two functions below as `external`.
//! Strings cross as Java strings; the jni crate turns them into Rust's UTF-8 and back (JNI speaks modified UTF-8).

use ::jni::EnvUnowned;
use ::jni::errors::ThrowRuntimeExAndDefault;
use ::jni::objects::{JClass, JObject, JString};

/// `ProviderCore.init(context)`: hands the JVM to rustls-platform-verifier, which reqwest checks certificates with –
/// on Android through the system's trust store, by calling into the JVM. Once per process, before the first
/// connection: the app's (Dart) and the provider's.
#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_kernoid_kernoid_ProviderCore_init<'caller>(
    mut env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    context: JObject<'caller>,
) {
    env.with_env(|env| rustls_platform_verifier::android::init_with_env(env, context))
        .resolve::<ThrowRuntimeExAndDefault>();
}

/// `ProviderCore.call(request)`: [`super::call`] – a JSON request in, a JSON answer out. Blocks the calling thread (a
/// binder thread of the provider, never the main thread) until the answer is there.
#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_kernoid_kernoid_ProviderCore_call<'caller>(
    mut env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    request: JString<'caller>,
) -> JObject<'caller> {
    env.with_env(|env| -> ::jni::errors::Result<JObject<'caller>> {
        let request = request.try_to_string(env)?;
        let answer = super::call(&request);
        Ok(JString::from_str(env, answer)?.into())
    })
    .resolve::<ThrowRuntimeExAndDefault>()
}
