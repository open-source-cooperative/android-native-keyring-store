use android_log_sys::{__android_log_write, LogPriority};
use jni::{
    JNIEnv,
    objects::{JObject, JString},
};
use std::{ffi::CString, fmt::Write};
use tracing::{Level, Subscriber, span};
use tracing_subscriber::{
    EnvFilter, Layer, Registry, layer::SubscriberExt, registry::LookupSpan, util::SubscriberInitExt,
};

// package io.crates.keyring
// class KeyringLog {
//     companion object {
//         external fun setLog(filter: String);
//     }
// }
#[unsafe(no_mangle)]
pub extern "system" fn Java_io_crates_keyring_KeyringLog_00024Companion_setLog(
    mut env: JNIEnv,
    _class: JObject,
    filter: JString,
) {
    let filter = {
        let filter = env.get_string(&filter).unwrap();
        filter.to_string_lossy().into_owned()
    };

    match Registry::default()
        .with(EnvFilter::from(&filter))
        .with(AndroidLogCat)
        .try_init()
    {
        Ok(()) => tracing::debug!(?filter, "Logger initialized"),
        Err(e) => {
            tracing::warn!(%e, "Trying to initialize logger twice");
            tracing::debug!(?e);
        }
    }
}

pub struct AndroidLogCat;
impl<S> Layer<S> for AndroidLogCat
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_new_span(
        &self,
        attrs: &span::Attributes<'_>,
        id: &span::Id,
        ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        SpanPrefix::on_new_span(attrs, id, ctx)
    }

    fn on_record(
        &self,
        id: &span::Id,
        values: &span::Record<'_>,
        ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        SpanPrefix::on_record(id, values, ctx)
    }

    fn on_event(&self, event: &tracing::Event<'_>, ctx: tracing_subscriber::layer::Context<'_, S>) {
        let priority = match *event.metadata().level() {
            Level::ERROR => LogPriority::ERROR,
            Level::WARN => LogPriority::WARN,
            Level::INFO => LogPriority::INFO,
            Level::DEBUG => LogPriority::DEBUG,
            Level::TRACE => LogPriority::VERBOSE,
        };

        let tag = CString::new(event.metadata().target()).unwrap();

        let message = SpanPrefix::on_event(event, ctx);
        let message = CString::new(message).unwrap_or_default();

        unsafe {
            __android_log_write(priority as i32, tag.as_ptr(), message.as_ptr());
        }
    }
}

pub struct SpanPrefix {
    name: String,
    values: String,
}
impl SpanPrefix {
    pub fn on_new_span<S>(
        attrs: &span::Attributes<'_>,
        id: &span::Id,
        ctx: tracing_subscriber::layer::Context<'_, S>,
    ) where
        S: Subscriber + for<'a> LookupSpan<'a>,
    {
        let span = ctx.span(id).expect("Span not found, this is a bug");
        let mut extensions = span.extensions_mut();
        match extensions.get_mut::<SpanPrefix>() {
            Some(prefix) => {
                prefix.name = attrs.metadata().name().to_string();
                attrs.record(&mut prefix.visit());
            }
            None => {
                let mut prefix = SpanPrefix::new(span.name().to_string());
                attrs.record(&mut prefix.visit());
                extensions.insert(prefix)
            }
        }
    }

    pub fn on_record<S>(
        id: &span::Id,
        values: &span::Record<'_>,
        ctx: tracing_subscriber::layer::Context<'_, S>,
    ) where
        S: Subscriber + for<'a> LookupSpan<'a>,
    {
        let span = ctx.span(id).expect("Span not found, this is a bug");
        let mut extensions = span.extensions_mut();
        match extensions.get_mut::<SpanPrefix>() {
            Some(prefix) => {
                values.record(&mut prefix.visit());
            }
            None => {
                let mut prefix = SpanPrefix::new(span.name().to_string());
                values.record(&mut prefix.visit());
                extensions.insert(prefix)
            }
        }
    }

    pub fn on_event<S>(
        event: &tracing::Event<'_>,
        ctx: tracing_subscriber::layer::Context<'_, S>,
    ) -> String
    where
        S: Subscriber + for<'a> LookupSpan<'a>,
    {
        let mut message = String::new();
        if let Some(scope) = ctx.event_scope(event) {
            for span in scope.from_root() {
                if let Some(prefix) = span.extensions().get::<SpanPrefix>() {
                    write!(message, "{prefix}").unwrap();
                }
            }
        };
        if !message.is_empty() {
            write!(message, " ").unwrap();
        }
        write!(message, "{}:", event.metadata().target()).unwrap();

        event.record(&mut Visitor(&mut message));
        message
    }

    fn new(name: String) -> Self {
        SpanPrefix {
            name,
            values: Default::default(),
        }
    }

    fn visit(&mut self) -> impl tracing::field::Visit + '_ {
        Visitor(&mut self.values)
    }
}
impl std::fmt::Display for SpanPrefix {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = &self.name;
        let values = &self.values;

        match values.is_empty() {
            true => write!(f, "{name}:"),
            false => write!(f, "{name}{{{values}}}:"),
        }
    }
}

struct Visitor<'a>(&'a mut String);
impl Visitor<'_> {
    fn record_field(&mut self, field: &tracing::field::Field) {
        if !self.0.is_empty() {
            write!(self.0, " ").unwrap();
        }

        if field.as_ref() != "message" {
            write!(self.0, "{field}=").unwrap();
        }
    }
}
impl tracing::field::Visit for Visitor<'_> {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.record_field(field);
        write!(self.0, "{value}").unwrap();
    }

    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.record_field(field);
        write!(self.0, "{value:?}").unwrap();
    }
}
