use std::{any::Any, fmt::Debug};

/// Defines the interface for configuration data used by the `Provider` trait methods.
///
/// This trait allows for dynamic configuration structures to be passed to methods
/// like `create_key` and `load_key`. It enables the `Provider` implementations to
/// handle various types of configurations in a type-safe manner.
///
/// The `Config` trait ensures that configuration data can be dynamically cast to the
/// appropriate type needed by the `Provider` implementation. This is done through
/// the `as_any` method, which provides a way to perform dynamic downcasting.
///
/// Implementors of this trait must also implement the `Debug` trait to provide
/// debugging information and the `Any` trait to support type-safe downcasting.
pub trait ProviderConfig: Any + Debug {
    /// Returns a reference to the underlying `Any` type.
    ///
    /// This method allows for downcasting the `Config` trait object to its concrete type.
    ///
    /// # Returns
    ///
    /// A reference to the `Any` trait object, which can then be downcast to the
    /// specific type implementing `Config`.
    fn as_any(&self) -> &dyn Any;
}
