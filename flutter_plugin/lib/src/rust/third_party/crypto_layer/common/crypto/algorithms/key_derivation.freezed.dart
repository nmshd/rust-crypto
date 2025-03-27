// coverage:ignore-file
// GENERATED CODE - DO NOT MODIFY BY HAND
// ignore_for_file: type=lint
// ignore_for_file: unused_element, deprecated_member_use, deprecated_member_use_from_same_package, use_function_type_syntax_for_parameters, unnecessary_const, avoid_init_to_null, invalid_override_different_default_values_named, prefer_expression_function_bodies, annotate_overrides, invalid_annotation_target, unnecessary_question_mark

part of 'key_derivation.dart';

// **************************************************************************
// FreezedGenerator
// **************************************************************************

T _$identity<T>(T value) => value;

final _privateConstructorUsedError = UnsupportedError(
    'It seems like you constructed your class using `MyClass._()`. This constructor is only meant to be used by freezed and you are not supposed to need it nor use it.\nPlease check the documentation here for more information: https://github.com/rrousselGit/freezed#adding-getters-and-methods-to-our-models');

/// @nodoc
mixin _$KDF {
  Argon2Options get field0 => throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function(Argon2Options field0) argon2D,
    required TResult Function(Argon2Options field0) argon2Id,
    required TResult Function(Argon2Options field0) argon2I,
  }) =>
      throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function(Argon2Options field0)? argon2D,
    TResult? Function(Argon2Options field0)? argon2Id,
    TResult? Function(Argon2Options field0)? argon2I,
  }) =>
      throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function(Argon2Options field0)? argon2D,
    TResult Function(Argon2Options field0)? argon2Id,
    TResult Function(Argon2Options field0)? argon2I,
    required TResult orElse(),
  }) =>
      throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(KDF_Argon2d value) argon2D,
    required TResult Function(KDF_Argon2id value) argon2Id,
    required TResult Function(KDF_Argon2i value) argon2I,
  }) =>
      throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(KDF_Argon2d value)? argon2D,
    TResult? Function(KDF_Argon2id value)? argon2Id,
    TResult? Function(KDF_Argon2i value)? argon2I,
  }) =>
      throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(KDF_Argon2d value)? argon2D,
    TResult Function(KDF_Argon2id value)? argon2Id,
    TResult Function(KDF_Argon2i value)? argon2I,
    required TResult orElse(),
  }) =>
      throw _privateConstructorUsedError;

  /// Create a copy of KDF
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  $KDFCopyWith<KDF> get copyWith => throw _privateConstructorUsedError;
}

/// @nodoc
abstract class $KDFCopyWith<$Res> {
  factory $KDFCopyWith(KDF value, $Res Function(KDF) then) =
      _$KDFCopyWithImpl<$Res, KDF>;
  @useResult
  $Res call({Argon2Options field0});
}

/// @nodoc
class _$KDFCopyWithImpl<$Res, $Val extends KDF> implements $KDFCopyWith<$Res> {
  _$KDFCopyWithImpl(this._value, this._then);

  // ignore: unused_field
  final $Val _value;
  // ignore: unused_field
  final $Res Function($Val) _then;

  /// Create a copy of KDF
  /// with the given fields replaced by the non-null parameter values.
  @pragma('vm:prefer-inline')
  @override
  $Res call({
    Object? field0 = null,
  }) {
    return _then(_value.copyWith(
      field0: null == field0
          ? _value.field0
          : field0 // ignore: cast_nullable_to_non_nullable
              as Argon2Options,
    ) as $Val);
  }
}

/// @nodoc
abstract class _$$KDF_Argon2dImplCopyWith<$Res> implements $KDFCopyWith<$Res> {
  factory _$$KDF_Argon2dImplCopyWith(
          _$KDF_Argon2dImpl value, $Res Function(_$KDF_Argon2dImpl) then) =
      __$$KDF_Argon2dImplCopyWithImpl<$Res>;
  @override
  @useResult
  $Res call({Argon2Options field0});
}

/// @nodoc
class __$$KDF_Argon2dImplCopyWithImpl<$Res>
    extends _$KDFCopyWithImpl<$Res, _$KDF_Argon2dImpl>
    implements _$$KDF_Argon2dImplCopyWith<$Res> {
  __$$KDF_Argon2dImplCopyWithImpl(
      _$KDF_Argon2dImpl _value, $Res Function(_$KDF_Argon2dImpl) _then)
      : super(_value, _then);

  /// Create a copy of KDF
  /// with the given fields replaced by the non-null parameter values.
  @pragma('vm:prefer-inline')
  @override
  $Res call({
    Object? field0 = null,
  }) {
    return _then(_$KDF_Argon2dImpl(
      null == field0
          ? _value.field0
          : field0 // ignore: cast_nullable_to_non_nullable
              as Argon2Options,
    ));
  }
}

/// @nodoc

class _$KDF_Argon2dImpl extends KDF_Argon2d {
  const _$KDF_Argon2dImpl(this.field0) : super._();

  @override
  final Argon2Options field0;

  @override
  String toString() {
    return 'KDF.argon2D(field0: $field0)';
  }

  @override
  bool operator ==(Object other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType &&
            other is _$KDF_Argon2dImpl &&
            (identical(other.field0, field0) || other.field0 == field0));
  }

  @override
  int get hashCode => Object.hash(runtimeType, field0);

  /// Create a copy of KDF
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  @override
  @pragma('vm:prefer-inline')
  _$$KDF_Argon2dImplCopyWith<_$KDF_Argon2dImpl> get copyWith =>
      __$$KDF_Argon2dImplCopyWithImpl<_$KDF_Argon2dImpl>(this, _$identity);

  @override
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function(Argon2Options field0) argon2D,
    required TResult Function(Argon2Options field0) argon2Id,
    required TResult Function(Argon2Options field0) argon2I,
  }) {
    return argon2D(field0);
  }

  @override
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function(Argon2Options field0)? argon2D,
    TResult? Function(Argon2Options field0)? argon2Id,
    TResult? Function(Argon2Options field0)? argon2I,
  }) {
    return argon2D?.call(field0);
  }

  @override
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function(Argon2Options field0)? argon2D,
    TResult Function(Argon2Options field0)? argon2Id,
    TResult Function(Argon2Options field0)? argon2I,
    required TResult orElse(),
  }) {
    if (argon2D != null) {
      return argon2D(field0);
    }
    return orElse();
  }

  @override
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(KDF_Argon2d value) argon2D,
    required TResult Function(KDF_Argon2id value) argon2Id,
    required TResult Function(KDF_Argon2i value) argon2I,
  }) {
    return argon2D(this);
  }

  @override
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(KDF_Argon2d value)? argon2D,
    TResult? Function(KDF_Argon2id value)? argon2Id,
    TResult? Function(KDF_Argon2i value)? argon2I,
  }) {
    return argon2D?.call(this);
  }

  @override
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(KDF_Argon2d value)? argon2D,
    TResult Function(KDF_Argon2id value)? argon2Id,
    TResult Function(KDF_Argon2i value)? argon2I,
    required TResult orElse(),
  }) {
    if (argon2D != null) {
      return argon2D(this);
    }
    return orElse();
  }
}

abstract class KDF_Argon2d extends KDF {
  const factory KDF_Argon2d(final Argon2Options field0) = _$KDF_Argon2dImpl;
  const KDF_Argon2d._() : super._();

  @override
  Argon2Options get field0;

  /// Create a copy of KDF
  /// with the given fields replaced by the non-null parameter values.
  @override
  @JsonKey(includeFromJson: false, includeToJson: false)
  _$$KDF_Argon2dImplCopyWith<_$KDF_Argon2dImpl> get copyWith =>
      throw _privateConstructorUsedError;
}

/// @nodoc
abstract class _$$KDF_Argon2idImplCopyWith<$Res> implements $KDFCopyWith<$Res> {
  factory _$$KDF_Argon2idImplCopyWith(
          _$KDF_Argon2idImpl value, $Res Function(_$KDF_Argon2idImpl) then) =
      __$$KDF_Argon2idImplCopyWithImpl<$Res>;
  @override
  @useResult
  $Res call({Argon2Options field0});
}

/// @nodoc
class __$$KDF_Argon2idImplCopyWithImpl<$Res>
    extends _$KDFCopyWithImpl<$Res, _$KDF_Argon2idImpl>
    implements _$$KDF_Argon2idImplCopyWith<$Res> {
  __$$KDF_Argon2idImplCopyWithImpl(
      _$KDF_Argon2idImpl _value, $Res Function(_$KDF_Argon2idImpl) _then)
      : super(_value, _then);

  /// Create a copy of KDF
  /// with the given fields replaced by the non-null parameter values.
  @pragma('vm:prefer-inline')
  @override
  $Res call({
    Object? field0 = null,
  }) {
    return _then(_$KDF_Argon2idImpl(
      null == field0
          ? _value.field0
          : field0 // ignore: cast_nullable_to_non_nullable
              as Argon2Options,
    ));
  }
}

/// @nodoc

class _$KDF_Argon2idImpl extends KDF_Argon2id {
  const _$KDF_Argon2idImpl(this.field0) : super._();

  @override
  final Argon2Options field0;

  @override
  String toString() {
    return 'KDF.argon2Id(field0: $field0)';
  }

  @override
  bool operator ==(Object other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType &&
            other is _$KDF_Argon2idImpl &&
            (identical(other.field0, field0) || other.field0 == field0));
  }

  @override
  int get hashCode => Object.hash(runtimeType, field0);

  /// Create a copy of KDF
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  @override
  @pragma('vm:prefer-inline')
  _$$KDF_Argon2idImplCopyWith<_$KDF_Argon2idImpl> get copyWith =>
      __$$KDF_Argon2idImplCopyWithImpl<_$KDF_Argon2idImpl>(this, _$identity);

  @override
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function(Argon2Options field0) argon2D,
    required TResult Function(Argon2Options field0) argon2Id,
    required TResult Function(Argon2Options field0) argon2I,
  }) {
    return argon2Id(field0);
  }

  @override
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function(Argon2Options field0)? argon2D,
    TResult? Function(Argon2Options field0)? argon2Id,
    TResult? Function(Argon2Options field0)? argon2I,
  }) {
    return argon2Id?.call(field0);
  }

  @override
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function(Argon2Options field0)? argon2D,
    TResult Function(Argon2Options field0)? argon2Id,
    TResult Function(Argon2Options field0)? argon2I,
    required TResult orElse(),
  }) {
    if (argon2Id != null) {
      return argon2Id(field0);
    }
    return orElse();
  }

  @override
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(KDF_Argon2d value) argon2D,
    required TResult Function(KDF_Argon2id value) argon2Id,
    required TResult Function(KDF_Argon2i value) argon2I,
  }) {
    return argon2Id(this);
  }

  @override
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(KDF_Argon2d value)? argon2D,
    TResult? Function(KDF_Argon2id value)? argon2Id,
    TResult? Function(KDF_Argon2i value)? argon2I,
  }) {
    return argon2Id?.call(this);
  }

  @override
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(KDF_Argon2d value)? argon2D,
    TResult Function(KDF_Argon2id value)? argon2Id,
    TResult Function(KDF_Argon2i value)? argon2I,
    required TResult orElse(),
  }) {
    if (argon2Id != null) {
      return argon2Id(this);
    }
    return orElse();
  }
}

abstract class KDF_Argon2id extends KDF {
  const factory KDF_Argon2id(final Argon2Options field0) = _$KDF_Argon2idImpl;
  const KDF_Argon2id._() : super._();

  @override
  Argon2Options get field0;

  /// Create a copy of KDF
  /// with the given fields replaced by the non-null parameter values.
  @override
  @JsonKey(includeFromJson: false, includeToJson: false)
  _$$KDF_Argon2idImplCopyWith<_$KDF_Argon2idImpl> get copyWith =>
      throw _privateConstructorUsedError;
}

/// @nodoc
abstract class _$$KDF_Argon2iImplCopyWith<$Res> implements $KDFCopyWith<$Res> {
  factory _$$KDF_Argon2iImplCopyWith(
          _$KDF_Argon2iImpl value, $Res Function(_$KDF_Argon2iImpl) then) =
      __$$KDF_Argon2iImplCopyWithImpl<$Res>;
  @override
  @useResult
  $Res call({Argon2Options field0});
}

/// @nodoc
class __$$KDF_Argon2iImplCopyWithImpl<$Res>
    extends _$KDFCopyWithImpl<$Res, _$KDF_Argon2iImpl>
    implements _$$KDF_Argon2iImplCopyWith<$Res> {
  __$$KDF_Argon2iImplCopyWithImpl(
      _$KDF_Argon2iImpl _value, $Res Function(_$KDF_Argon2iImpl) _then)
      : super(_value, _then);

  /// Create a copy of KDF
  /// with the given fields replaced by the non-null parameter values.
  @pragma('vm:prefer-inline')
  @override
  $Res call({
    Object? field0 = null,
  }) {
    return _then(_$KDF_Argon2iImpl(
      null == field0
          ? _value.field0
          : field0 // ignore: cast_nullable_to_non_nullable
              as Argon2Options,
    ));
  }
}

/// @nodoc

class _$KDF_Argon2iImpl extends KDF_Argon2i {
  const _$KDF_Argon2iImpl(this.field0) : super._();

  @override
  final Argon2Options field0;

  @override
  String toString() {
    return 'KDF.argon2I(field0: $field0)';
  }

  @override
  bool operator ==(Object other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType &&
            other is _$KDF_Argon2iImpl &&
            (identical(other.field0, field0) || other.field0 == field0));
  }

  @override
  int get hashCode => Object.hash(runtimeType, field0);

  /// Create a copy of KDF
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  @override
  @pragma('vm:prefer-inline')
  _$$KDF_Argon2iImplCopyWith<_$KDF_Argon2iImpl> get copyWith =>
      __$$KDF_Argon2iImplCopyWithImpl<_$KDF_Argon2iImpl>(this, _$identity);

  @override
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function(Argon2Options field0) argon2D,
    required TResult Function(Argon2Options field0) argon2Id,
    required TResult Function(Argon2Options field0) argon2I,
  }) {
    return argon2I(field0);
  }

  @override
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function(Argon2Options field0)? argon2D,
    TResult? Function(Argon2Options field0)? argon2Id,
    TResult? Function(Argon2Options field0)? argon2I,
  }) {
    return argon2I?.call(field0);
  }

  @override
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function(Argon2Options field0)? argon2D,
    TResult Function(Argon2Options field0)? argon2Id,
    TResult Function(Argon2Options field0)? argon2I,
    required TResult orElse(),
  }) {
    if (argon2I != null) {
      return argon2I(field0);
    }
    return orElse();
  }

  @override
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(KDF_Argon2d value) argon2D,
    required TResult Function(KDF_Argon2id value) argon2Id,
    required TResult Function(KDF_Argon2i value) argon2I,
  }) {
    return argon2I(this);
  }

  @override
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(KDF_Argon2d value)? argon2D,
    TResult? Function(KDF_Argon2id value)? argon2Id,
    TResult? Function(KDF_Argon2i value)? argon2I,
  }) {
    return argon2I?.call(this);
  }

  @override
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(KDF_Argon2d value)? argon2D,
    TResult Function(KDF_Argon2id value)? argon2Id,
    TResult Function(KDF_Argon2i value)? argon2I,
    required TResult orElse(),
  }) {
    if (argon2I != null) {
      return argon2I(this);
    }
    return orElse();
  }
}

abstract class KDF_Argon2i extends KDF {
  const factory KDF_Argon2i(final Argon2Options field0) = _$KDF_Argon2iImpl;
  const KDF_Argon2i._() : super._();

  @override
  Argon2Options get field0;

  /// Create a copy of KDF
  /// with the given fields replaced by the non-null parameter values.
  @override
  @JsonKey(includeFromJson: false, includeToJson: false)
  _$$KDF_Argon2iImplCopyWith<_$KDF_Argon2iImpl> get copyWith =>
      throw _privateConstructorUsedError;
}
