// coverage:ignore-file
// GENERATED CODE - DO NOT MODIFY BY HAND
// ignore_for_file: type=lint
// ignore_for_file: unused_element, deprecated_member_use, deprecated_member_use_from_same_package, use_function_type_syntax_for_parameters, unnecessary_const, avoid_init_to_null, invalid_override_different_default_values_named, prefer_expression_function_bodies, annotate_overrides, invalid_annotation_target, unnecessary_question_mark

part of 'config.dart';

// **************************************************************************
// FreezedGenerator
// **************************************************************************

T _$identity<T>(T value) => value;

final _privateConstructorUsedError = UnsupportedError(
    'It seems like you constructed your class using `MyClass._()`. This constructor is only meant to be used by freezed and you are not supposed to need it nor use it.\nPlease check the documentation here for more information: https://github.com/rrousselGit/freezed#adding-getters-and-methods-to-our-models');

/// @nodoc
mixin _$Spec {
  Object get field0 => throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function(KeySpec field0) keySpec,
    required TResult Function(KeyPairSpec field0) keyPairSpec,
  }) =>
      throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function(KeySpec field0)? keySpec,
    TResult? Function(KeyPairSpec field0)? keyPairSpec,
  }) =>
      throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function(KeySpec field0)? keySpec,
    TResult Function(KeyPairSpec field0)? keyPairSpec,
    required TResult orElse(),
  }) =>
      throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(Spec_KeySpec value) keySpec,
    required TResult Function(Spec_KeyPairSpec value) keyPairSpec,
  }) =>
      throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(Spec_KeySpec value)? keySpec,
    TResult? Function(Spec_KeyPairSpec value)? keyPairSpec,
  }) =>
      throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(Spec_KeySpec value)? keySpec,
    TResult Function(Spec_KeyPairSpec value)? keyPairSpec,
    required TResult orElse(),
  }) =>
      throw _privateConstructorUsedError;
}

/// @nodoc
abstract class $SpecCopyWith<$Res> {
  factory $SpecCopyWith(Spec value, $Res Function(Spec) then) =
      _$SpecCopyWithImpl<$Res, Spec>;
}

/// @nodoc
class _$SpecCopyWithImpl<$Res, $Val extends Spec>
    implements $SpecCopyWith<$Res> {
  _$SpecCopyWithImpl(this._value, this._then);

  // ignore: unused_field
  final $Val _value;
  // ignore: unused_field
  final $Res Function($Val) _then;

  /// Create a copy of Spec
  /// with the given fields replaced by the non-null parameter values.
}

/// @nodoc
abstract class _$$Spec_KeySpecImplCopyWith<$Res> {
  factory _$$Spec_KeySpecImplCopyWith(
          _$Spec_KeySpecImpl value, $Res Function(_$Spec_KeySpecImpl) then) =
      __$$Spec_KeySpecImplCopyWithImpl<$Res>;
  @useResult
  $Res call({KeySpec field0});
}

/// @nodoc
class __$$Spec_KeySpecImplCopyWithImpl<$Res>
    extends _$SpecCopyWithImpl<$Res, _$Spec_KeySpecImpl>
    implements _$$Spec_KeySpecImplCopyWith<$Res> {
  __$$Spec_KeySpecImplCopyWithImpl(
      _$Spec_KeySpecImpl _value, $Res Function(_$Spec_KeySpecImpl) _then)
      : super(_value, _then);

  /// Create a copy of Spec
  /// with the given fields replaced by the non-null parameter values.
  @pragma('vm:prefer-inline')
  @override
  $Res call({
    Object? field0 = null,
  }) {
    return _then(_$Spec_KeySpecImpl(
      null == field0
          ? _value.field0
          : field0 // ignore: cast_nullable_to_non_nullable
              as KeySpec,
    ));
  }
}

/// @nodoc

class _$Spec_KeySpecImpl extends Spec_KeySpec {
  const _$Spec_KeySpecImpl(this.field0) : super._();

  @override
  final KeySpec field0;

  @override
  String toString() {
    return 'Spec.keySpec(field0: $field0)';
  }

  @override
  bool operator ==(Object other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType &&
            other is _$Spec_KeySpecImpl &&
            (identical(other.field0, field0) || other.field0 == field0));
  }

  @override
  int get hashCode => Object.hash(runtimeType, field0);

  /// Create a copy of Spec
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  @override
  @pragma('vm:prefer-inline')
  _$$Spec_KeySpecImplCopyWith<_$Spec_KeySpecImpl> get copyWith =>
      __$$Spec_KeySpecImplCopyWithImpl<_$Spec_KeySpecImpl>(this, _$identity);

  @override
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function(KeySpec field0) keySpec,
    required TResult Function(KeyPairSpec field0) keyPairSpec,
  }) {
    return keySpec(field0);
  }

  @override
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function(KeySpec field0)? keySpec,
    TResult? Function(KeyPairSpec field0)? keyPairSpec,
  }) {
    return keySpec?.call(field0);
  }

  @override
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function(KeySpec field0)? keySpec,
    TResult Function(KeyPairSpec field0)? keyPairSpec,
    required TResult orElse(),
  }) {
    if (keySpec != null) {
      return keySpec(field0);
    }
    return orElse();
  }

  @override
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(Spec_KeySpec value) keySpec,
    required TResult Function(Spec_KeyPairSpec value) keyPairSpec,
  }) {
    return keySpec(this);
  }

  @override
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(Spec_KeySpec value)? keySpec,
    TResult? Function(Spec_KeyPairSpec value)? keyPairSpec,
  }) {
    return keySpec?.call(this);
  }

  @override
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(Spec_KeySpec value)? keySpec,
    TResult Function(Spec_KeyPairSpec value)? keyPairSpec,
    required TResult orElse(),
  }) {
    if (keySpec != null) {
      return keySpec(this);
    }
    return orElse();
  }
}

abstract class Spec_KeySpec extends Spec {
  const factory Spec_KeySpec(final KeySpec field0) = _$Spec_KeySpecImpl;
  const Spec_KeySpec._() : super._();

  @override
  KeySpec get field0;

  /// Create a copy of Spec
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  _$$Spec_KeySpecImplCopyWith<_$Spec_KeySpecImpl> get copyWith =>
      throw _privateConstructorUsedError;
}

/// @nodoc
abstract class _$$Spec_KeyPairSpecImplCopyWith<$Res> {
  factory _$$Spec_KeyPairSpecImplCopyWith(_$Spec_KeyPairSpecImpl value,
          $Res Function(_$Spec_KeyPairSpecImpl) then) =
      __$$Spec_KeyPairSpecImplCopyWithImpl<$Res>;
  @useResult
  $Res call({KeyPairSpec field0});
}

/// @nodoc
class __$$Spec_KeyPairSpecImplCopyWithImpl<$Res>
    extends _$SpecCopyWithImpl<$Res, _$Spec_KeyPairSpecImpl>
    implements _$$Spec_KeyPairSpecImplCopyWith<$Res> {
  __$$Spec_KeyPairSpecImplCopyWithImpl(_$Spec_KeyPairSpecImpl _value,
      $Res Function(_$Spec_KeyPairSpecImpl) _then)
      : super(_value, _then);

  /// Create a copy of Spec
  /// with the given fields replaced by the non-null parameter values.
  @pragma('vm:prefer-inline')
  @override
  $Res call({
    Object? field0 = null,
  }) {
    return _then(_$Spec_KeyPairSpecImpl(
      null == field0
          ? _value.field0
          : field0 // ignore: cast_nullable_to_non_nullable
              as KeyPairSpec,
    ));
  }
}

/// @nodoc

class _$Spec_KeyPairSpecImpl extends Spec_KeyPairSpec {
  const _$Spec_KeyPairSpecImpl(this.field0) : super._();

  @override
  final KeyPairSpec field0;

  @override
  String toString() {
    return 'Spec.keyPairSpec(field0: $field0)';
  }

  @override
  bool operator ==(Object other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType &&
            other is _$Spec_KeyPairSpecImpl &&
            (identical(other.field0, field0) || other.field0 == field0));
  }

  @override
  int get hashCode => Object.hash(runtimeType, field0);

  /// Create a copy of Spec
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  @override
  @pragma('vm:prefer-inline')
  _$$Spec_KeyPairSpecImplCopyWith<_$Spec_KeyPairSpecImpl> get copyWith =>
      __$$Spec_KeyPairSpecImplCopyWithImpl<_$Spec_KeyPairSpecImpl>(
          this, _$identity);

  @override
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function(KeySpec field0) keySpec,
    required TResult Function(KeyPairSpec field0) keyPairSpec,
  }) {
    return keyPairSpec(field0);
  }

  @override
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function(KeySpec field0)? keySpec,
    TResult? Function(KeyPairSpec field0)? keyPairSpec,
  }) {
    return keyPairSpec?.call(field0);
  }

  @override
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function(KeySpec field0)? keySpec,
    TResult Function(KeyPairSpec field0)? keyPairSpec,
    required TResult orElse(),
  }) {
    if (keyPairSpec != null) {
      return keyPairSpec(field0);
    }
    return orElse();
  }

  @override
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(Spec_KeySpec value) keySpec,
    required TResult Function(Spec_KeyPairSpec value) keyPairSpec,
  }) {
    return keyPairSpec(this);
  }

  @override
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(Spec_KeySpec value)? keySpec,
    TResult? Function(Spec_KeyPairSpec value)? keyPairSpec,
  }) {
    return keyPairSpec?.call(this);
  }

  @override
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(Spec_KeySpec value)? keySpec,
    TResult Function(Spec_KeyPairSpec value)? keyPairSpec,
    required TResult orElse(),
  }) {
    if (keyPairSpec != null) {
      return keyPairSpec(this);
    }
    return orElse();
  }
}

abstract class Spec_KeyPairSpec extends Spec {
  const factory Spec_KeyPairSpec(final KeyPairSpec field0) =
      _$Spec_KeyPairSpecImpl;
  const Spec_KeyPairSpec._() : super._();

  @override
  KeyPairSpec get field0;

  /// Create a copy of Spec
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  _$$Spec_KeyPairSpecImplCopyWith<_$Spec_KeyPairSpecImpl> get copyWith =>
      throw _privateConstructorUsedError;
}
