// coverage:ignore-file
// GENERATED CODE - DO NOT MODIFY BY HAND
// ignore_for_file: type=lint
// ignore_for_file: unused_element, deprecated_member_use, deprecated_member_use_from_same_package, use_function_type_syntax_for_parameters, unnecessary_const, avoid_init_to_null, invalid_override_different_default_values_named, prefer_expression_function_bodies, annotate_overrides, invalid_annotation_target, unnecessary_question_mark

part of 'encryption.dart';

// **************************************************************************
// FreezedGenerator
// **************************************************************************

T _$identity<T>(T value) => value;

final _privateConstructorUsedError = UnsupportedError(
    'It seems like you constructed your class using `MyClass._()`. This constructor is only meant to be used by freezed and you are not supposed to need it nor use it.\nPlease check the documentation here for more information: https://github.com/rrousselGit/freezed#adding-getters-and-methods-to-our-models');

/// @nodoc
mixin _$AsymmetricKeySpec {
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function(KeyBits field0) rsa,
    required TResult Function(EccSigningScheme scheme, EccCurve curve) ecc,
  }) =>
      throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function(KeyBits field0)? rsa,
    TResult? Function(EccSigningScheme scheme, EccCurve curve)? ecc,
  }) =>
      throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function(KeyBits field0)? rsa,
    TResult Function(EccSigningScheme scheme, EccCurve curve)? ecc,
    required TResult orElse(),
  }) =>
      throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(AsymmetricKeySpec_Rsa value) rsa,
    required TResult Function(AsymmetricKeySpec_Ecc value) ecc,
  }) =>
      throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(AsymmetricKeySpec_Rsa value)? rsa,
    TResult? Function(AsymmetricKeySpec_Ecc value)? ecc,
  }) =>
      throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(AsymmetricKeySpec_Rsa value)? rsa,
    TResult Function(AsymmetricKeySpec_Ecc value)? ecc,
    required TResult orElse(),
  }) =>
      throw _privateConstructorUsedError;
}

/// @nodoc
abstract class $AsymmetricKeySpecCopyWith<$Res> {
  factory $AsymmetricKeySpecCopyWith(
          AsymmetricKeySpec value, $Res Function(AsymmetricKeySpec) then) =
      _$AsymmetricKeySpecCopyWithImpl<$Res, AsymmetricKeySpec>;
}

/// @nodoc
class _$AsymmetricKeySpecCopyWithImpl<$Res, $Val extends AsymmetricKeySpec>
    implements $AsymmetricKeySpecCopyWith<$Res> {
  _$AsymmetricKeySpecCopyWithImpl(this._value, this._then);

  // ignore: unused_field
  final $Val _value;
  // ignore: unused_field
  final $Res Function($Val) _then;

  /// Create a copy of AsymmetricKeySpec
  /// with the given fields replaced by the non-null parameter values.
}

/// @nodoc
abstract class _$$AsymmetricKeySpec_RsaImplCopyWith<$Res> {
  factory _$$AsymmetricKeySpec_RsaImplCopyWith(
          _$AsymmetricKeySpec_RsaImpl value,
          $Res Function(_$AsymmetricKeySpec_RsaImpl) then) =
      __$$AsymmetricKeySpec_RsaImplCopyWithImpl<$Res>;
  @useResult
  $Res call({KeyBits field0});
}

/// @nodoc
class __$$AsymmetricKeySpec_RsaImplCopyWithImpl<$Res>
    extends _$AsymmetricKeySpecCopyWithImpl<$Res, _$AsymmetricKeySpec_RsaImpl>
    implements _$$AsymmetricKeySpec_RsaImplCopyWith<$Res> {
  __$$AsymmetricKeySpec_RsaImplCopyWithImpl(_$AsymmetricKeySpec_RsaImpl _value,
      $Res Function(_$AsymmetricKeySpec_RsaImpl) _then)
      : super(_value, _then);

  /// Create a copy of AsymmetricKeySpec
  /// with the given fields replaced by the non-null parameter values.
  @pragma('vm:prefer-inline')
  @override
  $Res call({
    Object? field0 = null,
  }) {
    return _then(_$AsymmetricKeySpec_RsaImpl(
      null == field0
          ? _value.field0
          : field0 // ignore: cast_nullable_to_non_nullable
              as KeyBits,
    ));
  }
}

/// @nodoc

class _$AsymmetricKeySpec_RsaImpl extends AsymmetricKeySpec_Rsa {
  const _$AsymmetricKeySpec_RsaImpl(this.field0) : super._();

  @override
  final KeyBits field0;

  @override
  String toString() {
    return 'AsymmetricKeySpec.rsa(field0: $field0)';
  }

  @override
  bool operator ==(Object other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType &&
            other is _$AsymmetricKeySpec_RsaImpl &&
            (identical(other.field0, field0) || other.field0 == field0));
  }

  @override
  int get hashCode => Object.hash(runtimeType, field0);

  /// Create a copy of AsymmetricKeySpec
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  @override
  @pragma('vm:prefer-inline')
  _$$AsymmetricKeySpec_RsaImplCopyWith<_$AsymmetricKeySpec_RsaImpl>
      get copyWith => __$$AsymmetricKeySpec_RsaImplCopyWithImpl<
          _$AsymmetricKeySpec_RsaImpl>(this, _$identity);

  @override
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function(KeyBits field0) rsa,
    required TResult Function(EccSigningScheme scheme, EccCurve curve) ecc,
  }) {
    return rsa(field0);
  }

  @override
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function(KeyBits field0)? rsa,
    TResult? Function(EccSigningScheme scheme, EccCurve curve)? ecc,
  }) {
    return rsa?.call(field0);
  }

  @override
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function(KeyBits field0)? rsa,
    TResult Function(EccSigningScheme scheme, EccCurve curve)? ecc,
    required TResult orElse(),
  }) {
    if (rsa != null) {
      return rsa(field0);
    }
    return orElse();
  }

  @override
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(AsymmetricKeySpec_Rsa value) rsa,
    required TResult Function(AsymmetricKeySpec_Ecc value) ecc,
  }) {
    return rsa(this);
  }

  @override
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(AsymmetricKeySpec_Rsa value)? rsa,
    TResult? Function(AsymmetricKeySpec_Ecc value)? ecc,
  }) {
    return rsa?.call(this);
  }

  @override
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(AsymmetricKeySpec_Rsa value)? rsa,
    TResult Function(AsymmetricKeySpec_Ecc value)? ecc,
    required TResult orElse(),
  }) {
    if (rsa != null) {
      return rsa(this);
    }
    return orElse();
  }
}

abstract class AsymmetricKeySpec_Rsa extends AsymmetricKeySpec {
  const factory AsymmetricKeySpec_Rsa(final KeyBits field0) =
      _$AsymmetricKeySpec_RsaImpl;
  const AsymmetricKeySpec_Rsa._() : super._();

  KeyBits get field0;

  /// Create a copy of AsymmetricKeySpec
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  _$$AsymmetricKeySpec_RsaImplCopyWith<_$AsymmetricKeySpec_RsaImpl>
      get copyWith => throw _privateConstructorUsedError;
}

/// @nodoc
abstract class _$$AsymmetricKeySpec_EccImplCopyWith<$Res> {
  factory _$$AsymmetricKeySpec_EccImplCopyWith(
          _$AsymmetricKeySpec_EccImpl value,
          $Res Function(_$AsymmetricKeySpec_EccImpl) then) =
      __$$AsymmetricKeySpec_EccImplCopyWithImpl<$Res>;
  @useResult
  $Res call({EccSigningScheme scheme, EccCurve curve});
}

/// @nodoc
class __$$AsymmetricKeySpec_EccImplCopyWithImpl<$Res>
    extends _$AsymmetricKeySpecCopyWithImpl<$Res, _$AsymmetricKeySpec_EccImpl>
    implements _$$AsymmetricKeySpec_EccImplCopyWith<$Res> {
  __$$AsymmetricKeySpec_EccImplCopyWithImpl(_$AsymmetricKeySpec_EccImpl _value,
      $Res Function(_$AsymmetricKeySpec_EccImpl) _then)
      : super(_value, _then);

  /// Create a copy of AsymmetricKeySpec
  /// with the given fields replaced by the non-null parameter values.
  @pragma('vm:prefer-inline')
  @override
  $Res call({
    Object? scheme = null,
    Object? curve = null,
  }) {
    return _then(_$AsymmetricKeySpec_EccImpl(
      scheme: null == scheme
          ? _value.scheme
          : scheme // ignore: cast_nullable_to_non_nullable
              as EccSigningScheme,
      curve: null == curve
          ? _value.curve
          : curve // ignore: cast_nullable_to_non_nullable
              as EccCurve,
    ));
  }
}

/// @nodoc

class _$AsymmetricKeySpec_EccImpl extends AsymmetricKeySpec_Ecc {
  const _$AsymmetricKeySpec_EccImpl({required this.scheme, required this.curve})
      : super._();

  @override
  final EccSigningScheme scheme;
  @override
  final EccCurve curve;

  @override
  String toString() {
    return 'AsymmetricKeySpec.ecc(scheme: $scheme, curve: $curve)';
  }

  @override
  bool operator ==(Object other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType &&
            other is _$AsymmetricKeySpec_EccImpl &&
            (identical(other.scheme, scheme) || other.scheme == scheme) &&
            (identical(other.curve, curve) || other.curve == curve));
  }

  @override
  int get hashCode => Object.hash(runtimeType, scheme, curve);

  /// Create a copy of AsymmetricKeySpec
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  @override
  @pragma('vm:prefer-inline')
  _$$AsymmetricKeySpec_EccImplCopyWith<_$AsymmetricKeySpec_EccImpl>
      get copyWith => __$$AsymmetricKeySpec_EccImplCopyWithImpl<
          _$AsymmetricKeySpec_EccImpl>(this, _$identity);

  @override
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function(KeyBits field0) rsa,
    required TResult Function(EccSigningScheme scheme, EccCurve curve) ecc,
  }) {
    return ecc(scheme, curve);
  }

  @override
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function(KeyBits field0)? rsa,
    TResult? Function(EccSigningScheme scheme, EccCurve curve)? ecc,
  }) {
    return ecc?.call(scheme, curve);
  }

  @override
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function(KeyBits field0)? rsa,
    TResult Function(EccSigningScheme scheme, EccCurve curve)? ecc,
    required TResult orElse(),
  }) {
    if (ecc != null) {
      return ecc(scheme, curve);
    }
    return orElse();
  }

  @override
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(AsymmetricKeySpec_Rsa value) rsa,
    required TResult Function(AsymmetricKeySpec_Ecc value) ecc,
  }) {
    return ecc(this);
  }

  @override
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(AsymmetricKeySpec_Rsa value)? rsa,
    TResult? Function(AsymmetricKeySpec_Ecc value)? ecc,
  }) {
    return ecc?.call(this);
  }

  @override
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(AsymmetricKeySpec_Rsa value)? rsa,
    TResult Function(AsymmetricKeySpec_Ecc value)? ecc,
    required TResult orElse(),
  }) {
    if (ecc != null) {
      return ecc(this);
    }
    return orElse();
  }
}

abstract class AsymmetricKeySpec_Ecc extends AsymmetricKeySpec {
  const factory AsymmetricKeySpec_Ecc(
      {required final EccSigningScheme scheme,
      required final EccCurve curve}) = _$AsymmetricKeySpec_EccImpl;
  const AsymmetricKeySpec_Ecc._() : super._();

  EccSigningScheme get scheme;
  EccCurve get curve;

  /// Create a copy of AsymmetricKeySpec
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  _$$AsymmetricKeySpec_EccImplCopyWith<_$AsymmetricKeySpec_EccImpl>
      get copyWith => throw _privateConstructorUsedError;
}
