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

/// @nodoc
mixin _$Cipher {
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function(SymmetricMode field0, KeyBits field1) aes,
    required TResult Function(TripleDesNumKeys field0) tripleDes,
    required TResult Function() des,
    required TResult Function(Rc2KeyBits field0) rc2,
    required TResult Function(SymmetricMode field0, KeyBits field1) camellia,
    required TResult Function() rc4,
    required TResult Function(ChCha20Mode field0) chacha20,
  }) =>
      throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function(SymmetricMode field0, KeyBits field1)? aes,
    TResult? Function(TripleDesNumKeys field0)? tripleDes,
    TResult? Function()? des,
    TResult? Function(Rc2KeyBits field0)? rc2,
    TResult? Function(SymmetricMode field0, KeyBits field1)? camellia,
    TResult? Function()? rc4,
    TResult? Function(ChCha20Mode field0)? chacha20,
  }) =>
      throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function(SymmetricMode field0, KeyBits field1)? aes,
    TResult Function(TripleDesNumKeys field0)? tripleDes,
    TResult Function()? des,
    TResult Function(Rc2KeyBits field0)? rc2,
    TResult Function(SymmetricMode field0, KeyBits field1)? camellia,
    TResult Function()? rc4,
    TResult Function(ChCha20Mode field0)? chacha20,
    required TResult orElse(),
  }) =>
      throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(Cipher_Aes value) aes,
    required TResult Function(Cipher_TripleDes value) tripleDes,
    required TResult Function(Cipher_Des value) des,
    required TResult Function(Cipher_Rc2 value) rc2,
    required TResult Function(Cipher_Camellia value) camellia,
    required TResult Function(Cipher_Rc4 value) rc4,
    required TResult Function(Cipher_Chacha20 value) chacha20,
  }) =>
      throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(Cipher_Aes value)? aes,
    TResult? Function(Cipher_TripleDes value)? tripleDes,
    TResult? Function(Cipher_Des value)? des,
    TResult? Function(Cipher_Rc2 value)? rc2,
    TResult? Function(Cipher_Camellia value)? camellia,
    TResult? Function(Cipher_Rc4 value)? rc4,
    TResult? Function(Cipher_Chacha20 value)? chacha20,
  }) =>
      throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(Cipher_Aes value)? aes,
    TResult Function(Cipher_TripleDes value)? tripleDes,
    TResult Function(Cipher_Des value)? des,
    TResult Function(Cipher_Rc2 value)? rc2,
    TResult Function(Cipher_Camellia value)? camellia,
    TResult Function(Cipher_Rc4 value)? rc4,
    TResult Function(Cipher_Chacha20 value)? chacha20,
    required TResult orElse(),
  }) =>
      throw _privateConstructorUsedError;
}

/// @nodoc
abstract class $CipherCopyWith<$Res> {
  factory $CipherCopyWith(Cipher value, $Res Function(Cipher) then) =
      _$CipherCopyWithImpl<$Res, Cipher>;
}

/// @nodoc
class _$CipherCopyWithImpl<$Res, $Val extends Cipher>
    implements $CipherCopyWith<$Res> {
  _$CipherCopyWithImpl(this._value, this._then);

  // ignore: unused_field
  final $Val _value;
  // ignore: unused_field
  final $Res Function($Val) _then;

  /// Create a copy of Cipher
  /// with the given fields replaced by the non-null parameter values.
}

/// @nodoc
abstract class _$$Cipher_AesImplCopyWith<$Res> {
  factory _$$Cipher_AesImplCopyWith(
          _$Cipher_AesImpl value, $Res Function(_$Cipher_AesImpl) then) =
      __$$Cipher_AesImplCopyWithImpl<$Res>;
  @useResult
  $Res call({SymmetricMode field0, KeyBits field1});
}

/// @nodoc
class __$$Cipher_AesImplCopyWithImpl<$Res>
    extends _$CipherCopyWithImpl<$Res, _$Cipher_AesImpl>
    implements _$$Cipher_AesImplCopyWith<$Res> {
  __$$Cipher_AesImplCopyWithImpl(
      _$Cipher_AesImpl _value, $Res Function(_$Cipher_AesImpl) _then)
      : super(_value, _then);

  /// Create a copy of Cipher
  /// with the given fields replaced by the non-null parameter values.
  @pragma('vm:prefer-inline')
  @override
  $Res call({
    Object? field0 = null,
    Object? field1 = null,
  }) {
    return _then(_$Cipher_AesImpl(
      null == field0
          ? _value.field0
          : field0 // ignore: cast_nullable_to_non_nullable
              as SymmetricMode,
      null == field1
          ? _value.field1
          : field1 // ignore: cast_nullable_to_non_nullable
              as KeyBits,
    ));
  }
}

/// @nodoc

class _$Cipher_AesImpl extends Cipher_Aes {
  const _$Cipher_AesImpl(this.field0, this.field1) : super._();

  @override
  final SymmetricMode field0;
  @override
  final KeyBits field1;

  @override
  String toString() {
    return 'Cipher.aes(field0: $field0, field1: $field1)';
  }

  @override
  bool operator ==(Object other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType &&
            other is _$Cipher_AesImpl &&
            (identical(other.field0, field0) || other.field0 == field0) &&
            (identical(other.field1, field1) || other.field1 == field1));
  }

  @override
  int get hashCode => Object.hash(runtimeType, field0, field1);

  /// Create a copy of Cipher
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  @override
  @pragma('vm:prefer-inline')
  _$$Cipher_AesImplCopyWith<_$Cipher_AesImpl> get copyWith =>
      __$$Cipher_AesImplCopyWithImpl<_$Cipher_AesImpl>(this, _$identity);

  @override
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function(SymmetricMode field0, KeyBits field1) aes,
    required TResult Function(TripleDesNumKeys field0) tripleDes,
    required TResult Function() des,
    required TResult Function(Rc2KeyBits field0) rc2,
    required TResult Function(SymmetricMode field0, KeyBits field1) camellia,
    required TResult Function() rc4,
    required TResult Function(ChCha20Mode field0) chacha20,
  }) {
    return aes(field0, field1);
  }

  @override
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function(SymmetricMode field0, KeyBits field1)? aes,
    TResult? Function(TripleDesNumKeys field0)? tripleDes,
    TResult? Function()? des,
    TResult? Function(Rc2KeyBits field0)? rc2,
    TResult? Function(SymmetricMode field0, KeyBits field1)? camellia,
    TResult? Function()? rc4,
    TResult? Function(ChCha20Mode field0)? chacha20,
  }) {
    return aes?.call(field0, field1);
  }

  @override
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function(SymmetricMode field0, KeyBits field1)? aes,
    TResult Function(TripleDesNumKeys field0)? tripleDes,
    TResult Function()? des,
    TResult Function(Rc2KeyBits field0)? rc2,
    TResult Function(SymmetricMode field0, KeyBits field1)? camellia,
    TResult Function()? rc4,
    TResult Function(ChCha20Mode field0)? chacha20,
    required TResult orElse(),
  }) {
    if (aes != null) {
      return aes(field0, field1);
    }
    return orElse();
  }

  @override
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(Cipher_Aes value) aes,
    required TResult Function(Cipher_TripleDes value) tripleDes,
    required TResult Function(Cipher_Des value) des,
    required TResult Function(Cipher_Rc2 value) rc2,
    required TResult Function(Cipher_Camellia value) camellia,
    required TResult Function(Cipher_Rc4 value) rc4,
    required TResult Function(Cipher_Chacha20 value) chacha20,
  }) {
    return aes(this);
  }

  @override
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(Cipher_Aes value)? aes,
    TResult? Function(Cipher_TripleDes value)? tripleDes,
    TResult? Function(Cipher_Des value)? des,
    TResult? Function(Cipher_Rc2 value)? rc2,
    TResult? Function(Cipher_Camellia value)? camellia,
    TResult? Function(Cipher_Rc4 value)? rc4,
    TResult? Function(Cipher_Chacha20 value)? chacha20,
  }) {
    return aes?.call(this);
  }

  @override
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(Cipher_Aes value)? aes,
    TResult Function(Cipher_TripleDes value)? tripleDes,
    TResult Function(Cipher_Des value)? des,
    TResult Function(Cipher_Rc2 value)? rc2,
    TResult Function(Cipher_Camellia value)? camellia,
    TResult Function(Cipher_Rc4 value)? rc4,
    TResult Function(Cipher_Chacha20 value)? chacha20,
    required TResult orElse(),
  }) {
    if (aes != null) {
      return aes(this);
    }
    return orElse();
  }
}

abstract class Cipher_Aes extends Cipher {
  const factory Cipher_Aes(final SymmetricMode field0, final KeyBits field1) =
      _$Cipher_AesImpl;
  const Cipher_Aes._() : super._();

  SymmetricMode get field0;
  KeyBits get field1;

  /// Create a copy of Cipher
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  _$$Cipher_AesImplCopyWith<_$Cipher_AesImpl> get copyWith =>
      throw _privateConstructorUsedError;
}

/// @nodoc
abstract class _$$Cipher_TripleDesImplCopyWith<$Res> {
  factory _$$Cipher_TripleDesImplCopyWith(_$Cipher_TripleDesImpl value,
          $Res Function(_$Cipher_TripleDesImpl) then) =
      __$$Cipher_TripleDesImplCopyWithImpl<$Res>;
  @useResult
  $Res call({TripleDesNumKeys field0});
}

/// @nodoc
class __$$Cipher_TripleDesImplCopyWithImpl<$Res>
    extends _$CipherCopyWithImpl<$Res, _$Cipher_TripleDesImpl>
    implements _$$Cipher_TripleDesImplCopyWith<$Res> {
  __$$Cipher_TripleDesImplCopyWithImpl(_$Cipher_TripleDesImpl _value,
      $Res Function(_$Cipher_TripleDesImpl) _then)
      : super(_value, _then);

  /// Create a copy of Cipher
  /// with the given fields replaced by the non-null parameter values.
  @pragma('vm:prefer-inline')
  @override
  $Res call({
    Object? field0 = null,
  }) {
    return _then(_$Cipher_TripleDesImpl(
      null == field0
          ? _value.field0
          : field0 // ignore: cast_nullable_to_non_nullable
              as TripleDesNumKeys,
    ));
  }
}

/// @nodoc

class _$Cipher_TripleDesImpl extends Cipher_TripleDes {
  const _$Cipher_TripleDesImpl(this.field0) : super._();

  @override
  final TripleDesNumKeys field0;

  @override
  String toString() {
    return 'Cipher.tripleDes(field0: $field0)';
  }

  @override
  bool operator ==(Object other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType &&
            other is _$Cipher_TripleDesImpl &&
            (identical(other.field0, field0) || other.field0 == field0));
  }

  @override
  int get hashCode => Object.hash(runtimeType, field0);

  /// Create a copy of Cipher
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  @override
  @pragma('vm:prefer-inline')
  _$$Cipher_TripleDesImplCopyWith<_$Cipher_TripleDesImpl> get copyWith =>
      __$$Cipher_TripleDesImplCopyWithImpl<_$Cipher_TripleDesImpl>(
          this, _$identity);

  @override
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function(SymmetricMode field0, KeyBits field1) aes,
    required TResult Function(TripleDesNumKeys field0) tripleDes,
    required TResult Function() des,
    required TResult Function(Rc2KeyBits field0) rc2,
    required TResult Function(SymmetricMode field0, KeyBits field1) camellia,
    required TResult Function() rc4,
    required TResult Function(ChCha20Mode field0) chacha20,
  }) {
    return tripleDes(field0);
  }

  @override
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function(SymmetricMode field0, KeyBits field1)? aes,
    TResult? Function(TripleDesNumKeys field0)? tripleDes,
    TResult? Function()? des,
    TResult? Function(Rc2KeyBits field0)? rc2,
    TResult? Function(SymmetricMode field0, KeyBits field1)? camellia,
    TResult? Function()? rc4,
    TResult? Function(ChCha20Mode field0)? chacha20,
  }) {
    return tripleDes?.call(field0);
  }

  @override
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function(SymmetricMode field0, KeyBits field1)? aes,
    TResult Function(TripleDesNumKeys field0)? tripleDes,
    TResult Function()? des,
    TResult Function(Rc2KeyBits field0)? rc2,
    TResult Function(SymmetricMode field0, KeyBits field1)? camellia,
    TResult Function()? rc4,
    TResult Function(ChCha20Mode field0)? chacha20,
    required TResult orElse(),
  }) {
    if (tripleDes != null) {
      return tripleDes(field0);
    }
    return orElse();
  }

  @override
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(Cipher_Aes value) aes,
    required TResult Function(Cipher_TripleDes value) tripleDes,
    required TResult Function(Cipher_Des value) des,
    required TResult Function(Cipher_Rc2 value) rc2,
    required TResult Function(Cipher_Camellia value) camellia,
    required TResult Function(Cipher_Rc4 value) rc4,
    required TResult Function(Cipher_Chacha20 value) chacha20,
  }) {
    return tripleDes(this);
  }

  @override
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(Cipher_Aes value)? aes,
    TResult? Function(Cipher_TripleDes value)? tripleDes,
    TResult? Function(Cipher_Des value)? des,
    TResult? Function(Cipher_Rc2 value)? rc2,
    TResult? Function(Cipher_Camellia value)? camellia,
    TResult? Function(Cipher_Rc4 value)? rc4,
    TResult? Function(Cipher_Chacha20 value)? chacha20,
  }) {
    return tripleDes?.call(this);
  }

  @override
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(Cipher_Aes value)? aes,
    TResult Function(Cipher_TripleDes value)? tripleDes,
    TResult Function(Cipher_Des value)? des,
    TResult Function(Cipher_Rc2 value)? rc2,
    TResult Function(Cipher_Camellia value)? camellia,
    TResult Function(Cipher_Rc4 value)? rc4,
    TResult Function(Cipher_Chacha20 value)? chacha20,
    required TResult orElse(),
  }) {
    if (tripleDes != null) {
      return tripleDes(this);
    }
    return orElse();
  }
}

abstract class Cipher_TripleDes extends Cipher {
  const factory Cipher_TripleDes(final TripleDesNumKeys field0) =
      _$Cipher_TripleDesImpl;
  const Cipher_TripleDes._() : super._();

  TripleDesNumKeys get field0;

  /// Create a copy of Cipher
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  _$$Cipher_TripleDesImplCopyWith<_$Cipher_TripleDesImpl> get copyWith =>
      throw _privateConstructorUsedError;
}

/// @nodoc
abstract class _$$Cipher_DesImplCopyWith<$Res> {
  factory _$$Cipher_DesImplCopyWith(
          _$Cipher_DesImpl value, $Res Function(_$Cipher_DesImpl) then) =
      __$$Cipher_DesImplCopyWithImpl<$Res>;
}

/// @nodoc
class __$$Cipher_DesImplCopyWithImpl<$Res>
    extends _$CipherCopyWithImpl<$Res, _$Cipher_DesImpl>
    implements _$$Cipher_DesImplCopyWith<$Res> {
  __$$Cipher_DesImplCopyWithImpl(
      _$Cipher_DesImpl _value, $Res Function(_$Cipher_DesImpl) _then)
      : super(_value, _then);

  /// Create a copy of Cipher
  /// with the given fields replaced by the non-null parameter values.
}

/// @nodoc

class _$Cipher_DesImpl extends Cipher_Des {
  const _$Cipher_DesImpl() : super._();

  @override
  String toString() {
    return 'Cipher.des()';
  }

  @override
  bool operator ==(Object other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType && other is _$Cipher_DesImpl);
  }

  @override
  int get hashCode => runtimeType.hashCode;

  @override
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function(SymmetricMode field0, KeyBits field1) aes,
    required TResult Function(TripleDesNumKeys field0) tripleDes,
    required TResult Function() des,
    required TResult Function(Rc2KeyBits field0) rc2,
    required TResult Function(SymmetricMode field0, KeyBits field1) camellia,
    required TResult Function() rc4,
    required TResult Function(ChCha20Mode field0) chacha20,
  }) {
    return des();
  }

  @override
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function(SymmetricMode field0, KeyBits field1)? aes,
    TResult? Function(TripleDesNumKeys field0)? tripleDes,
    TResult? Function()? des,
    TResult? Function(Rc2KeyBits field0)? rc2,
    TResult? Function(SymmetricMode field0, KeyBits field1)? camellia,
    TResult? Function()? rc4,
    TResult? Function(ChCha20Mode field0)? chacha20,
  }) {
    return des?.call();
  }

  @override
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function(SymmetricMode field0, KeyBits field1)? aes,
    TResult Function(TripleDesNumKeys field0)? tripleDes,
    TResult Function()? des,
    TResult Function(Rc2KeyBits field0)? rc2,
    TResult Function(SymmetricMode field0, KeyBits field1)? camellia,
    TResult Function()? rc4,
    TResult Function(ChCha20Mode field0)? chacha20,
    required TResult orElse(),
  }) {
    if (des != null) {
      return des();
    }
    return orElse();
  }

  @override
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(Cipher_Aes value) aes,
    required TResult Function(Cipher_TripleDes value) tripleDes,
    required TResult Function(Cipher_Des value) des,
    required TResult Function(Cipher_Rc2 value) rc2,
    required TResult Function(Cipher_Camellia value) camellia,
    required TResult Function(Cipher_Rc4 value) rc4,
    required TResult Function(Cipher_Chacha20 value) chacha20,
  }) {
    return des(this);
  }

  @override
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(Cipher_Aes value)? aes,
    TResult? Function(Cipher_TripleDes value)? tripleDes,
    TResult? Function(Cipher_Des value)? des,
    TResult? Function(Cipher_Rc2 value)? rc2,
    TResult? Function(Cipher_Camellia value)? camellia,
    TResult? Function(Cipher_Rc4 value)? rc4,
    TResult? Function(Cipher_Chacha20 value)? chacha20,
  }) {
    return des?.call(this);
  }

  @override
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(Cipher_Aes value)? aes,
    TResult Function(Cipher_TripleDes value)? tripleDes,
    TResult Function(Cipher_Des value)? des,
    TResult Function(Cipher_Rc2 value)? rc2,
    TResult Function(Cipher_Camellia value)? camellia,
    TResult Function(Cipher_Rc4 value)? rc4,
    TResult Function(Cipher_Chacha20 value)? chacha20,
    required TResult orElse(),
  }) {
    if (des != null) {
      return des(this);
    }
    return orElse();
  }
}

abstract class Cipher_Des extends Cipher {
  const factory Cipher_Des() = _$Cipher_DesImpl;
  const Cipher_Des._() : super._();
}

/// @nodoc
abstract class _$$Cipher_Rc2ImplCopyWith<$Res> {
  factory _$$Cipher_Rc2ImplCopyWith(
          _$Cipher_Rc2Impl value, $Res Function(_$Cipher_Rc2Impl) then) =
      __$$Cipher_Rc2ImplCopyWithImpl<$Res>;
  @useResult
  $Res call({Rc2KeyBits field0});
}

/// @nodoc
class __$$Cipher_Rc2ImplCopyWithImpl<$Res>
    extends _$CipherCopyWithImpl<$Res, _$Cipher_Rc2Impl>
    implements _$$Cipher_Rc2ImplCopyWith<$Res> {
  __$$Cipher_Rc2ImplCopyWithImpl(
      _$Cipher_Rc2Impl _value, $Res Function(_$Cipher_Rc2Impl) _then)
      : super(_value, _then);

  /// Create a copy of Cipher
  /// with the given fields replaced by the non-null parameter values.
  @pragma('vm:prefer-inline')
  @override
  $Res call({
    Object? field0 = null,
  }) {
    return _then(_$Cipher_Rc2Impl(
      null == field0
          ? _value.field0
          : field0 // ignore: cast_nullable_to_non_nullable
              as Rc2KeyBits,
    ));
  }
}

/// @nodoc

class _$Cipher_Rc2Impl extends Cipher_Rc2 {
  const _$Cipher_Rc2Impl(this.field0) : super._();

  @override
  final Rc2KeyBits field0;

  @override
  String toString() {
    return 'Cipher.rc2(field0: $field0)';
  }

  @override
  bool operator ==(Object other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType &&
            other is _$Cipher_Rc2Impl &&
            (identical(other.field0, field0) || other.field0 == field0));
  }

  @override
  int get hashCode => Object.hash(runtimeType, field0);

  /// Create a copy of Cipher
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  @override
  @pragma('vm:prefer-inline')
  _$$Cipher_Rc2ImplCopyWith<_$Cipher_Rc2Impl> get copyWith =>
      __$$Cipher_Rc2ImplCopyWithImpl<_$Cipher_Rc2Impl>(this, _$identity);

  @override
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function(SymmetricMode field0, KeyBits field1) aes,
    required TResult Function(TripleDesNumKeys field0) tripleDes,
    required TResult Function() des,
    required TResult Function(Rc2KeyBits field0) rc2,
    required TResult Function(SymmetricMode field0, KeyBits field1) camellia,
    required TResult Function() rc4,
    required TResult Function(ChCha20Mode field0) chacha20,
  }) {
    return rc2(field0);
  }

  @override
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function(SymmetricMode field0, KeyBits field1)? aes,
    TResult? Function(TripleDesNumKeys field0)? tripleDes,
    TResult? Function()? des,
    TResult? Function(Rc2KeyBits field0)? rc2,
    TResult? Function(SymmetricMode field0, KeyBits field1)? camellia,
    TResult? Function()? rc4,
    TResult? Function(ChCha20Mode field0)? chacha20,
  }) {
    return rc2?.call(field0);
  }

  @override
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function(SymmetricMode field0, KeyBits field1)? aes,
    TResult Function(TripleDesNumKeys field0)? tripleDes,
    TResult Function()? des,
    TResult Function(Rc2KeyBits field0)? rc2,
    TResult Function(SymmetricMode field0, KeyBits field1)? camellia,
    TResult Function()? rc4,
    TResult Function(ChCha20Mode field0)? chacha20,
    required TResult orElse(),
  }) {
    if (rc2 != null) {
      return rc2(field0);
    }
    return orElse();
  }

  @override
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(Cipher_Aes value) aes,
    required TResult Function(Cipher_TripleDes value) tripleDes,
    required TResult Function(Cipher_Des value) des,
    required TResult Function(Cipher_Rc2 value) rc2,
    required TResult Function(Cipher_Camellia value) camellia,
    required TResult Function(Cipher_Rc4 value) rc4,
    required TResult Function(Cipher_Chacha20 value) chacha20,
  }) {
    return rc2(this);
  }

  @override
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(Cipher_Aes value)? aes,
    TResult? Function(Cipher_TripleDes value)? tripleDes,
    TResult? Function(Cipher_Des value)? des,
    TResult? Function(Cipher_Rc2 value)? rc2,
    TResult? Function(Cipher_Camellia value)? camellia,
    TResult? Function(Cipher_Rc4 value)? rc4,
    TResult? Function(Cipher_Chacha20 value)? chacha20,
  }) {
    return rc2?.call(this);
  }

  @override
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(Cipher_Aes value)? aes,
    TResult Function(Cipher_TripleDes value)? tripleDes,
    TResult Function(Cipher_Des value)? des,
    TResult Function(Cipher_Rc2 value)? rc2,
    TResult Function(Cipher_Camellia value)? camellia,
    TResult Function(Cipher_Rc4 value)? rc4,
    TResult Function(Cipher_Chacha20 value)? chacha20,
    required TResult orElse(),
  }) {
    if (rc2 != null) {
      return rc2(this);
    }
    return orElse();
  }
}

abstract class Cipher_Rc2 extends Cipher {
  const factory Cipher_Rc2(final Rc2KeyBits field0) = _$Cipher_Rc2Impl;
  const Cipher_Rc2._() : super._();

  Rc2KeyBits get field0;

  /// Create a copy of Cipher
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  _$$Cipher_Rc2ImplCopyWith<_$Cipher_Rc2Impl> get copyWith =>
      throw _privateConstructorUsedError;
}

/// @nodoc
abstract class _$$Cipher_CamelliaImplCopyWith<$Res> {
  factory _$$Cipher_CamelliaImplCopyWith(_$Cipher_CamelliaImpl value,
          $Res Function(_$Cipher_CamelliaImpl) then) =
      __$$Cipher_CamelliaImplCopyWithImpl<$Res>;
  @useResult
  $Res call({SymmetricMode field0, KeyBits field1});
}

/// @nodoc
class __$$Cipher_CamelliaImplCopyWithImpl<$Res>
    extends _$CipherCopyWithImpl<$Res, _$Cipher_CamelliaImpl>
    implements _$$Cipher_CamelliaImplCopyWith<$Res> {
  __$$Cipher_CamelliaImplCopyWithImpl(
      _$Cipher_CamelliaImpl _value, $Res Function(_$Cipher_CamelliaImpl) _then)
      : super(_value, _then);

  /// Create a copy of Cipher
  /// with the given fields replaced by the non-null parameter values.
  @pragma('vm:prefer-inline')
  @override
  $Res call({
    Object? field0 = null,
    Object? field1 = null,
  }) {
    return _then(_$Cipher_CamelliaImpl(
      null == field0
          ? _value.field0
          : field0 // ignore: cast_nullable_to_non_nullable
              as SymmetricMode,
      null == field1
          ? _value.field1
          : field1 // ignore: cast_nullable_to_non_nullable
              as KeyBits,
    ));
  }
}

/// @nodoc

class _$Cipher_CamelliaImpl extends Cipher_Camellia {
  const _$Cipher_CamelliaImpl(this.field0, this.field1) : super._();

  @override
  final SymmetricMode field0;
  @override
  final KeyBits field1;

  @override
  String toString() {
    return 'Cipher.camellia(field0: $field0, field1: $field1)';
  }

  @override
  bool operator ==(Object other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType &&
            other is _$Cipher_CamelliaImpl &&
            (identical(other.field0, field0) || other.field0 == field0) &&
            (identical(other.field1, field1) || other.field1 == field1));
  }

  @override
  int get hashCode => Object.hash(runtimeType, field0, field1);

  /// Create a copy of Cipher
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  @override
  @pragma('vm:prefer-inline')
  _$$Cipher_CamelliaImplCopyWith<_$Cipher_CamelliaImpl> get copyWith =>
      __$$Cipher_CamelliaImplCopyWithImpl<_$Cipher_CamelliaImpl>(
          this, _$identity);

  @override
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function(SymmetricMode field0, KeyBits field1) aes,
    required TResult Function(TripleDesNumKeys field0) tripleDes,
    required TResult Function() des,
    required TResult Function(Rc2KeyBits field0) rc2,
    required TResult Function(SymmetricMode field0, KeyBits field1) camellia,
    required TResult Function() rc4,
    required TResult Function(ChCha20Mode field0) chacha20,
  }) {
    return camellia(field0, field1);
  }

  @override
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function(SymmetricMode field0, KeyBits field1)? aes,
    TResult? Function(TripleDesNumKeys field0)? tripleDes,
    TResult? Function()? des,
    TResult? Function(Rc2KeyBits field0)? rc2,
    TResult? Function(SymmetricMode field0, KeyBits field1)? camellia,
    TResult? Function()? rc4,
    TResult? Function(ChCha20Mode field0)? chacha20,
  }) {
    return camellia?.call(field0, field1);
  }

  @override
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function(SymmetricMode field0, KeyBits field1)? aes,
    TResult Function(TripleDesNumKeys field0)? tripleDes,
    TResult Function()? des,
    TResult Function(Rc2KeyBits field0)? rc2,
    TResult Function(SymmetricMode field0, KeyBits field1)? camellia,
    TResult Function()? rc4,
    TResult Function(ChCha20Mode field0)? chacha20,
    required TResult orElse(),
  }) {
    if (camellia != null) {
      return camellia(field0, field1);
    }
    return orElse();
  }

  @override
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(Cipher_Aes value) aes,
    required TResult Function(Cipher_TripleDes value) tripleDes,
    required TResult Function(Cipher_Des value) des,
    required TResult Function(Cipher_Rc2 value) rc2,
    required TResult Function(Cipher_Camellia value) camellia,
    required TResult Function(Cipher_Rc4 value) rc4,
    required TResult Function(Cipher_Chacha20 value) chacha20,
  }) {
    return camellia(this);
  }

  @override
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(Cipher_Aes value)? aes,
    TResult? Function(Cipher_TripleDes value)? tripleDes,
    TResult? Function(Cipher_Des value)? des,
    TResult? Function(Cipher_Rc2 value)? rc2,
    TResult? Function(Cipher_Camellia value)? camellia,
    TResult? Function(Cipher_Rc4 value)? rc4,
    TResult? Function(Cipher_Chacha20 value)? chacha20,
  }) {
    return camellia?.call(this);
  }

  @override
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(Cipher_Aes value)? aes,
    TResult Function(Cipher_TripleDes value)? tripleDes,
    TResult Function(Cipher_Des value)? des,
    TResult Function(Cipher_Rc2 value)? rc2,
    TResult Function(Cipher_Camellia value)? camellia,
    TResult Function(Cipher_Rc4 value)? rc4,
    TResult Function(Cipher_Chacha20 value)? chacha20,
    required TResult orElse(),
  }) {
    if (camellia != null) {
      return camellia(this);
    }
    return orElse();
  }
}

abstract class Cipher_Camellia extends Cipher {
  const factory Cipher_Camellia(
      final SymmetricMode field0, final KeyBits field1) = _$Cipher_CamelliaImpl;
  const Cipher_Camellia._() : super._();

  SymmetricMode get field0;
  KeyBits get field1;

  /// Create a copy of Cipher
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  _$$Cipher_CamelliaImplCopyWith<_$Cipher_CamelliaImpl> get copyWith =>
      throw _privateConstructorUsedError;
}

/// @nodoc
abstract class _$$Cipher_Rc4ImplCopyWith<$Res> {
  factory _$$Cipher_Rc4ImplCopyWith(
          _$Cipher_Rc4Impl value, $Res Function(_$Cipher_Rc4Impl) then) =
      __$$Cipher_Rc4ImplCopyWithImpl<$Res>;
}

/// @nodoc
class __$$Cipher_Rc4ImplCopyWithImpl<$Res>
    extends _$CipherCopyWithImpl<$Res, _$Cipher_Rc4Impl>
    implements _$$Cipher_Rc4ImplCopyWith<$Res> {
  __$$Cipher_Rc4ImplCopyWithImpl(
      _$Cipher_Rc4Impl _value, $Res Function(_$Cipher_Rc4Impl) _then)
      : super(_value, _then);

  /// Create a copy of Cipher
  /// with the given fields replaced by the non-null parameter values.
}

/// @nodoc

class _$Cipher_Rc4Impl extends Cipher_Rc4 {
  const _$Cipher_Rc4Impl() : super._();

  @override
  String toString() {
    return 'Cipher.rc4()';
  }

  @override
  bool operator ==(Object other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType && other is _$Cipher_Rc4Impl);
  }

  @override
  int get hashCode => runtimeType.hashCode;

  @override
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function(SymmetricMode field0, KeyBits field1) aes,
    required TResult Function(TripleDesNumKeys field0) tripleDes,
    required TResult Function() des,
    required TResult Function(Rc2KeyBits field0) rc2,
    required TResult Function(SymmetricMode field0, KeyBits field1) camellia,
    required TResult Function() rc4,
    required TResult Function(ChCha20Mode field0) chacha20,
  }) {
    return rc4();
  }

  @override
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function(SymmetricMode field0, KeyBits field1)? aes,
    TResult? Function(TripleDesNumKeys field0)? tripleDes,
    TResult? Function()? des,
    TResult? Function(Rc2KeyBits field0)? rc2,
    TResult? Function(SymmetricMode field0, KeyBits field1)? camellia,
    TResult? Function()? rc4,
    TResult? Function(ChCha20Mode field0)? chacha20,
  }) {
    return rc4?.call();
  }

  @override
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function(SymmetricMode field0, KeyBits field1)? aes,
    TResult Function(TripleDesNumKeys field0)? tripleDes,
    TResult Function()? des,
    TResult Function(Rc2KeyBits field0)? rc2,
    TResult Function(SymmetricMode field0, KeyBits field1)? camellia,
    TResult Function()? rc4,
    TResult Function(ChCha20Mode field0)? chacha20,
    required TResult orElse(),
  }) {
    if (rc4 != null) {
      return rc4();
    }
    return orElse();
  }

  @override
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(Cipher_Aes value) aes,
    required TResult Function(Cipher_TripleDes value) tripleDes,
    required TResult Function(Cipher_Des value) des,
    required TResult Function(Cipher_Rc2 value) rc2,
    required TResult Function(Cipher_Camellia value) camellia,
    required TResult Function(Cipher_Rc4 value) rc4,
    required TResult Function(Cipher_Chacha20 value) chacha20,
  }) {
    return rc4(this);
  }

  @override
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(Cipher_Aes value)? aes,
    TResult? Function(Cipher_TripleDes value)? tripleDes,
    TResult? Function(Cipher_Des value)? des,
    TResult? Function(Cipher_Rc2 value)? rc2,
    TResult? Function(Cipher_Camellia value)? camellia,
    TResult? Function(Cipher_Rc4 value)? rc4,
    TResult? Function(Cipher_Chacha20 value)? chacha20,
  }) {
    return rc4?.call(this);
  }

  @override
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(Cipher_Aes value)? aes,
    TResult Function(Cipher_TripleDes value)? tripleDes,
    TResult Function(Cipher_Des value)? des,
    TResult Function(Cipher_Rc2 value)? rc2,
    TResult Function(Cipher_Camellia value)? camellia,
    TResult Function(Cipher_Rc4 value)? rc4,
    TResult Function(Cipher_Chacha20 value)? chacha20,
    required TResult orElse(),
  }) {
    if (rc4 != null) {
      return rc4(this);
    }
    return orElse();
  }
}

abstract class Cipher_Rc4 extends Cipher {
  const factory Cipher_Rc4() = _$Cipher_Rc4Impl;
  const Cipher_Rc4._() : super._();
}

/// @nodoc
abstract class _$$Cipher_Chacha20ImplCopyWith<$Res> {
  factory _$$Cipher_Chacha20ImplCopyWith(_$Cipher_Chacha20Impl value,
          $Res Function(_$Cipher_Chacha20Impl) then) =
      __$$Cipher_Chacha20ImplCopyWithImpl<$Res>;
  @useResult
  $Res call({ChCha20Mode field0});
}

/// @nodoc
class __$$Cipher_Chacha20ImplCopyWithImpl<$Res>
    extends _$CipherCopyWithImpl<$Res, _$Cipher_Chacha20Impl>
    implements _$$Cipher_Chacha20ImplCopyWith<$Res> {
  __$$Cipher_Chacha20ImplCopyWithImpl(
      _$Cipher_Chacha20Impl _value, $Res Function(_$Cipher_Chacha20Impl) _then)
      : super(_value, _then);

  /// Create a copy of Cipher
  /// with the given fields replaced by the non-null parameter values.
  @pragma('vm:prefer-inline')
  @override
  $Res call({
    Object? field0 = null,
  }) {
    return _then(_$Cipher_Chacha20Impl(
      null == field0
          ? _value.field0
          : field0 // ignore: cast_nullable_to_non_nullable
              as ChCha20Mode,
    ));
  }
}

/// @nodoc

class _$Cipher_Chacha20Impl extends Cipher_Chacha20 {
  const _$Cipher_Chacha20Impl(this.field0) : super._();

  @override
  final ChCha20Mode field0;

  @override
  String toString() {
    return 'Cipher.chacha20(field0: $field0)';
  }

  @override
  bool operator ==(Object other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType &&
            other is _$Cipher_Chacha20Impl &&
            (identical(other.field0, field0) || other.field0 == field0));
  }

  @override
  int get hashCode => Object.hash(runtimeType, field0);

  /// Create a copy of Cipher
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  @override
  @pragma('vm:prefer-inline')
  _$$Cipher_Chacha20ImplCopyWith<_$Cipher_Chacha20Impl> get copyWith =>
      __$$Cipher_Chacha20ImplCopyWithImpl<_$Cipher_Chacha20Impl>(
          this, _$identity);

  @override
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function(SymmetricMode field0, KeyBits field1) aes,
    required TResult Function(TripleDesNumKeys field0) tripleDes,
    required TResult Function() des,
    required TResult Function(Rc2KeyBits field0) rc2,
    required TResult Function(SymmetricMode field0, KeyBits field1) camellia,
    required TResult Function() rc4,
    required TResult Function(ChCha20Mode field0) chacha20,
  }) {
    return chacha20(field0);
  }

  @override
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function(SymmetricMode field0, KeyBits field1)? aes,
    TResult? Function(TripleDesNumKeys field0)? tripleDes,
    TResult? Function()? des,
    TResult? Function(Rc2KeyBits field0)? rc2,
    TResult? Function(SymmetricMode field0, KeyBits field1)? camellia,
    TResult? Function()? rc4,
    TResult? Function(ChCha20Mode field0)? chacha20,
  }) {
    return chacha20?.call(field0);
  }

  @override
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function(SymmetricMode field0, KeyBits field1)? aes,
    TResult Function(TripleDesNumKeys field0)? tripleDes,
    TResult Function()? des,
    TResult Function(Rc2KeyBits field0)? rc2,
    TResult Function(SymmetricMode field0, KeyBits field1)? camellia,
    TResult Function()? rc4,
    TResult Function(ChCha20Mode field0)? chacha20,
    required TResult orElse(),
  }) {
    if (chacha20 != null) {
      return chacha20(field0);
    }
    return orElse();
  }

  @override
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(Cipher_Aes value) aes,
    required TResult Function(Cipher_TripleDes value) tripleDes,
    required TResult Function(Cipher_Des value) des,
    required TResult Function(Cipher_Rc2 value) rc2,
    required TResult Function(Cipher_Camellia value) camellia,
    required TResult Function(Cipher_Rc4 value) rc4,
    required TResult Function(Cipher_Chacha20 value) chacha20,
  }) {
    return chacha20(this);
  }

  @override
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(Cipher_Aes value)? aes,
    TResult? Function(Cipher_TripleDes value)? tripleDes,
    TResult? Function(Cipher_Des value)? des,
    TResult? Function(Cipher_Rc2 value)? rc2,
    TResult? Function(Cipher_Camellia value)? camellia,
    TResult? Function(Cipher_Rc4 value)? rc4,
    TResult? Function(Cipher_Chacha20 value)? chacha20,
  }) {
    return chacha20?.call(this);
  }

  @override
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(Cipher_Aes value)? aes,
    TResult Function(Cipher_TripleDes value)? tripleDes,
    TResult Function(Cipher_Des value)? des,
    TResult Function(Cipher_Rc2 value)? rc2,
    TResult Function(Cipher_Camellia value)? camellia,
    TResult Function(Cipher_Rc4 value)? rc4,
    TResult Function(Cipher_Chacha20 value)? chacha20,
    required TResult orElse(),
  }) {
    if (chacha20 != null) {
      return chacha20(this);
    }
    return orElse();
  }
}

abstract class Cipher_Chacha20 extends Cipher {
  const factory Cipher_Chacha20(final ChCha20Mode field0) =
      _$Cipher_Chacha20Impl;
  const Cipher_Chacha20._() : super._();

  ChCha20Mode get field0;

  /// Create a copy of Cipher
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  _$$Cipher_Chacha20ImplCopyWith<_$Cipher_Chacha20Impl> get copyWith =>
      throw _privateConstructorUsedError;
}
