// dart format width=80
// coverage:ignore-file
// GENERATED CODE - DO NOT MODIFY BY HAND
// ignore_for_file: type=lint
// ignore_for_file: unused_element, deprecated_member_use, deprecated_member_use_from_same_package, use_function_type_syntax_for_parameters, unnecessary_const, avoid_init_to_null, invalid_override_different_default_values_named, prefer_expression_function_bodies, annotate_overrides, invalid_annotation_target, unnecessary_question_mark

part of 'key_derivation.dart';

// **************************************************************************
// FreezedGenerator
// **************************************************************************

// dart format off
T _$identity<T>(T value) => value;
/// @nodoc
mixin _$KDF {

 Argon2Options get field0;
/// Create a copy of KDF
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$KDFCopyWith<KDF> get copyWith => _$KDFCopyWithImpl<KDF>(this as KDF, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is KDF&&(identical(other.field0, field0) || other.field0 == field0));
}


@override
int get hashCode => Object.hash(runtimeType,field0);

@override
String toString() {
  return 'KDF(field0: $field0)';
}


}

/// @nodoc
abstract mixin class $KDFCopyWith<$Res>  {
  factory $KDFCopyWith(KDF value, $Res Function(KDF) _then) = _$KDFCopyWithImpl;
@useResult
$Res call({
 Argon2Options field0
});




}
/// @nodoc
class _$KDFCopyWithImpl<$Res>
    implements $KDFCopyWith<$Res> {
  _$KDFCopyWithImpl(this._self, this._then);

  final KDF _self;
  final $Res Function(KDF) _then;

/// Create a copy of KDF
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') @override $Res call({Object? field0 = null,}) {
  return _then(_self.copyWith(
field0: null == field0 ? _self.field0 : field0 // ignore: cast_nullable_to_non_nullable
as Argon2Options,
  ));
}

}


/// @nodoc


class KDF_Argon2d extends KDF {
  const KDF_Argon2d(this.field0): super._();
  

@override final  Argon2Options field0;

/// Create a copy of KDF
/// with the given fields replaced by the non-null parameter values.
@override @JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$KDF_Argon2dCopyWith<KDF_Argon2d> get copyWith => _$KDF_Argon2dCopyWithImpl<KDF_Argon2d>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is KDF_Argon2d&&(identical(other.field0, field0) || other.field0 == field0));
}


@override
int get hashCode => Object.hash(runtimeType,field0);

@override
String toString() {
  return 'KDF.argon2D(field0: $field0)';
}


}

/// @nodoc
abstract mixin class $KDF_Argon2dCopyWith<$Res> implements $KDFCopyWith<$Res> {
  factory $KDF_Argon2dCopyWith(KDF_Argon2d value, $Res Function(KDF_Argon2d) _then) = _$KDF_Argon2dCopyWithImpl;
@override @useResult
$Res call({
 Argon2Options field0
});




}
/// @nodoc
class _$KDF_Argon2dCopyWithImpl<$Res>
    implements $KDF_Argon2dCopyWith<$Res> {
  _$KDF_Argon2dCopyWithImpl(this._self, this._then);

  final KDF_Argon2d _self;
  final $Res Function(KDF_Argon2d) _then;

/// Create a copy of KDF
/// with the given fields replaced by the non-null parameter values.
@override @pragma('vm:prefer-inline') $Res call({Object? field0 = null,}) {
  return _then(KDF_Argon2d(
null == field0 ? _self.field0 : field0 // ignore: cast_nullable_to_non_nullable
as Argon2Options,
  ));
}


}

/// @nodoc


class KDF_Argon2id extends KDF {
  const KDF_Argon2id(this.field0): super._();
  

@override final  Argon2Options field0;

/// Create a copy of KDF
/// with the given fields replaced by the non-null parameter values.
@override @JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$KDF_Argon2idCopyWith<KDF_Argon2id> get copyWith => _$KDF_Argon2idCopyWithImpl<KDF_Argon2id>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is KDF_Argon2id&&(identical(other.field0, field0) || other.field0 == field0));
}


@override
int get hashCode => Object.hash(runtimeType,field0);

@override
String toString() {
  return 'KDF.argon2Id(field0: $field0)';
}


}

/// @nodoc
abstract mixin class $KDF_Argon2idCopyWith<$Res> implements $KDFCopyWith<$Res> {
  factory $KDF_Argon2idCopyWith(KDF_Argon2id value, $Res Function(KDF_Argon2id) _then) = _$KDF_Argon2idCopyWithImpl;
@override @useResult
$Res call({
 Argon2Options field0
});




}
/// @nodoc
class _$KDF_Argon2idCopyWithImpl<$Res>
    implements $KDF_Argon2idCopyWith<$Res> {
  _$KDF_Argon2idCopyWithImpl(this._self, this._then);

  final KDF_Argon2id _self;
  final $Res Function(KDF_Argon2id) _then;

/// Create a copy of KDF
/// with the given fields replaced by the non-null parameter values.
@override @pragma('vm:prefer-inline') $Res call({Object? field0 = null,}) {
  return _then(KDF_Argon2id(
null == field0 ? _self.field0 : field0 // ignore: cast_nullable_to_non_nullable
as Argon2Options,
  ));
}


}

/// @nodoc


class KDF_Argon2i extends KDF {
  const KDF_Argon2i(this.field0): super._();
  

@override final  Argon2Options field0;

/// Create a copy of KDF
/// with the given fields replaced by the non-null parameter values.
@override @JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$KDF_Argon2iCopyWith<KDF_Argon2i> get copyWith => _$KDF_Argon2iCopyWithImpl<KDF_Argon2i>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is KDF_Argon2i&&(identical(other.field0, field0) || other.field0 == field0));
}


@override
int get hashCode => Object.hash(runtimeType,field0);

@override
String toString() {
  return 'KDF.argon2I(field0: $field0)';
}


}

/// @nodoc
abstract mixin class $KDF_Argon2iCopyWith<$Res> implements $KDFCopyWith<$Res> {
  factory $KDF_Argon2iCopyWith(KDF_Argon2i value, $Res Function(KDF_Argon2i) _then) = _$KDF_Argon2iCopyWithImpl;
@override @useResult
$Res call({
 Argon2Options field0
});




}
/// @nodoc
class _$KDF_Argon2iCopyWithImpl<$Res>
    implements $KDF_Argon2iCopyWith<$Res> {
  _$KDF_Argon2iCopyWithImpl(this._self, this._then);

  final KDF_Argon2i _self;
  final $Res Function(KDF_Argon2i) _then;

/// Create a copy of KDF
/// with the given fields replaced by the non-null parameter values.
@override @pragma('vm:prefer-inline') $Res call({Object? field0 = null,}) {
  return _then(KDF_Argon2i(
null == field0 ? _self.field0 : field0 // ignore: cast_nullable_to_non_nullable
as Argon2Options,
  ));
}


}

// dart format on
