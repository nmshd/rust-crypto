// dart format width=80
// coverage:ignore-file
// GENERATED CODE - DO NOT MODIFY BY HAND
// ignore_for_file: type=lint
// ignore_for_file: unused_element, deprecated_member_use, deprecated_member_use_from_same_package, use_function_type_syntax_for_parameters, unnecessary_const, avoid_init_to_null, invalid_override_different_default_values_named, prefer_expression_function_bodies, annotate_overrides, invalid_annotation_target, unnecessary_question_mark

part of 'error.dart';

// **************************************************************************
// FreezedGenerator
// **************************************************************************

// dart format off
T _$identity<T>(T value) => value;
/// @nodoc
mixin _$CalErrorKind {





@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is CalErrorKind);
}


@override
int get hashCode => runtimeType.hashCode;

@override
String toString() {
  return 'CalErrorKind()';
}


}

/// @nodoc
class $CalErrorKindCopyWith<$Res>  {
$CalErrorKindCopyWith(CalErrorKind _, $Res Function(CalErrorKind) __);
}


/// @nodoc


class CalErrorKind_NotImplemented extends CalErrorKind {
  const CalErrorKind_NotImplemented(): super._();
  






@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is CalErrorKind_NotImplemented);
}


@override
int get hashCode => runtimeType.hashCode;

@override
String toString() {
  return 'CalErrorKind.notImplemented()';
}


}




/// @nodoc


class CalErrorKind_BadParameter extends CalErrorKind {
  const CalErrorKind_BadParameter({required this.description, required this.internal}): super._();
  

 final  String description;
/// `true` if caused within this library. `false` if caused by another library.
 final  bool internal;

/// Create a copy of CalErrorKind
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$CalErrorKind_BadParameterCopyWith<CalErrorKind_BadParameter> get copyWith => _$CalErrorKind_BadParameterCopyWithImpl<CalErrorKind_BadParameter>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is CalErrorKind_BadParameter&&(identical(other.description, description) || other.description == description)&&(identical(other.internal, internal) || other.internal == internal));
}


@override
int get hashCode => Object.hash(runtimeType,description,internal);

@override
String toString() {
  return 'CalErrorKind.badParameter(description: $description, internal: $internal)';
}


}

/// @nodoc
abstract mixin class $CalErrorKind_BadParameterCopyWith<$Res> implements $CalErrorKindCopyWith<$Res> {
  factory $CalErrorKind_BadParameterCopyWith(CalErrorKind_BadParameter value, $Res Function(CalErrorKind_BadParameter) _then) = _$CalErrorKind_BadParameterCopyWithImpl;
@useResult
$Res call({
 String description, bool internal
});




}
/// @nodoc
class _$CalErrorKind_BadParameterCopyWithImpl<$Res>
    implements $CalErrorKind_BadParameterCopyWith<$Res> {
  _$CalErrorKind_BadParameterCopyWithImpl(this._self, this._then);

  final CalErrorKind_BadParameter _self;
  final $Res Function(CalErrorKind_BadParameter) _then;

/// Create a copy of CalErrorKind
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? description = null,Object? internal = null,}) {
  return _then(CalErrorKind_BadParameter(
description: null == description ? _self.description : description // ignore: cast_nullable_to_non_nullable
as String,internal: null == internal ? _self.internal : internal // ignore: cast_nullable_to_non_nullable
as bool,
  ));
}


}

/// @nodoc


class CalErrorKind_MissingKey extends CalErrorKind {
  const CalErrorKind_MissingKey({required this.keyId, required this.keyType}): super._();
  

 final  String keyId;
 final  KeyType keyType;

/// Create a copy of CalErrorKind
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$CalErrorKind_MissingKeyCopyWith<CalErrorKind_MissingKey> get copyWith => _$CalErrorKind_MissingKeyCopyWithImpl<CalErrorKind_MissingKey>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is CalErrorKind_MissingKey&&(identical(other.keyId, keyId) || other.keyId == keyId)&&(identical(other.keyType, keyType) || other.keyType == keyType));
}


@override
int get hashCode => Object.hash(runtimeType,keyId,keyType);

@override
String toString() {
  return 'CalErrorKind.missingKey(keyId: $keyId, keyType: $keyType)';
}


}

/// @nodoc
abstract mixin class $CalErrorKind_MissingKeyCopyWith<$Res> implements $CalErrorKindCopyWith<$Res> {
  factory $CalErrorKind_MissingKeyCopyWith(CalErrorKind_MissingKey value, $Res Function(CalErrorKind_MissingKey) _then) = _$CalErrorKind_MissingKeyCopyWithImpl;
@useResult
$Res call({
 String keyId, KeyType keyType
});




}
/// @nodoc
class _$CalErrorKind_MissingKeyCopyWithImpl<$Res>
    implements $CalErrorKind_MissingKeyCopyWith<$Res> {
  _$CalErrorKind_MissingKeyCopyWithImpl(this._self, this._then);

  final CalErrorKind_MissingKey _self;
  final $Res Function(CalErrorKind_MissingKey) _then;

/// Create a copy of CalErrorKind
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? keyId = null,Object? keyType = null,}) {
  return _then(CalErrorKind_MissingKey(
keyId: null == keyId ? _self.keyId : keyId // ignore: cast_nullable_to_non_nullable
as String,keyType: null == keyType ? _self.keyType : keyType // ignore: cast_nullable_to_non_nullable
as KeyType,
  ));
}


}

/// @nodoc


class CalErrorKind_MissingValue extends CalErrorKind {
  const CalErrorKind_MissingValue({required this.description, required this.internal}): super._();
  

 final  String description;
/// `true` if caused within this library. `false` if caused by another library.
 final  bool internal;

/// Create a copy of CalErrorKind
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$CalErrorKind_MissingValueCopyWith<CalErrorKind_MissingValue> get copyWith => _$CalErrorKind_MissingValueCopyWithImpl<CalErrorKind_MissingValue>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is CalErrorKind_MissingValue&&(identical(other.description, description) || other.description == description)&&(identical(other.internal, internal) || other.internal == internal));
}


@override
int get hashCode => Object.hash(runtimeType,description,internal);

@override
String toString() {
  return 'CalErrorKind.missingValue(description: $description, internal: $internal)';
}


}

/// @nodoc
abstract mixin class $CalErrorKind_MissingValueCopyWith<$Res> implements $CalErrorKindCopyWith<$Res> {
  factory $CalErrorKind_MissingValueCopyWith(CalErrorKind_MissingValue value, $Res Function(CalErrorKind_MissingValue) _then) = _$CalErrorKind_MissingValueCopyWithImpl;
@useResult
$Res call({
 String description, bool internal
});




}
/// @nodoc
class _$CalErrorKind_MissingValueCopyWithImpl<$Res>
    implements $CalErrorKind_MissingValueCopyWith<$Res> {
  _$CalErrorKind_MissingValueCopyWithImpl(this._self, this._then);

  final CalErrorKind_MissingValue _self;
  final $Res Function(CalErrorKind_MissingValue) _then;

/// Create a copy of CalErrorKind
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? description = null,Object? internal = null,}) {
  return _then(CalErrorKind_MissingValue(
description: null == description ? _self.description : description // ignore: cast_nullable_to_non_nullable
as String,internal: null == internal ? _self.internal : internal // ignore: cast_nullable_to_non_nullable
as bool,
  ));
}


}

/// @nodoc


class CalErrorKind_FailedOperation extends CalErrorKind {
  const CalErrorKind_FailedOperation({required this.description, required this.internal}): super._();
  

 final  String description;
/// `true` if caused within this library. `false` if caused by another library.
 final  bool internal;

/// Create a copy of CalErrorKind
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$CalErrorKind_FailedOperationCopyWith<CalErrorKind_FailedOperation> get copyWith => _$CalErrorKind_FailedOperationCopyWithImpl<CalErrorKind_FailedOperation>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is CalErrorKind_FailedOperation&&(identical(other.description, description) || other.description == description)&&(identical(other.internal, internal) || other.internal == internal));
}


@override
int get hashCode => Object.hash(runtimeType,description,internal);

@override
String toString() {
  return 'CalErrorKind.failedOperation(description: $description, internal: $internal)';
}


}

/// @nodoc
abstract mixin class $CalErrorKind_FailedOperationCopyWith<$Res> implements $CalErrorKindCopyWith<$Res> {
  factory $CalErrorKind_FailedOperationCopyWith(CalErrorKind_FailedOperation value, $Res Function(CalErrorKind_FailedOperation) _then) = _$CalErrorKind_FailedOperationCopyWithImpl;
@useResult
$Res call({
 String description, bool internal
});




}
/// @nodoc
class _$CalErrorKind_FailedOperationCopyWithImpl<$Res>
    implements $CalErrorKind_FailedOperationCopyWith<$Res> {
  _$CalErrorKind_FailedOperationCopyWithImpl(this._self, this._then);

  final CalErrorKind_FailedOperation _self;
  final $Res Function(CalErrorKind_FailedOperation) _then;

/// Create a copy of CalErrorKind
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? description = null,Object? internal = null,}) {
  return _then(CalErrorKind_FailedOperation(
description: null == description ? _self.description : description // ignore: cast_nullable_to_non_nullable
as String,internal: null == internal ? _self.internal : internal // ignore: cast_nullable_to_non_nullable
as bool,
  ));
}


}

/// @nodoc


class CalErrorKind_InitializationError extends CalErrorKind {
  const CalErrorKind_InitializationError({required this.description, required this.internal}): super._();
  

 final  String description;
/// `true` if caused within this library. `false` if caused by another library.
 final  bool internal;

/// Create a copy of CalErrorKind
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$CalErrorKind_InitializationErrorCopyWith<CalErrorKind_InitializationError> get copyWith => _$CalErrorKind_InitializationErrorCopyWithImpl<CalErrorKind_InitializationError>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is CalErrorKind_InitializationError&&(identical(other.description, description) || other.description == description)&&(identical(other.internal, internal) || other.internal == internal));
}


@override
int get hashCode => Object.hash(runtimeType,description,internal);

@override
String toString() {
  return 'CalErrorKind.initializationError(description: $description, internal: $internal)';
}


}

/// @nodoc
abstract mixin class $CalErrorKind_InitializationErrorCopyWith<$Res> implements $CalErrorKindCopyWith<$Res> {
  factory $CalErrorKind_InitializationErrorCopyWith(CalErrorKind_InitializationError value, $Res Function(CalErrorKind_InitializationError) _then) = _$CalErrorKind_InitializationErrorCopyWithImpl;
@useResult
$Res call({
 String description, bool internal
});




}
/// @nodoc
class _$CalErrorKind_InitializationErrorCopyWithImpl<$Res>
    implements $CalErrorKind_InitializationErrorCopyWith<$Res> {
  _$CalErrorKind_InitializationErrorCopyWithImpl(this._self, this._then);

  final CalErrorKind_InitializationError _self;
  final $Res Function(CalErrorKind_InitializationError) _then;

/// Create a copy of CalErrorKind
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? description = null,Object? internal = null,}) {
  return _then(CalErrorKind_InitializationError(
description: null == description ? _self.description : description // ignore: cast_nullable_to_non_nullable
as String,internal: null == internal ? _self.internal : internal // ignore: cast_nullable_to_non_nullable
as bool,
  ));
}


}

/// @nodoc


class CalErrorKind_NonExportable extends CalErrorKind {
  const CalErrorKind_NonExportable(): super._();
  






@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is CalErrorKind_NonExportable);
}


@override
int get hashCode => runtimeType.hashCode;

@override
String toString() {
  return 'CalErrorKind.nonExportable()';
}


}




/// @nodoc


class CalErrorKind_UnsupportedAlgorithm extends CalErrorKind {
  const CalErrorKind_UnsupportedAlgorithm(this.field0): super._();
  

 final  String field0;

/// Create a copy of CalErrorKind
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$CalErrorKind_UnsupportedAlgorithmCopyWith<CalErrorKind_UnsupportedAlgorithm> get copyWith => _$CalErrorKind_UnsupportedAlgorithmCopyWithImpl<CalErrorKind_UnsupportedAlgorithm>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is CalErrorKind_UnsupportedAlgorithm&&(identical(other.field0, field0) || other.field0 == field0));
}


@override
int get hashCode => Object.hash(runtimeType,field0);

@override
String toString() {
  return 'CalErrorKind.unsupportedAlgorithm(field0: $field0)';
}


}

/// @nodoc
abstract mixin class $CalErrorKind_UnsupportedAlgorithmCopyWith<$Res> implements $CalErrorKindCopyWith<$Res> {
  factory $CalErrorKind_UnsupportedAlgorithmCopyWith(CalErrorKind_UnsupportedAlgorithm value, $Res Function(CalErrorKind_UnsupportedAlgorithm) _then) = _$CalErrorKind_UnsupportedAlgorithmCopyWithImpl;
@useResult
$Res call({
 String field0
});




}
/// @nodoc
class _$CalErrorKind_UnsupportedAlgorithmCopyWithImpl<$Res>
    implements $CalErrorKind_UnsupportedAlgorithmCopyWith<$Res> {
  _$CalErrorKind_UnsupportedAlgorithmCopyWithImpl(this._self, this._then);

  final CalErrorKind_UnsupportedAlgorithm _self;
  final $Res Function(CalErrorKind_UnsupportedAlgorithm) _then;

/// Create a copy of CalErrorKind
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? field0 = null,}) {
  return _then(CalErrorKind_UnsupportedAlgorithm(
null == field0 ? _self.field0 : field0 // ignore: cast_nullable_to_non_nullable
as String,
  ));
}


}

/// @nodoc


class CalErrorKind_EphemeralKeyError extends CalErrorKind {
  const CalErrorKind_EphemeralKeyError(): super._();
  






@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is CalErrorKind_EphemeralKeyError);
}


@override
int get hashCode => runtimeType.hashCode;

@override
String toString() {
  return 'CalErrorKind.ephemeralKeyError()';
}


}




/// @nodoc


class CalErrorKind_Other extends CalErrorKind {
  const CalErrorKind_Other(): super._();
  






@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is CalErrorKind_Other);
}


@override
int get hashCode => runtimeType.hashCode;

@override
String toString() {
  return 'CalErrorKind.other()';
}


}




// dart format on
