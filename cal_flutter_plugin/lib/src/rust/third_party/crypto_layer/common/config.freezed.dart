// dart format width=80
// coverage:ignore-file
// GENERATED CODE - DO NOT MODIFY BY HAND
// ignore_for_file: type=lint
// ignore_for_file: unused_element, deprecated_member_use, deprecated_member_use_from_same_package, use_function_type_syntax_for_parameters, unnecessary_const, avoid_init_to_null, invalid_override_different_default_values_named, prefer_expression_function_bodies, annotate_overrides, invalid_annotation_target, unnecessary_question_mark

part of 'config.dart';

// **************************************************************************
// FreezedGenerator
// **************************************************************************

// dart format off
T _$identity<T>(T value) => value;
/// @nodoc
mixin _$AdditionalConfig {





@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is AdditionalConfig);
}


@override
int get hashCode => runtimeType.hashCode;

@override
String toString() {
  return 'AdditionalConfig()';
}


}

/// @nodoc
class $AdditionalConfigCopyWith<$Res>  {
$AdditionalConfigCopyWith(AdditionalConfig _, $Res Function(AdditionalConfig) __);
}


/// @nodoc


class AdditionalConfig_KVStoreConfig extends AdditionalConfig {
  const AdditionalConfig_KVStoreConfig({required this.getFn, required this.storeFn, required this.deleteFn, required this.allKeysFn}): super._();
  

 final  ArcFnStringDynFutureOptionVecU8 getFn;
 final  ArcFnStringVecU8DynFutureBool storeFn;
 final  ArcFnStringPinBoxFutureOutput deleteFn;
 final  ArcFnDynFutureVecString allKeysFn;

/// Create a copy of AdditionalConfig
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$AdditionalConfig_KVStoreConfigCopyWith<AdditionalConfig_KVStoreConfig> get copyWith => _$AdditionalConfig_KVStoreConfigCopyWithImpl<AdditionalConfig_KVStoreConfig>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is AdditionalConfig_KVStoreConfig&&(identical(other.getFn, getFn) || other.getFn == getFn)&&(identical(other.storeFn, storeFn) || other.storeFn == storeFn)&&(identical(other.deleteFn, deleteFn) || other.deleteFn == deleteFn)&&(identical(other.allKeysFn, allKeysFn) || other.allKeysFn == allKeysFn));
}


@override
int get hashCode => Object.hash(runtimeType,getFn,storeFn,deleteFn,allKeysFn);

@override
String toString() {
  return 'AdditionalConfig.kvStoreConfig(getFn: $getFn, storeFn: $storeFn, deleteFn: $deleteFn, allKeysFn: $allKeysFn)';
}


}

/// @nodoc
abstract mixin class $AdditionalConfig_KVStoreConfigCopyWith<$Res> implements $AdditionalConfigCopyWith<$Res> {
  factory $AdditionalConfig_KVStoreConfigCopyWith(AdditionalConfig_KVStoreConfig value, $Res Function(AdditionalConfig_KVStoreConfig) _then) = _$AdditionalConfig_KVStoreConfigCopyWithImpl;
@useResult
$Res call({
 ArcFnStringDynFutureOptionVecU8 getFn, ArcFnStringVecU8DynFutureBool storeFn, ArcFnStringPinBoxFutureOutput deleteFn, ArcFnDynFutureVecString allKeysFn
});




}
/// @nodoc
class _$AdditionalConfig_KVStoreConfigCopyWithImpl<$Res>
    implements $AdditionalConfig_KVStoreConfigCopyWith<$Res> {
  _$AdditionalConfig_KVStoreConfigCopyWithImpl(this._self, this._then);

  final AdditionalConfig_KVStoreConfig _self;
  final $Res Function(AdditionalConfig_KVStoreConfig) _then;

/// Create a copy of AdditionalConfig
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? getFn = null,Object? storeFn = null,Object? deleteFn = null,Object? allKeysFn = null,}) {
  return _then(AdditionalConfig_KVStoreConfig(
getFn: null == getFn ? _self.getFn : getFn // ignore: cast_nullable_to_non_nullable
as ArcFnStringDynFutureOptionVecU8,storeFn: null == storeFn ? _self.storeFn : storeFn // ignore: cast_nullable_to_non_nullable
as ArcFnStringVecU8DynFutureBool,deleteFn: null == deleteFn ? _self.deleteFn : deleteFn // ignore: cast_nullable_to_non_nullable
as ArcFnStringPinBoxFutureOutput,allKeysFn: null == allKeysFn ? _self.allKeysFn : allKeysFn // ignore: cast_nullable_to_non_nullable
as ArcFnDynFutureVecString,
  ));
}


}

/// @nodoc


class AdditionalConfig_FileStoreConfig extends AdditionalConfig {
  const AdditionalConfig_FileStoreConfig({required this.dbDir}): super._();
  

/// Path to a directory where the database holding key metadata will be saved.
 final  String dbDir;

/// Create a copy of AdditionalConfig
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$AdditionalConfig_FileStoreConfigCopyWith<AdditionalConfig_FileStoreConfig> get copyWith => _$AdditionalConfig_FileStoreConfigCopyWithImpl<AdditionalConfig_FileStoreConfig>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is AdditionalConfig_FileStoreConfig&&(identical(other.dbDir, dbDir) || other.dbDir == dbDir));
}


@override
int get hashCode => Object.hash(runtimeType,dbDir);

@override
String toString() {
  return 'AdditionalConfig.fileStoreConfig(dbDir: $dbDir)';
}


}

/// @nodoc
abstract mixin class $AdditionalConfig_FileStoreConfigCopyWith<$Res> implements $AdditionalConfigCopyWith<$Res> {
  factory $AdditionalConfig_FileStoreConfigCopyWith(AdditionalConfig_FileStoreConfig value, $Res Function(AdditionalConfig_FileStoreConfig) _then) = _$AdditionalConfig_FileStoreConfigCopyWithImpl;
@useResult
$Res call({
 String dbDir
});




}
/// @nodoc
class _$AdditionalConfig_FileStoreConfigCopyWithImpl<$Res>
    implements $AdditionalConfig_FileStoreConfigCopyWith<$Res> {
  _$AdditionalConfig_FileStoreConfigCopyWithImpl(this._self, this._then);

  final AdditionalConfig_FileStoreConfig _self;
  final $Res Function(AdditionalConfig_FileStoreConfig) _then;

/// Create a copy of AdditionalConfig
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? dbDir = null,}) {
  return _then(AdditionalConfig_FileStoreConfig(
dbDir: null == dbDir ? _self.dbDir : dbDir // ignore: cast_nullable_to_non_nullable
as String,
  ));
}


}

/// @nodoc


class AdditionalConfig_StorageConfigHMAC extends AdditionalConfig {
  const AdditionalConfig_StorageConfigHMAC(this.field0): super._();
  

 final  KeyHandle field0;

/// Create a copy of AdditionalConfig
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$AdditionalConfig_StorageConfigHMACCopyWith<AdditionalConfig_StorageConfigHMAC> get copyWith => _$AdditionalConfig_StorageConfigHMACCopyWithImpl<AdditionalConfig_StorageConfigHMAC>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is AdditionalConfig_StorageConfigHMAC&&(identical(other.field0, field0) || other.field0 == field0));
}


@override
int get hashCode => Object.hash(runtimeType,field0);

@override
String toString() {
  return 'AdditionalConfig.storageConfigHmac(field0: $field0)';
}


}

/// @nodoc
abstract mixin class $AdditionalConfig_StorageConfigHMACCopyWith<$Res> implements $AdditionalConfigCopyWith<$Res> {
  factory $AdditionalConfig_StorageConfigHMACCopyWith(AdditionalConfig_StorageConfigHMAC value, $Res Function(AdditionalConfig_StorageConfigHMAC) _then) = _$AdditionalConfig_StorageConfigHMACCopyWithImpl;
@useResult
$Res call({
 KeyHandle field0
});




}
/// @nodoc
class _$AdditionalConfig_StorageConfigHMACCopyWithImpl<$Res>
    implements $AdditionalConfig_StorageConfigHMACCopyWith<$Res> {
  _$AdditionalConfig_StorageConfigHMACCopyWithImpl(this._self, this._then);

  final AdditionalConfig_StorageConfigHMAC _self;
  final $Res Function(AdditionalConfig_StorageConfigHMAC) _then;

/// Create a copy of AdditionalConfig
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? field0 = null,}) {
  return _then(AdditionalConfig_StorageConfigHMAC(
null == field0 ? _self.field0 : field0 // ignore: cast_nullable_to_non_nullable
as KeyHandle,
  ));
}


}

/// @nodoc


class AdditionalConfig_StorageConfigDSA extends AdditionalConfig {
  const AdditionalConfig_StorageConfigDSA(this.field0): super._();
  

 final  KeyPairHandle field0;

/// Create a copy of AdditionalConfig
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$AdditionalConfig_StorageConfigDSACopyWith<AdditionalConfig_StorageConfigDSA> get copyWith => _$AdditionalConfig_StorageConfigDSACopyWithImpl<AdditionalConfig_StorageConfigDSA>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is AdditionalConfig_StorageConfigDSA&&(identical(other.field0, field0) || other.field0 == field0));
}


@override
int get hashCode => Object.hash(runtimeType,field0);

@override
String toString() {
  return 'AdditionalConfig.storageConfigDsa(field0: $field0)';
}


}

/// @nodoc
abstract mixin class $AdditionalConfig_StorageConfigDSACopyWith<$Res> implements $AdditionalConfigCopyWith<$Res> {
  factory $AdditionalConfig_StorageConfigDSACopyWith(AdditionalConfig_StorageConfigDSA value, $Res Function(AdditionalConfig_StorageConfigDSA) _then) = _$AdditionalConfig_StorageConfigDSACopyWithImpl;
@useResult
$Res call({
 KeyPairHandle field0
});




}
/// @nodoc
class _$AdditionalConfig_StorageConfigDSACopyWithImpl<$Res>
    implements $AdditionalConfig_StorageConfigDSACopyWith<$Res> {
  _$AdditionalConfig_StorageConfigDSACopyWithImpl(this._self, this._then);

  final AdditionalConfig_StorageConfigDSA _self;
  final $Res Function(AdditionalConfig_StorageConfigDSA) _then;

/// Create a copy of AdditionalConfig
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? field0 = null,}) {
  return _then(AdditionalConfig_StorageConfigDSA(
null == field0 ? _self.field0 : field0 // ignore: cast_nullable_to_non_nullable
as KeyPairHandle,
  ));
}


}

/// @nodoc


class AdditionalConfig_StorageConfigSymmetricEncryption extends AdditionalConfig {
  const AdditionalConfig_StorageConfigSymmetricEncryption(this.field0): super._();
  

 final  KeyHandle field0;

/// Create a copy of AdditionalConfig
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$AdditionalConfig_StorageConfigSymmetricEncryptionCopyWith<AdditionalConfig_StorageConfigSymmetricEncryption> get copyWith => _$AdditionalConfig_StorageConfigSymmetricEncryptionCopyWithImpl<AdditionalConfig_StorageConfigSymmetricEncryption>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is AdditionalConfig_StorageConfigSymmetricEncryption&&(identical(other.field0, field0) || other.field0 == field0));
}


@override
int get hashCode => Object.hash(runtimeType,field0);

@override
String toString() {
  return 'AdditionalConfig.storageConfigSymmetricEncryption(field0: $field0)';
}


}

/// @nodoc
abstract mixin class $AdditionalConfig_StorageConfigSymmetricEncryptionCopyWith<$Res> implements $AdditionalConfigCopyWith<$Res> {
  factory $AdditionalConfig_StorageConfigSymmetricEncryptionCopyWith(AdditionalConfig_StorageConfigSymmetricEncryption value, $Res Function(AdditionalConfig_StorageConfigSymmetricEncryption) _then) = _$AdditionalConfig_StorageConfigSymmetricEncryptionCopyWithImpl;
@useResult
$Res call({
 KeyHandle field0
});




}
/// @nodoc
class _$AdditionalConfig_StorageConfigSymmetricEncryptionCopyWithImpl<$Res>
    implements $AdditionalConfig_StorageConfigSymmetricEncryptionCopyWith<$Res> {
  _$AdditionalConfig_StorageConfigSymmetricEncryptionCopyWithImpl(this._self, this._then);

  final AdditionalConfig_StorageConfigSymmetricEncryption _self;
  final $Res Function(AdditionalConfig_StorageConfigSymmetricEncryption) _then;

/// Create a copy of AdditionalConfig
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? field0 = null,}) {
  return _then(AdditionalConfig_StorageConfigSymmetricEncryption(
null == field0 ? _self.field0 : field0 // ignore: cast_nullable_to_non_nullable
as KeyHandle,
  ));
}


}

/// @nodoc


class AdditionalConfig_StorageConfigAsymmetricEncryption extends AdditionalConfig {
  const AdditionalConfig_StorageConfigAsymmetricEncryption(this.field0): super._();
  

 final  KeyPairHandle field0;

/// Create a copy of AdditionalConfig
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$AdditionalConfig_StorageConfigAsymmetricEncryptionCopyWith<AdditionalConfig_StorageConfigAsymmetricEncryption> get copyWith => _$AdditionalConfig_StorageConfigAsymmetricEncryptionCopyWithImpl<AdditionalConfig_StorageConfigAsymmetricEncryption>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is AdditionalConfig_StorageConfigAsymmetricEncryption&&(identical(other.field0, field0) || other.field0 == field0));
}


@override
int get hashCode => Object.hash(runtimeType,field0);

@override
String toString() {
  return 'AdditionalConfig.storageConfigAsymmetricEncryption(field0: $field0)';
}


}

/// @nodoc
abstract mixin class $AdditionalConfig_StorageConfigAsymmetricEncryptionCopyWith<$Res> implements $AdditionalConfigCopyWith<$Res> {
  factory $AdditionalConfig_StorageConfigAsymmetricEncryptionCopyWith(AdditionalConfig_StorageConfigAsymmetricEncryption value, $Res Function(AdditionalConfig_StorageConfigAsymmetricEncryption) _then) = _$AdditionalConfig_StorageConfigAsymmetricEncryptionCopyWithImpl;
@useResult
$Res call({
 KeyPairHandle field0
});




}
/// @nodoc
class _$AdditionalConfig_StorageConfigAsymmetricEncryptionCopyWithImpl<$Res>
    implements $AdditionalConfig_StorageConfigAsymmetricEncryptionCopyWith<$Res> {
  _$AdditionalConfig_StorageConfigAsymmetricEncryptionCopyWithImpl(this._self, this._then);

  final AdditionalConfig_StorageConfigAsymmetricEncryption _self;
  final $Res Function(AdditionalConfig_StorageConfigAsymmetricEncryption) _then;

/// Create a copy of AdditionalConfig
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? field0 = null,}) {
  return _then(AdditionalConfig_StorageConfigAsymmetricEncryption(
null == field0 ? _self.field0 : field0 // ignore: cast_nullable_to_non_nullable
as KeyPairHandle,
  ));
}


}

/// @nodoc
mixin _$Spec {

 Object get field0;



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is Spec&&const DeepCollectionEquality().equals(other.field0, field0));
}


@override
int get hashCode => Object.hash(runtimeType,const DeepCollectionEquality().hash(field0));

@override
String toString() {
  return 'Spec(field0: $field0)';
}


}

/// @nodoc
class $SpecCopyWith<$Res>  {
$SpecCopyWith(Spec _, $Res Function(Spec) __);
}


/// @nodoc


class Spec_KeySpec extends Spec {
  const Spec_KeySpec(this.field0): super._();
  

@override final  KeySpec field0;

/// Create a copy of Spec
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$Spec_KeySpecCopyWith<Spec_KeySpec> get copyWith => _$Spec_KeySpecCopyWithImpl<Spec_KeySpec>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is Spec_KeySpec&&(identical(other.field0, field0) || other.field0 == field0));
}


@override
int get hashCode => Object.hash(runtimeType,field0);

@override
String toString() {
  return 'Spec.keySpec(field0: $field0)';
}


}

/// @nodoc
abstract mixin class $Spec_KeySpecCopyWith<$Res> implements $SpecCopyWith<$Res> {
  factory $Spec_KeySpecCopyWith(Spec_KeySpec value, $Res Function(Spec_KeySpec) _then) = _$Spec_KeySpecCopyWithImpl;
@useResult
$Res call({
 KeySpec field0
});




}
/// @nodoc
class _$Spec_KeySpecCopyWithImpl<$Res>
    implements $Spec_KeySpecCopyWith<$Res> {
  _$Spec_KeySpecCopyWithImpl(this._self, this._then);

  final Spec_KeySpec _self;
  final $Res Function(Spec_KeySpec) _then;

/// Create a copy of Spec
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? field0 = null,}) {
  return _then(Spec_KeySpec(
null == field0 ? _self.field0 : field0 // ignore: cast_nullable_to_non_nullable
as KeySpec,
  ));
}


}

/// @nodoc


class Spec_KeyPairSpec extends Spec {
  const Spec_KeyPairSpec(this.field0): super._();
  

@override final  KeyPairSpec field0;

/// Create a copy of Spec
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$Spec_KeyPairSpecCopyWith<Spec_KeyPairSpec> get copyWith => _$Spec_KeyPairSpecCopyWithImpl<Spec_KeyPairSpec>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is Spec_KeyPairSpec&&(identical(other.field0, field0) || other.field0 == field0));
}


@override
int get hashCode => Object.hash(runtimeType,field0);

@override
String toString() {
  return 'Spec.keyPairSpec(field0: $field0)';
}


}

/// @nodoc
abstract mixin class $Spec_KeyPairSpecCopyWith<$Res> implements $SpecCopyWith<$Res> {
  factory $Spec_KeyPairSpecCopyWith(Spec_KeyPairSpec value, $Res Function(Spec_KeyPairSpec) _then) = _$Spec_KeyPairSpecCopyWithImpl;
@useResult
$Res call({
 KeyPairSpec field0
});




}
/// @nodoc
class _$Spec_KeyPairSpecCopyWithImpl<$Res>
    implements $Spec_KeyPairSpecCopyWith<$Res> {
  _$Spec_KeyPairSpecCopyWithImpl(this._self, this._then);

  final Spec_KeyPairSpec _self;
  final $Res Function(Spec_KeyPairSpec) _then;

/// Create a copy of Spec
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? field0 = null,}) {
  return _then(Spec_KeyPairSpec(
null == field0 ? _self.field0 : field0 // ignore: cast_nullable_to_non_nullable
as KeyPairSpec,
  ));
}


}

// dart format on
