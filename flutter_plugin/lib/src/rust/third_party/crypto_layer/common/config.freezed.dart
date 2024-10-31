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
mixin _$ProviderImplConfig {
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function(ArcMutexJavaVm vm) android,
    required TResult Function() stub,
  }) =>
      throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function(ArcMutexJavaVm vm)? android,
    TResult? Function()? stub,
  }) =>
      throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function(ArcMutexJavaVm vm)? android,
    TResult Function()? stub,
    required TResult orElse(),
  }) =>
      throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(ProviderImplConfig_Android value) android,
    required TResult Function(ProviderImplConfig_Stub value) stub,
  }) =>
      throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(ProviderImplConfig_Android value)? android,
    TResult? Function(ProviderImplConfig_Stub value)? stub,
  }) =>
      throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(ProviderImplConfig_Android value)? android,
    TResult Function(ProviderImplConfig_Stub value)? stub,
    required TResult orElse(),
  }) =>
      throw _privateConstructorUsedError;
}

/// @nodoc
abstract class $ProviderImplConfigCopyWith<$Res> {
  factory $ProviderImplConfigCopyWith(
          ProviderImplConfig value, $Res Function(ProviderImplConfig) then) =
      _$ProviderImplConfigCopyWithImpl<$Res, ProviderImplConfig>;
}

/// @nodoc
class _$ProviderImplConfigCopyWithImpl<$Res, $Val extends ProviderImplConfig>
    implements $ProviderImplConfigCopyWith<$Res> {
  _$ProviderImplConfigCopyWithImpl(this._value, this._then);

  // ignore: unused_field
  final $Val _value;
  // ignore: unused_field
  final $Res Function($Val) _then;

  /// Create a copy of ProviderImplConfig
  /// with the given fields replaced by the non-null parameter values.
}

/// @nodoc
abstract class _$$ProviderImplConfig_AndroidImplCopyWith<$Res> {
  factory _$$ProviderImplConfig_AndroidImplCopyWith(
          _$ProviderImplConfig_AndroidImpl value,
          $Res Function(_$ProviderImplConfig_AndroidImpl) then) =
      __$$ProviderImplConfig_AndroidImplCopyWithImpl<$Res>;
  @useResult
  $Res call({ArcMutexJavaVm vm});
}

/// @nodoc
class __$$ProviderImplConfig_AndroidImplCopyWithImpl<$Res>
    extends _$ProviderImplConfigCopyWithImpl<$Res,
        _$ProviderImplConfig_AndroidImpl>
    implements _$$ProviderImplConfig_AndroidImplCopyWith<$Res> {
  __$$ProviderImplConfig_AndroidImplCopyWithImpl(
      _$ProviderImplConfig_AndroidImpl _value,
      $Res Function(_$ProviderImplConfig_AndroidImpl) _then)
      : super(_value, _then);

  /// Create a copy of ProviderImplConfig
  /// with the given fields replaced by the non-null parameter values.
  @pragma('vm:prefer-inline')
  @override
  $Res call({
    Object? vm = null,
  }) {
    return _then(_$ProviderImplConfig_AndroidImpl(
      vm: null == vm
          ? _value.vm
          : vm // ignore: cast_nullable_to_non_nullable
              as ArcMutexJavaVm,
    ));
  }
}

/// @nodoc

class _$ProviderImplConfig_AndroidImpl extends ProviderImplConfig_Android {
  const _$ProviderImplConfig_AndroidImpl({required this.vm}) : super._();

  @override
  final ArcMutexJavaVm vm;

  @override
  String toString() {
    return 'ProviderImplConfig.android(vm: $vm)';
  }

  @override
  bool operator ==(Object other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType &&
            other is _$ProviderImplConfig_AndroidImpl &&
            (identical(other.vm, vm) || other.vm == vm));
  }

  @override
  int get hashCode => Object.hash(runtimeType, vm);

  /// Create a copy of ProviderImplConfig
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  @override
  @pragma('vm:prefer-inline')
  _$$ProviderImplConfig_AndroidImplCopyWith<_$ProviderImplConfig_AndroidImpl>
      get copyWith => __$$ProviderImplConfig_AndroidImplCopyWithImpl<
          _$ProviderImplConfig_AndroidImpl>(this, _$identity);

  @override
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function(ArcMutexJavaVm vm) android,
    required TResult Function() stub,
  }) {
    return android(vm);
  }

  @override
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function(ArcMutexJavaVm vm)? android,
    TResult? Function()? stub,
  }) {
    return android?.call(vm);
  }

  @override
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function(ArcMutexJavaVm vm)? android,
    TResult Function()? stub,
    required TResult orElse(),
  }) {
    if (android != null) {
      return android(vm);
    }
    return orElse();
  }

  @override
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(ProviderImplConfig_Android value) android,
    required TResult Function(ProviderImplConfig_Stub value) stub,
  }) {
    return android(this);
  }

  @override
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(ProviderImplConfig_Android value)? android,
    TResult? Function(ProviderImplConfig_Stub value)? stub,
  }) {
    return android?.call(this);
  }

  @override
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(ProviderImplConfig_Android value)? android,
    TResult Function(ProviderImplConfig_Stub value)? stub,
    required TResult orElse(),
  }) {
    if (android != null) {
      return android(this);
    }
    return orElse();
  }
}

abstract class ProviderImplConfig_Android extends ProviderImplConfig {
  const factory ProviderImplConfig_Android({required final ArcMutexJavaVm vm}) =
      _$ProviderImplConfig_AndroidImpl;
  const ProviderImplConfig_Android._() : super._();

  ArcMutexJavaVm get vm;

  /// Create a copy of ProviderImplConfig
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  _$$ProviderImplConfig_AndroidImplCopyWith<_$ProviderImplConfig_AndroidImpl>
      get copyWith => throw _privateConstructorUsedError;
}

/// @nodoc
abstract class _$$ProviderImplConfig_StubImplCopyWith<$Res> {
  factory _$$ProviderImplConfig_StubImplCopyWith(
          _$ProviderImplConfig_StubImpl value,
          $Res Function(_$ProviderImplConfig_StubImpl) then) =
      __$$ProviderImplConfig_StubImplCopyWithImpl<$Res>;
}

/// @nodoc
class __$$ProviderImplConfig_StubImplCopyWithImpl<$Res>
    extends _$ProviderImplConfigCopyWithImpl<$Res,
        _$ProviderImplConfig_StubImpl>
    implements _$$ProviderImplConfig_StubImplCopyWith<$Res> {
  __$$ProviderImplConfig_StubImplCopyWithImpl(
      _$ProviderImplConfig_StubImpl _value,
      $Res Function(_$ProviderImplConfig_StubImpl) _then)
      : super(_value, _then);

  /// Create a copy of ProviderImplConfig
  /// with the given fields replaced by the non-null parameter values.
}

/// @nodoc

class _$ProviderImplConfig_StubImpl extends ProviderImplConfig_Stub {
  const _$ProviderImplConfig_StubImpl() : super._();

  @override
  String toString() {
    return 'ProviderImplConfig.stub()';
  }

  @override
  bool operator ==(Object other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType &&
            other is _$ProviderImplConfig_StubImpl);
  }

  @override
  int get hashCode => runtimeType.hashCode;

  @override
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function(ArcMutexJavaVm vm) android,
    required TResult Function() stub,
  }) {
    return stub();
  }

  @override
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function(ArcMutexJavaVm vm)? android,
    TResult? Function()? stub,
  }) {
    return stub?.call();
  }

  @override
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function(ArcMutexJavaVm vm)? android,
    TResult Function()? stub,
    required TResult orElse(),
  }) {
    if (stub != null) {
      return stub();
    }
    return orElse();
  }

  @override
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(ProviderImplConfig_Android value) android,
    required TResult Function(ProviderImplConfig_Stub value) stub,
  }) {
    return stub(this);
  }

  @override
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(ProviderImplConfig_Android value)? android,
    TResult? Function(ProviderImplConfig_Stub value)? stub,
  }) {
    return stub?.call(this);
  }

  @override
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(ProviderImplConfig_Android value)? android,
    TResult Function(ProviderImplConfig_Stub value)? stub,
    required TResult orElse(),
  }) {
    if (stub != null) {
      return stub(this);
    }
    return orElse();
  }
}

abstract class ProviderImplConfig_Stub extends ProviderImplConfig {
  const factory ProviderImplConfig_Stub() = _$ProviderImplConfig_StubImpl;
  const ProviderImplConfig_Stub._() : super._();
}
