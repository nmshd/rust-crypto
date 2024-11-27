package com.example.cal_flutter_app

import android.content.Context
import androidx.annotation.NonNull
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel.MethodCallHandler
import io.flutter.plugin.common.MethodChannel.Result

class MainActivity : FlutterActivity() {
    override fun configureFlutterEngine(
            @NonNull flutterEngine: FlutterEngine,
    ) {
        super.configureFlutterEngine(flutterEngine)
        flutterEngine.plugins.add(MyPlugin())
    }
}

class MyPlugin : FlutterPlugin, MethodCallHandler {
    companion object {
        init {
            System.loadLibrary("cal_flutter_plugin")
        }
    }

    external fun init_android(ctx: Context)

    override fun onAttachedToEngine(
            @NonNull flutterPluginBinding: FlutterPlugin.FlutterPluginBinding,
    ) {
        init_android(flutterPluginBinding.applicationContext)
    }

    override fun onMethodCall(
            @NonNull call: MethodCall,
            @NonNull result: Result,
    ) {
        result.notImplemented()
    }

    override fun onDetachedFromEngine(
            @NonNull binding: FlutterPlugin.FlutterPluginBinding,
    ) {}
}
