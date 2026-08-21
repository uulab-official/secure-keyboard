package com.uulab.securekeypad.reactnative

import com.facebook.react.ReactPackage
import com.facebook.react.bridge.NativeModule
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.uimanager.ViewManager

/**
 * React Native package entry point used by CLI autolinking.
 *
 * Keeping registration here makes the native view manager discoverable in
 * both the legacy bridge and the new-architecture host build. No secret or
 * session data is retained by the package object.
 */
public class SecureKeypadReactPackage : ReactPackage {
    override fun createNativeModules(reactContext: ReactApplicationContext): List<NativeModule> = emptyList()

    override fun createViewManagers(reactContext: ReactApplicationContext): List<ViewManager<*, *>> =
        listOf(SecureKeypadViewManager())
}
