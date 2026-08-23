# Keep the private Kotlin object whose external methods are resolved by the JNI
# symbol names in secure_keypad_jni.c.
-keep class com.uulab.securekeypad.SecureKeypadNative { *; }
-keep class com.uulab.securekeypad.SecureKeypadView { *; }
-keepclasseswithmembers,includedescriptorclasses class * {
    native <methods>;
}
