-allowaccessmodification
-repackageclasses

-keepclassmembers class * implements android.os.Parcelable {
    public static final ** CREATOR;
}

-assumenosideeffects class kotlin.jvm.internal.Intrinsics {
	public static void check*(...);
	public static void throw*(...);
}

-assumenosideeffects class java.util.Objects{
    ** requireNonNull(...);
}

-assumenosideeffects class android.util.Log {
    public static int v(...);
    public static int d(...);
}

-keep class com.google.android.material.theme.MaterialComponentsViewInflater {
    <init>();
}

# 1. Keep the Key Attestation classes
# If you are using Google's sample libraries or your own custom attestation classes
-keep class com.google.virt.KeyAttestation** { *; }
-keep class * extends java.security.cert.Certificate { *; }

# 2. Keep the models used for JSON/XML parsing
# Replace 'your.package.name.models' with the actual package where your 
# revocation and keybox data classes live.
-keepclassmembers class your.package.name.models.** { *; }

# 3. Prevent obfuscation of native methods (important for security-heavy apps)
-keepclasseswithmembernames class * {
    native <methods>;
}

# 4. Keep the 'revoked' and 'caching' logic visible for your UI
# This ensures your custom parsing doesn't break when checking for "REVOKED"
-keepattributes Signature, AnnotationDefault, EnclosingMethod
