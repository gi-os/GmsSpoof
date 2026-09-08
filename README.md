# GmsSpoof

An Xposed module that makes Google's apps trust a microG install on a phone
that has no Google. Built against the Kyocera DIGNO KY-42C.

## Why it exists

microG installs on the KY-42C as a plain sideloaded APK, patched with LSPatch
so it loads alongside the phone's Xposed runtime. But Google's own apps —
Maps, and anything using a Google client library — check two things microG
cannot answer honestly:

- **The signature.** Google apps verify that `com.google.android.gms`,
  `com.android.vending` and `com.google.android.apps.maps` carry Google's
  signing certificate. microG is not signed by Google, so those checks fail
  and the app declares GMS absent, however complete microG is.
- **The code context.** LSPatch nests the real microG APK inside a stub, so
  code Google apps load *out of* the GMS apk (the Dynamite loader, the
  `ProviderInstaller` client) hits the LSPatch stub and dies with an
  `ExceptionInInitializerError`. A working GMS is invisible to that loader.

GmsSpoof fixes both, plus the two small gaps they expose. It is a probe, not
a product: `minSdk 21`, `versionCode 1`, no icon, no UI — one module, one job.

## What it hooks

**Signature spoofing.** For the three Google packages it reports the real
Google signing certificate from `getPackageInfo`, `getPackageInfoAsUser`,
`getPackageInfo(…AsUser)`, builds a matching `SigningInfo` on API 28+, and
answers `hasSigningCertificate` true. The certificate is the well-known
Google Android platform key, embedded in the module.

**Real microG code contexts.** Any app that asks for a *code* context of the
GMS package (`CONTEXT_INCLUDE_CODE`) gets back a `ContextWrapper` whose
`sourceDir`, `classLoader` and resources point at the **origin microG APK**
— extracted once from `assets/lspatch/origin/` inside the patched install and
cached. Its classloader is parented on this module so `ProviderInstallerImpl`
here wins, and for Google's own apps the `DynamiteLoader` class is hidden so
their `ProviderInstaller` takes the no-Dynamite fallback instead of waiting
for a module microG does not have. Non-code contexts keep the original
behaviour.

**TLS provider shim.** Client libraries expect a `GmsCore_OpenSSL` security
provider (that is what "install provider" calls on the GMS context). microG
does not register one, so GmsSpoof re-inserts the platform `AndroidOpenSSL`
under that name, at the top of the provider list.

**Google Sans font fix.** Fonts requested from `com.google.android.gms.fonts`
normally come from Google's font provider; microG has none, so requests
returned nothing and Google's apps drew blank glyphs. Requests for that
authority are now served from the system Roboto/Noto Sans files, honouring the
requested weight from the query string.

## Target apps

`com.google.android.apps.maps`, `com.google.android.gms`, and
`com.ollix.fogofworld`. The module only acts inside those three.

## Build & install

```
./gradlew :app:assembleDebug
```

The APK installs as a normal Xposed module — enable it in LSPosed, target the
three apps above, reboot. `libs/XposedBridgeAPI-82.jar` is `compileOnly`.

## Status

Built and run against the KY-42C (Android 10, API 29, `armeabi-v7a`). A
working prototype: Maps launches and talks to microG's location provider with
the spoofed signature and a served code context. The exact hooks an app needs
vary by app and by Google client-library version, so this is a starting point
more than a finished thing — extend `TARGET_APPS` and the hook set as you find
what each app asks for.
