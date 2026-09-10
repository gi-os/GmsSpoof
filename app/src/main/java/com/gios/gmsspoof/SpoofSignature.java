package com.gios.gmsspoof;

import android.annotation.TargetApi;
import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.Signature;
import android.content.pm.SigningInfo;
import android.os.Build;
import android.os.CancellationSignal;
import android.provider.FontRequest;
import android.net.Uri;
import android.graphics.fonts.FontVariationAxis;
import java.io.File;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import android.util.ArraySet;
import android.util.Base64;

import java.io.ByteArrayInputStream;
import java.lang.reflect.Constructor;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.AbstractMap.SimpleEntry;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage.LoadPackageParam;

public class SpoofSignature implements IXposedHookLoadPackage {

    private static final String TAG = "GmsSpoof";
    private static final String GMS = "com.google.android.gms";
    private static final String[] TARGET_APPS = { "com.ollix.fogofworld", "com.google.android.apps.maps", "com.espn.fantasy.lm.football", "com.google.android.gms" };
    private static final String[] SPOOFED_PACKAGES = { "com.google.android.gms", "com.android.vending", "com.google.android.apps.maps" };

    private static final String X509_CERT =
            "MIIEQzCCAyugAwIBAgIJAMLgh0ZkSjCNMA0GCSqGSIb3DQEBBAUAMHQxCzAJBgNVBAYTAlVTMRMwEQYD"
          + "VQQIEwpDYWxpZm9ybmlhMRYwFAYDVQQHEw1Nb3VudGFpbiBWaWV3MRQwEgYDVQQKEwtHb29nbGUgSW5j"
          + "LjEQMA4GA1UECxMHQW5kcm9pZDEQMA4GA1UEAxMHQW5kcm9pZDAeFw0wODA4MjEyMzEzMzRaFw0zNjAx"
          + "MDcyMzEzMzRaMHQxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRYwFAYDVQQHEw1Nb3Vu"
          + "dGFpbiBWaWV3MRQwEgYDVQQKEwtHb29nbGUgSW5jLjEQMA4GA1UECxMHQW5kcm9pZDEQMA4GA1UEAxMH"
          + "QW5kcm9pZDCCASAwDQYJKoZIhvcNAQEBBQADggENADCCAQgCggEBAKtWLgDYO6IIrgqWbxJOKdoR8qtW"
          + "0I9Y4sypEwPpt1TTcvZApxsdyxMJZ2JORland2qSGT2y5b+3JKkedxiLDmpHpDsz2WCbdxgxRczfey5Y"
          + "ZnTJ4VZbH0xqWVW/8lGmPav5xVwnIiJS6HXk+BVKZF+JcWjAsb/GEuq/eFdpuzSqeYTcfi6idkyugwfY"
          + "wXFU1+5fZKUaRKYCwkkFQVfcAs1fXA5V+++FGfvjJ/CxURaSxaBvGdGDhfXE28LWuT9ozCl5xw4Yq5OG"
          + "azvV24mZVSoOO0yZ31j7kYvtwYK6NeADwbSxDdJEqO4k//0zOHKrUiGYXtqw/A0LFFtqoZKFjnkCAQOj"
          + "gdkwgdYwHQYDVR0OBBYEFMd9jMIhF1Ylmn/Tgt9r45jk14alMIGmBgNVHSMEgZ4wgZuAFMd9jMIhF1Yl"
          + "mn/Tgt9r45jk14aloXikdjB0MQswCQYDVQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5pYTEWMBQGA1UE"
          + "BxMNTW91bnRhaW4gVmlldzEUMBIGA1UEChMLR29vZ2xlIEluYy4xEDAOBgNVBAsTB0FuZHJvaWQxEDAO"
          + "BgNVBAMTB0FuZHJvaWSCCQDC4IdGZEowjTAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBBAUAA4IBAQBt"
          + "0lLO74UwLDYKqs6Tm8/yzKkEu116FmH4rkaymUIE0P9KaMftGlMexFlaYjzmB2OxZyl6euNXEsQH8gjw"
          + "yxCUKRJNexBiGcCEyj6z+a1fuHHvkiaai+KL8W1EyNmgjmyy8AW7P+LLlkR+ho5zEHatRbM/YAnqGcFh"
          + "5iZBqpknHf1SKMXFh4dd239FJ1jWYfbMDMy3NS5CTMQ2XFI1MvcyUTdZPErjQfTbQe3aDQsQcafEQPD+"
          + "nqActifKZ0Np0IS9L9kR/wbNvyz6ENwPiTrjV2KRkEjH78ZMcUQXg0L3BYHJ3lc69Vs5Ddf9uUGGMYld"
          + "X3WfMBEmh/9iFBDAaTCK";

    @Override
    public void handleLoadPackage(LoadPackageParam lpparam) throws Throwable {
        boolean isTarget = false;
        for (String app : TARGET_APPS) {
            if (app.equals(lpparam.packageName)) { isTarget = true; break; }
        }
        if (!isTarget) return;

        installFontFix(lpparam);
        if (!"com.google.android.gms".equals(lpparam.packageName)) installGmsCodeGuard(lpparam);

        final byte[] certBytes = Base64.decode(X509_CERT, Base64.DEFAULT);
        final Certificate cert = CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(certBytes));
        final Signature googleSig = new Signature(certBytes);

        XC_MethodHook packageInfoHook = new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam param) {
                Object result = param.getResult();
                if (!(result instanceof PackageInfo)) return;
                PackageInfo pi = (PackageInfo) result;
                if (pi.packageName == null || !shouldSpoof(pi.packageName)) return;

                pi.signatures = new Signature[]{ googleSig };
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                    SigningInfo si = createSigningInfo(googleSig, cert.getPublicKey());
                    if (si != null) pi.signingInfo = si;
                }
                param.setResult(pi);
                XposedBridge.log(TAG + ": spoofed signature for " + pi.packageName);
            }
        };

        Class<?> apm = XposedHelpers.findClass("android.app.ApplicationPackageManager", lpparam.classLoader);
        XposedBridge.hookAllMethods(apm, "getPackageInfo", packageInfoHook);
        XposedBridge.hookAllMethods(apm, "getPackageInfoAsUser", packageInfoHook);

        XposedBridge.hookAllMethods(apm, "hasSigningCertificate", new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam param) {
                if (param.args.length > 0 && param.args[0] instanceof String
                        && shouldSpoof((String) param.args[0])) {
                    param.setResult(Boolean.TRUE);
                    XposedBridge.log(TAG + ": hasSigningCertificate -> true for " + param.args[0]);
                }
            }
        });

        XposedBridge.log(TAG + ": hooks installed in " + lpparam.packageName);
    }

    /** LSPatch leaves FontsContract.sContext null in manager mode (crash), and microG has no
     *  fonts provider, so "Google Sans" requests return nothing (blank glyphs). Serve the
     *  request from the system Roboto file and skip the provider lookup entirely. */
    private static void installFontFix(LoadPackageParam lpparam) {
        try {
            XposedHelpers.findAndHookMethod("android.provider.FontsContract", lpparam.classLoader,
                "fetchFonts", Context.class, CancellationSignal.class, FontRequest.class,
                new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) {
                        FontRequest fr = (FontRequest) param.args[2];
                        if ("com.google.android.gms.fonts".equals(fr.getProviderAuthority())) {
                            try {
                                param.setResult(localFontResult(fr.getQuery()));
                                return;
                            } catch (Throwable t) {
                                XposedBridge.log(TAG + ": local font failed: " + t);
                            }
                        }
                        if (param.args[0] == null) {
                            Context app = (Context) XposedHelpers.callStaticMethod(
                                XposedHelpers.findClass("android.app.ActivityThread", null), "currentApplication");
                            if (app != null) param.args[0] = app;
                        }
                    }
                });
            Class<?> fiCls = XposedHelpers.findClass("android.provider.FontsContract$FontInfo", lpparam.classLoader);
            Class<?> fiArr = java.lang.reflect.Array.newInstance(fiCls, 0).getClass();
            XposedHelpers.findAndHookMethod("android.provider.FontsContract", lpparam.classLoader,
                "buildTypeface", Context.class, CancellationSignal.class, fiArr,
                new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) {
                        if (param.args[0] == null) {
                            Context app = (Context) XposedHelpers.callStaticMethod(
                                XposedHelpers.findClass("android.app.ActivityThread", null), "currentApplication");
                            if (app != null) param.args[0] = app;
                        }
                    }
                });
        } catch (Throwable t) {
            XposedBridge.log(TAG + ": font fix not installed: " + t);
        }
    }

    private static final String[] LOCAL_FONTS = {
        "/system/fonts/Roboto-Regular.ttf", "/system/fonts/RobotoStatic-Regular.ttf", "/system/fonts/NotoSans-Regular.ttf" };

    private static Object localFontResult(String query) throws Exception {
        int weight = 400;
        Matcher m = Pattern.compile("(?::|weight=)(\\d{3})").matcher(query == null ? "" : query);
        if (m.find()) weight = Integer.parseInt(m.group(1));
        File f = null;
        for (String p : LOCAL_FONTS) { File c = new File(p); if (c.exists()) { f = c; break; } }
        if (f == null) throw new java.io.FileNotFoundException("no system font");
        FontVariationAxis[] axes = { new FontVariationAxis("wght", weight) };
        Class<?> fiCls = Class.forName("android.provider.FontsContract$FontInfo");
        Object fi = XposedHelpers.newInstance(fiCls, Uri.fromFile(f), 0, axes, weight, false, 0);
        Object[] arr = (Object[]) java.lang.reflect.Array.newInstance(fiCls, 1);
        arr[0] = fi;
        Class<?> ffrCls = Class.forName("android.provider.FontsContract$FontFamilyResult");
        XposedBridge.log(TAG + ": served " + f.getName() + " wght=" + weight + " for '" + query + "'");
        return XposedHelpers.newInstance(ffrCls, 0, arr);
    }

    /** microG is LSPatched: its real dex lives in a nested apk only LSPatch's loader can open.
     *  Any app that loads code out of the GMS apk (Dynamite, ProviderInstaller) instantiates the
     *  LSPatch stub in its own process and dies with ExceptionInInitializerError. Report the
     *  package as not found for code contexts so client libs take their no-GMS fallback, and
     *  give that fallback the TLS provider name it expects. */
    private static Context currentApp() {
        return (Context) XposedHelpers.callStaticMethod(
                XposedHelpers.findClass("android.app.ActivityThread", null), "currentApplication");
    }

    private static ClassLoader sGmsLoader;
    private static File sOrigin;
    private static android.content.pm.ApplicationInfo sGmsInfo;

    /** The ORIGINAL microG apk that LSPatch nests inside the patched one, extracted once. */
    private static synchronized File originApk(Context app) throws Exception {
        if (sOrigin != null && sOrigin.exists()) return sOrigin;
        android.content.pm.ApplicationInfo gms = app.getPackageManager().getApplicationInfo(GMS, 0);
        File dir = new File(app.getCodeCacheDir(), "gmsspoof"); dir.mkdirs();
        File origin = new File(dir, "gms-origin-" + new File(gms.sourceDir).lastModified() + ".apk");
        if (!origin.exists()) {
            for (File old : dir.listFiles()) old.delete();
            try (java.util.zip.ZipFile z = new java.util.zip.ZipFile(gms.sourceDir)) {
                java.util.zip.ZipEntry hit = null;
                for (java.util.Enumeration<? extends java.util.zip.ZipEntry> e = z.entries(); e.hasMoreElements();) {
                    java.util.zip.ZipEntry ze = e.nextElement();
                    if (ze.getName().startsWith("assets/lspatch/origin") && ze.getName().endsWith(".apk")) { hit = ze; break; }
                }
                if (hit == null) throw new java.io.FileNotFoundException("no assets/lspatch/origin/*.apk in " + gms.sourceDir);
                File tmp = new File(dir, "tmp.apk");
                try (java.io.InputStream in = z.getInputStream(hit); java.io.FileOutputStream out = new java.io.FileOutputStream(tmp)) {
                    byte[] b = new byte[1 << 16]; int n; while ((n = in.read(b)) > 0) out.write(b, 0, n);
                }
                tmp.setReadOnly();
                if (!tmp.renameTo(origin)) throw new java.io.IOException("rename failed");
            }
            XposedBridge.log(TAG + ": extracted microG origin apk (" + origin.length() + " bytes)");
        }
        sOrigin = origin;
        return origin;
    }

    /** microG's ApplicationInfo with sourceDir pointing at the origin apk, so anything that
     *  builds its own PathClassLoader from sourceDir (microG's DynamiteContextFactory does)
     *  gets real classes instead of the LSPatch stub. */
    private static synchronized android.content.pm.ApplicationInfo gmsAppInfo(Context app) throws Exception {
        if (sGmsInfo != null) return sGmsInfo;
        android.content.pm.ApplicationInfo ai = new android.content.pm.ApplicationInfo(
                app.getPackageManager().getApplicationInfo(GMS, 0));
        String o = originApk(app).getPath();
        ai.sourceDir = o; ai.publicSourceDir = o;
        sGmsInfo = ai;
        return ai;
    }

    /** Origin-apk classloader parented on this module's apk (ProviderInstallerImpl wins,
     *  parent-first). For Google's own apps, hide DynamiteLoaderImpl: with it visible their
     *  ProviderInstaller asks Dynamite for a module microG lacks and never falls back. */
    private static synchronized ClassLoader gmsClassLoader(Context app, final boolean hideDynamite) throws Exception {
        if (sGmsLoader != null) return sGmsLoader;
        android.content.pm.ApplicationInfo gms = app.getPackageManager().getApplicationInfo(GMS, 0);
        android.content.pm.ApplicationInfo me = app.getPackageManager().getApplicationInfo("com.gios.gmsspoof", 0);
        File origin = originApk(app);
        String libs = gms.nativeLibraryDir + File.pathSeparator + origin.getPath() + "!/lib/arm64-v8a";
        ClassLoader parent = new dalvik.system.PathClassLoader(me.sourceDir, null, ClassLoader.getSystemClassLoader());
        sGmsLoader = new dalvik.system.PathClassLoader(origin.getPath(), libs, parent) {
            @Override
            protected Class<?> loadClass(String name, boolean resolve) throws ClassNotFoundException {
                if (hideDynamite && name.startsWith("com.google.android.gms.chimera.container.DynamiteLoader"))
                    throw new ClassNotFoundException(name + " (hidden by GmsSpoof for Google apps)");
                return super.loadClass(name, resolve);
            }
        };
        return sGmsLoader;
    }

    private static void installGmsCodeGuard(final LoadPackageParam lpparam) {
        try {
            Class<?> ctxImpl = XposedHelpers.findClass("android.app.ContextImpl", lpparam.classLoader);
            final boolean googleApp = lpparam.packageName.startsWith("com.google.");
            XC_MethodHook redirect = new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    if (!(param.args[0] instanceof String) || !(param.args[1] instanceof Integer)) return;
                    if (!GMS.equals(param.args[0])) return;
                    final int flags = (Integer) param.args[1];
                    final boolean code = (flags & Context.CONTEXT_INCLUDE_CODE) != 0;
                    final Context app = currentApp();
                    if (app == null) return;
                    final android.content.pm.ApplicationInfo gmsAi = gmsAppInfo(app);
                    final Context base;
                    if (code) {
                        Object[] a = param.args.clone();
                        a[0] = "com.gios.gmsspoof";
                        a[1] = flags | Context.CONTEXT_IGNORE_SECURITY;
                        base = (Context) XposedBridge.invokeOriginalMethod(param.method, param.thisObject, a);
                    } else {
                        base = (Context) XposedBridge.invokeOriginalMethod(param.method, param.thisObject, param.args);
                    }
                    final android.content.res.Resources res = code ? app.getPackageManager().getResourcesForApplication(GMS) : null;
                    final ClassLoader cl = code ? gmsClassLoader(app, googleApp) : null;
                    param.setResult(new android.content.ContextWrapper(base) {
                        private android.content.res.Resources.Theme theme;
                        @Override public android.content.pm.ApplicationInfo getApplicationInfo() { return gmsAi; }
                        @Override public String getPackageResourcePath() { return gmsAi.sourceDir; }
                        @Override public String getPackageCodePath() { return gmsAi.sourceDir; }
                        @Override public ClassLoader getClassLoader() { return cl != null ? cl : super.getClassLoader(); }
                        @Override public android.content.res.Resources getResources() { return res != null ? res : super.getResources(); }
                        @Override public android.content.res.AssetManager getAssets() { return res != null ? res.getAssets() : super.getAssets(); }
                        @Override public String getPackageName() { return GMS; }
                        @Override public synchronized android.content.res.Resources.Theme getTheme() {
                            if (res == null) return super.getTheme();
                            if (theme == null) { theme = res.newTheme(); theme.applyStyle(gmsAi.theme, true); }
                            return theme;
                        }
                    });
                    XposedBridge.log(TAG + ": served microG context (code=" + code + ", dynamite " + (googleApp ? "hidden" : "visible") + ")");
                }
            };
            XposedBridge.hookAllMethods(ctxImpl, "createPackageContext", redirect);
            XposedBridge.hookAllMethods(ctxImpl, "createPackageContextAsUser", redirect);
            XposedBridge.log(TAG + ": GMS code contexts served from microG origin apk");
        } catch (Throwable t) {
            XposedBridge.log(TAG + ": code guard not installed: " + t);
        }
        try {
            if (java.security.Security.getProvider("GmsCore_OpenSSL") == null) {
                java.security.Provider base = java.security.Security.getProvider("AndroidOpenSSL");
                java.security.Provider p = (java.security.Provider) XposedHelpers.newInstance(base.getClass(), "GmsCore_OpenSSL");
                java.security.Security.insertProviderAt(p, 1);
                XposedBridge.log(TAG + ": installed GmsCore_OpenSSL as " + base.getClass().getName());
            }
        } catch (Throwable t) {
            XposedBridge.log(TAG + ": ssl provider shim failed: " + t);
        }
    }


    private static boolean shouldSpoof(String packageName) {
        for (String p : SPOOFED_PACKAGES) if (p.equals(packageName)) return true;
        return false;
    }

    private static Class<?> findFirstLoadableClass(String... candidates) throws ClassNotFoundException {
        ClassNotFoundException last = new ClassNotFoundException();
        for (String candidate : candidates) {
            try { return Class.forName(candidate); }
            catch (ClassNotFoundException e) { last = e; }
        }
        throw last;
    }

    @SafeVarargs
    private static <T> T invokeFirstConstructor(
            Class<T> cls, SimpleEntry<Class<?>[], Object[]>... candidates) throws Exception {
        NoSuchMethodException last = new NoSuchMethodException();
        for (SimpleEntry<Class<?>[], Object[]> candidate : candidates) {
            Constructor<T> constructor;
            try { constructor = cls.getDeclaredConstructor(candidate.getKey()); }
            catch (NoSuchMethodException e) { last = e; continue; }
            constructor.setAccessible(true);
            return constructor.newInstance(candidate.getValue());
        }
        throw last;
    }

    @TargetApi(Build.VERSION_CODES.P)
    private static SigningInfo createSigningInfo(Signature sig, PublicKey publicKey) {
        final int SIGNING_BLOCK_V3 = 3;
        final Signature[] sigs = new Signature[]{ sig };
        final ArraySet<PublicKey> keys = new ArraySet<>();
        keys.add(publicKey);
        try {
            Class<?> signingDetailsClass = findFirstLoadableClass(
                    "android.content.pm.SigningDetails",
                    "android.content.pm.PackageParser$SigningDetails");
            Object signingDetails = invokeFirstConstructor(
                    signingDetailsClass,
                    new SimpleEntry<>(
                            new Class<?>[]{ Signature[].class, int.class, ArraySet.class, Signature[].class },
                            new Object[]{ sigs, SIGNING_BLOCK_V3, keys, null }),
                    new SimpleEntry<>(
                            new Class<?>[]{ Signature[].class, int.class, ArraySet.class, Signature[].class, int[].class },
                            new Object[]{ sigs, SIGNING_BLOCK_V3, keys, null, null }));
            Constructor<SigningInfo> c = SigningInfo.class.getDeclaredConstructor(signingDetailsClass);
            c.setAccessible(true);
            return c.newInstance(signingDetails);
        } catch (Exception e) {
            XposedBridge.log(TAG + ": failed to build SigningInfo");
            XposedBridge.log(e);
            return null;
        }
    }
}
