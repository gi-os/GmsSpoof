package com.google.android.gms.common.security;

import android.content.Context;
import android.util.Log;
import java.security.Provider;
import java.security.Security;

/** Loaded by Google apps' ProviderInstaller client via a code context that GmsSpoof redirects
 *  here. Must not reference Xposed classes: this classloader can't see them. */
public final class ProviderInstallerImpl {
    private static final String TAG = "GmsSpoof.PI";
    private static final String NAME = "GmsCore_OpenSSL";

    public static void insertProvider(Context context) {
        try {
            Provider p = Security.getProvider(NAME);
            if (p == null) {
                Provider base = Security.getProvider("AndroidOpenSSL");
                p = (Provider) base.getClass().getConstructor(String.class).newInstance(NAME);
            } else {
                Security.removeProvider(NAME);   // re-insert so we sit ABOVE the app's Ssl_Guard
            }
            int pos = Security.insertProviderAt(p, 1);
            Log.i(TAG, "inserted " + NAME + " at " + pos + "; providers now: " + java.util.Arrays.toString(Security.getProviders()));
        } catch (Throwable t) {
            Log.w(TAG, "could not insert provider, reporting success anyway: " + t);
        }
    }

    public static void reportRequestStats(Context context, long a, long b) { }
}
