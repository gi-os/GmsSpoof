# Changelog

## 1.1.0

- ESPN Fantasy (`com.espn.fantasy.lm.football`) added to `TARGET_APPS`. The
  signature spoof alone is enough; the app needs none of the Maps-specific
  work. Without it, Disney's shell reports `ConnectionResult=9` and shows an
  error screen instead of the app.
- README: how to tell an ART baseline-profile crash loop from a module fault,
  and why the LSPatch jar has to match the installed manager.

## 1.0.0

- First release. Signature spoofing, microG code contexts, the TLS provider
  shim and the Google Sans font fix, for Google Maps, microG and Fog of World.
