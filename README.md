# GameCenterAuth

Basic C# .NET library for validating Apple Game Center identity signatures.

## Usage

On your iOS app, call [`-[GKLocalPlayer fetchItemsForIdentityVerificationSignature:]`](https://developer.apple.com/documentation/gamekit/gklocalplayer/3516283-fetchitemsforidentityverificatio?language=objc)
and send the values returned from this function to your server, along with the
GKLocalPlayer's `teamPlayerID` (or `gamePlayerID` when on Apple Arcade).

(*Note: `-[GKLocalPlayer generateIdentityVerificationSignatureWithCompletionHandler:]`
has been deprecated by Apple since iOS 13.5, however this library can still validate
tokens issued by it when provided `-[GKLocalPlayer playerID]`. **Do not use that API
in new projects.***)

On the server side:

```csharp
using GameCenterAuth;
GCAuth gcAuth = new GCAuth("your.app.bundle.id.here");

// ... and in your auth server stuff ...

bool isAuthenticated = await gcAuth.VerifySignature(authRequest.TeamPlayerID,
    authRequest.PublicKeyURL, authRequest.Timestamp, authRequest.Salt,
    authRequest.Signature);
```

Auth tokens are deemed to have expired if they are 2 minutes old by default. The
"timeout" overload on the GCAuth constructor, specified in *milliseconds* can be
used to lengthen this (default: 120000).

It's recommended to keep one GCAuth instance across the lifetime of your server,
as the public keys are cached per-instance. I think it's thread safe.

If you need to support multiple bundle IDs on the same backend, create several
GCAuth instances.

## Stability / Security

I created this with no warranty as a hobby project and don't hold it to high
stability standards. If you run into any  issues, please let me know in the
[GitHub issue tracker](https://github.com/InvoxiPlayGames/GameCenterAuth/issues).

This library *should* be secure and only allow authentication to pass for genuine
Apple certificates, and disallow any attempts at requesting a certificate from
servers other than the Game Center auth server.

If you have discovered a security vulnerability in this library that enables
either denial of service or authentication bypass, that you are *certain* is in
the library itself and isn't triggered by implementation defect, please let me
know via e-mail.

## License

MIT, see LICENSE.txt. If you do use this library, it'd be nice if you dropped by
anywhere and said thanks :)
