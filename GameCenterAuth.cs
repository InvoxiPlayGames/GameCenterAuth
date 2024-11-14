/*
 * GameCenterAuth.cs - https://github.com/InvoxiPlayGames/GameCenterAuth
 * SPDX-License-Identifier: MIT
 */
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace GameCenterAuth
{
    /// <summary>
    /// Provides authentication for Apple's Game Center.
    /// </summary>
    public class GCAuth
    {
        private string _bundleId;
        public int _expiryTime;

        private Dictionary<string, X509Certificate2> _certs;

        public HttpClient _http;

        /// <summary>
        /// Creates a <c>GCAuth</c> class to verify tokens for the specified bundle ID.
        /// </summary>
        /// <param name="bundleId">The application bundle ID to verify tokens for.</param>
        /// <param name="expiryTime">The length of time to allow a token to be valid for before considered expired. (default 120000 / 2 minutes)</param>
        /// <param name="sandbox">Whether to enforce sandbox URLs for fetching the public keys.</param>
        /// <returns>An initialised <c>GCAuth</c> instance.</returns>
        public GCAuth(string bundleId, int expiryTime = 120000, bool sandbox = false)
        {
            _bundleId = bundleId;
            _expiryTime = expiryTime;

            // create a http client that doesn't allow redirects
            HttpClientHandler h = new HttpClientHandler()
            {
                AllowAutoRedirect = false
            };
            _http = new HttpClient(h);
            if (sandbox) // i'm not an apple developer lol this sandbox address doesn't resolve properly?
                _http.BaseAddress = new Uri("https://sandbox.gc.apple.com/public-key/");
            else
                _http.BaseAddress = new Uri("https://static.gc.apple.com/public-key/");

            // create a dictionary to cache our certs
            _certs = new Dictionary<string, X509Certificate2>();
        }

        private async Task<byte[]?> DownloadPublicKey(string publicKeyName)
        {
            HttpResponseMessage? res = await _http.GetAsync(publicKeyName);
            if (res == null)
            {
                return null;
            }
            res.EnsureSuccessStatusCode();
            byte[] resBytes = await res.Content.ReadAsByteArrayAsync();
            return resBytes;
        }

        private bool VerifyAndCachePublicKey(string publicKeyName, byte[] publicKeyData, out X509Certificate2 outCert)
        {
            X509Certificate2 cert = new X509Certificate2(publicKeyData);
            outCert = cert;
            // verify it against the OS root trust store
            if (!cert.Verify())
                return false;
            if (!cert.Subject.Contains("CN=Apple Inc.,"))
                return false;
            // add it to the cache if it's valid
            lock (_certs)
                _certs[publicKeyName] = cert;
            return true;
        }

        private async Task<X509Certificate2?> GetPublicKey(string publicKeyName)
        {
            X509Certificate2? r = null;
            // fetch the certificate from the cache
            lock (_certs)
            {
                if (_certs.ContainsKey(publicKeyName))
                    r = _certs[publicKeyName];
            }
            if (r != null)
                return r;
            // download and verify the certificate
            byte[]? keyBytes = await DownloadPublicKey(publicKeyName);
            if (keyBytes == null)
                return null; // download failed
            if (!VerifyAndCachePublicKey(publicKeyName, keyBytes, out r))
                return null;
            return r;
        }

        /// <summary>
        /// Verifies a Game Center signature to be valid for the given player ID.
        /// </summary>
        /// <param name="playerId">The player ID provided by the application.</param>
        /// <param name="publicKeyUrl">The public key URL returned by <c>fetchItemsForIdentityVerificationSignature:</c>.</param>
        /// <param name="timestamp">The timestamp the token was issued, returned by <c>fetchItemsForIdentityVerificationSignature:</c>.</param>
        /// <param name="salt">The salt returned by <c>fetchItemsForIdentityVerificationSignature:</c>.</param>
        /// <param name="signature">The signature returned by <c>fetchItemsForIdentityVerificationSignature:</c>.</param>
        /// <returns>True if the signature is valid, False otherwise.</returns>
        public async Task<bool> VerifySignature(string playerId, string publicKeyUrl, long timestamp, byte[] salt, byte[] signature)
        {
            // verify the expiry to not have passed
            long currentTime = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            if (timestamp + _expiryTime < currentTime)
                return false;

            // verify the length of the signature
            // 512 bytes as of 14-11-2024 (gc-auth-6 from 29-07-2021 switched to RSA-4096)
            if (signature.Length != 0x100 && signature.Length != 0x200 &&
                signature.Length != 0x400 && signature.Length != 0x800)
                return false;

            // cap the salt length (apple usually uses smaller ones)
            if (salt.Length > 0x80)
                return false;

            // cap the player ID length and make sure it starts with a known prefix
            if (playerId.Length > 64)
                return false;
            if (!playerId.StartsWith("A:") && // gamePlayerID
                !playerId.StartsWith("T:") && // teamPlayerID
                !playerId.StartsWith("G:")) // playerID (deprecated)
                return false;

            // verify the URL before downloading the key
            Uri uri = new Uri(publicKeyUrl.ToLower());
            if (uri.Host != _http.BaseAddress!.Host)
                return false;
            string publicKeyPath = uri.AbsolutePath;
            if (!publicKeyPath.StartsWith("/public-key/gc-") ||
                !publicKeyPath.EndsWith(".cer"))
                return false;
            string publicKeyName = Path.GetFileName(publicKeyPath);

            // download the key (or fetch it from cache)
            X509Certificate2? publicKey = null;
            try
            {
                publicKey = await GetPublicKey(publicKeyName);
            } catch (Exception)
            {
                return false;
            }
            if (publicKey == null)
                return false;

            // get the rsa public key instance. this should never fail!
            RSA? rsa = publicKey.GetRSAPublicKey();
            if (rsa == null)
                return false;

            // convert timestamp to big endian bytes
            byte[] timestampBytes = BitConverter.GetBytes(timestamp);
            Array.Reverse(timestampBytes);

            // hash the data
            byte[] bytesToSign =
            [
                .. Encoding.UTF8.GetBytes(playerId),
                .. Encoding.UTF8.GetBytes(_bundleId),
                .. timestampBytes,
                .. salt,
            ];
            byte[] hash = SHA256.Create().ComputeHash(bytesToSign);

            if (rsa.VerifyHash(hash, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1))
                return true;

            return false;
        }
    }
}
