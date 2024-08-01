using System;
using System.Collections.Generic;
using System.Text;

using NippyWard.OpenSSL.ASN1;
using NippyWard.OpenSSL.Interop.SafeHandles.Crypto;
using NippyWard.OpenSSL.Interop.SafeHandles.Crypto.EC;

namespace NippyWard.OpenSSL.Keys
{
    public class ECKey : PrivateKey
    {
        internal SafeECKeyHandle ECHandle
            => CryptoWrapper.EVP_PKEY_get0_EC_KEY(this._Handle);

        public override KeyType KeyType => KeyType.EC;

        private static List<string>? _SupportedCurveTypes;
        public static List<string> SupportedCurveTypes
        {
            get
            {
                if (_SupportedCurveTypes != null)
                    return _SupportedCurveTypes;

                BuiltinCurves curves = new BuiltinCurves();
                return (_SupportedCurveTypes = curves.Result);
            }
        }

        internal ECKey(SafeKeyHandle keyHandle)
            : base(keyHandle)
        { }

        public ECKey(ECCurveType curveType)
            : this(GenerateECKey(curveType.NID))
        {
            //when loading from file for usage in SSL
            //https://wiki.openssl.org/index.php/Elliptic_Curve_Cryptography

            SafeKeyHandle.CryptoWrapper.EC_KEY_set_asn1_flag(this.ECHandle, 0x001);
        }

        private static SafeKeyHandle GenerateECKey(int curveName)
        {
            using (SafeECKeyHandle handle = CryptoWrapper.EC_KEY_new_by_curve_name(curveName))
            {
                CryptoWrapper.EC_KEY_generate_key(handle);

                SafeKeyHandle keyHandle = CryptoWrapper.EVP_PKEY_new();
                CryptoWrapper.EVP_PKEY_set1_EC_KEY(keyHandle, handle);
                return keyHandle;
            }
        }

        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);
        }
    }
}
