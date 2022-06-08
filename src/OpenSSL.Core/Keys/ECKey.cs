using System;
using System.Collections.Generic;
using System.Text;

using OpenSSL.Core.ASN1;
using OpenSSL.Core.Interop.SafeHandles.Crypto;
using OpenSSL.Core.Interop.SafeHandles.Crypto.EC;

namespace OpenSSL.Core.Keys
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
        { }

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
