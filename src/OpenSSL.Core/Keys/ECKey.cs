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
        private SafeECKeyHandle ecHandle;

        public override KeyType KeyType => KeyType.EC;

        private static List<string> supportedCurveTypes;
        public static List<string> SupportedCurveTypes
        {
            get
            {
                if (supportedCurveTypes != null)
                    return supportedCurveTypes;

                BuiltinCurves curves = new BuiltinCurves();
                return (supportedCurveTypes = curves.Result);
            }
        }

        internal ECKey(KeyInternal handleWrapper)
            : base(handleWrapper) { }

        internal ECKey(SafeKeyHandle keyHandle)
            : base(keyHandle)
        {
            this.ecHandle = this.CryptoWrapper.EVP_PKEY_get0_EC_KEY(this.KeyWrapper.Handle);
        }

        //TODO: more options?
        public ECKey(string curveName)
            : base()
        {
            int nid = this.CryptoWrapper.OBJ_txt2nid(curveName);
            this.generateEC(nid);
        }

        public ECKey(ECCurveType curveType)
            : base()
        {
            this.generateEC(curveType.NID);
        }

        private void generateEC(int curveName)
        {
            this.ecHandle = this.CryptoWrapper.EC_KEY_new_by_curve_name(curveName);
            this.CryptoWrapper.EC_KEY_generate_key(this.ecHandle);
        }

        internal override KeyInternal GenerateKeyInternal()
        {
            if (this.ecHandle is null || this.ecHandle.IsInvalid)
                throw new InvalidOperationException("RSA key has not been created yet");

            this.CryptoWrapper.EC_KEY_check_key(this.ecHandle);

            SafeKeyHandle keyHandle = this.CryptoWrapper.EVP_PKEY_new();
            this.CryptoWrapper.EVP_PKEY_set1_EC_KEY(keyHandle, this.ecHandle);
            return new KeyInternal(keyHandle);
        }

        protected override void Dispose(bool disposing)
        {
            if (!(this.ecHandle is null) && !this.ecHandle.IsInvalid)
                this.ecHandle.Dispose();

            base.Dispose(disposing);
        }
    }
}
