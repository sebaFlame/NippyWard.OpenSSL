using System;
using System.Collections.Generic;
using System.Text;
using OpenSSL.Core.ASN1;
using OpenSSL.Core.Interop;
using OpenSSL.Core.Interop.SafeHandles.Crypto;

namespace OpenSSL.Core.Digests
{
    public abstract class DigestBase : Base
    {
        internal SafeMessageDigestHandle digestHandle { get; private set; }
        internal SafeMessageDigestContextHandle digestCtxHandle { get; private set; }

        private static HashSet<string> supportedDigests;
        public static HashSet<string> SupportedDigests
        {
            get
            {
                if (!(supportedDigests is null))
                    return supportedDigests;

                NameCollector collector = new NameCollector(Native.OBJ_NAME_TYPE_MD_METH, true);
                return supportedDigests = collector.Result;
            }
        }

        protected DigestBase(DigestType digestType)
            : base()
        {
            this.digestHandle = this.CryptoWrapper.EVP_get_digestbyname(digestType.ShortNamePtr);
            this.digestCtxHandle = this.CryptoWrapper.EVP_MD_CTX_new();
        }

        public override void Dispose()
        {
            if (!(this.digestCtxHandle is null) && !this.digestCtxHandle.IsInvalid)
                this.digestCtxHandle.Dispose();

            if (!(this.digestHandle is null) && !this.digestHandle.IsInvalid)
                this.digestHandle.Dispose();
        }
    }
}
