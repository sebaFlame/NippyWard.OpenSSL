using System;
using System.Collections.Generic;
using System.Text;
using OpenSSL.Core.ASN1;
using OpenSSL.Core.Interop;
using OpenSSL.Core.Interop.SafeHandles.Crypto;

namespace OpenSSL.Core.Digests
{
    [Wrapper(typeof(DigestInternal))]
    public abstract class DigestBase : OpenSslWrapperBase
    {
        internal class DigestInternal : SafeHandleWrapper<SafeMessageDigestHandle>
        {
            internal DigestInternal(SafeMessageDigestHandle safeHandle)
                : base(safeHandle) { }
        }

        internal DigestInternal DigestWrapper { get; private set; }
        internal override ISafeHandleWrapper HandleWrapper => this.DigestWrapper;

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

        internal DigestBase(DigestInternal handleWarpper)
            : base()
        {
            this.DigestWrapper = handleWarpper;
        }

        protected DigestBase(DigestType digestType)
            : base()
        {
            this.DigestWrapper = new DigestInternal(this.CryptoWrapper.EVP_get_digestbyname(digestType.ShortNamePtr));
            this.digestCtxHandle = this.CryptoWrapper.EVP_MD_CTX_new();
        }

        protected override void Dispose(bool disposing)
        {
            if (!(this.digestCtxHandle is null) && !this.digestCtxHandle.IsInvalid)
                this.digestCtxHandle.Dispose();
        }
    }
}
