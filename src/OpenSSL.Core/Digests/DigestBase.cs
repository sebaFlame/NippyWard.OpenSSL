using System;
using System.Collections.Generic;
using System.Text;
using System.Runtime.InteropServices;

using OpenSSL.Core.ASN1;
using OpenSSL.Core.Interop;
using OpenSSL.Core.Interop.SafeHandles.Crypto;
using OpenSSL.Core.Collections;

namespace OpenSSL.Core.Digests
{
    public abstract class DigestBase
        : OpenSslWrapperBase,
            ISafeHandleWrapper<SafeMessageDigestHandle>
    {
        SafeMessageDigestHandle ISafeHandleWrapper<SafeMessageDigestHandle>.Handle
            => this._Handle;
        public override SafeHandle Handle
            => this._Handle;

        internal SafeMessageDigestContextHandle DigestCtxHandle { get; private set; }

        private static HashSet<string>? _SupportedDigests;
        public static HashSet<string> SupportedDigests
        {
            get
            {
                if (!(_SupportedDigests is null))
                    return _SupportedDigests;

                NameCollector collector = new NameCollector(Native.OBJ_NAME_TYPE_MD_METH, true);
                return _SupportedDigests = collector.Result;
            }
        }

        internal SafeMessageDigestHandle _Handle;

        protected DigestBase(DigestType digestType)
            : base()
        {
            this._Handle = CryptoWrapper.EVP_get_digestbyname(digestType.ShortNamePtr);
            this.DigestCtxHandle = CryptoWrapper.EVP_MD_CTX_new();
        }

        protected override void Dispose(bool disposing)
        {
            if (this.DigestCtxHandle.IsClosed
                || this.DigestCtxHandle.IsInvalid)
            {
                return;
            }

            this.DigestCtxHandle.Dispose();
        }
    }
}
