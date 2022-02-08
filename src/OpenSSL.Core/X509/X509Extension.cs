using System;
using System.Collections.Generic;
using System.Text;

using OpenSSL.Core.ASN1;
using OpenSSL.Core.Interop;
using OpenSSL.Core.Interop.SafeHandles;
using OpenSSL.Core.Interop.SafeHandles.X509;
using OpenSSL.Core.Error;

namespace OpenSSL.Core.X509
{
    [Wrapper(typeof(X509ExtensionInternal))]
    public class X509Extension : OpenSslWrapperBase
    {
        internal class X509ExtensionInternal : SafeHandleWrapper<SafeX509ExtensionHandle>
        {
            internal X509ExtensionInternal(SafeX509ExtensionHandle safeHandle)
                : base(safeHandle) { }
        }

        internal X509ExtensionInternal X509ExtensionWrapper { get; private set; }
        internal override ISafeHandleWrapper HandleWrapper => this.X509ExtensionWrapper;

        private X509ExtensionType extensionType;

        public string Name => this.extensionType.LongName;
        public bool Critical => CryptoWrapper.X509_EXTENSION_get_critical(this.X509ExtensionWrapper.Handle) == 1;

        private string data;
        public string Data
        {
            get
            {
                if (!string.IsNullOrEmpty(this.data))
                    return this.data;

                using (SafeBioHandle bio = CryptoWrapper.BIO_new(CryptoWrapper.BIO_s_mem()))
                {
                    CryptoWrapper.X509V3_EXT_print(bio, this.X509ExtensionWrapper.Handle, 0, 0);
                    int bLength = (int)CryptoWrapper.BIO_ctrl_pending(bio);
                    int ret;

                    unsafe
                    {
                        byte* bBuf = stackalloc byte[bLength];
                        Span<byte> bSpan = new Span<byte>(bBuf, bLength);
                        if ((ret = CryptoWrapper.BIO_read(bio, ref bSpan.GetPinnableReference(), bLength)) != bLength)
                            throw new OpenSslException();

                        int cLength = Encoding.ASCII.GetDecoder().GetCharCount(bBuf, bSpan.Length, false);
                        char* cBuf = stackalloc char[cLength];
                        Encoding.ASCII.GetDecoder().GetChars(bBuf, bSpan.Length, cBuf, cLength, true);

                        return (this.data = new string(cBuf, 0, cLength));
                    }
                }
            }
        }

        internal X509Extension(X509ExtensionInternal handleWrapper)
            : base()
        {
            this.X509ExtensionWrapper = handleWrapper;
        }

        internal X509Extension(SafeX509ExtensionHandle extensionHandle)
            : base()
        {
            this.X509ExtensionWrapper = new X509ExtensionInternal(extensionHandle);
            this.extensionType = new X509ExtensionType(CryptoWrapper.X509_EXTENSION_get_object(this.X509ExtensionWrapper.Handle));
        }

        protected override void Dispose(bool disposing)
        {
            if (!(this.extensionType is null))
                this.extensionType.Dispose();
        }
    }
}
