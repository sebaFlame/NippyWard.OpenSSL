using System;
using System.Collections.Generic;
using System.Text;
using System.Runtime.InteropServices;

using NippyWard.OpenSSL.ASN1;
using NippyWard.OpenSSL.Interop;
using NippyWard.OpenSSL.Interop.SafeHandles;
using NippyWard.OpenSSL.Interop.SafeHandles.X509;
using NippyWard.OpenSSL.Error;
using NippyWard.OpenSSL.Collections;

namespace NippyWard.OpenSSL.X509
{
    public class X509Extension
        : OpenSslWrapperBase,
            ISafeHandleWrapper<SafeX509ExtensionHandle>
    {
        SafeX509ExtensionHandle ISafeHandleWrapper<SafeX509ExtensionHandle>.Handle
            => this._Handle;
        public override SafeHandle Handle
            => this._Handle;

        public bool Critical => CryptoWrapper.X509_EXTENSION_get_critical(this._Handle) == 1;

        private string? _data;
        public string Data
        {
            get
            {
                if (!string.IsNullOrEmpty(this._data))
                    return this._data;

                using (SafeBioHandle bio = CryptoWrapper.BIO_new(CryptoWrapper.BIO_s_mem()))
                {
                    CryptoWrapper.X509V3_EXT_print(bio, this._Handle, 0, 0);
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

                        return (this._data = new string(cBuf, 0, cLength));
                    }
                }
            }
        }

        internal readonly SafeX509ExtensionHandle _Handle;

        internal X509Extension(SafeX509ExtensionHandle extensionHandle)
            : base()
        {
            this._Handle = extensionHandle;
            //this._extensionType = new X509ExtensionType(CryptoWrapper.X509_EXTENSION_get_object(extensionHandle));
        }

        protected override void Dispose(bool disposing)
        {
            //NOP
        }
    }
}
