using System;
using System.Collections.Generic;
using System.Text;

using NippyWard.OpenSSL.Interop;
using NippyWard.OpenSSL.X509;

namespace NippyWard.OpenSSL.Error
{
    public class VerifyError : BaseOpenSslError
    {
        private string? _message;

        public VerifyError(VerifyResult verifyResult)
            : base((ulong)verifyResult) { }

        public override string Message
            => this._message
            ?? (_message = Native.PtrToStringAnsi(Native.CryptoWrapper.X509_verify_cert_error_string((int)this.ErrorCode), false));
    }
}
