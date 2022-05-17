using System;
using System.Collections.Generic;
using System.Text;
using OpenSSL.Core.Interop;

namespace OpenSSL.Core.Error
{
    /// <summary>
    /// This is a struct that contains a uint for the native openssl error code.
    /// It provides helper methods to convert this error code into strings.
    /// </summary>
    public class OpenSslError : BaseOpenSslError
    {
        private string message;

        /// <summary>
        /// Constructs an OpenSslError object.
        /// </summary>
        /// <param name="err">The native error code</param>
        public OpenSslError(ulong err)
            : base(err) { }


        /// <summary>
        /// Returns the result of ERR_lib_error_string()
        /// </summary>
        public string Library
        {
            get { return Native.PtrToStringAnsi(Native.CryptoWrapper.ERR_lib_error_string(this.ErrorCode), false); }
        }

        /// <summary>
        /// Returns the results of ERR_reason_error_string()
        /// </summary>
        public string Reason
        {
            get { return Native.PtrToStringAnsi(Native.CryptoWrapper.ERR_reason_error_string(this.ErrorCode), false); }
        }

        /// <summary>
        /// Returns the results of ERR_func_error_string()
        /// </summary>
        public string Function
        {
            get { return Native.PtrToStringAnsi(Native.CryptoWrapper.ERR_func_error_string(this.ErrorCode), false); }
        }

        /// <summary>
        /// Returns the results of ERR_error_string_n()
        /// </summary>
        public override string Message
        {
            get
            {
                if (!string.IsNullOrEmpty(this.message))
                {
                    return this.message;
                }

                unsafe
                {
                    byte* buf = stackalloc byte[1024];
                    Span<byte> span = new Span<byte>(buf, 1024);
                    Native.CryptoWrapper.ERR_error_string_n((nuint)this.ErrorCode, ref span.GetPinnableReference(), (nuint)span.Length);

                    int length = 0;
                    byte b;
                    //determine string length
                    do
                        b = span[length++];
                    while (b != 0);
                    length--;

                    this.message = Encoding.ASCII.GetString(buf, length);
                }

                if(string.IsNullOrWhiteSpace(this.message))
                {
                    return (this.message = this.ErrorCode.ToString());
                }

                return this.message;
            }
        }

        public static List<string> GetErrors()
        {
            var errors = new List<string>();
            Native.CryptoWrapper.ERR_print_errors_cb((IntPtr str, nuint len, IntPtr u) =>
            {
                errors.Add(Native.PtrToStringAnsi(str, false));
                return 1;
            }, IntPtr.Zero);
            return errors;
        }
    }
}
