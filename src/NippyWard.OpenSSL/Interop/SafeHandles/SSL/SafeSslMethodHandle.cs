// Copyright (c) 2009 Ben Henderson
// All rights reserved.

// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
// 1. Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
// 3. The name of the author may not be used to endorse or promote products
//    derived from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
// OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
// IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
// INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
// NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
// THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

using NippyWard.OpenSSL.Interop.Wrappers;
using System;
using System.Runtime.InteropServices;

namespace NippyWard.OpenSSL.Interop.SafeHandles.SSL
{
	/// <summary>
	/// Wraps the SSL_METHOD structure and methods
	/// </summary>
	internal abstract class SafeSslMethodHandle : SafeBaseHandle
    {
        /// <summary>
        /// Not implemented, these objects should never be disposed
        /// </summary>
        internal override OPENSSL_sk_freefunc FreeFunc => Native._FreeShimFunc;

        //always is read-only
        internal SafeSslMethodHandle(bool takeOwnership)
            : base(false) { }

        //always is read-only
        internal SafeSslMethodHandle(IntPtr ptr, bool takeOwnership)
            : base(ptr, false)
        { }

        /// <summary>
        /// Default client method
        /// </summary>
        public static SafeSslMethodHandle DefaultClientMethod => TLS_client_method;


        public static SafeSslMethodHandle DefaultServerMethod => TLS_server_method;

        /// <summary>
        /// TLSv1_method()
        /// </summary>
        public static SafeSslMethodHandle TLSv1_method = Native.SSLWrapper.TLSv1_method();

        /// <summary>
        /// TLSv1_server_method()
        /// </summary>
        public static SafeSslMethodHandle TLSv1_server_method = Native.SSLWrapper.TLSv1_server_method();

        /// <summary>
        /// TLSv1_client_method()
        /// </summary>
        public static SafeSslMethodHandle TLSv1_client_method = Native.SSLWrapper.TLSv1_client_method();

        /// <summary>
        /// TLSv11_method()
        /// </summary>
        public static SafeSslMethodHandle TLSv11_method = Native.SSLWrapper.TLSv1_1_method();

        /// <summary>
        /// TLSv11_server_method()
        /// </summary>
        public static SafeSslMethodHandle TLSv11_server_method = Native.SSLWrapper.TLSv1_1_server_method();

        /// <summary>
        /// TLSv11_client_method()
        /// </summary>
        public static SafeSslMethodHandle TLSv11_client_method = Native.SSLWrapper.TLSv1_1_client_method();

        /// <summary>
        /// TLSv12_method()
        /// </summary>
        public static SafeSslMethodHandle TLSv12_method = Native.SSLWrapper.TLSv1_2_method();

        /// <summary>
        /// TLSv12_server_method()
        /// </summary>
        public static SafeSslMethodHandle TLSv12_server_method = Native.SSLWrapper.TLSv1_2_server_method();

        /// <summary>
        /// TLSv12_client_method()
        /// </summary>
        public static SafeSslMethodHandle TLSv12_client_method = Native.SSLWrapper.TLSv1_2_client_method();

        /// <summary>
        /// DTLSv1_method()
        /// </summary>
        public static SafeSslMethodHandle DTLSv1_method = Native.SSLWrapper.DTLSv1_method();

        /// <summary>
        /// DTLSv1_server_method()
        /// </summary>
        public static SafeSslMethodHandle DTLSv1_server_method = Native.SSLWrapper.DTLSv1_server_method();

        /// <summary>
        /// DTLSv1_client_method()
        /// </summary>
        public static SafeSslMethodHandle DTLSv1_client_method = Native.SSLWrapper.DTLSv1_client_method();

        /// <summary>
        /// TLS_server_method()
        /// </summary>
        public static SafeSslMethodHandle TLS_server_method = Native.SSLWrapper.TLS_server_method();


        /// <summary>
        /// TLS_client_method()
        /// </summary>
        public static SafeSslMethodHandle TLS_client_method = Native.SSLWrapper.TLS_client_method();
    }
}
