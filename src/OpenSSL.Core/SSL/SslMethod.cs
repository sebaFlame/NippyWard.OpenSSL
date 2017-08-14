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

using OpenSSL.Core.Core;
using System;

namespace OpenSSL.Core.SSL
{
	/// <summary>
	/// Wraps the SSL_METHOD structure and methods
	/// </summary>
	public class SslMethod : Base
	{
		private SslMethod(IntPtr ptr, bool owner) :
			base(ptr, owner)
		{
		}

		/// <summary>
		/// Throws NotImplementedException()
		/// </summary>
		protected override void OnDispose()
		{
			throw new NotImplementedException();
		}

	    /// <summary>
	    /// SSLv3_method()
	    /// </summary>
	    private static SslMethod _SSLv3_method;
        public static SslMethod SSLv3_method => _SSLv3_method ?? (_SSLv3_method = new SslMethod(Native.SSLv3_method(), false));

	    /// <summary>
	    /// SSLv3_server_method()
	    /// </summary>
	    private static SslMethod _SSLv3_server_method;
        public static SslMethod SSLv3_server_method => _SSLv3_server_method ?? (_SSLv3_server_method = new SslMethod(Native.SSLv3_server_method(), false));

	    /// <summary>
	    /// SSLv3_client_method()
	    /// </summary>
	    private static SslMethod _SSLv3_client_method;
        public static SslMethod SSLv3_client_method => _SSLv3_client_method ?? (_SSLv3_client_method = new SslMethod(Native.SSLv3_client_method(), false));

	    /// <summary>
	    /// SSLv23_method()
	    /// </summary>
	    private static SslMethod _SSLv23_method;
        public static SslMethod SSLv23_method => _SSLv23_method ?? (_SSLv23_method = new SslMethod(Native.SSLv23_method(), false));

        /// <summary>
        /// SSLv23_server_method()
        /// </summary>
        private static SslMethod _SSLv23_server_method;
        public static SslMethod SSLv23_server_method => _SSLv23_server_method ?? (_SSLv23_server_method = new SslMethod(Native.SSLv23_server_method(), false));

        /// <summary>
        /// SSLv23_client_method()
        /// </summary>
        private static SslMethod _SSLv23_client_method;
        public static SslMethod SSLv23_client_method => _SSLv23_client_method ?? (_SSLv23_client_method = new SslMethod(Native.SSLv23_client_method(), false));

	    /// <summary>
	    /// TLS_client_method()
	    /// </summary>
	    private static SslMethod _TLS_client_method;
        public static SslMethod TLS_client_method => _TLS_client_method ?? (_TLS_client_method = new SslMethod(Native.TLS_client_method(), false));

        /// <summary>
        /// TLSv1_method()
        /// </summary>
        private static SslMethod _TLSv1_method;
        public static SslMethod TLSv1_method => _TLSv1_method ?? (_TLSv1_method = new SslMethod(Native.TLSv1_method(), false));

        /// <summary>
        /// TLSv1_server_method()
        /// </summary>
        private static SslMethod _TLSv1_server_method;
        public static SslMethod TLSv1_server_method => _TLSv1_server_method ?? (_TLSv1_server_method = new SslMethod(Native.TLSv1_server_method(), false));

        /// <summary>
        /// TLSv1_client_method()
        /// </summary>
        private static SslMethod _TLSv1_client_method;
        public static SslMethod TLSv1_client_method => _TLSv1_client_method ?? (_TLSv1_client_method = new SslMethod(Native.TLSv1_client_method(), false));

        /// <summary>
        /// TLSv11_method()
        /// </summary>
        private static SslMethod _TLSv11_method;
        public static SslMethod TLSv11_method => _TLSv11_method ?? (_TLSv11_method = new SslMethod(Native.TLSv1_1_method(), false));

        /// <summary>
        /// TLSv11_server_method()
        /// </summary>
        private static SslMethod _TLSv11_server_method;
        public static SslMethod TLSv11_server_method => _TLSv11_server_method ?? (_TLSv11_server_method = new SslMethod(Native.TLSv1_1_server_method(), false));

        /// <summary>
        /// TLSv11_client_method()
        /// </summary>
        private static SslMethod _TLSv11_client_method;
        public static SslMethod TLSv11_client_method => _TLSv11_client_method ?? (_TLSv11_client_method = new SslMethod(Native.TLSv1_1_client_method(), false));

        /// <summary>
        /// TLSv12_method()
        /// </summary>
        private static SslMethod _TLSv12_method;
        public static SslMethod TLSv12_method => _TLSv12_method ?? (_TLSv12_method = new SslMethod(Native.TLSv1_2_method(), false));

        /// <summary>
        /// TLSv12_server_method()
        /// </summary>
        private static SslMethod _TLSv12_server_method;
        public static SslMethod TLSv12_server_method => _TLSv12_server_method ?? (_TLSv12_server_method = new SslMethod(Native.TLSv1_2_server_method(), false));

        /// <summary>
        /// TLSv12_client_method()
        /// </summary>
        private static SslMethod _TLSv12_client_method;
        public static SslMethod TLSv12_client_method => _TLSv12_client_method ?? (_TLSv12_client_method = new SslMethod(Native.TLSv1_2_client_method(), false));

        /// <summary>
        /// DTLSv1_method()
        /// </summary>
        private static SslMethod _DTLSv1_method;
        public static SslMethod DTLSv1_method => _DTLSv1_method ?? (_DTLSv1_method = new SslMethod(Native.DTLSv1_method(), false));

        /// <summary>
        /// DTLSv1_server_method()
        /// </summary>
        private static SslMethod _DTLSv1_server_method;
        public static SslMethod DTLSv1_server_method => _DTLSv1_server_method ?? (_DTLSv1_server_method = new SslMethod(Native.DTLSv1_server_method(), false));

        /// <summary>
        /// DTLSv1_client_method()
        /// </summary>
        private static SslMethod _DTLSv1_client_method;
        public static SslMethod DTLSv1_client_method => _DTLSv1_client_method ?? (_DTLSv1_client_method = new SslMethod(Native.DTLSv1_client_method(), false));

	}
}
