// Copyright (c) 2006-2007 Frank Laub
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

using System;
using System.Collections.Generic;
using System.Text;
using System.Linq;

using OpenSSL.Core.Interop;

namespace OpenSSL.Core.Error
{
	/// <summary>
	/// Exception class to provide OpenSSL specific information when errors occur.
	/// </summary>
	public class OpenSslException : Exception
	{
		private readonly List<BaseOpenSslError> errors = new List<BaseOpenSslError>();

		private OpenSslException(List<BaseOpenSslError> context)
			: base(GetErrorMessage(context))
		{
			errors = context;
		}

        /// <summary>
        /// When this class is instantiated, GetErrorMessage() is called automatically.
        /// This will call ERR_get_error() on the native openssl interface, once for every
        /// error that is in the current context. The exception message is the concatenation
        /// of each of these errors turned into strings using ERR_error_string_n().
        /// </summary>
        public OpenSslException()
            : this(GetCurrentContext()) { }

        internal OpenSslException(params BaseOpenSslError[] errors)
            : this(errors.ToList()) { }

        internal OpenSslException(string message)
            : base(message) { }

        public static List<BaseOpenSslError> GetCurrentContext()
		{
			var ret = new List<BaseOpenSslError>();

			while (true)
			{
				ulong err = Native.CryptoWrapper.ERR_get_error();

				if (err == 0)
					break;

				ret.Add(new OpenSslError(err));
			}

			return ret;
		}

		private static string GetErrorMessage(List<BaseOpenSslError> context)
		{
			var sb = new StringBuilder();
			var isFirst = true;

			foreach (var err in context)
			{
				if (isFirst)
					isFirst = false;
				else
					sb.Append("\n");

				sb.Append(err.Message);
			}

			return sb.ToString();
		}

		/// <summary>
		/// Returns the list of errors associated with this exception.
		/// </summary>
		public List<BaseOpenSslError> Errors
		{
			get { return errors; }
		}
	}
}
