// Copyright (c) 2006-2010 Frank Laub
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
using System.Runtime.InteropServices;
using OpenSSL.Core.Interop.SafeHandles.Crypto;
using OpenSSL.Core.Interop.Wrappers;

namespace OpenSSL.Core.Interop.SafeHandles.X509
{
	/// <summary>
	/// Wraps the X509 object
	/// </summary>
	internal abstract class SafeX509CertificateHandle : BaseReference, IComparable<SafeX509CertificateHandle>, IStackable, IEquatable<SafeX509CertificateHandle>
	{
        public static SafeX509CertificateHandle Zero
            => Native.SafeHandleFactory.CreateWrapperSafeHandle<SafeX509CertificateHandle>(IntPtr.Zero);

        //this also frees the private key if it is set
        /// <summary>
        /// Calls X509_free()
        /// </summary>
        internal override OPENSSL_sk_freefunc FreeFunc => _FreeFunc;

        private static OPENSSL_sk_freefunc _FreeFunc;

        static SafeX509CertificateHandle()
        {
            _FreeFunc = new OPENSSL_sk_freefunc(CryptoWrapper.X509_free);
        }

        internal SafeX509CertificateHandle(bool takeOwnership)
            : base(takeOwnership)
        { }

        internal SafeX509CertificateHandle(IntPtr ptr, bool takeOwnership)
            : base(ptr, takeOwnership)
        { }

        #region Overrides

        internal override void AddReference()
        {
            CryptoWrapper.X509_up_ref(this);
        }


		#endregion

		#region IComparable Members

		public int CompareTo(SafeX509CertificateHandle other)
		{
			return CryptoWrapper.X509_cmp(this, other);
		}

        public bool Equals(SafeX509CertificateHandle other)
        {
            return CryptoWrapper.X509_cmp(this, other) == 0;
        }

        #endregion
    }
}
