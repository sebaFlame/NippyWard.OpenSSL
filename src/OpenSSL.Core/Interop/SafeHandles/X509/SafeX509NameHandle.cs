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

namespace OpenSSL.Core.Interop.SafeHandles.X509
{
	/// <summary>
	/// Encapsulates the X509_NAME_* functions
	/// </summary>
	internal abstract class SafeX509NameHandle : BaseValue, IComparable<SafeX509NameHandle>, IStackable, IEquatable<SafeX509NameHandle>
	{
        internal SafeX509NameHandle(bool takeOwnership, bool isNew)
            : base(takeOwnership, isNew)
        { }

        internal SafeX509NameHandle(IntPtr ptr, bool takeOwnership, bool isNew)
            : base(ptr, takeOwnership, isNew)
        { }

        #region Overrides

        /// <summary>
        /// Calls X509_NAME_free()
        /// </summary>
        protected override bool ReleaseHandle()
		{
			CryptoWrapper.X509_NAME_free(this.handle);
            return true;
		}

		internal override IntPtr Duplicate()
		{
			return CryptoWrapper.X509_NAME_dup(this);
		}

		#endregion

		#region IComparable<X509Name> Members

		/// <summary>
		/// Returns X509_NAME_cmp()
		/// </summary>
		/// <param name="other"></param>
		/// <returns></returns>
		public int CompareTo(SafeX509NameHandle other)
		{
			return CryptoWrapper.X509_NAME_cmp(this, other);
		}

        public bool Equals(SafeX509NameHandle other)
        {
            return CryptoWrapper.X509_NAME_cmp(this, other) == 0;
        }

        #endregion
    }
}
