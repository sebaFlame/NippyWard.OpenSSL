// Copyright (c) 2009 Frank Laub
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
using NippyWard.OpenSSL.Interop.Wrappers;

namespace NippyWard.OpenSSL.Interop.SafeHandles
{
	/// <summary>
	/// Wraps ASN1_STRING_*
	/// </summary>
	internal abstract class SafeAsn1StringHandle : BaseValue, IComparable<SafeAsn1StringHandle>
	{
        public static SafeAsn1StringHandle Zero
            => Native.SafeHandleFactory.CreateWrapperSafeHandle<SafeAsn1StringHandle>(IntPtr.Zero);

        /// <summary>
        /// Calls ASN1_STRING_free()
        /// </summary>
        internal override OPENSSL_sk_freefunc FreeFunc => _FreeFunc;

        private static readonly OPENSSL_sk_freefunc _FreeFunc;

        static SafeAsn1StringHandle()
        {
            _FreeFunc = new OPENSSL_sk_freefunc(CryptoWrapper.ASN1_STRING_free);
        }

        #region debug references
#if DEBUG
        //internal struct asn1_string_st
        //{
        //    public int length;
        //    public int type;
        //    public IntPtr data;
        //    public long flags;
        //};

        //internal int Length
        //{
        //    get
        //    {
        //        asn1_string_st raw = Marshal.PtrToStructure<asn1_string_st>(this.handle);
        //        return raw.length;
        //    }
        //}

        //internal int Type
        //{
        //    get
        //    {
        //        asn1_string_st raw = Marshal.PtrToStructure<asn1_string_st>(this.handle);
        //        return raw.type;
        //    }
        //}
#endif
        #endregion

        internal SafeAsn1StringHandle(bool takeOwnership)
            : base(takeOwnership)
        { }

        internal SafeAsn1StringHandle(IntPtr ptr, bool takeOwnership)
            : base(ptr, takeOwnership)
        { }

		#region IComparable<Asn1String> Members

		public int CompareTo(SafeAsn1StringHandle? other)
		{
			return CryptoWrapper.ASN1_STRING_cmp(this, other ?? SafeAsn1StringHandle.Zero);
		}

		#endregion
	}
}
