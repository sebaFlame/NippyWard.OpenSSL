// Copyright (c) 2012 Frank Laub
// All rights reserved.
//
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

namespace OpenSSL.Core.Interop.SafeHandles
{
	/// <summary>
	/// Asn1 object.
	/// </summary>
	internal abstract class SafeAsn1ObjectHandle : BaseValue, IEquatable<SafeAsn1ObjectHandle>
	{
        [StructLayout(LayoutKind.Sequential)]
        private struct asn1_object_st
        {
            public IntPtr sn;
            public IntPtr ln;
            public int nid;
            public int length;
            public IntPtr data;
            public int flags;
        }

        internal IntPtr ShortName => Marshal.PtrToStructure<asn1_object_st>(this.handle).sn;

        internal SafeAsn1ObjectHandle(bool takeOwnership)
            : base(takeOwnership)
        { }

        internal SafeAsn1ObjectHandle(IntPtr ptr, bool takeOwnership)
            : base(ptr, takeOwnership)
        { }

        public bool Equals(SafeAsn1ObjectHandle other)
        {
            return CryptoWrapper.OBJ_cmp(this, other) == 0;
        }

        protected override bool ReleaseHandle()
        {
            CryptoWrapper.ASN1_OBJECT_free(this.handle);
            return true;
        }
    }
}

