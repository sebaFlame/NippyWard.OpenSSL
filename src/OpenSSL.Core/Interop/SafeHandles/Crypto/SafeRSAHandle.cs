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

using OpenSSL.Core.Interop;
using System;
using System.Runtime.InteropServices;
using OpenSSL.Core.Interop.Wrappers;

namespace OpenSSL.Core.Interop.SafeHandles.Crypto
{
	/// <summary>
	/// Wraps the RSA_* functions
	/// </summary>
	internal abstract class SafeRSAHandle : BaseReference
	{
        public static SafeRSAHandle Zero
            => Native.SafeHandleFactory.CreateWrapperSafeHandle<SafeRSAHandle>(IntPtr.Zero);

        internal override OPENSSL_sk_freefunc FreeFunc => _FreeFunc;

        private static OPENSSL_sk_freefunc _FreeFunc;

        static SafeRSAHandle()
        {
            _FreeFunc = new OPENSSL_sk_freefunc(CryptoWrapper.RSA_free);
        }

        #region reference count debug
#if DEBUG
        [StructLayout(LayoutKind.Sequential)]
        internal struct rsa_st
        {
            public int pad;
            public int version;
            public IntPtr meth;

            public IntPtr engine;
            public IntPtr n;
            public IntPtr e;
            public IntPtr d;
            public IntPtr p;
            public IntPtr q;
            public IntPtr dmp1;
            public IntPtr dmq1;
            public IntPtr iqmp;

            public IntPtr prime_infos;
            public IntPtr pss;

            public IntPtr ex_data_sk;
            public int references;
            public int flags;

            public IntPtr _method_mod_n;
            public IntPtr _method_mod_p;
            public IntPtr _method_mod_q;

            public IntPtr bignum_data;
            public IntPtr blinding;
            public IntPtr mt_blinding;
            public IntPtr _lock;
        }

        internal int References
        {
            get
            {
                rsa_st raw = Marshal.PtrToStructure<rsa_st>(this.handle);
                return raw.references;
            }
        }
#endif
        #endregion

        internal SafeRSAHandle(bool takeOwnership)
            : base(takeOwnership)
        { }

        internal SafeRSAHandle(IntPtr ptr, bool takeOwnership)
            : base(ptr, takeOwnership)
        { }

        internal override void AddReference()
        {
            CryptoWrapper.RSA_up_ref(this);
        }
	}
}
