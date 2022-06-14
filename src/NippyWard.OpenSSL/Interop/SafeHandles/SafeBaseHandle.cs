// Copyright (c) 2006-2009 Frank Laub
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
using NippyWard.OpenSSL.Interop.Wrappers;
using System.Runtime.InteropServices;

namespace NippyWard.OpenSSL.Interop.SafeHandles
{
    internal abstract class SafeBaseHandle : SafeZeroHandle
    {
        internal readonly static ILibCryptoWrapper CryptoWrapper;
        internal readonly static ILibSSLWrapper SSLWrapper;
        internal readonly static IStackWrapper StackWrapper;
        internal readonly static ISafeHandleFactory SafeHandleFactory;

        internal abstract OPENSSL_sk_freefunc FreeFunc { get; }

        static SafeBaseHandle()
        {
            CryptoWrapper = Native.CryptoWrapper;
            SSLWrapper = Native.SSLWrapper;
            StackWrapper = Native.StackWrapper;
            SafeHandleFactory = Native.SafeHandleFactory;
        }

        /// <summary>
        /// Handles to be constructed by P/Invoke
        /// DO NOT construct manually
        /// </summary>
        protected SafeBaseHandle(bool takeOwnership)
            : base(takeOwnership)
        { }

        protected SafeBaseHandle(IntPtr ptr, bool takeOwnership)
            : this(takeOwnership)
        {
            this.SetHandle(ptr);
        }

        protected override bool ReleaseHandle()
        {
            try
            {
                this.FreeFunc(this.handle);
                return true;
            }
            //catch exception so native does not crash
            //TODO: log exception
            catch(Exception)
            {
                return false;
            }
        }
    }

	internal abstract class BaseReference : SafeBaseHandle
	{
        protected BaseReference(bool takeOwnership)
            : base(takeOwnership)
        { }

        protected BaseReference(IntPtr ptr, bool takeOwnership)
            : base(ptr, takeOwnership)
        { }

        /// <summary>
        /// Derived classes must use a _up_ref() method to add a reference
        /// </summary>
        /// <returns></returns>
        internal abstract void AddReference();
	}

    /// <summary>
    /// Helper base class that handles the AddRef() method by using a _dup() method.
    /// </summary>
    internal abstract class BaseValue : SafeBaseHandle
	{
        protected BaseValue(bool takeOwnership)
            : base(takeOwnership)
        { }

        protected BaseValue(IntPtr ptr, bool takeOwnership)
            : base(ptr, takeOwnership)
        { }
	}

    internal abstract class SafeZeroHandle : SafeHandle
    {
        public override bool IsInvalid => this.handle == IntPtr.Zero;

        internal bool TakeOwnership { get; private set; }

        protected SafeZeroHandle(bool takeOwnership)
            : base(IntPtr.Zero, takeOwnership)
        {
            this.TakeOwnership = takeOwnership;
        }
    }
}
