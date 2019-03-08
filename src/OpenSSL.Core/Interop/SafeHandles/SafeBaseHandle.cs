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
using OpenSSL.Core.Interop.Wrappers;
using System.Runtime.InteropServices;

namespace OpenSSL.Core.Interop.SafeHandles
{
    internal abstract class SafeBaseHandle : SafeZeroHandle
    {
        internal ILibCryptoWrapper CryptoWrapper { get; private set; }
        internal ILibSSLWrapper SSLWrapper { get; private set; }

        protected bool IsNew { get; private set; }

        /// <summary>
        /// Handles to be constructed by P/Invoke
        /// DO NOT construct manually
        /// </summary>
        protected SafeBaseHandle(bool takeOwnership, bool isNew)
            : base(takeOwnership)
        {
            this.IsNew = isNew;

            this.CryptoWrapper = Native.CryptoWrapper;
            this.SSLWrapper = Native.SSLWrapper;
        }

        protected SafeBaseHandle(IntPtr ptr, bool takeOwnership)
            : this(takeOwnership, false)
        {
            this.SetHandle(ptr);
        }

        protected SafeBaseHandle(IntPtr ptr, bool takeOwnership, bool isNew)
            : this(takeOwnership, isNew)
        {
            this.SetHandle(ptr);
        }

        /// <summary>
        /// Method to be executed by dynamic code generation
        /// After class construction
        /// </summary>
        internal abstract void PostConstruction();
    }

	internal abstract class BaseReference : SafeBaseHandle
	{
        protected BaseReference(bool takeOwnership, bool isNew)
            : base(takeOwnership, isNew)
        { }

        protected BaseReference(IntPtr ptr, bool takeOwnership)
            : base(ptr, takeOwnership)
        { }

        protected BaseReference(IntPtr ptr, bool takeOwnership, bool isNew)
            : base(ptr, takeOwnership, isNew)
        { }

        internal override void PostConstruction()
        {
            if (this.TakeOwnership && !this.IsNew)
                this.AddRef();
        }

        /// <summary>
        /// Derived classes must use a _up_ref() method to add a reference
        /// </summary>
        /// <returns></returns>
        internal abstract void AddRef();
	}

    /// <summary>
    /// Helper base class that handles the AddRef() method by using a _dup() method.
    /// </summary>
    internal abstract class BaseValue : SafeBaseHandle
	{
        protected BaseValue(bool takeOwnership, bool isNew)
            : base(takeOwnership, isNew)
        { }

        protected BaseValue(IntPtr ptr, bool takeOwnership)
            : base(ptr, takeOwnership)
        { }

        protected BaseValue(IntPtr ptr, bool takeOwnership, bool isNew)
            : base(ptr, takeOwnership, isNew)
        { }

        internal override void PostConstruction()
        {
            if (this.TakeOwnership && !this.IsNew)
                this.SetHandle(this.Duplicate());
        }

        /// <summary>
        /// Derived classes must use a _dup() method to make a copy of the underlying native data structure.
        /// </summary>
        /// <returns></returns>
        internal abstract IntPtr Duplicate();
	}

    internal abstract class SafeZeroHandle : SafeHandle
    {
        public override bool IsInvalid => this.handle == IntPtr.Zero;

        protected bool TakeOwnership { get; private set; }

        protected SafeZeroHandle(bool takeOwnership)
            : base(IntPtr.Zero, takeOwnership)
        {
            this.TakeOwnership = takeOwnership;
        }
    }
}
