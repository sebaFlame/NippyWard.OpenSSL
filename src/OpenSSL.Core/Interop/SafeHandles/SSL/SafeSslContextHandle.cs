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

using System;

namespace OpenSSL.Core.Interop.SafeHandles.SSL
{
	/// <summary>
	///     Wraps the SST_CTX structure and methods
	/// </summary>
	internal abstract class SafeSslContextHandle : BaseReference
    {
        /// <summary>
        ///     Calls SSL_CTX_new()
        /// </summary>
        /// <param name="sslMethod"></param>
        /// <param name="end"></param>
        /// <param name="protoList"></param>
        internal SafeSslContextHandle(bool takeOwnership)
            : base(takeOwnership)
        { }

        internal SafeSslContextHandle(IntPtr ptr, bool takeOwnership)
            : base(ptr, takeOwnership)
        { }

        #region IDisposable Members

        /// <summary>
        ///     base override - calls SSL_CTX_free()
        /// </summary>
        protected override bool ReleaseHandle()
		{
			SSLWrapper.SSL_CTX_free(this.handle);
            return true;
		}

        internal override void AddReference()
        {
            SSLWrapper.SSL_CTX_up_ref(this);
        }

        #endregion
    }
}
