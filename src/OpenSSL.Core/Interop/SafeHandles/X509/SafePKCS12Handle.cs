// Copyright (c) 2009-2011 Frank Laub
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
using OpenSSL.Core.Interop.SafeHandles.Crypto;

namespace OpenSSL.Core.Interop.SafeHandles.X509
{
	/// <summary>
	/// Wraps PCKS12_*
	/// </summary>
	internal abstract class SafePKCS12Handle : BaseValue
	{
        internal SafePKCS12Handle(bool takeOwnership, bool isNew)
            : base(takeOwnership, isNew)
        { }

        internal SafePKCS12Handle(IntPtr ptr, bool takeOwnership)
            : base(ptr, takeOwnership)
        { }

		#region Overrides

		/// <summary>
		/// Calls PKCS12_free()
		/// </summary>
		protected override bool ReleaseHandle()
		{
			this.CryptoWrapper.PKCS12_free(this.handle);
            return true;
		}

        internal override IntPtr Duplicate()
        {
            throw new NotSupportedException();
        }

        #endregion

        /// <summary>
        /// Password-Based Encryption (from PKCS #5)
        /// </summary>
        private enum PBE
        {
            /// <summary>
            ///
            /// </summary>
            Default = 0,
            /// <summary>
            /// NID_pbeWithMD2AndDES_CBC
            /// </summary>
            MD2_DES = 9,
            /// <summary>
            /// NID_pbeWithMD5AndDES_CBC
            /// </summary>
            MD5_DES = 10,
            /// <summary>
            /// NID_pbeWithMD2AndRC2_CBC
            /// </summary>
            MD2_RC2_64 = 168,
            /// <summary>
            /// NID_pbeWithMD5AndRC2_CBC
            /// </summary>
            MD5_RC2_64 = 169,
            /// <summary>
            /// NID_pbeWithSHA1AndDES_CBC
            /// </summary>
            SHA1_DES = 170,
            /// <summary>
            /// NID_pbeWithSHA1AndRC2_CBC
            /// </summary>
            SHA1_RC2_64 = 68,
            /// <summary>
            /// NID_pbe_WithSHA1And128BitRC4
            /// </summary>
            SHA1_RC4_128 = 144,
            /// <summary>
            /// NID_pbe_WithSHA1And40BitRC4
            /// </summary>
            SHA1_RC4_40 = 145,
            /// <summary>
            /// NID_pbe_WithSHA1And3_Key_TripleDES_CBC
            /// </summary>
            SHA1_3DES = 146,
            /// <summary>
            /// NID_pbe_WithSHA1And2_Key_TripleDES_CBC
            /// </summary>
            SHA1_2DES = 147,
            /// <summary>
            /// NID_pbe_WithSHA1And128BitRC2_CBC
            /// </summary>
            SHA1_RC2_128 = 148,
            /// <summary>
            /// NID_pbe_WithSHA1And40BitRC2_CBC
            /// </summary>
            SHA1_RC2_40 = 149
        }

        /// <summary>
        /// This is a non standard extension that is only currently interpreted by MSIE
        /// </summary>
        private enum KeyType
        {
            /// <summary>
            /// omit the flag from the private key
            /// </summary>
            KEY_DEFAULT = 0,

            /// <summary>
            /// the key can be used for signing only
            /// </summary>
            KEY_SIG = 0x80,

            /// <summary>
            /// the key can be used for signing and encryption
            /// </summary>
            KEY_EX = 0x10,
        }
    }
}
