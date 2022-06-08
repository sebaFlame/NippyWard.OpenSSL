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
using System.Globalization;
using System.Text;
using System.Runtime.InteropServices;
using OpenSSL.Core.Interop.Wrappers;

namespace OpenSSL.Core.Interop.SafeHandles
{
	internal abstract class SafeAsn1DateTimeHandle : SafeAsn1StringHandle
    {
        public new static SafeAsn1DateTimeHandle Zero
            => Native.SafeHandleFactory.CreateWrapperSafeHandle<SafeAsn1DateTimeHandle>(IntPtr.Zero);

        internal override OPENSSL_sk_freefunc FreeFunc => _FreeFunc;

        private static readonly OPENSSL_sk_freefunc _FreeFunc;

        static SafeAsn1DateTimeHandle()
        {
            _FreeFunc = new OPENSSL_sk_freefunc(CryptoWrapper.ASN1_TIME_free);
        }

        internal SafeAsn1DateTimeHandle(bool takeOwnership)
            : base(takeOwnership)
        { }

        internal SafeAsn1DateTimeHandle(IntPtr ptr, bool takeOwnership)
            : base(ptr, takeOwnership)
        { }

        public DateTime DateTime => ToDateTime();

        public static long DateTimeToTimeT(DateTime value)
		{
            DateTimeOffset offset = new DateTimeOffset(value.ToUniversalTime());
            return offset.ToUnixTimeSeconds();
		}

        private DateTime ToDateTime()
        {
            return AsnTimeToDateTime().ToLocalTime();
        }

        private DateTime AsnTimeToDateTime()
        {
            string str;
            SafeBioHandle bio;

            using (bio = CryptoWrapper.BIO_new(CryptoWrapper.BIO_s_mem()))
            {
                CryptoWrapper.ASN1_TIME_print(bio, this);

                ulong bioLength = CryptoWrapper.BIO_ctrl_pending(bio);
                int bioLengthInt = (int)bioLength;
                unsafe
                {
                    byte* b = stackalloc byte[bioLengthInt];
                    Span<byte> dateBuf = new Span<byte>(b, bioLengthInt);
                    CryptoWrapper.BIO_read(bio, ref dateBuf.GetPinnableReference(), bioLengthInt);

                    int charCount = Encoding.ASCII.GetDecoder().GetCharCount(b, bioLengthInt, false);
                    char* c = stackalloc char[charCount];
                    Encoding.ASCII.GetDecoder().GetChars(b, bioLengthInt, c, charCount, true);

                    str = new string(c, 0, charCount);
                }
            }

            string[] fmts =
            {
                "MMM  d HH:mm:ss yyyy G\\MT",
                "MMM dd HH:mm:ss yyyy G\\MT"
            };

            return DateTime.ParseExact(str, fmts, new DateTimeFormatInfo(), DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal);
        }
    }
}
