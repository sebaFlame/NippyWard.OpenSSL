// Copyright (c) 2006-2012 Frank Laub
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
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Diagnostics;

using OpenSSL.Core.Error;
using OpenSSL.Core.Interop.Wrappers;

using OpenSSL.Core.Interop.Attributes;
using OpenSSL.Core.Interop.SafeHandles;
using OpenSSL.Core.Interop.SafeHandles.X509;
using OpenSSL.Core.Interop.SafeHandles.Crypto;
using OpenSSL.Core.Interop.SafeHandles.Crypto.EC;

[assembly: InternalsVisibleTo("OpenSSL.Core.Tests")]
[assembly: InternalsVisibleTo("OpenSSL.Core.Interop.Dynamic")]

namespace OpenSSL.Core.Interop
{
    /// <summary>
    /// This is the low-level C-style interface to the crypto API.
    /// Use this interface with caution.
    /// </summary>
    internal class Native
    {
        /// <summary>
        /// This is the name of the DLL that P/Invoke loads and tries to bind all of
        /// these native functions to.
        /// </summary>
        internal static string DLLNAME { get; private set; }
        internal static string SSLDLLNAME { get; private set; }

        private const string _BaseCryptoName = "libcrypto";
        private const string _BaseSslName = "libssl";

        internal readonly static ILibCryptoWrapper CryptoWrapper;
        internal readonly static ILibSSLWrapper SSLWrapper;
        internal readonly static IStackWrapper StackWrapper;
        internal readonly static ISafeHandleFactory SafeHandleFactory;

        #region Initialization

        static Native()
        {
            //while(!Debugger.IsAttached) Thread.Sleep(500);

            //get correct dll name
            switch (RuntimeInformation.RuntimeIdentifier)
            {
                case "win7-x64":
                case "win8-x64":
                case "win81-x64":
                case "win10-x64":
                    DLLNAME = "libcrypto-1_1-x64";
                    SSLDLLNAME = "libssl-1_1-x64";
                    break;
                case "win7-x86":
                case "win8-x86":
                case "win81-x86":
                case "win10-x86":
                    DLLNAME = "libcrypto-1_1";
                    SSLDLLNAME = "libssl-1_1";
                    break;
                case "ubuntu.16.04-x64":
                case "debian.8-x64":
                case "debian.9-x64":
                default:
                    DLLNAME = "libcrypto.so.1.1";
                    SSLDLLNAME = "libssl.so.1.1";
                    break;
            }

            //initialize dll resolver
            NativeLibrary.SetDllImportResolver(Assembly.GetExecutingAssembly(), DllImportResolver);

            //assign interfaces implementations
            CryptoWrapper = new LibCryptoWrapper();
            SSLWrapper = new LibSSLWrapper();
            StackWrapper = new StackWrapper();
            SafeHandleFactory = new SafeHandleFactory();

            //check for >= 1.1 or change config (SSLEnum, deprecated functions and whatnot)
            if (Version.Library < Version.MinimumOpenSslVersion)
            {
                throw new Exception(string.Format("Invalid version of {0}, expecting {1}, got: {2}", DLLNAME, Version.MinimumOpenSslVersion, Version.Library));
            }

#if ENABLE_MEMORYTRACKER
            MemoryTracker.Init();
#endif

            SSLWrapper.OPENSSL_init_ssl(
                OPENSSL_INIT_LOAD_SSL_STRINGS |
                OPENSSL_INIT_LOAD_CRYPTO_STRINGS |
                OPENSSL_INIT_NO_ADD_ALL_MACS |
                OPENSSL_INIT_ENGINE_ALL_BUILTIN, IntPtr.Zero);

            CryptoWrapper.ENGINE_load_builtin_engines();
            CryptoWrapper.ENGINE_register_all_complete();

            //seed the RNG
            byte[] seed = new byte[128];
            RandomNumberGenerator rng;
            using (rng = RandomNumberGenerator.Create())
            {
                do
                {
                    rng.GetBytes(seed);
                    Span<byte> seedSpan = new Span<byte>(seed);
                    CryptoWrapper.RAND_seed(seedSpan.GetPinnableReference(), seedSpan.Length);
                } while (CryptoWrapper.RAND_status() != 1);
            }

            //initialize SSL_CTX static context
            SSLWrapper.SSL_get_ex_data_X509_STORE_CTX_idx();
        }

        //Resolved dll's get retried when IntPtr.Zero and get cached further up the chain
        private static IntPtr DllImportResolver(string libraryName, Assembly assembly, DllImportSearchPath? searchPath)
        {
            switch (libraryName)
            {
                case _BaseCryptoName:
                    return NativeLibrary.Load(DLLNAME, assembly, searchPath);
                case _BaseSslName:
                    return NativeLibrary.Load(SSLDLLNAME, assembly, searchPath);
                default:
                    return IntPtr.Zero;
            }
        }

        #endregion

        #region Constants

        public const int SSL2_MAX_RECORD_LENGTH_3_BYTE_HEADER = 16383;

        public const int OBJ_NAME_TYPE_UNDEF = 0x00;
        public const int OBJ_NAME_TYPE_MD_METH = 0x01;
        public const int OBJ_NAME_TYPE_CIPHER_METH = 0x02;
        public const int OBJ_NAME_TYPE_PKEY_METH = 0x03;
        public const int OBJ_NAME_TYPE_COMP_METH = 0x04;
        public const int OBJ_NAME_TYPE_NUM = 0x05;

        public const int ASN1_STRFLGS_RFC2253 =
            ASN1_STRFLGS_ESC_2253 |
            ASN1_STRFLGS_ESC_CTRL |
            ASN1_STRFLGS_ESC_MSB |
            ASN1_STRFLGS_UTF8_CONVERT |
            ASN1_STRFLGS_DUMP_UNKNOWN |
            ASN1_STRFLGS_DUMP_DER;

        public const int ASN1_STRFLGS_ESC_2253 = 1;
        public const int ASN1_STRFLGS_ESC_CTRL = 2;
        public const int ASN1_STRFLGS_ESC_MSB = 4;
        public const int ASN1_STRFLGS_ESC_QUOTE = 8;
        public const int ASN1_STRFLGS_UTF8_CONVERT = 0x10;
        public const int ASN1_STRFLGS_DUMP_UNKNOWN = 0x100;
        public const int ASN1_STRFLGS_DUMP_DER = 0x200;
        public const int XN_FLAG_SEP_COMMA_PLUS = (1 << 16);
        public const int XN_FLAG_FN_SN = 0;

        public const int EVP_MAX_MD_SIZE = 64;
        //!!(16+20);
        public const int EVP_MAX_KEY_LENGTH = 32;
        public const int EVP_MAX_IV_LENGTH = 16;
        public const int EVP_MAX_BLOCK_LENGTH = 32;

        public const int EVP_CIPH_STREAM_CIPHER = 0x0;
        public const int EVP_CIPH_ECB_MODE = 0x1;
        public const int EVP_CIPH_CBC_MODE = 0x2;
        public const int EVP_CIPH_CFB_MODE = 0x3;
        public const int EVP_CIPH_OFB_MODE = 0x4;
        public const int EVP_CIPH_MODE = 0x7;
        public const int EVP_CIPH_VARIABLE_LENGTH = 0x8;
        public const int EVP_CIPH_CUSTOM_IV = 0x10;
        public const int EVP_CIPH_ALWAYS_CALL_INIT = 0x20;
        public const int EVP_CIPH_CTRL_INIT = 0x40;
        public const int EVP_CIPH_CUSTOM_KEY_LENGTH = 0x80;
        public const int EVP_CIPH_NO_PADDING = 0x100;
        public const int EVP_CIPH_FLAG_FIPS = 0x400;
        public const int EVP_CIPH_FLAG_NON_FIPS_ALLOW = 0x800;

        public const int BIO_C_SET_FD = 104;
        public const int BIO_C_SET_MD = 111;
        public const int BIO_C_GET_MD = 112;
        public const int BIO_C_GET_MD_CTX = 120;
        public const int BIO_C_FILE_TELL = 133;
        public const int BIO_C_SET_MD_CTX = 148;

        public const int BIO_NOCLOSE = 0x00;
        public const int BIO_CLOSE = 0x01;
        public static byte[] ReadOnly = new byte[1] { (int)'r' };
        public static byte[] WriteOnly = new byte[1] { (int)'w' };

        public const ulong OPENSSL_INIT_NO_LOAD_CRYPTO_STRINGS = 0x00000001L;
        public const ulong OPENSSL_INIT_LOAD_CRYPTO_STRINGS = 0x00000002L;
        public const ulong OPENSSL_INIT_ADD_ALL_CIPHERS = 0x00000004L;
        public const ulong OPENSSL_INIT_ADD_ALL_DIGESTS = 0x00000008L;
        public const ulong OPENSSL_INIT_NO_ADD_ALL_CIPHERS = 0x00000010L;
        public const ulong OPENSSL_INIT_NO_ADD_ALL_DIGESTS = 0x00000020L;
        public const ulong OPENSSL_INIT_LOAD_CONFIG = 0x00000040L;
        public const ulong OPENSSL_INIT_NO_LOAD_CONFIG = 0x00000080L;
        public const ulong OPENSSL_INIT_ASYNC = 0x00000100L;
        public const ulong OPENSSL_INIT_ENGINE_RDRAND = 0x00000200L;
        public const ulong OPENSSL_INIT_ENGINE_DYNAMIC = 0x00000400L;
        public const ulong OPENSSL_INIT_ENGINE_OPENSSL = 0x00000800L;
        public const ulong OPENSSL_INIT_ENGINE_CRYPTODEV = 0x00001000L;
        public const ulong OPENSSL_INIT_ENGINE_CAPI = 0x00002000L;
        public const ulong OPENSSL_INIT_ENGINE_PADLOCK = 0x00004000L;
        public const ulong OPENSSL_INIT_ENGINE_AFALG = 0x00008000L;
        public const ulong OPENSSL_INIT_ATFORK = 0x00020000L;
        public const ulong OPENSSL_INIT_NO_ATEXIT = 0x00080000L;
        public const ulong OPENSSL_INIT_NO_ADD_ALL_MACS = 0x04000000L;
        public const ulong OPENSSL_INIT_ADD_ALL_MACS = 0x08000000L;
        public const ulong OPENSSL_INIT_ENGINE_ALL_BUILTIN = (OPENSSL_INIT_ENGINE_RDRAND | OPENSSL_INIT_ENGINE_DYNAMIC
                | OPENSSL_INIT_ENGINE_CRYPTODEV | OPENSSL_INIT_ENGINE_CAPI | OPENSSL_INIT_ENGINE_PADLOCK);

        public const ulong OPENSSL_INIT_NO_LOAD_SSL_STRINGS = 0x00100000L;
        public const ulong OPENSSL_INIT_LOAD_SSL_STRINGS = 0x00200000L;

        public const int SSL_CTRL_MODE = 33;
        public const int SSL_CTRL_SET_READ_AHEAD = 41;
        public const int SSL_CTRL_SET_SESS_CACHE_MODE = 44;

        public const int SSL_SESS_CACHE_OFF = 0x0000;
        public const int SSL_SESS_CACHE_CLIENT = 0x0001;
        public const int SSL_SESS_CACHE_SERVER = 0x0002;
        public const int SSL_SESS_CACHE_BOTH = (SSL_SESS_CACHE_CLIENT | SSL_SESS_CACHE_SERVER);
        public const int SSL_SESS_CACHE_NO_AUTO_CLEAR = 0x0080;
        public const int SSL_SESS_CACHE_NO_INTERNAL_LOOKUP = 0x0100;
        public const int SSL_SESS_CACHE_NO_INTERNAL_STORE = 0x0200;
        public const int SSL_SESS_CACHE_NO_INTERNAL = (SSL_SESS_CACHE_NO_INTERNAL_LOOKUP | SSL_SESS_CACHE_NO_INTERNAL_STORE);

        public const int B_ASN1_NUMERICSTRING = 0x0001;
        public const int B_ASN1_PRINTABLESTRING = 0x0002;
        public const int B_ASN1_T61STRING = 0x0004;
        public const int B_ASN1_TELETEXSTRING = 0x0004;
        public const int B_ASN1_VIDEOTEXSTRING = 0x0008;
        public const int B_ASN1_IA5STRING = 0x0010;
        public const int B_ASN1_GRAPHICSTRING = 0x0020;
        public const int B_ASN1_ISO64STRING = 0x0040;
        public const int B_ASN1_VISIBLESTRING = 0x0040;
        public const int B_ASN1_GENERALSTRING = 0x0080;
        public const int B_ASN1_UNIVERSALSTRING = 0x0100;
        public const int B_ASN1_OCTET_STRING = 0x0200;
        public const int B_ASN1_BIT_STRING = 0x0400;
        public const int B_ASN1_BMPSTRING = 0x0800;
        public const int B_ASN1_UNKNOWN = 0x1000;
        public const int B_ASN1_UTF8STRING = 0x2000;
        public const int B_ASN1_UTCTIME = 0x4000;
        public const int B_ASN1_GENERALIZEDTIME = 0x8000;
        public const int B_ASN1_SEQUENCE = 0x10000;

        public const int MBSTRING_FLAG = 0x1000;
        public const int MBSTRING_UTF8 = (MBSTRING_FLAG);
        public const int MBSTRING_ASC = (MBSTRING_FLAG | 1);
        public const int MBSTRING_BMP = (MBSTRING_FLAG | 2);
        public const int MBSTRING_UNIV = (MBSTRING_FLAG | 4);
        public const int SMIME_OLDMIME = 0x400;
        public const int SMIME_CRLFEOL = 0x800;
        public const int SMIME_STREAM = 0x1000;

        public const int V_ASN1_OCTET_STRING = 4;
        #endregion

        #region Utilities

        internal static string PtrToStringAnsi(IntPtr ptr, bool hasOwnership)
        {
            int length = 0;
            byte b;

            //determine string length
            do
                b = Marshal.ReadByte(ptr, length++);
            while (b != 0);
            length--;

            return PtrToStringAnsi(ptr, length, hasOwnership);
        }

        internal static string PtrToStringAnsi(IntPtr ptr, int length, bool hasOwnership)
        {
            char[] strChars;
            unsafe
            {
                byte* buf = (byte*)ptr.ToPointer();
                int charLength = Encoding.ASCII.GetDecoder().GetCharCount(buf, length, false);

                strChars = new char[charLength];
                fixed (char* c = strChars)
                {
                    Encoding.ASCII.GetDecoder().GetChars(buf, length, c, charLength, true);
                }
            }

            if (hasOwnership)
                Free(ptr);

            return new string(strChars);
        }

        internal unsafe static void Free(IntPtr ptr)
        {
            ReadOnlySpan<char> span = Assembly.GetEntryAssembly().FullName.AsSpan();

            fixed (char* c = span)
            {
                int bufLength = Encoding.ASCII.GetEncoder().GetByteCount(c, span.Length, false);
                byte* b = stackalloc byte[bufLength + 1];
                Encoding.ASCII.GetEncoder().GetBytes(c, span.Length, b, bufLength, true);
                Span<byte> buf = new Span<byte>(b, bufLength + 1);
                CryptoWrapper.CRYPTO_free(ptr, buf.GetPinnableReference(), 0);
            }
        }

        //check if the safehandle is invalid and throws an exception if that's the case
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void ExpectNonNull(SafeHandle handle)
        {
            if (handle.IsInvalid)
            {
                throw new OpenSslException();
            }
        }

        //check if the return value is invalid and throws an exception if that's the case
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void ExpectSuccess(int ret)
        {
            if (ret <= 0)
            {
                throw new OpenSslException();
            }
        }

        internal static TStackable CreateStackableItem<TStackable>(SafeStackHandle<TStackable> stack, IntPtr ptr)
            where TStackable : SafeBaseHandle, IStackable
        {
            //if the stack is owned, all items should also be owned!
            if (stack.TakeOwnership)
            {
                return SafeHandleFactory.CreateTakeOwnershipSafeHandle<TStackable>(ptr);
            }
            else
            {
                return SafeHandleFactory.CreateWrapperSafeHandle<TStackable>(ptr);
            }
        }
        #endregion

    }
}
