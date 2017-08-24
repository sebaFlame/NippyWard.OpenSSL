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
using System.Collections.Generic;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

namespace OpenSSL.Core.Core
{
    /// <summary>
    ///
    /// </summary>
    public static class FIPS
    {
        /// <summary>
        ///
        /// </summary>
        public static bool Enabled { get; set; }
    }

    public enum CryptoLockTypes
    {
        CRYPTO_LOCK_ERR = 1,
        CRYPTO_LOCK_EX_DATA = 2,
        CRYPTO_LOCK_X509 = 3,
        CRYPTO_LOCK_X509_INFO = 4,
        CRYPTO_LOCK_X509_PKEY = 5,
        CRYPTO_LOCK_X509_CRL = 6,
        CRYPTO_LOCK_X509_REQ = 7,
        CRYPTO_LOCK_DSA = 8,
        CRYPTO_LOCK_RSA = 9,
        CRYPTO_LOCK_EVP_PKEY = 10,
        CRYPTO_LOCK_X509_STORE = 11,
        CRYPTO_LOCK_SSL_CTX = 12,
        CRYPTO_LOCK_SSL_CERT = 13,
        CRYPTO_LOCK_SSL_SESSION = 14,
        CRYPTO_LOCK_SSL_SESS_CERT = 15,
        CRYPTO_LOCK_SSL = 16,
        CRYPTO_LOCK_SSL_METHOD = 17,
        CRYPTO_LOCK_RAND = 18,
        CRYPTO_LOCK_RAND2 = 19,
        CRYPTO_LOCK_MALLOC = 20,
        CRYPTO_LOCK_BIO = 21,
        CRYPTO_LOCK_GETHOSTBYNAME = 22,
        CRYPTO_LOCK_GETSERVBYNAME = 23,
        CRYPTO_LOCK_READDIR = 24,
        CRYPTO_LOCK_RSA_BLINDING = 25,
        CRYPTO_LOCK_DH = 26,
        CRYPTO_LOCK_MALLOC2 = 27,
        CRYPTO_LOCK_DSO = 28,
        CRYPTO_LOCK_DYNLOCK = 29,
        CRYPTO_LOCK_ENGINE = 30,
        CRYPTO_LOCK_UI = 31,
        CRYPTO_LOCK_ECDSA = 32,
        CRYPTO_LOCK_EC = 33,
        CRYPTO_LOCK_ECDH = 34,
        CRYPTO_LOCK_BN = 35,
        CRYPTO_LOCK_EC_PRE_COMP = 36,
        CRYPTO_LOCK_STORE = 37,
        CRYPTO_LOCK_COMP = 38,
        CRYPTO_LOCK_FIPS = 39,
        CRYPTO_LOCK_FIPS2 = 40,
        CRYPTO_NUM_LOCKS = 41,
    }

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

        private static ILibCryptoWrapper cryptoWrapper;
        internal static ILibCryptoWrapper CryptoWrapper
        {
            get
            {
                if (cryptoWrapper == null)
                    cryptoWrapper = (ILibCryptoWrapper)Activator.CreateInstance(DynamicTypeBuilder.CreateOpenSSLWrapper<ILibCryptoWrapper>(DLLNAME));
                return cryptoWrapper;
            }
        }

        private static ILibSSLWrapper sslWrapper;
        internal static ILibSSLWrapper SSLWrapper
        {
            get
            {
                if (sslWrapper == null)
                    sslWrapper = (ILibSSLWrapper)Activator.CreateInstance(DynamicTypeBuilder.CreateOpenSSLWrapper<ILibSSLWrapper>(SSLDLLNAME));
                return sslWrapper;
            }
        }

        #region Initialization

        static Native()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                DLLNAME = "libeay32";
                SSLDLLNAME = "ssleay32";
            }
            else
            {
                DLLNAME = "libcrypto.so.1.0.2";
                SSLDLLNAME = "libssl.so.1.0.2";
            }

            var lib = Version.Library;
            var wrapper = Version.Wrapper;
            //if (lib.Raw < wrapper.Raw)
            //    throw new Exception(string.Format("Invalid version of {0}, expecting {1}, got: {2}",
            //        DLLNAME, wrapper, lib));

#if MEMORY_TRACKER
			MemoryTracker.Init();
#endif

            // Enable FIPS mode
            if (FIPS.Enabled)
            {
                if (FIPS_mode_set(1) == 0)
                {
                    throw new Exception("Failed to initialize FIPS mode");
                }
            }

            ERR_load_crypto_strings();
            SSL_load_error_strings();

            OPENSSL_add_all_algorithms_noconf();

            // Initialize SSL library
            Native.ExpectSuccess(SSL_library_init());

            var seed = new byte[128];
            var rng = RandomNumberGenerator.Create();
            rng.GetBytes(seed);
            RAND_seed(seed, seed.Length);
        }

        #endregion

        #region Version

        // 1.0.2a Release
        public const uint Wrapper = 0x1000201F;

        public static IntPtr SSLeay_version(int type)
        {
            return CryptoWrapper.SSLeay_version(type);
        }

        public static uint SSLeay()
        {
            return CryptoWrapper.SSLeay();
        }

        public static IntPtr BN_options()
        {
            return CryptoWrapper.BN_options();
        }

        public static IntPtr MD2_options()
        {
            return CryptoWrapper.MD2_options();
        }

        public static IntPtr RC4_options()
        {
            return CryptoWrapper.RC4_options();
        }

        public static IntPtr DES_options()
        {
            return CryptoWrapper.DES_options();
        }

        public static IntPtr idea_options()
        {
            return CryptoWrapper.idea_options();
        }

        public static IntPtr BF_options()
        {
            return CryptoWrapper.BF_options();
        }

        #endregion

        #region Threading

        public static int CRYPTO_THREADID_set_callback(CRYPTO_id_callback cb)
        {
            return CryptoWrapper.CRYPTO_THREADID_set_callback(cb);
        }

        public static void CRYPTO_THREADID_set_numeric(IntPtr id, uint val)
        {
            CryptoWrapper.CRYPTO_THREADID_set_numeric(id, val);
        }

        public static void CRYPTO_set_locking_callback(CRYPTO_locking_callback cb)
        {
            CryptoWrapper.CRYPTO_set_locking_callback(cb);
        }

        public static int CRYPTO_num_locks()
        {
            return CryptoWrapper.CRYPTO_num_locks();
        }

        public static int CRYPTO_add_lock(IntPtr ptr, int amount, CryptoLockTypes type, string file, int line)
        {
            return CryptoWrapper.CRYPTO_add_lock(ptr, amount, type, file, line);
        }

        #endregion

        #region CRYPTO

        public static void OPENSSL_add_all_algorithms_noconf()
        {
            CryptoWrapper.OPENSSL_add_all_algorithms_noconf();
        }

        public static void OPENSSL_add_all_algorithms_conf()
        {
            CryptoWrapper.OPENSSL_add_all_algorithms_conf();
        }

        /// <summary>
        /// #define OPENSSL_malloc(num)	CRYPTO_malloc((int)num,__FILE__,__LINE__)
        /// </summary>
        /// <param name="cbSize"></param>
        /// <returns></returns>
        public static IntPtr OPENSSL_malloc(int cbSize)
        {
            return CRYPTO_malloc(cbSize, Assembly.GetEntryAssembly().FullName, 0);
        }

        /// <summary>
        /// #define OPENSSL_free(addr) CRYPTO_free(addr)
        /// </summary>
        /// <param name="p"></param>
        public static void OPENSSL_free(IntPtr p)
        {
            CRYPTO_free(p);
        }

        public static void CRYPTO_free(IntPtr p)
        {
            CryptoWrapper.CRYPTO_free(p);
        }

        public static IntPtr CRYPTO_malloc(int num, string file, int line)
        {
            return CryptoWrapper.CRYPTO_malloc(num, file, line);
        }

        public static int CRYPTO_set_mem_ex_functions(MallocFunctionPtr m, ReallocFunctionPtr r, FreeFunctionPtr f)
        {
            return CryptoWrapper.CRYPTO_set_mem_ex_functions(m, r, f);
        }

        public static void CRYPTO_cleanup_all_ex_data()
        {
            CryptoWrapper.CRYPTO_cleanup_all_ex_data();
        }

        #endregion

        #region OBJ

        public const int NID_undef = 0;

        public const int OBJ_undef = 0;

        public const int OBJ_NAME_TYPE_UNDEF = 0x00;
        public const int OBJ_NAME_TYPE_MD_METH = 0x01;
        public const int OBJ_NAME_TYPE_CIPHER_METH = 0x02;
        public const int OBJ_NAME_TYPE_PKEY_METH = 0x03;
        public const int OBJ_NAME_TYPE_COMP_METH = 0x04;
        public const int OBJ_NAME_TYPE_NUM = 0x05;

        public static void OBJ_NAME_do_all(int type, ObjectNameHandler fn, IntPtr arg)
        {
            CryptoWrapper.OBJ_NAME_do_all(type, fn, arg);
        }

        public static void OBJ_NAME_do_all_sorted(int type, ObjectNameHandler fn, IntPtr arg)
        {
            CryptoWrapper.OBJ_NAME_do_all_sorted(type, fn, arg);
        }

        public static int OBJ_txt2nid(string s)
        {
            return CryptoWrapper.OBJ_txt2nid(s);
        }

        public static IntPtr OBJ_nid2obj(int n)
        {
            return CryptoWrapper.OBJ_nid2obj(n);
        }

        public static IntPtr OBJ_nid2ln(int n)
        {
            return CryptoWrapper.OBJ_nid2ln(n);
        }

        public static IntPtr OBJ_nid2sn(int n)
        {
            return CryptoWrapper.OBJ_nid2sn(n);
        }

        public static int OBJ_obj2nid(IntPtr o)
        {
            return CryptoWrapper.OBJ_obj2nid(o);
        }

        public static IntPtr OBJ_txt2obj(string s, int no_name)
        {
            return CryptoWrapper.OBJ_txt2obj(s, no_name);
        }

        public static int OBJ_ln2nid(string s)
        {
            return CryptoWrapper.OBJ_ln2nid(s);
        }

        public static int OBJ_sn2nid(string s)
        {
            return CryptoWrapper.OBJ_sn2nid(s);
        }

        #endregion

        #region stack

        public static IntPtr sk_new_null()
        {
            return CryptoWrapper.sk_new_null();
        }

        public static int sk_num(IntPtr stack)
        {
            return CryptoWrapper.sk_num(stack);
        }

        public static int sk_find(IntPtr stack, IntPtr data)
        {
            return CryptoWrapper.sk_find(stack, data);
        }

        public static int sk_insert(IntPtr stack, IntPtr data, int where)
        {
            return CryptoWrapper.sk_insert(stack, data, where);
        }

        public static IntPtr sk_shift(IntPtr stack)
        {
            return CryptoWrapper.sk_shift(stack);
        }

        public static int sk_unshift(IntPtr stack, IntPtr data)
        {
            return CryptoWrapper.sk_unshift(stack, data);
        }

        public static int sk_push(IntPtr stack, IntPtr data)
        {
            return CryptoWrapper.sk_push(stack, data);
        }

        public static IntPtr sk_pop(IntPtr stack)
        {
            return CryptoWrapper.sk_pop(stack);
        }

        public static IntPtr sk_delete(IntPtr stack, int loc)
        {
            return CryptoWrapper.sk_delete(stack, loc);
        }

        public static IntPtr sk_delete_ptr(IntPtr stack, IntPtr p)
        {
            return CryptoWrapper.sk_delete_ptr(stack, p);
        }

        public static IntPtr sk_value(IntPtr stack, int index)
        {
            return CryptoWrapper.sk_value(stack, index);
        }

        public static IntPtr sk_set(IntPtr stack, int index, IntPtr data)
        {
            return CryptoWrapper.sk_set(stack, index, data);
        }

        public static IntPtr sk_dup(IntPtr stack)
        {
            return CryptoWrapper.sk_dup(stack);
        }

        public static void sk_zero(IntPtr stack)
        {
            CryptoWrapper.sk_zero(stack);
        }

        public static void sk_free(IntPtr stack)
        {
            CryptoWrapper.sk_free(stack);
        }

        #endregion

        #region SHA

        public const int SHA_DIGEST_LENGTH = 20;

        #endregion

        #region ASN1

        public static IntPtr ASN1_INTEGER_new()
        {
            return CryptoWrapper.ASN1_INTEGER_new();
        }

        public static void ASN1_INTEGER_free(IntPtr x)
        {
            CryptoWrapper.ASN1_INTEGER_free(x);
        }

        public static int ASN1_INTEGER_set(IntPtr a, int v)
        {
            return CryptoWrapper.ASN1_INTEGER_set(a, v);
        }

        public static int ASN1_INTEGER_get(IntPtr a)
        {
            return CryptoWrapper.ASN1_INTEGER_get(a);
        }

        public static IntPtr ASN1_TIME_set(IntPtr s, long t)
        {
            return CryptoWrapper.ASN1_TIME_set(s, t);
        }

        public static int ASN1_UTCTIME_print(IntPtr bp, IntPtr a)
        {
            return CryptoWrapper.ASN1_UTCTIME_print(bp, a);
        }

        public static IntPtr ASN1_TIME_new()
        {
            return CryptoWrapper.ASN1_TIME_new();
        }

        public static void ASN1_TIME_free(IntPtr x)
        {
            CryptoWrapper.ASN1_TIME_free(x);
        }

        public const int V_ASN1_OCTET_STRING = 4;

        public static IntPtr ASN1_STRING_type_new(int type)
        {
            return CryptoWrapper.ASN1_STRING_type_new(type);
        }

        public static IntPtr ASN1_STRING_dup(IntPtr a)
        {
            return CryptoWrapper.ASN1_STRING_dup(a);
        }

        public static void ASN1_STRING_free(IntPtr a)
        {
            CryptoWrapper.ASN1_STRING_free(a);
        }

        public static int ASN1_STRING_cmp(IntPtr a, IntPtr b)
        {
            return CryptoWrapper.ASN1_STRING_cmp(a, b);
        }

        public static int ASN1_STRING_set(IntPtr str, byte[] data, int len)
        {
            return CryptoWrapper.ASN1_STRING_set(str, data, len);
        }

        public static IntPtr ASN1_STRING_data(IntPtr x)
        {
            return CryptoWrapper.ASN1_STRING_data(x);
        }

        public static int ASN1_STRING_length(IntPtr x)
        {
            return CryptoWrapper.ASN1_STRING_length(x);
        }

        public static void ASN1_OBJECT_free(IntPtr obj)
        {
            CryptoWrapper.ASN1_OBJECT_free(obj);
        }

        #endregion

        #region X509_REQ

        public static IntPtr X509_REQ_new()
        {
            return CryptoWrapper.X509_REQ_new();
        }

        public static int X509_REQ_set_version(IntPtr x, int version)
        {
            return CryptoWrapper.X509_REQ_set_version(x, version);
        }

        public static int X509_REQ_set_pubkey(IntPtr x, IntPtr pkey)
        {
            return CryptoWrapper.X509_REQ_set_pubkey(x, pkey);
        }

        public static IntPtr X509_REQ_get_pubkey(IntPtr req)
        {
            return CryptoWrapper.X509_REQ_get_pubkey(req);
        }

        public static int X509_REQ_set_subject_name(IntPtr x, IntPtr name)
        {
            return CryptoWrapper.X509_REQ_set_subject_name(x, name);
        }

        public static int X509_REQ_sign(IntPtr x, IntPtr pkey, IntPtr md)
        {
            return CryptoWrapper.X509_REQ_sign(x, pkey, md);
        }

        public static int X509_REQ_verify(IntPtr x, IntPtr pkey)
        {
            return CryptoWrapper.X509_REQ_verify(x, pkey);
        }

        public static int X509_REQ_digest(IntPtr data, IntPtr type, byte[] md, ref uint len)
        {
            return CryptoWrapper.X509_REQ_digest(data, type, md, ref len);
        }

        public static void X509_REQ_free(IntPtr a)
        {
            CryptoWrapper.X509_REQ_free(a);
        }

        public static IntPtr X509_REQ_to_X509(IntPtr r, int days, IntPtr pkey)
        {
            return CryptoWrapper.X509_REQ_to_X509(r, days, pkey);
        }

        public static int X509_REQ_print_ex(IntPtr bp, IntPtr x, uint nmflag, uint cflag)
        {
            return CryptoWrapper.X509_REQ_print_ex(bp, x, nmflag, cflag);
        }

        public static int X509_REQ_print(IntPtr bp, IntPtr x)
        {
            return CryptoWrapper.X509_REQ_print(bp, x);
        }

        #endregion

        #region X509

        public static IntPtr X509_new()
        {
            return CryptoWrapper.X509_new();
        }

        public static IntPtr X509_dup(IntPtr x509)
        {
            return CryptoWrapper.X509_dup(x509);
        }

        public static int X509_cmp(IntPtr a, IntPtr b)
        {
            return CryptoWrapper.X509_cmp(a, b);
        }

        public static int X509_sign(IntPtr x, IntPtr pkey, IntPtr md)
        {
            return CryptoWrapper.X509_sign(x, pkey, md);
        }

        public static int X509_check_private_key(IntPtr x509, IntPtr pkey)
        {
            return CryptoWrapper.X509_check_private_key(x509, pkey);
        }

        public static int X509_verify(IntPtr x, IntPtr pkey)
        {
            return CryptoWrapper.X509_verify(x, pkey);
        }

        public static int X509_pubkey_digest(IntPtr data, IntPtr type, byte[] md, ref uint len)
        {
            return CryptoWrapper.X509_pubkey_digest(data, type, md, ref len);
        }

        public static int X509_digest(IntPtr data, IntPtr type, byte[] md, ref uint len)
        {
            return CryptoWrapper.X509_digest(data, type, md, ref len);
        }

        public static int X509_set_version(IntPtr x, int version)
        {
            return CryptoWrapper.X509_set_version(x, version);
        }

        public static int X509_set_serialNumber(IntPtr x, IntPtr serial)
        {
            return CryptoWrapper.X509_set_serialNumber(x, serial);
        }

        public static IntPtr X509_get_serialNumber(IntPtr x)
        {
            return CryptoWrapper.X509_get_serialNumber(x);
        }

        public static int X509_set_issuer_name(IntPtr x, IntPtr name)
        {
            return CryptoWrapper.X509_set_issuer_name(x, name);
        }

        public static IntPtr X509_get_issuer_name(IntPtr a)
        {
            return CryptoWrapper.X509_get_issuer_name(a);
        }

        public static int X509_set_subject_name(IntPtr x, IntPtr name)
        {
            return CryptoWrapper.X509_set_subject_name(x, name);
        }

        public static IntPtr X509_get_subject_name(IntPtr a)
        {
            return CryptoWrapper.X509_get_subject_name(a);
        }

        public static int X509_set_notBefore(IntPtr x, IntPtr tm)
        {
            return CryptoWrapper.X509_set_notBefore(x, tm);
        }

        public static int X509_set_notAfter(IntPtr x, IntPtr tm)
        {
            return CryptoWrapper.X509_set_notAfter(x, tm);
        }

        public static int X509_set_pubkey(IntPtr x, IntPtr pkey)
        {
            return CryptoWrapper.X509_set_pubkey(x, pkey);
        }

        public static IntPtr X509_get_pubkey(IntPtr x)
        {
            return CryptoWrapper.X509_get_pubkey(x);
        }

        public static void X509_free(IntPtr x)
        {
            CryptoWrapper.X509_free(x);
        }

        public static int X509_verify_cert(IntPtr ctx)
        {
            return CryptoWrapper.X509_verify_cert(ctx);
        }

        public static IntPtr X509_verify_cert_error_string(int n)
        {
            return CryptoWrapper.X509_verify_cert_error_string(n);
        }

        public static IntPtr X509_to_X509_REQ(IntPtr x, IntPtr pkey, IntPtr md)
        {
            return CryptoWrapper.X509_to_X509_REQ(x, pkey, md);
        }

        public static int X509_print_ex(IntPtr bp, IntPtr x, uint nmflag, uint cflag)
        {
            return CryptoWrapper.X509_print_ex(bp, x, nmflag, cflag);
        }

        public static int X509_print(IntPtr bp, IntPtr x)
        {
            return CryptoWrapper.X509_print(bp, x);
        }

        public static IntPtr X509_find_by_issuer_and_serial(IntPtr sk, IntPtr name, IntPtr serial)
        {
            return CryptoWrapper.X509_find_by_issuer_and_serial(sk, name, serial);
        }

        public static IntPtr X509_find_by_subject(IntPtr sk, IntPtr name)
        {
            return CryptoWrapper.X509_find_by_subject(sk, name);
        }

        public static int X509_check_trust(IntPtr x, int id, int flags)
        {
            return CryptoWrapper.X509_check_trust(x, id, flags);
        }

        public static IntPtr X509_time_adj(IntPtr s, int adj, ref long t)
        {
            return CryptoWrapper.X509_time_adj(s, adj, ref t);
        }

        public static IntPtr X509_gmtime_adj(IntPtr s, int adj)
        {
            return CryptoWrapper.X509_gmtime_adj(s, adj);
        }

        public static IntPtr d2i_X509_bio(IntPtr bp, ref IntPtr x509)
        {
            return CryptoWrapper.d2i_X509_bio(bp, ref x509);
        }

        public static int i2d_X509_bio(IntPtr bp, IntPtr x509)
        {
            return CryptoWrapper.i2d_X509_bio(bp, x509);
        }

        public static void X509_PUBKEY_free(IntPtr pkey)
        {
            CryptoWrapper.X509_PUBKEY_free(pkey);
        }

        public static void X509_OBJECT_up_ref_count(IntPtr a)
        {
            CryptoWrapper.X509_OBJECT_up_ref_count(a);
        }

        public static void X509_OBJECT_free_contents(IntPtr a)
        {
            CryptoWrapper.X509_OBJECT_free_contents(a);
        }

        #endregion

        #region X509_EXTENSION

        public static IntPtr X509_EXTENSION_new()
        {
            return CryptoWrapper.X509_EXTENSION_new();
        }

        public static void X509_EXTENSION_free(IntPtr x)
        {
            CryptoWrapper.X509_EXTENSION_free(x);
        }

        public static IntPtr X509_EXTENSION_dup(IntPtr ex)
        {
            return CryptoWrapper.X509_EXTENSION_dup(ex);
        }

        public static int X509V3_EXT_print(IntPtr bio, IntPtr ext, uint flag, int indent)
        {
            return CryptoWrapper.X509V3_EXT_print(bio, ext, flag, indent);
        }

        public static IntPtr X509V3_EXT_get_nid(int nid)
        {
            return CryptoWrapper.X509V3_EXT_get_nid(nid);
        }

        public static int X509_add_ext(IntPtr x, IntPtr ex, int loc)
        {
            return CryptoWrapper.X509_add_ext(x, ex, loc);
        }

        public static int X509_add1_ext_i2d(IntPtr x, int nid, byte[] value, int crit, uint flags)
        {
            return CryptoWrapper.X509_add1_ext_i2d(x, nid, value, crit, flags);
        }

        //X509_EXTENSION* X509V3_EXT_conf_nid(LHASH* conf, X509V3_CTX* ctx, int ext_nid, char* value);
        public static IntPtr X509V3_EXT_conf_nid(IntPtr conf, IntPtr ctx, int ext_nid, string value)
        {
            return CryptoWrapper.X509V3_EXT_conf_nid(conf, ctx, ext_nid, value);
        }

        //X509_EXTENSION* X509_EXTENSION_create_by_NID(X509_EXTENSION** ex, int nid, int crit, ASN1_OCTET_STRING* data);
        public static IntPtr X509_EXTENSION_create_by_NID(IntPtr ex, int nid, int crit, IntPtr data)
        {
            return CryptoWrapper.X509_EXTENSION_create_by_NID(ex, nid, crit, data);
        }

        //X509_EXTENSION* X509_EXTENSION_create_by_OBJ(X509_EXTENSION** ex, ASN1_OBJECT* obj, int crit, ASN1_OCTET_STRING* data);
        //int X509_EXTENSION_set_object(X509_EXTENSION* ex, ASN1_OBJECT* obj);
        //int X509_EXTENSION_set_critical(X509_EXTENSION* ex, int crit);
        public static int X509_EXTENSION_set_critical(IntPtr ex, int crit)
        {
            return CryptoWrapper.X509_EXTENSION_set_critical(ex, crit);
        }

        //int X509_EXTENSION_set_data(X509_EXTENSION* ex, ASN1_OCTET_STRING* data);
        public static int X509_EXTENSION_set_data(IntPtr ex, IntPtr data)
        {
            return CryptoWrapper.X509_EXTENSION_set_data(ex, data);
        }

        //ASN1_OBJECT* X509_EXTENSION_get_object(X509_EXTENSION* ex);
        public static IntPtr X509_EXTENSION_get_object(IntPtr ex)
        {
            return CryptoWrapper.X509_EXTENSION_get_object(ex);
        }

        //ASN1_OCTET_STRING* X509_EXTENSION_get_data(X509_EXTENSION* ne);
        public static IntPtr X509_EXTENSION_get_data(IntPtr ne)
        {
            return CryptoWrapper.X509_EXTENSION_get_data(ne);
        }

        //int X509_EXTENSION_get_critical(X509_EXTENSION* ex);
        public static int X509_EXTENSION_get_critical(IntPtr ex)
        {
            return CryptoWrapper.X509_EXTENSION_get_critical(ex);
        }

        #endregion

        #region X509_STORE

        public static IntPtr X509_STORE_new()
        {
            return CryptoWrapper.X509_STORE_new();
        }

        public static int X509_STORE_add_cert(IntPtr ctx, IntPtr x)
        {
            return CryptoWrapper.X509_STORE_add_cert(ctx, x);
        }

        public static void X509_STORE_free(IntPtr x)
        {
            CryptoWrapper.X509_STORE_free(x);
        }

        public static int X509_STORE_up_ref(IntPtr x)
        {
            return CryptoWrapper.X509_STORE_up_ref(x);
        }

        public static IntPtr X509_STORE_CTX_new()
        {
            return CryptoWrapper.X509_STORE_CTX_new();
        }

        public static int X509_STORE_CTX_init(IntPtr ctx, IntPtr store, IntPtr x509, IntPtr chain)
        {
            return CryptoWrapper.X509_STORE_CTX_init(ctx, store, x509, chain);
        }

        public static void X509_STORE_CTX_free(IntPtr x)
        {
            CryptoWrapper.X509_STORE_CTX_free(x);
        }

        public static IntPtr X509_STORE_CTX_get_current_cert(IntPtr x509_store_ctx)
        {
            return CryptoWrapper.X509_STORE_CTX_get_current_cert(x509_store_ctx);
        }

        public static int X509_STORE_CTX_get_error_depth(IntPtr x509_store_ctx)
        {
            return CryptoWrapper.X509_STORE_CTX_get_error_depth(x509_store_ctx);
        }

        public static IntPtr X509_STORE_CTX_get0_store(IntPtr ctx)
        {
            return CryptoWrapper.X509_STORE_CTX_get0_store(ctx);
        }

        public static int X509_STORE_CTX_get_error(IntPtr x509_store_ctx)
        {
            return CryptoWrapper.X509_STORE_CTX_get_error(x509_store_ctx);
        }

        public static void X509_STORE_CTX_set_error(IntPtr x509_store_ctx, int error)
        {
            CryptoWrapper.X509_STORE_CTX_set_error(x509_store_ctx, error);
        }

        #endregion

        #region X509_INFO

        public static void X509_INFO_free(IntPtr a)
        {
            CryptoWrapper.X509_INFO_free(a);
        }

        public static int X509_INFO_up_ref(IntPtr a)
        {
            return CryptoWrapper.X509_INFO_up_ref(a);
        }

        #endregion

        #region X509_NAME

        public const int MBSTRING_FLAG = 0x1000;

        public const int MBSTRING_ASC = MBSTRING_FLAG | 1;

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

        public static IntPtr X509_NAME_new()
        {
            return CryptoWrapper.X509_NAME_new();
        }

        public static void X509_NAME_free(IntPtr a)
        {
            CryptoWrapper.X509_NAME_free(a);
        }

        public static IntPtr X509_NAME_dup(IntPtr xn)
        {
            return CryptoWrapper.X509_NAME_dup(xn);
        }

        public static int X509_NAME_cmp(IntPtr a, IntPtr b)
        {
            return CryptoWrapper.X509_NAME_cmp(a, b);
        }

        public static int X509_NAME_entry_count(IntPtr name)
        {
            return CryptoWrapper.X509_NAME_entry_count(name);
        }

        public static int X509_NAME_add_entry_by_NID(IntPtr name, int nid, int type, byte[] bytes, int len, int loc, int set)
        {
            return CryptoWrapper.X509_NAME_add_entry_by_NID(name, nid, type, bytes, len, loc, set);
        }

        public static int X509_NAME_add_entry_by_txt(
            IntPtr name,
            byte[] field,
            int type,
            byte[] bytes,
            int len,
            int loc,
            int set)
        {
            return CryptoWrapper.X509_NAME_add_entry_by_txt(name, field, type, bytes, len, loc, set);
        }

        public static int X509_NAME_get_text_by_NID(IntPtr name, int nid, byte[] buf, int len)
        {
            return CryptoWrapper.X509_NAME_get_text_by_NID(name, nid, buf, len);
        }

        public static IntPtr X509_NAME_get_entry(IntPtr name, int loc)
        {
            return CryptoWrapper.X509_NAME_get_entry(name, loc);
        }

        public static IntPtr X509_NAME_delete_entry(IntPtr name, int loc)
        {
            return CryptoWrapper.X509_NAME_delete_entry(name, loc);
        }

        public static int X509_NAME_get_index_by_NID(IntPtr name, int nid, int lastpos)
        {
            return CryptoWrapper.X509_NAME_get_index_by_NID(name, nid, lastpos);
        }

        public static int X509_NAME_digest(IntPtr data, IntPtr type, byte[] md, ref uint len)
        {
            return CryptoWrapper.X509_NAME_digest(data, type, md, ref len);
        }

        public static IntPtr X509_NAME_oneline(IntPtr a, byte[] buf, int size)
        {
            return CryptoWrapper.X509_NAME_oneline(a, buf, size);
        }

        public static int X509_NAME_print(IntPtr bp, IntPtr name, int obase)
        {
            return CryptoWrapper.X509_NAME_print(bp, name, obase);
        }

        public static int X509_NAME_print_ex(IntPtr bp, IntPtr nm, int indent, uint flags)
        {
            return CryptoWrapper.X509_NAME_print_ex(bp, nm, indent, flags);
        }

        #endregion

        #region RAND

        public static int RAND_set_rand_method(IntPtr meth)
        {
            return CryptoWrapper.RAND_set_rand_method(meth);
        }

        public static IntPtr RAND_get_rand_method()
        {
            return CryptoWrapper.RAND_get_rand_method();
        }

        public static void RAND_cleanup()
        {
            CryptoWrapper.RAND_cleanup();
        }

        public static void RAND_seed(byte[] buf, int len)
        {
            CryptoWrapper.RAND_seed(buf, len);
        }

        public static int RAND_pseudo_bytes(byte[] buf, int len)
        {
            return CryptoWrapper.RAND_pseudo_bytes(buf, len);
        }

        public static int RAND_bytes(byte[] buf, int num)
        {
            return CryptoWrapper.RAND_bytes(buf, num);
        }

        public static void RAND_add(byte[] buf, int num, double entropy)
        {
            CryptoWrapper.RAND_add(buf, num, entropy);
        }

        public static int RAND_load_file(string file, int max_bytes)
        {
            return CryptoWrapper.RAND_load_file(file, max_bytes);
        }

        public static int RAND_write_file(string file)
        {
            return CryptoWrapper.RAND_write_file(file);
        }

        public static string RAND_file_name(byte[] buf, uint num)
        {
            return CryptoWrapper.RAND_file_name(buf, num);
        }

        public static int RAND_status()
        {
            return CryptoWrapper.RAND_status();
        }

        public static int RAND_query_egd_bytes(string path, byte[] buf, int bytes)
        {
            return CryptoWrapper.RAND_query_egd_bytes(path, buf, bytes);
        }

        public static int RAND_egd(string path)
        {
            return CryptoWrapper.RAND_egd(path);
        }

        public static int RAND_egd_bytes(string path, int bytes)
        {
            return CryptoWrapper.RAND_egd_bytes(path, bytes);
        }

        public static int RAND_poll()
        {
            return CryptoWrapper.RAND_poll();
        }

        public static int BN_rand(IntPtr rnd, int bits, int top, int bottom)
        {
            return CryptoWrapper.BN_rand(rnd, bits, top, bottom);
        }

        public static int BN_pseudo_rand(IntPtr rnd, int bits, int top, int bottom)
        {
            return CryptoWrapper.BN_pseudo_rand(rnd, bits, top, bottom);
        }

        public static int BN_rand_range(IntPtr rnd, IntPtr range)
        {
            return CryptoWrapper.BN_rand_range(rnd, range);
        }

        public static int BN_pseudo_rand_range(IntPtr rnd, IntPtr range)
        {
            return CryptoWrapper.BN_pseudo_rand_range(rnd, range);
        }

        #endregion

        #region DSA

        public static
        int DSA_generate_parameters_ex(IntPtr dsa,
            int bits,
            byte[] seed,
            int seed_len,
            out int counter_ret,
            out IntPtr h_ret,
            bn_gencb_st callback)
        {
            return CryptoWrapper.DSA_generate_parameters_ex(dsa, bits, seed, seed_len, out counter_ret, out h_ret, callback);
        }

        public static int DSA_generate_key(IntPtr dsa)
        {
            return CryptoWrapper.DSA_generate_key(dsa);
        }

        public static IntPtr DSA_new()
        {
            return CryptoWrapper.DSA_new();
        }

        public static void DSA_free(IntPtr dsa)
        {
            CryptoWrapper.DSA_free(dsa);
        }

        public static int DSA_up_ref(IntPtr dsa)
        {
            return CryptoWrapper.DSA_up_ref(dsa);
        }

        public static int DSA_size(IntPtr dsa)
        {
            return CryptoWrapper.DSA_size(dsa);
        }

        public static int DSAparams_print(IntPtr bp, IntPtr x)
        {
            return CryptoWrapper.DSAparams_print(bp, x);
        }

        public static int DSA_print(IntPtr bp, IntPtr x, int off)
        {
            return CryptoWrapper.DSA_print(bp, x, off);
        }

        public static int DSA_sign(int type, byte[] dgst, int dlen, byte[] sig, out uint siglen, IntPtr dsa)
        {
            return CryptoWrapper.DSA_sign(type, dgst, dlen, sig, out siglen, dsa);
        }

        public static int DSA_verify(int type, byte[] dgst, int dgst_len, byte[] sigbuf, int siglen, IntPtr dsa)
        {
            return CryptoWrapper.DSA_verify(type, dgst, dgst_len, sigbuf, siglen, dsa);
        }

        #endregion

        #region RSA

        public static IntPtr RSA_new()
        {
            return CryptoWrapper.RSA_new();
        }

        public static void RSA_free(IntPtr rsa)
        {
            CryptoWrapper.RSA_free(rsa);
        }

        public static int RSA_up_ref(IntPtr rsa)
        {
            return CryptoWrapper.RSA_up_ref(rsa);
        }

        public static int RSA_size(IntPtr rsa)
        {
            return CryptoWrapper.RSA_size(rsa);
        }

        public static int RSA_generate_key_ex(IntPtr rsa, int bits, IntPtr e, bn_gencb_st cb)
        {
            return CryptoWrapper.RSA_generate_key_ex(rsa, bits, e, cb);
        }

        public static int RSA_check_key(IntPtr rsa)
        {
            return CryptoWrapper.RSA_check_key(rsa);
        }

        public static int RSA_public_encrypt(int flen, byte[] from, byte[] to, IntPtr rsa, int padding)
        {
            return CryptoWrapper.RSA_public_encrypt(flen, from, to, rsa, padding);
        }

        public static int RSA_private_encrypt(int flen, byte[] from, byte[] to, IntPtr rsa, int padding)
        {
            return CryptoWrapper.RSA_private_encrypt(flen, from, to, rsa, padding);
        }

        public static int RSA_public_decrypt(int flen, byte[] from, byte[] to, IntPtr rsa, int padding)
        {
            return CryptoWrapper.RSA_public_decrypt(flen, from, to, rsa, padding);
        }

        public static int RSA_private_decrypt(int flen, byte[] from, byte[] to, IntPtr rsa, int padding)
        {
            return CryptoWrapper.RSA_private_decrypt(flen, from, to, rsa, padding);
        }

        public static int RSA_sign(int type, byte[] m, uint m_length, byte[] sigret, out uint siglen, IntPtr rsa)
        {
            return CryptoWrapper.RSA_sign(type, m, m_length, sigret, out siglen, rsa);
        }

        public static int RSA_verify(int type, byte[] m, uint m_length, byte[] sigbuf, uint siglen, IntPtr rsa)
        {
            return CryptoWrapper.RSA_verify(type, m, m_length, sigbuf, siglen, rsa);
        }

        public static int RSA_print(IntPtr bp, IntPtr r, int offset)
        {
            return CryptoWrapper.RSA_print(bp, r, offset);
        }

        #endregion

        #region DH

        public static IntPtr DH_generate_parameters(int prime_len, int generator, IntPtr callback, IntPtr cb_arg)
        {
            return CryptoWrapper.DH_generate_parameters(prime_len, generator, callback, cb_arg);
        }

        public static int DH_generate_parameters_ex(IntPtr dh, int prime_len, int generator, bn_gencb_st cb)
        {
            return CryptoWrapper.DH_generate_parameters_ex(dh, prime_len, generator, cb);
        }

        public static int DH_generate_key(IntPtr dh)
        {
            return CryptoWrapper.DH_generate_key(dh);
        }

        public static int DH_compute_key(byte[] key, IntPtr pub_key, IntPtr dh)
        {
            return CryptoWrapper.DH_compute_key(key, pub_key, dh);
        }

        public static IntPtr DH_new()
        {
            return CryptoWrapper.DH_new();
        }

        public static void DH_free(IntPtr dh)
        {
            CryptoWrapper.DH_free(dh);
        }

        public static int DH_up_ref(IntPtr dh)
        {
            return CryptoWrapper.DH_up_ref(dh);
        }

        public static int DH_check(IntPtr dh, out int codes)
        {
            return CryptoWrapper.DH_check(dh, out codes);
        }

        public static int DHparams_print(IntPtr bp, IntPtr x)
        {
            return CryptoWrapper.DHparams_print(bp, x);
        }

        public static int DH_size(IntPtr dh)
        {
            return CryptoWrapper.DH_size(dh);
        }

        #endregion

        #region BIGNUM

        public static IntPtr BN_value_one()
        {
            return CryptoWrapper.BN_value_one();
        }

        public static IntPtr BN_CTX_new()
        {
            return CryptoWrapper.BN_CTX_new();
        }

        public static void BN_CTX_init(IntPtr c)
        {
            CryptoWrapper.BN_CTX_init(c);
        }

        public static void BN_CTX_free(IntPtr c)
        {
            CryptoWrapper.BN_CTX_free(c);
        }

        public static void BN_CTX_start(IntPtr ctx)
        {
            CryptoWrapper.BN_CTX_start(ctx);
        }

        public static IntPtr BN_CTX_get(IntPtr ctx)
        {
            return CryptoWrapper.BN_CTX_get(ctx);
        }

        public static void BN_CTX_end(IntPtr ctx)
        {
            CryptoWrapper.BN_CTX_end(ctx);
        }

        public static IntPtr BN_new()
        {
            return CryptoWrapper.BN_new();
        }

        public static void BN_free(IntPtr a)
        {
            CryptoWrapper.BN_free(a);
        }

        public static void BN_init(IntPtr a)
        {
            CryptoWrapper.BN_init(a);
        }

        public static IntPtr BN_bin2bn(byte[] s, int len, IntPtr ret)
        {
            return CryptoWrapper.BN_bin2bn(s, len, ret);
        }

        public static int BN_bn2bin(IntPtr a, byte[] to)
        {
            return CryptoWrapper.BN_bn2bin(a, to);
        }

        public static void BN_clear_free(IntPtr a)
        {
            CryptoWrapper.BN_clear_free(a);
        }

        public static void BN_clear(IntPtr a)
        {
            CryptoWrapper.BN_clear(a);
        }

        public static IntPtr BN_dup(IntPtr a)
        {
            return CryptoWrapper.BN_dup(a);
        }

        public static IntPtr BN_copy(IntPtr a, IntPtr b)
        {
            return CryptoWrapper.BN_copy(a, b);
        }

        public static void BN_swap(IntPtr a, IntPtr b)
        {
            CryptoWrapper.BN_swap(a, b);
        }

        public static int BN_cmp(IntPtr a, IntPtr b)
        {
            return CryptoWrapper.BN_cmp(a, b);
        }

        public static int BN_sub(IntPtr r, IntPtr a, IntPtr b)
        {
            return CryptoWrapper.BN_sub(r, a, b);
        }

        public static int BN_add(IntPtr r, IntPtr a, IntPtr b)
        {
            return CryptoWrapper.BN_add(r, a, b);
        }

        public static int BN_mul(IntPtr r, IntPtr a, IntPtr b, IntPtr ctx)
        {
            return CryptoWrapper.BN_mul(r, a, b, ctx);
        }

        public static int BN_num_bits(IntPtr a)
        {
            return CryptoWrapper.BN_num_bits(a);
        }

        public static int BN_sqr(IntPtr r, IntPtr a, IntPtr ctx)
        {
            return CryptoWrapper.BN_sqr(r, a, ctx);
        }

        public static int BN_div(IntPtr dv, IntPtr rem, IntPtr m, IntPtr d, IntPtr ctx)
        {
            return CryptoWrapper.BN_div(dv, rem, m, d, ctx);
        }

        public static int BN_print(IntPtr fp, IntPtr a)
        {
            return CryptoWrapper.BN_print(fp, a);
        }

        public static IntPtr BN_bn2hex(IntPtr a)
        {
            return CryptoWrapper.BN_bn2hex(a);
        }

        public static IntPtr BN_bn2dec(IntPtr a)
        {
            return CryptoWrapper.BN_bn2dec(a);
        }

        public static int BN_hex2bn(out IntPtr a, byte[] str)
        {
            return CryptoWrapper.BN_hex2bn(out a, str);
        }

        public static int BN_dec2bn(out IntPtr a, byte[] str)
        {
            return CryptoWrapper.BN_dec2bn(out a, str);
        }

        public static uint BN_mod_word(IntPtr a, uint w)
        {
            return CryptoWrapper.BN_mod_word(a, w);
        }

        public static uint BN_div_word(IntPtr a, uint w)
        {
            return CryptoWrapper.BN_div_word(a, w);
        }

        public static int BN_mul_word(IntPtr a, uint w)
        {
            return CryptoWrapper.BN_mul_word(a, w);
        }

        public static int BN_add_word(IntPtr a, uint w)
        {
            return CryptoWrapper.BN_add_word(a, w);
        }

        public static int BN_sub_word(IntPtr a, uint w)
        {
            return CryptoWrapper.BN_sub_word(a, w);
        }

        public static int BN_set_word(IntPtr a, uint w)
        {
            return CryptoWrapper.BN_set_word(a, w);
        }

        public static uint BN_get_word(IntPtr a)
        {
            return CryptoWrapper.BN_get_word(a);
        }

        #endregion

        #region DER

        //#define d2i_DHparams_bio(bp,x) ASN1_d2i_bio_of(DH,DH_new,d2i_DHparams,bp,x)
        //#define i2d_DHparams_bio(bp,x) ASN1_i2d_bio_of_const(DH,i2d_DHparams,bp,x)
        //
        //#define ASN1_d2i_bio_of(type,xnew,d2i,in,x) \
        //    ((type*)ASN1_d2i_bio( CHECKED_NEW_OF(type, xnew), \
        //              CHECKED_D2I_OF(type, d2i), \
        //              in, \
        //              CHECKED_PPTR_OF(type, x)))
        //
        //#define ASN1_i2d_bio_of_const(type,i2d,out,x) \
        //    (ASN1_i2d_bio(CHECKED_I2D_OF(const type, i2d), \
        //          out, \
        //          CHECKED_PTR_OF(const type, x)))
        //
        //#define CHECKED_I2D_OF(type, i2d) \
        //    ((i2d_of_void*) (1 ? i2d : ((I2D_OF(type))0)))
        //
        //#define I2D_OF(type) int (*)(type *,byte[] *)
        //
        //#define CHECKED_PTR_OF(type, p) \
        //    ((void*) (1 ? p : (type*)0))

        public static IntPtr d2i_DHparams(out IntPtr a, IntPtr pp, int length)
        {
            return CryptoWrapper.d2i_DHparams(out a, pp, length);
        }

        public static int i2d_DHparams(IntPtr a, IntPtr pp)
        {
            return CryptoWrapper.i2d_DHparams(a, pp);
        }

        public static IntPtr ASN1_d2i_bio(IntPtr xnew, IntPtr d2i, IntPtr bp, IntPtr x)
        {
            return CryptoWrapper.ASN1_d2i_bio(xnew, d2i, bp, x);
        }

        public static int ASN1_i2d_bio(IntPtr i2d, IntPtr bp, IntPtr x)
        {
            return CryptoWrapper.ASN1_i2d_bio(i2d, bp, x);
        }

        #endregion

        #region PEM

        #region X509

        public static int PEM_write_bio_X509(IntPtr bp, IntPtr x)
        {
            return CryptoWrapper.PEM_write_bio_X509(bp, x);
        }

        public static IntPtr PEM_read_bio_X509(IntPtr bp, IntPtr x, pem_password_cb cb, IntPtr u)
        {
            return CryptoWrapper.PEM_read_bio_X509(bp, x, cb, u);
        }

        public static IntPtr PEM_read_bio_PKCS7(IntPtr bp, IntPtr x, pem_password_cb cb, IntPtr u)
        {
            return CryptoWrapper.PEM_read_bio_PKCS7(bp, x, cb, u);
        }

        public static IntPtr d2i_PKCS7_bio(IntPtr bp, IntPtr p7)
        {
            return CryptoWrapper.d2i_PKCS7_bio(bp, p7);
        }

        public static void PKCS7_free(IntPtr p7)
        {
            CryptoWrapper.PKCS7_free(p7);
        }

        public static IntPtr d2i_PKCS12_bio(IntPtr bp, IntPtr p12)
        {
            return CryptoWrapper.d2i_PKCS12_bio(bp, p12);
        }

        public static int i2d_PKCS12_bio(IntPtr bp, IntPtr p12)
        {
            return CryptoWrapper.i2d_PKCS12_bio(bp, p12);
        }

        public static IntPtr PKCS12_create(
            string pass,
            string name,
            IntPtr pkey,
            IntPtr cert,
            IntPtr ca,
            int nid_key,
            int nid_cert,
            int iter,
            int mac_iter,
            int keytype)
        {
            return CryptoWrapper.PKCS12_create(pass, name, pkey, cert, ca, nid_key, nid_cert, iter, mac_iter, keytype);
        }

        public static int PKCS12_parse(IntPtr p12, string pass, out IntPtr pkey, out IntPtr cert, out IntPtr ca)
        {
            return CryptoWrapper.PKCS12_parse(p12, pass, out pkey, out cert, out ca);
        }

        public static void PKCS12_free(IntPtr p12)
        {
            CryptoWrapper.PKCS12_free(p12);
        }

        public static int PEM_write_bio_PKCS8PrivateKey(
            IntPtr bp,
            IntPtr evp_pkey,
            IntPtr evp_cipher,
            IntPtr kstr,
            int klen,
            pem_password_cb cb,
            IntPtr user_data)
        {
            return CryptoWrapper.PEM_write_bio_PKCS8PrivateKey(bp, evp_pkey, evp_cipher, kstr, klen, cb, user_data);
        }

        #endregion

        #region X509_INFO

        public static int PEM_write_bio_X509_INFO(IntPtr bp, IntPtr x)
        {
            return CryptoWrapper.PEM_write_bio_X509_INFO(bp, x);
        }

        public static IntPtr PEM_read_bio_X509_INFO(IntPtr bp, IntPtr x, pem_password_cb cb, IntPtr u)
        {
            return CryptoWrapper.PEM_read_bio_X509_INFO(bp, x, cb, u);
        }

        #endregion

        #region X509_AUX

        public static int PEM_write_bio_X509_AUX(IntPtr bp, IntPtr x)
        {
            return CryptoWrapper.PEM_write_bio_X509_AUX(bp, x);
        }

        public static IntPtr PEM_read_bio_X509_AUX(IntPtr bp, IntPtr x, pem_password_cb cb, IntPtr u)
        {
            return CryptoWrapper.PEM_read_bio_X509_AUX(bp, x, cb, u);
        }

        #endregion

        #region X509_REQ

        public static int PEM_write_bio_X509_REQ(IntPtr bp, IntPtr x)
        {
            return CryptoWrapper.PEM_write_bio_X509_REQ(bp, x);
        }

        public static IntPtr PEM_read_bio_X509_REQ(IntPtr bp, IntPtr x, pem_password_cb cb, IntPtr u)
        {
            return CryptoWrapper.PEM_read_bio_X509_REQ(bp, x, cb, u);
        }

        #endregion

        #region X509_REQ_NEW

        public static int PEM_write_bio_X509_REQ_NEW(IntPtr bp, IntPtr x)
        {
            return CryptoWrapper.PEM_write_bio_X509_REQ_NEW(bp, x);
        }

        public static IntPtr PEM_read_bio_X509_REQ_NEW(IntPtr bp, IntPtr x, pem_password_cb cb, IntPtr u)
        {
            return CryptoWrapper.PEM_read_bio_X509_REQ_NEW(bp, x, cb, u);
        }

        #endregion

        #region X509_CRL

        public static int PEM_write_bio_X509_CRL(IntPtr bp, IntPtr x)
        {
            return CryptoWrapper.PEM_write_bio_X509_CRL(bp, x);
        }

        public static IntPtr PEM_read_bio_X509_CRL(IntPtr bp, IntPtr x, pem_password_cb cb, IntPtr u)
        {
            return CryptoWrapper.PEM_read_bio_X509_CRL(bp, x, cb, u);
        }

        #endregion

        #region X509Chain

        public static IntPtr PEM_X509_INFO_read_bio(IntPtr bp, IntPtr sk, pem_password_cb cb, IntPtr u)
        {
            return CryptoWrapper.PEM_X509_INFO_read_bio(bp, sk, cb, u);
        }

        public static int PEM_X509_INFO_write_bio(
            IntPtr bp,
            IntPtr xi,
            IntPtr enc,
            byte[] kstr,
            int klen,
            IntPtr cd,
            IntPtr u)
        {
            return CryptoWrapper.PEM_X509_INFO_write_bio(bp, xi, enc, kstr, klen, cd, u);
        }

        #endregion

        #region DSA

        public static int PEM_write_bio_DSAPrivateKey(
            IntPtr bp,
            IntPtr x,
            IntPtr enc,
            byte[] kstr,
            int klen,
            pem_password_cb cb,
            IntPtr u)
        {
            return CryptoWrapper.PEM_write_bio_DSAPrivateKey(bp, x, enc, kstr, klen, cb, u);
        }

        public static IntPtr PEM_read_bio_DSAPrivateKey(IntPtr bp, IntPtr x, pem_password_cb cb, IntPtr u)
        {
            return CryptoWrapper.PEM_read_bio_DSAPrivateKey(bp, x, cb, u);
        }

        public static int PEM_write_bio_DSA_PUBKEY(IntPtr bp, IntPtr x)
        {
            return CryptoWrapper.PEM_write_bio_DSA_PUBKEY(bp, x);
        }

        public static IntPtr PEM_read_bio_DSA_PUBKEY(IntPtr bp, IntPtr x, pem_password_cb cb, IntPtr u)
        {
            return CryptoWrapper.PEM_read_bio_DSA_PUBKEY(bp, x, cb, u);
        }

        #endregion

        #region DSAparams

        public static int PEM_write_bio_DSAparams(IntPtr bp, IntPtr x)
        {
            return CryptoWrapper.PEM_write_bio_DSAparams(bp, x);
        }

        public static IntPtr PEM_read_bio_DSAparams(IntPtr bp, IntPtr x, pem_password_cb cb, IntPtr u)
        {
            return CryptoWrapper.PEM_read_bio_DSAparams(bp, x, cb, u);
        }

        #endregion

        #region RSA

        public static int PEM_write_bio_RSA_PUBKEY(IntPtr bp, IntPtr x)
        {
            return CryptoWrapper.PEM_write_bio_RSA_PUBKEY(bp, x);
        }

        public static IntPtr PEM_read_bio_RSA_PUBKEY(IntPtr bp, IntPtr x, pem_password_cb cb, IntPtr u)
        {
            return CryptoWrapper.PEM_read_bio_RSA_PUBKEY(bp, x, cb, u);
        }

        public static int PEM_write_bio_RSAPrivateKey(
            IntPtr bp,
            IntPtr x,
            IntPtr enc,
            byte[] kstr,
            int klen,
            pem_password_cb cb,
            IntPtr u)
        {
            return CryptoWrapper.PEM_write_bio_RSAPrivateKey(bp, x, enc, kstr, klen, cb, u);
        }

        public static IntPtr PEM_read_bio_RSAPrivateKey(IntPtr bp, IntPtr x, pem_password_cb cb, IntPtr u)
        {
            return CryptoWrapper.PEM_read_bio_RSAPrivateKey(bp, x, cb, u);
        }

        #endregion

        #region DHparams

        public static int PEM_write_bio_DHparams(IntPtr bp, IntPtr x)
        {
            return CryptoWrapper.PEM_write_bio_DHparams(bp, x);
        }

        public static IntPtr PEM_read_bio_DHparams(IntPtr bp, IntPtr x, pem_password_cb cb, IntPtr u)
        {
            return CryptoWrapper.PEM_read_bio_DHparams(bp, x, cb, u);
        }

        #endregion

        #region PrivateKey

        public static int PEM_write_bio_PrivateKey(
            IntPtr bp,
            IntPtr x,
            IntPtr enc,
            byte[] kstr,
            int klen,
            pem_password_cb cb,
            IntPtr u)
        {
            return CryptoWrapper.PEM_write_bio_PrivateKey(bp, x, enc, kstr, klen, cb, u);
        }

        public static IntPtr PEM_read_bio_PrivateKey(IntPtr bp, IntPtr x, pem_password_cb cb, IntPtr u)
        {
            return CryptoWrapper.PEM_read_bio_PrivateKey(bp, x, cb, u);
        }

        #endregion

        #region PUBKEY

        public static int PEM_write_bio_PUBKEY(IntPtr bp, IntPtr x)
        {
            return CryptoWrapper.PEM_write_bio_PUBKEY(bp, x);
        }

        public static IntPtr PEM_read_bio_PUBKEY(IntPtr bp, IntPtr x, pem_password_cb cb, IntPtr u)
        {
            return CryptoWrapper.PEM_read_bio_PUBKEY(bp, x, cb, u);
        }

        #endregion

        #endregion

        #region EVP

        #region Constants

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

        #endregion

        #region Message Digests

        public static IntPtr EVP_md_null()
        {
            return CryptoWrapper.EVP_md_null();
        }

        public static IntPtr EVP_md2()
        {
            return CryptoWrapper.EVP_md2();
        }

        public static IntPtr EVP_md4()
        {
            return CryptoWrapper.EVP_md4();
        }

        public static IntPtr EVP_md5()
        {
            return CryptoWrapper.EVP_md5();
        }

        public static IntPtr EVP_sha()
        {
            return CryptoWrapper.EVP_sha();
        }

        public static IntPtr EVP_sha1()
        {
            return CryptoWrapper.EVP_sha1();
        }

        public static IntPtr EVP_sha224()
        {
            return CryptoWrapper.EVP_sha224();
        }

        public static IntPtr EVP_sha256()
        {
            return CryptoWrapper.EVP_sha256();
        }

        public static IntPtr EVP_sha384()
        {
            return CryptoWrapper.EVP_sha384();
        }

        public static IntPtr EVP_sha512()
        {
            return CryptoWrapper.EVP_sha512();
        }

        public static IntPtr EVP_dss()
        {
            return CryptoWrapper.EVP_dss();
        }

        public static IntPtr EVP_dss1()
        {
            return CryptoWrapper.EVP_dss1();
        }

        public static IntPtr EVP_mdc2()
        {
            return CryptoWrapper.EVP_mdc2();
        }

        public static IntPtr EVP_ripemd160()
        {
            return CryptoWrapper.EVP_ripemd160();
        }

        public static IntPtr EVP_ecdsa()
        {
            return CryptoWrapper.EVP_ecdsa();
        }

        #endregion

        #region HMAC

        public const int HMAC_MAX_MD_CBLOCK = 128;

        //!!void HMAC_CTX_init(HMAC_CTX *ctx);
        public static void HMAC_CTX_init(IntPtr ctx)
        {
            CryptoWrapper.HMAC_CTX_init(ctx);
        }

        public static void HMAC_CTX_set_flags(IntPtr ctx, uint flags)
        {
            CryptoWrapper.HMAC_CTX_set_flags(ctx, flags);
        }

        public static void HMAC_CTX_cleanup(IntPtr ctx)
        {
            CryptoWrapper.HMAC_CTX_cleanup(ctx);
        }

        public static void HMAC_Init(IntPtr ctx, byte[] key, int len, IntPtr md)
        {
            CryptoWrapper.HMAC_Init(ctx, key, len, md);
        }
        /* deprecated */

        //!!public static void HMAC_Init_ex(IntPtr ctx, const void *key, int len, const EVP_MD *md, ENGINE *impl);
        public static void HMAC_Init_ex(IntPtr ctx, byte[] key, int len, IntPtr md, IntPtr engine_impl)
        {
            CryptoWrapper.HMAC_Init_ex(ctx, key, len, md, engine_impl);
        }

        public static void HMAC_Update(IntPtr ctx, byte[] data, int len)
        {
            CryptoWrapper.HMAC_Update(ctx, data, len);
        }

        public static void HMAC_Final(IntPtr ctx, byte[] md, ref uint len)
        {
            CryptoWrapper.HMAC_Final(ctx, md, ref len);
        }

        public static IntPtr HMAC(IntPtr evp_md, byte[] key, int key_len, byte[] d, int n, byte[] md, ref uint md_len)
        {
            return CryptoWrapper.HMAC(evp_md, key, key_len, d, n, md, ref md_len);
        }

        #endregion

        #region Ciphers

        public static IntPtr EVP_get_cipherbyname(byte[] name)
        {
            return CryptoWrapper.EVP_get_cipherbyname(name);
        }

        public static IntPtr EVP_enc_null()
        {
            return CryptoWrapper.EVP_enc_null();
        }

        public static IntPtr EVP_des_ecb()
        {
            return CryptoWrapper.EVP_des_ecb();
        }

        public static IntPtr EVP_des_ede()
        {
            return CryptoWrapper.EVP_des_ede();
        }

        public static IntPtr EVP_des_ede3()
        {
            return CryptoWrapper.EVP_des_ede3();
        }

        public static IntPtr EVP_des_ede_ecb()
        {
            return CryptoWrapper.EVP_des_ede_ecb();
        }

        public static IntPtr EVP_des_ede3_ecb()
        {
            return CryptoWrapper.EVP_des_ede3_ecb();
        }

        public static IntPtr EVP_des_cfb64()
        {
            return CryptoWrapper.EVP_des_cfb64();
        }

        public static IntPtr EVP_des_cfb1()
        {
            return CryptoWrapper.EVP_des_cfb1();
        }

        public static IntPtr EVP_des_cfb8()
        {
            return CryptoWrapper.EVP_des_cfb8();
        }

        public static IntPtr EVP_des_ede_cfb64()
        {
            return CryptoWrapper.EVP_des_ede_cfb64();
        }

        public static IntPtr EVP_des_ede3_cfb64()
        {
            return CryptoWrapper.EVP_des_ede3_cfb64();
        }

        public static IntPtr EVP_des_ede3_cfb1()
        {
            return CryptoWrapper.EVP_des_ede3_cfb1();
        }

        public static IntPtr EVP_des_ede3_cfb8()
        {
            return CryptoWrapper.EVP_des_ede3_cfb8();
        }

        public static IntPtr EVP_des_ofb()
        {
            return CryptoWrapper.EVP_des_ofb();
        }

        public static IntPtr EVP_des_ede_ofb()
        {
            return CryptoWrapper.EVP_des_ede_ofb();
        }

        public static IntPtr EVP_des_ede3_ofb()
        {
            return CryptoWrapper.EVP_des_ede3_ofb();
        }

        public static IntPtr EVP_des_cbc()
        {
            return CryptoWrapper.EVP_des_cbc();
        }

        public static IntPtr EVP_des_ede_cbc()
        {
            return CryptoWrapper.EVP_des_ede_cbc();
        }

        public static IntPtr EVP_des_ede3_cbc()
        {
            return CryptoWrapper.EVP_des_ede3_cbc();
        }

        public static IntPtr EVP_desx_cbc()
        {
            return CryptoWrapper.EVP_desx_cbc();
        }

        public static IntPtr EVP_rc4()
        {
            return CryptoWrapper.EVP_rc4();
        }

        public static IntPtr EVP_rc4_40()
        {
            return CryptoWrapper.EVP_rc4_40();
        }

        public static IntPtr EVP_idea_ecb()
        {
            return CryptoWrapper.EVP_idea_ecb();
        }

        public static IntPtr EVP_idea_cfb64()
        {
            return CryptoWrapper.EVP_idea_cfb64();
        }

        public static IntPtr EVP_idea_ofb()
        {
            return CryptoWrapper.EVP_idea_ofb();
        }

        public static IntPtr EVP_idea_cbc()
        {
            return CryptoWrapper.EVP_idea_cbc();
        }

        public static IntPtr EVP_rc2_ecb()
        {
            return CryptoWrapper.EVP_rc2_ecb();
        }

        public static IntPtr EVP_rc2_cbc()
        {
            return CryptoWrapper.EVP_rc2_cbc();
        }

        public static IntPtr EVP_rc2_40_cbc()
        {
            return CryptoWrapper.EVP_rc2_40_cbc();
        }

        public static IntPtr EVP_rc2_64_cbc()
        {
            return CryptoWrapper.EVP_rc2_64_cbc();
        }

        public static IntPtr EVP_rc2_cfb64()
        {
            return CryptoWrapper.EVP_rc2_cfb64();
        }

        public static IntPtr EVP_rc2_ofb()
        {
            return CryptoWrapper.EVP_rc2_ofb();
        }

        public static IntPtr EVP_bf_ecb()
        {
            return CryptoWrapper.EVP_bf_ecb();
        }

        public static IntPtr EVP_bf_cbc()
        {
            return CryptoWrapper.EVP_bf_cbc();
        }

        public static IntPtr EVP_bf_cfb64()
        {
            return CryptoWrapper.EVP_bf_cfb64();
        }

        public static IntPtr EVP_bf_ofb()
        {
            return CryptoWrapper.EVP_bf_ofb();
        }

        public static IntPtr EVP_cast5_ecb()
        {
            return CryptoWrapper.EVP_cast5_ecb();
        }

        public static IntPtr EVP_cast5_cbc()
        {
            return CryptoWrapper.EVP_cast5_cbc();
        }

        public static IntPtr EVP_cast5_cfb64()
        {
            return CryptoWrapper.EVP_cast5_cfb64();
        }

        public static IntPtr EVP_cast5_ofb()
        {
            return CryptoWrapper.EVP_cast5_ofb();
        }

        public static IntPtr EVP_rc5_32_12_16_cbc()
        {
            return CryptoWrapper.EVP_rc5_32_12_16_cbc();
        }

        public static IntPtr EVP_rc5_32_12_16_ecb()
        {
            return CryptoWrapper.EVP_rc5_32_12_16_ecb();
        }

        public static IntPtr EVP_rc5_32_12_16_cfb64()
        {
            return CryptoWrapper.EVP_rc5_32_12_16_cfb64();
        }

        public static IntPtr EVP_rc5_32_12_16_ofb()
        {
            return CryptoWrapper.EVP_rc5_32_12_16_ofb();
        }

        public static IntPtr EVP_aes_128_ecb()
        {
            return CryptoWrapper.EVP_aes_128_ecb();
        }

        public static IntPtr EVP_aes_128_cbc()
        {
            return CryptoWrapper.EVP_aes_128_cbc();
        }

        public static IntPtr EVP_aes_128_cfb1()
        {
            return CryptoWrapper.EVP_aes_128_cfb1();
        }

        public static IntPtr EVP_aes_128_cfb8()
        {
            return CryptoWrapper.EVP_aes_128_cfb8();
        }

        public static IntPtr EVP_aes_128_cfb128()
        {
            return CryptoWrapper.EVP_aes_128_cfb128();
        }

        public static IntPtr EVP_aes_128_ofb()
        {
            return CryptoWrapper.EVP_aes_128_ofb();
        }

        public static IntPtr EVP_aes_192_ecb()
        {
            return CryptoWrapper.EVP_aes_192_ecb();
        }

        public static IntPtr EVP_aes_192_cbc()
        {
            return CryptoWrapper.EVP_aes_192_cbc();
        }

        public static IntPtr EVP_aes_192_cfb1()
        {
            return CryptoWrapper.EVP_aes_192_cfb1();
        }

        public static IntPtr EVP_aes_192_cfb8()
        {
            return CryptoWrapper.EVP_aes_192_cfb8();
        }

        public static IntPtr EVP_aes_192_cfb128()
        {
            return CryptoWrapper.EVP_aes_192_cfb128();
        }

        public static IntPtr EVP_aes_192_ofb()
        {
            return CryptoWrapper.EVP_aes_192_ofb();
        }

        public static IntPtr EVP_aes_256_ecb()
        {
            return CryptoWrapper.EVP_aes_256_ecb();
        }

        public static IntPtr EVP_aes_256_cbc()
        {
            return CryptoWrapper.EVP_aes_256_cbc();
        }

        public static IntPtr EVP_aes_256_cfb1()
        {
            return CryptoWrapper.EVP_aes_256_cfb1();
        }

        public static IntPtr EVP_aes_256_cfb8()
        {
            return CryptoWrapper.EVP_aes_256_cfb8();
        }

        public static IntPtr EVP_aes_256_cfb128()
        {
            return CryptoWrapper.EVP_aes_256_cfb128();
        }

        public static IntPtr EVP_aes_256_ofb()
        {
            return CryptoWrapper.EVP_aes_256_ofb();
        }

        #endregion

        #region EVP_PKEY

        public static IntPtr EVP_PKEY_new()
        {
            return CryptoWrapper.EVP_PKEY_new();
        }

        public static void EVP_PKEY_free(IntPtr pkey)
        {
            CryptoWrapper.EVP_PKEY_free(pkey);
        }

        public static int EVP_PKEY_cmp(IntPtr a, IntPtr b)
        {
            return CryptoWrapper.EVP_PKEY_cmp(a, b);
        }

        public static int EVP_PKEY_decrypt(byte[] dec_key, byte[] enc_key, int enc_key_len, IntPtr private_key)
        {
            return CryptoWrapper.EVP_PKEY_decrypt(dec_key, enc_key, enc_key_len, private_key);
        }

        public static int EVP_PKEY_encrypt(byte[] enc_key, byte[] key, int key_len, IntPtr pub_key)
        {
            return CryptoWrapper.EVP_PKEY_encrypt(enc_key, key, key_len, pub_key);
        }

        public static int EVP_PKEY_encrypt_old(byte[] enc_key, byte[] key, int key_len, IntPtr pub_key)
        {
            return CryptoWrapper.EVP_PKEY_encrypt_old(enc_key, key, key_len, pub_key);
        }

        public static int EVP_PKEY_type(int type)
        {
            return CryptoWrapper.EVP_PKEY_type(type);
        }

        public static int EVP_PKEY_bits(IntPtr pkey)
        {
            return CryptoWrapper.EVP_PKEY_bits(pkey);
        }

        public static int EVP_PKEY_size(IntPtr pkey)
        {
            return CryptoWrapper.EVP_PKEY_size(pkey);
        }

        public static int EVP_PKEY_assign(IntPtr pkey, int type, IntPtr key)
        {
            return CryptoWrapper.EVP_PKEY_assign(pkey, type, key);
        }

        public static int EVP_PKEY_set1_DSA(IntPtr pkey, IntPtr key)
        {
            return CryptoWrapper.EVP_PKEY_set1_DSA(pkey, key);
        }

        public static IntPtr EVP_PKEY_get1_DSA(IntPtr pkey)
        {
            return CryptoWrapper.EVP_PKEY_get1_DSA(pkey);
        }

        public static int EVP_PKEY_set1_RSA(IntPtr pkey, IntPtr key)
        {
            return CryptoWrapper.EVP_PKEY_set1_RSA(pkey, key);
        }

        public static IntPtr EVP_PKEY_get1_RSA(IntPtr pkey)
        {
            return CryptoWrapper.EVP_PKEY_get1_RSA(pkey);
        }

        public static int EVP_PKEY_set1_EC_KEY(IntPtr pkey, IntPtr key)
        {
            return CryptoWrapper.EVP_PKEY_set1_EC_KEY(pkey, key);
        }

        public static IntPtr EVP_PKEY_get1_EC_KEY(IntPtr pkey)
        {
            return CryptoWrapper.EVP_PKEY_get1_EC_KEY(pkey);
        }

        public static int EVP_PKEY_set1_DH(IntPtr pkey, IntPtr key)
        {
            return CryptoWrapper.EVP_PKEY_set1_DH(pkey, key);
        }

        public static IntPtr EVP_PKEY_get1_DH(IntPtr pkey)
        {
            return CryptoWrapper.EVP_PKEY_get1_DH(pkey);
        }

        public static int EVP_PKEY_copy_parameters(IntPtr to, IntPtr from)
        {
            return CryptoWrapper.EVP_PKEY_copy_parameters(to, from);
        }

        public static int EVP_PKEY_missing_parameters(IntPtr pkey)
        {
            return CryptoWrapper.EVP_PKEY_missing_parameters(pkey);
        }

        public static int EVP_PKEY_save_parameters(IntPtr pkey, int mode)
        {
            return CryptoWrapper.EVP_PKEY_save_parameters(pkey, mode);
        }

        public static int EVP_PKEY_cmp_parameters(IntPtr a, IntPtr b)
        {
            return CryptoWrapper.EVP_PKEY_cmp_parameters(a, b);
        }

        #endregion

        #region EVP_CIPHER

        public static void EVP_CIPHER_CTX_init(IntPtr a)
        {
            CryptoWrapper.EVP_CIPHER_CTX_init(a);
        }

        public static int EVP_CIPHER_CTX_rand_key(IntPtr ctx, byte[] key)
        {
            return CryptoWrapper.EVP_CIPHER_CTX_rand_key(ctx, key);
        }

        public static int EVP_CIPHER_CTX_set_padding(IntPtr x, int padding)
        {
            return CryptoWrapper.EVP_CIPHER_CTX_set_padding(x, padding);
        }

        public static int EVP_CIPHER_CTX_set_key_length(IntPtr x, int keylen)
        {
            return CryptoWrapper.EVP_CIPHER_CTX_set_key_length(x, keylen);
        }

        public static int EVP_CIPHER_CTX_ctrl(IntPtr ctx, int type, int arg, IntPtr ptr)
        {
            return CryptoWrapper.EVP_CIPHER_CTX_ctrl(ctx, type, arg, ptr);
        }

        public static int EVP_CIPHER_CTX_cleanup(IntPtr a)
        {
            return CryptoWrapper.EVP_CIPHER_CTX_cleanup(a);
        }

        public static int EVP_CIPHER_type(IntPtr ctx)
        {
            return CryptoWrapper.EVP_CIPHER_type(ctx);
        }

        public static int EVP_CipherInit_ex(IntPtr ctx, IntPtr type, IntPtr impl, byte[] key, byte[] iv, int enc)
        {
            return CryptoWrapper.EVP_CipherInit_ex(ctx, type, impl, key, iv, enc);
        }

        public static int EVP_CipherUpdate(IntPtr ctx, byte[] outb, out int outl, byte[] inb, int inl)
        {
            return CryptoWrapper.EVP_CipherUpdate(ctx, outb, out outl, inb, inl);
        }

        public static int EVP_CipherFinal_ex(IntPtr ctx, byte[] outm, ref int outl)
        {
            return CryptoWrapper.EVP_CipherFinal_ex(ctx, outm, ref outl);
        }

        public static int EVP_OpenInit(IntPtr ctx, IntPtr type, byte[] ek, int ekl, byte[] iv, IntPtr priv)
        {
            return CryptoWrapper.EVP_OpenInit(ctx, type, ek, ekl, iv, priv);
        }

        public static int EVP_OpenFinal(IntPtr ctx, byte[] outb, out int outl)
        {
            return CryptoWrapper.EVP_OpenFinal(ctx, outb, out outl);
        }

        public static int EVP_SealInit(
            IntPtr ctx,
            IntPtr type,
            IntPtr[] ek,
            int[] ekl,
            byte[] iv,
            IntPtr[] pubk,
            int npubk)
        {
            return CryptoWrapper.EVP_SealInit(ctx, type, ek, ekl, iv, pubk, npubk);
        }

        public static int EVP_SealFinal(IntPtr ctx, byte[] outb, out int outl)
        {
            return CryptoWrapper.EVP_SealFinal(ctx, outb, out outl);
        }

        public static int EVP_DecryptUpdate(IntPtr ctx, byte[] output, out int outl, byte[] input, int inl)
        {
            return CryptoWrapper.EVP_DecryptUpdate(ctx, output, out outl, input, inl);
        }

        public static int EVP_EncryptInit_ex(IntPtr ctx, IntPtr cipher, IntPtr impl, byte[] key, byte[] iv)
        {
            return CryptoWrapper.EVP_EncryptInit_ex(ctx, cipher, impl, key, iv);
        }

        public static int EVP_EncryptUpdate(IntPtr ctx, byte[] output, out int outl, byte[] input, int inl)
        {
            return CryptoWrapper.EVP_EncryptUpdate(ctx, output, out outl, input, inl);
        }

        public static int EVP_BytesToKey(
            IntPtr type,
            IntPtr md,
            byte[] salt,
            byte[] data,
            int datal,
            int count,
            byte[] key,
            byte[] iv)
        {
            return CryptoWrapper.EVP_BytesToKey(type, md, salt, data, datal, count, key, iv);
        }

        #endregion

        #region EVP_MD

        public static int EVP_MD_type(IntPtr md)
        {
            return CryptoWrapper.EVP_MD_type(md);
        }

        public static int EVP_MD_pkey_type(IntPtr md)
        {
            return CryptoWrapper.EVP_MD_pkey_type(md);
        }

        public static int EVP_MD_size(IntPtr md)
        {
            return CryptoWrapper.EVP_MD_size(md);
        }

        public static int EVP_MD_block_size(IntPtr md)
        {
            return CryptoWrapper.EVP_MD_block_size(md);
        }

        public static uint EVP_MD_flags(IntPtr md)
        {
            return CryptoWrapper.EVP_MD_flags(md);
        }

        public static IntPtr EVP_get_digestbyname(byte[] name)
        {
            return CryptoWrapper.EVP_get_digestbyname(name);
        }

        public static void EVP_MD_CTX_init(IntPtr ctx)
        {
            CryptoWrapper.EVP_MD_CTX_init(ctx);
        }

        public static int EVP_MD_CTX_cleanup(IntPtr ctx)
        {
            return CryptoWrapper.EVP_MD_CTX_cleanup(ctx);
        }

        public static IntPtr EVP_MD_CTX_create()
        {
            return CryptoWrapper.EVP_MD_CTX_create();
        }

        public static void EVP_MD_CTX_destroy(IntPtr ctx)
        {
            CryptoWrapper.EVP_MD_CTX_destroy(ctx);
        }

        public static int EVP_DigestInit_ex(IntPtr ctx, IntPtr type, IntPtr impl)
        {
            return CryptoWrapper.EVP_DigestInit_ex(ctx, type, impl);
        }

        public static int EVP_DigestUpdate(IntPtr ctx, byte[] d, uint cnt)
        {
            return CryptoWrapper.EVP_DigestUpdate(ctx, d, cnt);
        }

        public static int EVP_DigestFinal_ex(IntPtr ctx, byte[] md, ref uint s)
        {
            return CryptoWrapper.EVP_DigestFinal_ex(ctx, md, ref s);
        }

        public static int EVP_Digest(byte[] data, uint count, byte[] md, ref uint size, IntPtr type, IntPtr impl)
        {
            return CryptoWrapper.EVP_Digest(data, count, md, ref size, type, impl);
        }

        public static int EVP_SignFinal(IntPtr ctx, byte[] md, ref uint s, IntPtr pkey)
        {
            return CryptoWrapper.EVP_SignFinal(ctx, md, ref s, pkey);
        }

        public static int EVP_VerifyFinal(IntPtr ctx, byte[] sigbuf, uint siglen, IntPtr pkey)
        {
            return CryptoWrapper.EVP_VerifyFinal(ctx, sigbuf, siglen, pkey);
        }

        #endregion

        #endregion

        #region EC

        public static int EC_get_builtin_curves(IntPtr r, int nitems)
        {
            return CryptoWrapper.EC_get_builtin_curves(r, nitems);
        }

        #region EC_METHOD

        public static IntPtr EC_GFp_simple_method()
        {
            return CryptoWrapper.EC_GFp_simple_method();
        }

        public static IntPtr EC_GFp_mont_method()
        {
            return CryptoWrapper.EC_GFp_mont_method();
        }

        public static IntPtr EC_GFp_nist_method()
        {
            return CryptoWrapper.EC_GFp_nist_method();
        }

        public static IntPtr EC_GF2m_simple_method()
        {
            return CryptoWrapper.EC_GF2m_simple_method();
        }

        public static int EC_METHOD_get_field_type(IntPtr meth)
        {
            return CryptoWrapper.EC_METHOD_get_field_type(meth);
        }

        #endregion

        #region EC_GROUP

        public static IntPtr EC_GROUP_new(IntPtr meth)
        {
            return CryptoWrapper.EC_GROUP_new(meth);
        }

        public static void EC_GROUP_free(IntPtr group)
        {
            CryptoWrapper.EC_GROUP_free(group);
        }

        public static void EC_GROUP_clear_free(IntPtr group)
        {
            CryptoWrapper.EC_GROUP_clear_free(group);
        }

        public static int EC_GROUP_copy(IntPtr dst, IntPtr src)
        {
            return CryptoWrapper.EC_GROUP_copy(dst, src);
        }

        public static IntPtr EC_GROUP_dup(IntPtr src)
        {
            return CryptoWrapper.EC_GROUP_dup(src);
        }

        public static IntPtr EC_GROUP_method_of(IntPtr group)
        {
            return CryptoWrapper.EC_GROUP_method_of(group);
        }

        public static int EC_GROUP_set_generator(IntPtr group, IntPtr generator, IntPtr order, IntPtr cofactor)
        {
            return CryptoWrapper.EC_GROUP_set_generator(group, generator, order, cofactor);
        }

        public static IntPtr EC_GROUP_get0_generator(IntPtr group)
        {
            return CryptoWrapper.EC_GROUP_get0_generator(group);
        }

        public static int EC_GROUP_get_order(IntPtr group, IntPtr order, IntPtr ctx)
        {
            return CryptoWrapper.EC_GROUP_get_order(group, order, ctx);
        }

        public static int EC_GROUP_get_cofactor(IntPtr group, IntPtr cofactor, IntPtr ctx)
        {
            return CryptoWrapper.EC_GROUP_get_cofactor(group, cofactor, ctx);
        }

        public static void EC_GROUP_set_curve_name(IntPtr group, int nid)
        {
            CryptoWrapper.EC_GROUP_set_curve_name(group, nid);
        }

        public static int EC_GROUP_get_curve_name(IntPtr group)
        {
            return CryptoWrapper.EC_GROUP_get_curve_name(group);
        }

        public static void EC_GROUP_set_asn1_flag(IntPtr group, int flag)
        {
            CryptoWrapper.EC_GROUP_set_asn1_flag(group, flag);
        }

        public static int EC_GROUP_get_asn1_flag(IntPtr group)
        {
            return CryptoWrapper.EC_GROUP_get_asn1_flag(group);
        }

        public static void EC_GROUP_set_point_conversion_form(IntPtr x, int y)
        {
            CryptoWrapper.EC_GROUP_set_point_conversion_form(x, y);
        }

        public static int EC_GROUP_get_point_conversion_form(IntPtr x)
        {
            return CryptoWrapper.EC_GROUP_get_point_conversion_form(x);
        }

        public static byte[] EC_GROUP_get0_seed(IntPtr x)
        {
            return CryptoWrapper.EC_GROUP_get0_seed(x);
        }

        public static int EC_GROUP_get_seed_len(IntPtr x)
        {
            return CryptoWrapper.EC_GROUP_get_seed_len(x);
        }

        public static int EC_GROUP_set_seed(IntPtr x, byte[] buf, int len)
        {
            return CryptoWrapper.EC_GROUP_set_seed(x, buf, len);
        }

        public static int EC_GROUP_set_curve_GFp(IntPtr group, IntPtr p, IntPtr a, IntPtr b, IntPtr ctx)
        {
            return CryptoWrapper.EC_GROUP_set_curve_GFp(group, p, a, b, ctx);
        }

        public static int EC_GROUP_get_curve_GFp(IntPtr group, IntPtr p, IntPtr a, IntPtr b, IntPtr ctx)
        {
            return CryptoWrapper.EC_GROUP_get_curve_GFp(group, p, a, b, ctx);
        }

        public static int EC_GROUP_set_curve_GF2m(IntPtr group, IntPtr p, IntPtr a, IntPtr b, IntPtr ctx)
        {
            return CryptoWrapper.EC_GROUP_set_curve_GF2m(group, p, a, b, ctx);
        }

        public static int EC_GROUP_get_curve_GF2m(IntPtr group, IntPtr p, IntPtr a, IntPtr b, IntPtr ctx)
        {
            return CryptoWrapper.EC_GROUP_get_curve_GF2m(group, p, a, b, ctx);
        }

        public static int EC_GROUP_get_degree(IntPtr group)
        {
            return CryptoWrapper.EC_GROUP_get_degree(group);
        }

        public static int EC_GROUP_check(IntPtr group, IntPtr ctx)
        {
            return CryptoWrapper.EC_GROUP_check(group, ctx);
        }

        public static int EC_GROUP_check_discriminant(IntPtr group, IntPtr ctx)
        {
            return CryptoWrapper.EC_GROUP_check_discriminant(group, ctx);
        }

        public static int EC_GROUP_cmp(IntPtr a, IntPtr b, IntPtr ctx)
        {
            return CryptoWrapper.EC_GROUP_cmp(a, b, ctx);
        }

        public static IntPtr EC_GROUP_new_curve_GFp(IntPtr p, IntPtr a, IntPtr b, IntPtr ctx)
        {
            return CryptoWrapper.EC_GROUP_new_curve_GFp(p, a, b, ctx);
        }

        public static IntPtr EC_GROUP_new_curve_GF2m(IntPtr p, IntPtr a, IntPtr b, IntPtr ctx)
        {
            return CryptoWrapper.EC_GROUP_new_curve_GF2m(p, a, b, ctx);
        }

        public static IntPtr EC_GROUP_new_by_curve_name(int nid)
        {
            return CryptoWrapper.EC_GROUP_new_by_curve_name(nid);
        }

        public static int EC_GROUP_precompute_mult(IntPtr group, IntPtr ctx)
        {
            return CryptoWrapper.EC_GROUP_precompute_mult(group, ctx);
        }

        public static int EC_GROUP_have_precompute_mult(IntPtr group)
        {
            return CryptoWrapper.EC_GROUP_have_precompute_mult(group);
        }

        #endregion

        #region EC_POINT

        public static IntPtr EC_POINT_new(IntPtr group)
        {
            return CryptoWrapper.EC_POINT_new(group);
        }

        public static void EC_POINT_free(IntPtr point)
        {
            CryptoWrapper.EC_POINT_free(point);
        }

        public static void EC_POINT_clear_free(IntPtr point)
        {
            CryptoWrapper.EC_POINT_clear_free(point);
        }

        public static int EC_POINT_copy(IntPtr dst, IntPtr src)
        {
            return CryptoWrapper.EC_POINT_copy(dst, src);
        }

        public static IntPtr EC_POINT_dup(IntPtr src, IntPtr group)
        {
            return CryptoWrapper.EC_POINT_dup(src, group);
        }

        public static IntPtr EC_POINT_method_of(IntPtr point)
        {
            return CryptoWrapper.EC_POINT_method_of(point);
        }

        public static int EC_POINT_set_to_infinity(IntPtr group, IntPtr point)
        {
            return CryptoWrapper.EC_POINT_set_to_infinity(group, point);
        }

        public static int EC_POINT_set_Jprojective_coordinates_GFp(
            IntPtr group,
            IntPtr p,
            IntPtr x,
            IntPtr y,
            IntPtr z,
            IntPtr ctx)
        {
            return CryptoWrapper.EC_POINT_set_Jprojective_coordinates_GFp(group, p, x, y, z, ctx);
        }

        public static int EC_POINT_get_Jprojective_coordinates_GFp(
            IntPtr group,
            IntPtr p,
            IntPtr x,
            IntPtr y,
            IntPtr z,
            IntPtr ctx)
        {
            return CryptoWrapper.EC_POINT_get_Jprojective_coordinates_GFp(group, p, x, y, z, ctx);
        }

        public static int EC_POINT_set_affine_coordinates_GFp(IntPtr group, IntPtr p, IntPtr x, IntPtr y, IntPtr ctx)
        {
            return CryptoWrapper.EC_POINT_set_affine_coordinates_GFp(group, p, x, y, ctx);
        }

        public static int EC_POINT_get_affine_coordinates_GFp(IntPtr group, IntPtr p, IntPtr x, IntPtr y, IntPtr ctx)
        {
            return CryptoWrapper.EC_POINT_get_affine_coordinates_GFp(group, p, x, y, ctx);
        }

        public static int EC_POINT_set_compressed_coordinates_GFp(
            IntPtr group,
            IntPtr p,
            IntPtr x,
            int y_bit,
            IntPtr ctx)
        {
            return CryptoWrapper.EC_POINT_set_compressed_coordinates_GFp(group, p, x, y_bit, ctx);
        }

        public static int EC_POINT_set_affine_coordinates_GF2m(IntPtr group, IntPtr p, IntPtr x, IntPtr y, IntPtr ctx)
        {
            return CryptoWrapper.EC_POINT_set_affine_coordinates_GF2m(group, p, x, y, ctx);
        }

        public static int EC_POINT_get_affine_coordinates_GF2m(IntPtr group, IntPtr p, IntPtr x, IntPtr y, IntPtr ctx)
        {
            return CryptoWrapper.EC_POINT_get_affine_coordinates_GF2m(group, p, x, y, ctx);
        }

        public static int EC_POINT_set_compressed_coordinates_GF2m(
            IntPtr group,
            IntPtr p,
            IntPtr x,
            int y_bit,
            IntPtr ctx)
        {
            return CryptoWrapper.EC_POINT_set_compressed_coordinates_GF2m(group, p, x, y_bit, ctx);
        }

        public static int EC_POINT_point2oct(IntPtr group, IntPtr p, int form, byte[] buf, int len, IntPtr ctx)
        {
            return CryptoWrapper.EC_POINT_point2oct(group, p, form, buf, len, ctx);
        }

        public static int EC_POINT_oct2point(IntPtr group, IntPtr p, byte[] buf, int len, IntPtr ctx)
        {
            return CryptoWrapper.EC_POINT_oct2point(group, p, buf, len, ctx);
        }

        public static IntPtr EC_POINT_point2bn(IntPtr a, IntPtr b, int form, IntPtr c, IntPtr d)
        {
            return CryptoWrapper.EC_POINT_point2bn(a, b, form, c, d);
        }

        public static IntPtr EC_POINT_bn2point(IntPtr a, IntPtr b, IntPtr c, IntPtr d)
        {
            return CryptoWrapper.EC_POINT_bn2point(a, b, c, d);
        }

        public static string EC_POINT_point2hex(IntPtr a, IntPtr b, int form, IntPtr c)
        {
            return CryptoWrapper.EC_POINT_point2hex(a, b, form, c);
        }

        public static IntPtr EC_POINT_hex2point(IntPtr a, string s, IntPtr b, IntPtr c)
        {
            return CryptoWrapper.EC_POINT_hex2point(a, s, b, c);
        }

        public static int EC_POINT_add(IntPtr group, IntPtr r, IntPtr a, IntPtr b, IntPtr ctx)
        {
            return CryptoWrapper.EC_POINT_add(group, r, a, b, ctx);
        }

        public static int EC_POINT_dbl(IntPtr group, IntPtr r, IntPtr a, IntPtr ctx)
        {
            return CryptoWrapper.EC_POINT_dbl(group, r, a, ctx);
        }

        public static int EC_POINT_invert(IntPtr group, IntPtr a, IntPtr ctx)
        {
            return CryptoWrapper.EC_POINT_invert(group, a, ctx);
        }

        public static int EC_POINT_is_at_infinity(IntPtr group, IntPtr p)
        {
            return CryptoWrapper.EC_POINT_is_at_infinity(group, p);
        }

        public static int EC_POINT_is_on_curve(IntPtr group, IntPtr point, IntPtr ctx)
        {
            return CryptoWrapper.EC_POINT_is_on_curve(group, point, ctx);
        }

        public static int EC_POINT_cmp(IntPtr group, IntPtr a, IntPtr b, IntPtr ctx)
        {
            return CryptoWrapper.EC_POINT_cmp(group, a, b, ctx);
        }

        public static int EC_POINT_make_affine(IntPtr a, IntPtr b, IntPtr c)
        {
            return CryptoWrapper.EC_POINT_make_affine(a, b, c);
        }

        public static int EC_POINTs_make_affine(IntPtr a, int num, IntPtr[] b, IntPtr c)
        {
            return CryptoWrapper.EC_POINTs_make_affine(a, num, b, c);
        }

        public static int EC_POINTs_mul(IntPtr group, IntPtr r, IntPtr n, int num, IntPtr[] p, IntPtr[] m, IntPtr ctx)
        {
            return CryptoWrapper.EC_POINTs_mul(group, r, n, num, p, m, ctx);
        }

        public static int EC_POINT_mul(IntPtr group, IntPtr r, IntPtr n, IntPtr q, IntPtr m, IntPtr ctx)
        {
            return CryptoWrapper.EC_POINT_mul(group, r, n, q, m, ctx);
        }

        #endregion

        #region EC_KEY
        public static IntPtr EC_KEY_new()
        {
            return CryptoWrapper.EC_KEY_new();
        }

        public static IntPtr EC_KEY_new_by_curve_name(int nid)
        {
            return CryptoWrapper.EC_KEY_new_by_curve_name(nid);
        }

        public static void EC_KEY_free(IntPtr key)
        {
            CryptoWrapper.EC_KEY_free(key);
        }

        public static IntPtr EC_KEY_copy(IntPtr dst, IntPtr src)
        {
            return CryptoWrapper.EC_KEY_copy(dst, src);
        }

        public static IntPtr EC_KEY_dup(IntPtr src)
        {
            return CryptoWrapper.EC_KEY_dup(src);
        }

        public static int EC_KEY_up_ref(IntPtr key)
        {
            return CryptoWrapper.EC_KEY_up_ref(key);
        }

        public static IntPtr EC_KEY_get0_group(IntPtr key)
        {
            return CryptoWrapper.EC_KEY_get0_group(key);
        }

        public static int EC_KEY_set_group(IntPtr key, IntPtr group)
        {
            return CryptoWrapper.EC_KEY_set_group(key, group);
        }

        public static IntPtr EC_KEY_get0_private_key(IntPtr key)
        {
            return CryptoWrapper.EC_KEY_get0_private_key(key);
        }

        public static int EC_KEY_set_private_key(IntPtr key, IntPtr prv)
        {
            return CryptoWrapper.EC_KEY_set_private_key(key, prv);
        }

        public static IntPtr EC_KEY_get0_public_key(IntPtr key)
        {
            return CryptoWrapper.EC_KEY_get0_public_key(key);
        }

        public static int EC_KEY_set_public_key(IntPtr key, IntPtr pub)
        {
            return CryptoWrapper.EC_KEY_set_public_key(key, pub);
        }

        public static uint EC_KEY_get_enc_flags(IntPtr key)
        {
            return CryptoWrapper.EC_KEY_get_enc_flags(key);
        }

        public static void EC_KEY_set_enc_flags(IntPtr x, uint y)
        {
            CryptoWrapper.EC_KEY_set_enc_flags(x, y);
        }

        public static int EC_KEY_get_conv_form(IntPtr x)
        {
            return CryptoWrapper.EC_KEY_get_conv_form(x);
        }

        public static void EC_KEY_set_conv_form(IntPtr x, int y)
        {
            CryptoWrapper.EC_KEY_set_conv_form(x, y);
        }

        public static IntPtr EC_KEY_get_key_method_data(
            IntPtr x,
            EC_KEY_dup_func dup_func,
            EC_KEY_free_func free_func,
            EC_KEY_free_func clear_free_func)
        {
            return CryptoWrapper.EC_KEY_get_key_method_data(x, dup_func, free_func, clear_free_func);
        }

        public static void EC_KEY_insert_key_method_data(
            IntPtr x,
            IntPtr data,
            EC_KEY_dup_func dup_func,
            EC_KEY_free_func free_func,
            EC_KEY_free_func clear_free_func)
        {
            CryptoWrapper.EC_KEY_insert_key_method_data(x, data, dup_func, free_func, clear_free_func);
        }

        public static void EC_KEY_set_asn1_flag(IntPtr x, int y)
        {
            CryptoWrapper.EC_KEY_set_asn1_flag(x, y);
        }

        public static int EC_KEY_precompute_mult(IntPtr key, IntPtr ctx)
        {
            return CryptoWrapper.EC_KEY_precompute_mult(key, ctx);
        }

        public static int EC_KEY_generate_key(IntPtr key)
        {
            return CryptoWrapper.EC_KEY_generate_key(key);
        }

        public static int EC_KEY_check_key(IntPtr key)
        {
            return CryptoWrapper.EC_KEY_check_key(key);
        }

        #endregion

        #region ECDSA

        public static IntPtr ECDSA_SIG_new()
        {
            return CryptoWrapper.ECDSA_SIG_new();
        }

        public static void ECDSA_SIG_free(IntPtr sig)
        {
            CryptoWrapper.ECDSA_SIG_free(sig);
        }

        public static int i2d_ECDSA_SIG(IntPtr sig, byte[] pp)
        {
            return CryptoWrapper.i2d_ECDSA_SIG(sig, pp);
        }

        public static IntPtr d2i_ECDSA_SIG(IntPtr sig, byte[] pp, long len)
        {
            return CryptoWrapper.d2i_ECDSA_SIG(sig, pp, len);
        }

        public static IntPtr ECDSA_do_sign(byte[] dgst, int dgst_len, IntPtr eckey)
        {
            return CryptoWrapper.ECDSA_do_sign(dgst, dgst_len, eckey);
        }

        public static IntPtr ECDSA_do_sign_ex(byte[] dgst, int dgstlen, IntPtr kinv, IntPtr rp, IntPtr eckey)
        {
            return CryptoWrapper.ECDSA_do_sign_ex(dgst, dgstlen, kinv, rp, eckey);
        }

        public static int ECDSA_do_verify(byte[] dgst, int dgst_len, IntPtr sig, IntPtr eckey)
        {
            return CryptoWrapper.ECDSA_do_verify(dgst, dgst_len, sig, eckey);
        }

        public static IntPtr ECDSA_OpenSSL()
        {
            return CryptoWrapper.ECDSA_OpenSSL();
        }

        public static void ECDSA_set_default_method(IntPtr meth)
        {
            CryptoWrapper.ECDSA_set_default_method(meth);
        }

        public static IntPtr ECDSA_get_default_method()
        {
            return CryptoWrapper.ECDSA_get_default_method();
        }

        public static int ECDSA_set_method(IntPtr eckey, IntPtr meth)
        {
            return CryptoWrapper.ECDSA_set_method(eckey, meth);
        }

        public static int ECDSA_size(IntPtr eckey)
        {
            return CryptoWrapper.ECDSA_size(eckey);
        }

        public static int ECDSA_sign_setup(IntPtr eckey, IntPtr ctx, IntPtr kinv, IntPtr rp)
        {
            return CryptoWrapper.ECDSA_sign_setup(eckey, ctx, kinv, rp);
        }

        public static int ECDSA_sign(int type, byte[] dgst, int dgstlen, byte[] sig, ref uint siglen, IntPtr eckey)
        {
            return CryptoWrapper.ECDSA_sign(type, dgst, dgstlen, sig, ref siglen, eckey);
        }

        public static int ECDSA_sign_ex(
            int type,
            byte[] dgst,
            int dgstlen,
            byte[] sig,
            ref uint siglen,
            IntPtr kinv,
            IntPtr rp,
            IntPtr eckey)
        {
            return CryptoWrapper.ECDSA_sign_ex(type, dgst, dgstlen, sig, ref siglen, kinv, rp, eckey);
        }

        public static int ECDSA_verify(int type, byte[] dgst, int dgstlen, byte[] sig, int siglen, IntPtr eckey)
        {
            return CryptoWrapper.ECDSA_verify(type, dgst, dgstlen, sig, siglen, eckey);
        }

        public static int ECDSA_get_ex_new_index(
            IntPtr argl,
            IntPtr argp,
            IntPtr new_func,
            IntPtr dup_func,
            IntPtr free_func)
        {
            return CryptoWrapper.ECDSA_get_ex_new_index(argl, argp, new_func, dup_func, free_func);
        }

        public static int ECDSA_set_ex_data(IntPtr d, int idx, IntPtr arg)
        {
            return CryptoWrapper.ECDSA_set_ex_data(d, idx, arg);
        }

        public static IntPtr ECDSA_get_ex_data(IntPtr d, int idx)
        {
            return CryptoWrapper.ECDSA_get_ex_data(d, idx);
        }

        public static void ERR_load_ECDSA_strings()
        {
            CryptoWrapper.ERR_load_ECDSA_strings();
        }

        #endregion

        #region ECDH

        public static IntPtr ECDH_OpenSSL()
        {
            return CryptoWrapper.ECDH_OpenSSL();
        }

        public static void ECDH_set_default_method(IntPtr method)
        {
            CryptoWrapper.ECDH_set_default_method(method);
        }

        public static IntPtr ECDH_get_default_method()
        {
            return CryptoWrapper.ECDH_get_default_method();
        }

        public static int ECDH_set_method(IntPtr key, IntPtr method)
        {
            return CryptoWrapper.ECDH_set_method(key, method);
        }

        public static int ECDH_compute_key(byte[] pout, int outlen, IntPtr pub_key, IntPtr ecdh, ECDH_KDF kdf)
        {
            return CryptoWrapper.ECDH_compute_key(pout, outlen, pub_key, ecdh, kdf);
        }

        public static int ECDH_get_ex_new_index(
            IntPtr argl,
            IntPtr argp,
            IntPtr new_func,
            IntPtr dup_func,
            IntPtr free_func)
        {
            return CryptoWrapper.ECDH_get_ex_new_index(argl, argp, new_func, dup_func, free_func);
        }

        public static int ECDH_set_ex_data(IntPtr d, int idx, IntPtr arg)
        {
            return CryptoWrapper.ECDH_set_ex_data(d, idx, arg);
        }

        public static IntPtr ECDH_get_ex_data(IntPtr d, int idx)
        {
            return CryptoWrapper.ECDH_get_ex_data(d, idx);
        }

        public static void ERR_load_ECDH_strings()
        {
            CryptoWrapper.ERR_load_ECDH_strings();
        }

        #endregion

        #endregion

        #region BIO
        public static IntPtr BIO_new_file(string filename, string mode)
        {
            return CryptoWrapper.BIO_new_file(filename, mode);
        }

        public static IntPtr BIO_new_mem_buf(byte[] buf, int len)
        {
            return CryptoWrapper.BIO_new_mem_buf(buf, len);
        }

        public static IntPtr BIO_s_mem()
        {
            return CryptoWrapper.BIO_s_mem();
        }

        public static IntPtr BIO_f_md()
        {
            return CryptoWrapper.BIO_f_md();
        }

        public static IntPtr BIO_f_null()
        {
            return CryptoWrapper.BIO_f_null();
        }

        const int BIO_C_SET_FD = 104;
        const int BIO_C_SET_MD = 111;
        const int BIO_C_GET_MD = 112;
        const int BIO_C_GET_MD_CTX = 120;
        const int BIO_C_SET_MD_CTX = 148;

        public const int BIO_NOCLOSE = 0x00;
        public const int BIO_CLOSE = 0x01;

        public static void BIO_set_md(IntPtr bp, IntPtr md)
        {
            Native.ExpectSuccess(BIO_ctrl(bp, BIO_C_SET_MD, 0, md));
        }

        // Unsupported!
        //public static void BIO_set_fd(IntPtr bp, int fd, int c)
        //{
        //    Native.ExpectSuccess(BIO_int_ctrl(bp, BIO_C_SET_FD, c, fd));
        //}

        public static IntPtr BIO_get_md(IntPtr bp)
        {
            var ptr = Marshal.AllocHGlobal(4);

            try
            {
                ExpectSuccess(BIO_ctrl(bp, BIO_C_GET_MD, 0, ptr));
                return Marshal.ReadIntPtr(ptr);
            }
            finally
            {
                Marshal.FreeHGlobal(ptr);
            }
        }

        public static IntPtr BIO_get_md_ctx(IntPtr bp)
        {
            var ptr = Marshal.AllocHGlobal(4);

            try
            {
                ExpectSuccess(BIO_ctrl(bp, BIO_C_GET_MD_CTX, 0, ptr));
                return Marshal.ReadIntPtr(ptr);
            }
            finally
            {
                Marshal.FreeHGlobal(ptr);
            }
        }

        public static void BIO_set_md_ctx(IntPtr bp, IntPtr mdcp)
        {
            Native.ExpectSuccess(BIO_ctrl(bp, BIO_C_SET_MD_CTX, 0, mdcp));
        }

        /* man - set the 'close' on free */
        const int BIO_CTRL_SET_CLOSE = 9;

        //#define BIO_set_close(b,c)	(int)BIO_ctrl(b,BIO_CTRL_SET_CLOSE,(c),NULL)
        public static int BIO_set_close(IntPtr bp, int arg)
        {
            return BIO_ctrl(bp, BIO_CTRL_SET_CLOSE, arg, IntPtr.Zero);
        }

        public static IntPtr BIO_push(IntPtr bp, IntPtr append)
        {
            return CryptoWrapper.BIO_push(bp, append);
        }

        public static int BIO_ctrl(IntPtr bp, int cmd, int larg, IntPtr parg)
        {
            return CryptoWrapper.BIO_ctrl(bp, cmd, larg, parg);
        }

        public static int BIO_int_ctrl(IntPtr bp, int cmd, int larg, int parg)
        {
            return CryptoWrapper.BIO_int_ctrl(bp, cmd, larg, parg);
        }

        public static IntPtr BIO_new(IntPtr type)
        {
            return CryptoWrapper.BIO_new(type);
        }

        public static int BIO_read(IntPtr b, byte[] buf, int len)
        {
            return CryptoWrapper.BIO_read(b, buf, len);
        }

        public static int BIO_write(IntPtr b, byte[] buf, int len)
        {
            return CryptoWrapper.BIO_write(b, buf, len);
        }

        public static int BIO_puts(IntPtr b, byte[] buf)
        {
            return CryptoWrapper.BIO_puts(b, buf);
        }

        public static int BIO_gets(IntPtr b, byte[] buf, int len)
        {
            return CryptoWrapper.BIO_gets(b, buf, len);
        }

        public static int BIO_free(IntPtr bio)
        {
            return CryptoWrapper.BIO_free(bio);
        }

        public static void BIO_free_all(IntPtr bio)
        {
            CryptoWrapper.BIO_free_all(bio);
        }

        public static uint BIO_number_read(IntPtr bio)
        {
            return CryptoWrapper.BIO_number_read(bio);
        }

        public static uint BIO_number_written(IntPtr bio)
        {
            return CryptoWrapper.BIO_number_written(bio);
        }

        public static uint BIO_ctrl_pending(IntPtr bio)
        {
            return CryptoWrapper.BIO_ctrl_pending(bio);
        }

        #endregion

        #region ERR

        public static void ERR_load_crypto_strings()
        {
            CryptoWrapper.ERR_load_crypto_strings();
        }

        public static uint ERR_get_error()
        {
            return CryptoWrapper.ERR_get_error();
        }

        public static void ERR_error_string_n(uint e, byte[] buf, int len)
        {
            CryptoWrapper.ERR_error_string_n(e, buf, len);
        }

        public static IntPtr ERR_lib_error_string(uint e)
        {
            return CryptoWrapper.ERR_lib_error_string(e);
        }

        public static IntPtr ERR_func_error_string(uint e)
        {
            return CryptoWrapper.ERR_func_error_string(e);
        }

        public static IntPtr ERR_reason_error_string(uint e)
        {
            return CryptoWrapper.ERR_reason_error_string(e);
        }

        public static void ERR_remove_thread_state(IntPtr tid)
        {
            CryptoWrapper.ERR_remove_thread_state(tid);
        }

        public static void ERR_clear_error()
        {
            CryptoWrapper.ERR_clear_error();
        }

        public static void ERR_print_errors_cb(err_cb cb, IntPtr u)
        {
            CryptoWrapper.ERR_print_errors_cb(cb, u);
        }

        #endregion

        #region NCONF

        public static IntPtr NCONF_new(IntPtr meth)
        {
            return CryptoWrapper.NCONF_new(meth);
        }

        public static void NCONF_free(IntPtr conf)
        {
            CryptoWrapper.NCONF_free(conf);
        }

        public static int NCONF_load(IntPtr conf, string file, ref int eline)
        {
            return CryptoWrapper.NCONF_load(conf, file, ref eline);
        }

        public static IntPtr NCONF_get_string(IntPtr conf, byte[] group, byte[] name)
        {
            return CryptoWrapper.NCONF_get_string(conf, group, name);
        }

        public static void X509V3_set_ctx(
            IntPtr ctx,
            IntPtr issuer,
            IntPtr subject,
            IntPtr req,
            IntPtr crl,
            int flags)
        {
            CryptoWrapper.X509V3_set_ctx(ctx, issuer, subject, req, crl, flags);
        }

        public static void X509V3_set_nconf(IntPtr ctx, IntPtr conf)
        {
            CryptoWrapper.X509V3_set_nconf(ctx, conf);
        }

        public static int X509V3_EXT_add_nconf(IntPtr conf, IntPtr ctx, byte[] section, IntPtr cert)
        {
            return CryptoWrapper.X509V3_EXT_add_nconf(conf, ctx, section, cert);
        }

        #endregion

        #region FIPS

        public static int FIPS_mode_set(int onoff)
        {
            return CryptoWrapper.FIPS_mode_set(onoff);
        }

        #endregion

        #region SSL Routines

        #region Initialization

        public static void SSL_load_error_strings()
        {
            SSLWrapper.SSL_load_error_strings();
        }

        public static int SSL_library_init()
        {
            return SSLWrapper.SSL_library_init();
        }

        #endregion

        #region SSL Methods

        public static IntPtr SSLv2_method()
        {
            return SSLWrapper.SSLv2_method();
        }

        public static IntPtr SSLv2_server_method()
        {
            return SSLWrapper.SSLv2_server_method();
        }

        public static IntPtr SSLv2_client_method()
        {
            return SSLWrapper.SSLv2_client_method();
        }

        public static IntPtr SSLv3_method()
        {
            return SSLWrapper.SSLv3_method();
        }

        public static IntPtr SSLv3_server_method()
        {
            return SSLWrapper.SSLv3_server_method();
        }

        public static IntPtr SSLv3_client_method()
        {
            return SSLWrapper.SSLv3_client_method();
        }

        public static IntPtr SSLv23_method()
        {
            return SSLWrapper.SSLv23_method();
        }

        public static IntPtr SSLv23_server_method()
        {
            return SSLWrapper.SSLv23_server_method();
        }

        public static IntPtr SSLv23_client_method()
        {
            return SSLWrapper.SSLv23_client_method();
        }

        public static IntPtr TLSv1_method()
        {
            return SSLWrapper.TLSv1_method();
        }

        public static IntPtr TLSv1_client_method()
        {
            return SSLWrapper.TLSv1_client_method();
        }

        public static IntPtr TLSv1_server_method()
        {
            return SSLWrapper.TLSv1_server_method();
        }

        public static IntPtr TLSv1_1_method()
        {
            return SSLWrapper.TLSv1_1_method();
        }

        public static IntPtr TLSv1_1_server_method()
        {
            return SSLWrapper.TLSv1_1_server_method();
        }

        public static IntPtr TLSv1_1_client_method()
        {
            return SSLWrapper.TLSv1_1_client_method();
        }

        public static IntPtr TLSv1_2_method()
        {
            return SSLWrapper.TLSv1_2_method();
        }

        public static IntPtr TLSv1_2_server_method()
        {
            return SSLWrapper.TLSv1_2_server_method();
        }

        public static IntPtr TLSv1_2_client_method()
        {
            return SSLWrapper.TLSv1_2_client_method();
        }

        public static IntPtr DTLSv1_method()
        {
            return SSLWrapper.DTLSv1_method();
        }

        public static IntPtr DTLSv1_client_method()
        {
            return SSLWrapper.DTLSv1_client_method();
        }

        public static IntPtr DTLSv1_server_method()
        {
            return SSLWrapper.DTLSv1_server_method();
        }

        public static IntPtr DTLSv1_2_method()
        {
            return SSLWrapper.DTLSv1_2_method();
        }

        public static IntPtr DTLSv1_2_client_method()
        {
            return SSLWrapper.DTLSv1_2_client_method();
        }

        public static IntPtr DTLSv1_2_server_method()
        {
            return SSLWrapper.DTLSv1_2_server_method();
        }


        #endregion

        #region SSL_CTX

        public static IntPtr SSL_CTX_new(IntPtr sslMethod)
        {
            return SSLWrapper.SSL_CTX_new(sslMethod);
        }

        public static void SSL_CTX_free(IntPtr ctx)
        {
            SSLWrapper.SSL_CTX_free(ctx);
        }

        public static int SSL_CTX_ctrl(IntPtr ctx, int cmd, int arg, IntPtr parg)
        {
            return SSLWrapper.SSL_CTX_ctrl(ctx, cmd, arg, parg);
        }

        public const int SSL_CTRL_OPTIONS = 32;
        public const int SSL_CTRL_MODE = 33;

        public const int SSL_OP_MICROSOFT_SESS_ID_BUG = 0x00000001;
        public const int SSL_OP_NETSCAPE_CHALLENGE_BUG = 0x00000002;
        public const int SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG = 0x00000008;
        public const int SSL_OP_SSLREF2_REUSE_CERT_TYPE_BUG = 0x00000010;
        public const int SSL_OP_MICROSOFT_BIG_SSLV3_BUFFER = 0x00000020;
        /* no effect since 0.9.7h and 0.9.8b */
        public const int SSL_OP_MSIE_SSLV2_RSA_PADDING = 0x00000040;
        public const int SSL_OP_SSLEAY_080_CLIENT_DH_BUG = 0x00000080;
        public const int SSL_OP_TLS_D5_BUG = 0x00000100;
        public const int SSL_OP_TLS_BLOCK_PADDING_BUG = 0x00000200;

        /* Disable SSL 3.0/TLS 1.0 CBC vulnerability workaround that was added
         * in OpenSSL 0.9.6d.  Usually (depending on the application protocol)
         * the workaround is not needed.  Unfortunately some broken SSL/TLS
         * implementations cannot handle it at all, which is why we include
         * it in SSL_OP_ALL. */
        /* added in 0.9.6e */
        public const int SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS = 0x00000800;

        /* SSL_OP_ALL: various bug workarounds that should be rather harmless.
         *             This used to be 0x000FFFFFL before 0.9.7. */
        public const int SSL_OP_ALL = (0x00000FFF ^ SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG);

        /* As server, disallow session resumption on renegotiation */
        public const int SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION = 0x00010000;
        /* If set, always create a new key when using tmp_dh parameters */
        public const int SSL_OP_SINGLE_DH_USE = 0x00100000;
        /* Set to always use the tmp_rsa key when doing RSA operations,
         * even when this violates protocol specs */
        public const int SSL_OP_EPHEMERAL_RSA = 0x00200000;
        /* Set on servers to choose the cipher according to the server's
         * preferences */
        public const int SSL_OP_CIPHER_SERVER_PREFERENCE = 0x00400000;
        /* If set, a server will allow a client to issue a SSLv3.0 version number
         * as latest version supported in the premaster secret, even when TLSv1.0
         * (version 3.1) was announced in the client hello. Normally this is
         * forbidden to prevent version rollback attacks. */
        public const int SSL_OP_TLS_ROLLBACK_BUG = 0x00800000;

        public const int SSL_OP_NO_SSLv2 = 0x01000000;
        public const int SSL_OP_NO_SSLv3 = 0x02000000;
        public const int SSL_OP_NO_TLSv1 = 0x04000000;

        /* The next flag deliberately changes the ciphertest, this is a check
         * for the PKCS#1 attack */
        public const int SSL_OP_PKCS1_CHECK_1 = 0x08000000;
        public const int SSL_OP_PKCS1_CHECK_2 = 0x10000000;
        public const int SSL_OP_NETSCAPE_CA_DN_BUG = 0x20000000;
        public const int SSL_OP_NETSCAPE_DEMO_CIPHER_CHANGE_BUG = 0x40000000;


        /* Allow SSL_write(..., n) to return r with 0 < r < n (i.e. report success
         * when just a single record has been written): */
        public const int SSL_MODE_ENABLE_PARTIAL_WRITE = 0x00000001;
        /* Make it possible to retry SSL_write() with changed buffer location
         * (buffer contents must stay the same!); this is not the default to avoid
         * the misconception that non-blocking SSL_write() behaves like
         * non-blocking write(): */
        public const int SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER = 0x00000002;
        /* Never bother the application with retries if the transport
         * is blocking: */
        public const int SSL_MODE_AUTO_RETRY = 0x00000004;
        /* Don't attempt to automatically build certificate chain */
        public const int SSL_MODE_NO_AUTO_CHAIN = 0x00000008;

        /// <summary>
        /// #define SSL_CTX_ctrl in ssl.h - calls SSL_CTX_ctrl()
        /// </summary>
        /// <param name="ctx"></param>
        /// <param name="op"></param>
        /// <returns></returns>
        public static int SSL_CTX_set_mode(IntPtr ctx, int op)
        {
            return SSL_CTX_ctrl(ctx, SSL_CTRL_MODE, op, IntPtr.Zero);
        }

        /// <summary>
        /// #define SSL_CTX_get_mode in ssl.h - calls SSL_CTX_ctrl
        /// </summary>
        /// <param name="ctx"></param>
        /// <returns></returns>
        public static int SSL_CTX_get_mode(IntPtr ctx)
        {
            return SSL_CTX_ctrl(ctx, SSL_CTRL_MODE, 0, IntPtr.Zero);
        }

        /// <summary>
        /// #define SSL_CTX_set_options in ssl.h - calls SSL_CTX_ctrl
        /// </summary>
        /// <param name="ctx"></param>
        /// <param name="op"></param>
        /// <returns></returns>
        public static int SSL_CTX_set_options(IntPtr ctx, int op)
        {
            return SSL_CTX_ctrl(ctx, SSL_CTRL_OPTIONS, op, IntPtr.Zero);
        }

        /// <summary>
        /// #define SSL_CTX_get_options in ssl.h - calls SSL_CTX_ctrl
        /// </summary>
        /// <param name="ctx"></param>
        /// <returns>Int32 representation of options set in the context</returns>
        public static int SSL_CTX_get_options(IntPtr ctx)
        {
            return SSL_CTX_ctrl(ctx, SSL_CTRL_OPTIONS, 0, IntPtr.Zero);
        }

        public static void SSL_CTX_set_cert_store(IntPtr ctx, IntPtr cert_store)
        {
            SSLWrapper.SSL_CTX_set_cert_store(ctx, cert_store);
        }

        public const int SSL_VERIFY_NONE = 0x00;
        public const int SSL_VERIFY_PEER = 0x01;
        public const int SSL_VERIFY_FAIL_IF_NO_PEER_CERT = 0x02;
        public const int SSL_VERIFY_CLIENT_ONCE = 0x04;

        public static void SSL_CTX_set_verify(IntPtr ctx, int mode, VerifyCertCallback callback)
        {
            SSLWrapper.SSL_CTX_set_verify(ctx, mode, callback);
        }

        public static void SSL_CTX_set_verify_depth(IntPtr ctx, int depth)
        {
            SSLWrapper.SSL_CTX_set_verify_depth(ctx, depth);
        }

        public static void SSL_CTX_set_client_CA_list(IntPtr ctx, IntPtr name_list)
        {
            SSLWrapper.SSL_CTX_set_client_CA_list(ctx, name_list);
        }

        public static IntPtr SSL_CTX_get_client_CA_list(IntPtr ctx)
        {
            return SSLWrapper.SSL_CTX_get_client_CA_list(ctx);
        }

        public static int SSL_CTX_load_verify_locations(IntPtr ctx, string file, string path)
        {
            return SSLWrapper.SSL_CTX_load_verify_locations(ctx, file, path);
        }

        public static int SSL_CTX_set_default_verify_paths(IntPtr ctx)
        {
            return SSLWrapper.SSL_CTX_set_default_verify_paths(ctx);
        }

        public static int SSL_CTX_set_cipher_list(IntPtr ctx, string cipher_string)
        {
            return SSLWrapper.SSL_CTX_set_cipher_list(ctx, cipher_string);
        }

        public static int SSL_CTX_use_certificate_chain_file(IntPtr ctx, string file)
        {
            return SSLWrapper.SSL_CTX_use_certificate_chain_file(ctx, file);
        }

        public static int SSL_CTX_use_certificate(IntPtr ctx, IntPtr cert)
        {
            return SSLWrapper.SSL_CTX_use_certificate(ctx, cert);
        }

        public static int SSL_CTX_use_PrivateKey(IntPtr ctx, IntPtr pkey)
        {
            return SSLWrapper.SSL_CTX_use_PrivateKey(ctx, pkey);
        }

        public static int SSL_CTX_use_PrivateKey_file(IntPtr ctx, string file, int type)
        {
            return SSLWrapper.SSL_CTX_use_PrivateKey_file(ctx, file, type);
        }

        public static int SSL_CTX_check_private_key(IntPtr ctx)
        {
            return SSLWrapper.SSL_CTX_check_private_key(ctx);
        }

        public const int SSL_MAX_SID_CTX_LENGTH = 32;

        public static int SSL_CTX_set_session_id_context(IntPtr ctx, byte[] sid_ctx, uint sid_ctx_len)
        {
            return SSLWrapper.SSL_CTX_set_session_id_context(ctx, sid_ctx, sid_ctx_len);
        }

        public static void SSL_CTX_set_default_passwd_cb_userdata(IntPtr ssl, IntPtr data)
        {
            SSLWrapper.SSL_CTX_set_default_passwd_cb_userdata(ssl, data);
        }

        public static void SSL_CTX_set_default_passwd_cb(IntPtr ssl, pem_password_cb callback)
        {
            SSLWrapper.SSL_CTX_set_default_passwd_cb(ssl, callback);
        }

        public static void SSL_CTX_set_client_cert_cb(IntPtr ssl_ctx, client_cert_cb callback)
        {
            SSLWrapper.SSL_CTX_set_client_cert_cb(ssl_ctx, callback);
        }

        #endregion

        #region SSL functions

        public static string SSL_CIPHER_description(IntPtr ssl_cipher, byte[] buf, int buf_len)
        {
            return SSLWrapper.SSL_CIPHER_description(ssl_cipher, buf, buf_len);
        }

        public static IntPtr SSL_CIPHER_get_name(IntPtr ssl_cipher)
        {
            return SSLWrapper.SSL_CIPHER_get_name(ssl_cipher);
        }

        public static int SSL_CIPHER_get_bits(IntPtr ssl_cipher, out int alg_bits)
        {
            return SSLWrapper.SSL_CIPHER_get_bits(ssl_cipher, out alg_bits);
        }

        public static IntPtr SSL_CIPHER_get_version(IntPtr ssl_cipher)
        {
            return SSLWrapper.SSL_CIPHER_get_version(ssl_cipher);
        }

        public static IntPtr SSL_get_current_cipher(IntPtr ssl)
        {
            return SSLWrapper.SSL_get_current_cipher(ssl);
        }

        public static IntPtr SSL_get_ciphers(IntPtr ssl)
        {
            return SSLWrapper.SSL_get_ciphers(ssl);
        }

        public static int SSL_get_verify_result(IntPtr ssl)
        {
            return SSLWrapper.SSL_get_verify_result(ssl);
        }

        public static int SSL_set_verify_result(IntPtr ssl, int v)
        {
            return SSLWrapper.SSL_set_verify_result(ssl, v);
        }

        public static IntPtr SSL_get_peer_certificate(IntPtr ssl)
        {
            return SSLWrapper.SSL_get_peer_certificate(ssl);
        }

        public static int SSL_get_error(IntPtr ssl, int ret_code)
        {
            return SSLWrapper.SSL_get_error(ssl, ret_code);
        }

        public static int SSL_accept(IntPtr ssl)
        {
            return SSLWrapper.SSL_accept(ssl);
        }

        public static int SSL_shutdown(IntPtr ssl)
        {
            return SSLWrapper.SSL_shutdown(ssl);
        }

        public static int SSL_write(IntPtr ssl, byte[] buf, int len)
        {
            return SSLWrapper.SSL_write(ssl, buf, len);
        }

        public static int SSL_read(IntPtr ssl, byte[] buf, int len)
        {
            return SSLWrapper.SSL_read(ssl, buf, len);
        }

        public static int SSL_renegotiate(IntPtr ssl)
        {
            return SSLWrapper.SSL_renegotiate(ssl);
        }

        public static int SSL_set_session_id_context(IntPtr ssl, byte[] sid_ctx, uint sid_ctx_len)
        {
            return SSLWrapper.SSL_set_session_id_context(ssl, sid_ctx, sid_ctx_len);
        }

        public static int SSL_do_handshake(IntPtr ssl)
        {
            return SSLWrapper.SSL_do_handshake(ssl);
        }

        public static void SSL_set_connect_state(IntPtr ssl)
        {
            SSLWrapper.SSL_set_connect_state(ssl);
        }

        public static void SSL_set_accept_state(IntPtr ssl)
        {
            SSLWrapper.SSL_set_accept_state(ssl);
        }

        public static int SSL_connect(IntPtr ssl)
        {
            return SSLWrapper.SSL_connect(ssl);
        }

        public static IntPtr SSL_new(IntPtr ctx)
        {
            return SSLWrapper.SSL_new(ctx);
        }

        public static void SSL_free(IntPtr ssl)
        {
            SSLWrapper.SSL_free(ssl);
        }

        public static int SSL_state(IntPtr ssl)
        {
            return SSLWrapper.SSL_state(ssl);
        }

        public static void SSL_set_state(IntPtr ssl, int state)
        {
            SSLWrapper.SSL_set_state(ssl, state);
        }

        public static void SSL_set_bio(IntPtr ssl, IntPtr read_bio, IntPtr write_bio)
        {
            SSLWrapper.SSL_set_bio(ssl, read_bio, write_bio);
        }

        public static int SSL_use_certificate_file(IntPtr ssl, string file, int type)
        {
            return SSLWrapper.SSL_use_certificate_file(ssl, file, type);
        }

        public static int SSL_use_PrivateKey_file(IntPtr ssl, string file, int type)
        {
            return SSLWrapper.SSL_use_PrivateKey_file(ssl, file, type);
        }

        public static int SSL_version(IntPtr ssl)
        {
            return SSLWrapper.SSL_version(ssl);
        }

        public static int SSL_clear(IntPtr ssl)
        {
            return SSLWrapper.SSL_clear(ssl);
        }

        public static IntPtr SSL_load_client_CA_file(string file)
        {
            return SSLWrapper.SSL_load_client_CA_file(file);
        }

        public static IntPtr SSL_get_client_CA_list(IntPtr ssl)
        {
            return SSLWrapper.SSL_get_client_CA_list(ssl);
        }

        public static void SSL_set_client_CA_list(IntPtr ssl, IntPtr name_list)
        {
            SSLWrapper.SSL_set_client_CA_list(ssl, name_list);
        }

        public static IntPtr SSL_get_certificate(IntPtr ssl)
        {
            return SSLWrapper.SSL_get_certificate(ssl);
        }

        public static int SSL_use_certificate(IntPtr ssl, IntPtr x509)
        {
            return SSLWrapper.SSL_use_certificate(ssl, x509);
        }

        public static int SSL_use_PrivateKey(IntPtr ssl, IntPtr evp_pkey)
        {
            return SSLWrapper.SSL_use_PrivateKey(ssl, evp_pkey);
        }

        public static int SSL_ctrl(IntPtr ssl, int cmd, int larg, IntPtr parg)
        {
            return SSLWrapper.SSL_ctrl(ssl, cmd, larg, parg);
        }

        public static IntPtr SSL_get_servername(IntPtr s, int type)
        {
            return SSLWrapper.SSL_get_servername(s, type);
        }

        public static int SSL_get_servername_type(IntPtr s)
        {
            return SSLWrapper.SSL_get_servername_type(s);
        }

        public static IntPtr SSL_get_session(IntPtr s)
        {
            return SSLWrapper.SSL_get_session(s);
        }

        public static int SSL_CTX_callback_ctrl(IntPtr ctx, int cmd, IntPtr cb)
        {
            return SSLWrapper.SSL_CTX_callback_ctrl(ctx, cmd, cb);
        }

        #endregion

        #endregion

        #region Utilities

        public static string StaticString(IntPtr ptr)
        {
            return Marshal.PtrToStringAnsi(ptr);
        }

        public static string PtrToStringAnsi(IntPtr ptr, bool hasOwnership)
        {
            var len = 0;
            for (var i = 0; i < 1024; i++, len++)
            {
                var octet = Marshal.ReadByte(ptr, i);
                if (octet == 0)
                    break;
            }

            if (len == 1024)
                return "Invalid string";

            var buf = new byte[len];
            Marshal.Copy(ptr, buf, 0, len);
            if (hasOwnership)
                Native.OPENSSL_free(ptr);

            return Encoding.ASCII.GetString(buf, 0, len);
        }

        public static IntPtr ExpectNonNull(IntPtr ptr)
        {
            if (ptr == IntPtr.Zero)
                throw new OpenSslException();

            return ptr;
        }

        public static int ExpectSuccess(int ret)
        {
            if (ret <= 0)
                throw new OpenSslException();

            return ret;
        }

        public static int TextToNID(string text)
        {
            var nid = Native.OBJ_txt2nid(text);

            if (nid == Native.NID_undef)
                throw new OpenSslException();

            return nid;
        }

        #endregion
    }

    class NameCollector
    {
        [StructLayout(LayoutKind.Sequential)]
        struct OBJ_NAME
        {
            public int type;
            public int alias;
            public IntPtr name;
            public IntPtr data;
        };

        private List<string> list = new List<string>();

        public List<string> Result { get { return list; } }

        public NameCollector(int type, bool isSorted)
        {
            if (isSorted)
                Native.OBJ_NAME_do_all_sorted(type, OnObjectName, IntPtr.Zero);
            else
                Native.OBJ_NAME_do_all(type, OnObjectName, IntPtr.Zero);
        }

        private void OnObjectName(IntPtr ptr, IntPtr arg)
        {
            var name = Marshal.PtrToStructure<OBJ_NAME>(ptr);
            var str = Native.PtrToStringAnsi(name.name, false);
            list.Add(str);
        }
    }
}
