using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Runtime.InteropServices;

using OpenSSL.Core.Interop.Attributes;
using OpenSSL.Core.Interop.SafeHandles;
using OpenSSL.Core.Interop.SafeHandles.X509;
using OpenSSL.Core.Interop.SafeHandles.Crypto;
using OpenSSL.Core.Interop.SafeHandles.Crypto.EC;

namespace OpenSSL.Core.Interop.Wrappers
{
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate int err_cb(IntPtr str, uint len, IntPtr u);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate int pem_password_cb(IntPtr buf, int size, int rwflag, IntPtr userdata);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate int GeneratorHandler(int p, int n, IntPtr arg);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate void ObjectNameHandler(IntPtr name, IntPtr arg);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate void CRYPTO_locking_callback(int mode, int type, string file, int line);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate void CRYPTO_id_callback(IntPtr tid);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate IntPtr MallocFunctionPtr(uint num, IntPtr file, int line);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate IntPtr ReallocFunctionPtr(IntPtr addr, uint num, IntPtr file, int line);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate IntPtr FreeFunctionPtr(IntPtr addr, IntPtr file, int line);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate IntPtr EC_KEY_dup_func(IntPtr x);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate IntPtr ECDH_KDF([MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 1)] byte[] pin, int inlen, IntPtr pout, ref int outlen);

    [StructLayout(LayoutKind.Sequential)]
    public class bn_gencb_st
    {
        /// To handle binary (in)compatibility
        public uint ver;
        /// callback-specific data
        public IntPtr arg;
        public GeneratorHandler cb;
    }

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate void EC_KEY_free_func(IntPtr x);

    internal delegate void OPENSSL_sk_freefunc(IntPtr ptr);

    internal interface ILibCryptoWrapper
    {
        //const char *SSLeay_version(int type);
        IntPtr OpenSSL_version(int type);
        //long SSLeay(void);
        ulong OpenSSL_version_num();

        //int OPENSSL_init_crypto(uint64_t opts, const OPENSSL_INIT_SETTINGS *settings);
        int OPENSSL_init_crypto(ulong opts, IntPtr settings);

        //void OpenSSL_add_all_algorithms(void);
        void OPENSSL_add_all_algorithms_noconf();
        void OPENSSL_add_all_algorithms_conf();

        void OBJ_NAME_do_all(int type, ObjectNameHandler fn, IntPtr arg);
        void OBJ_NAME_do_all_sorted(int type, ObjectNameHandler fn, IntPtr arg);

        //int OBJ_txt2nid(const char *s);
        int OBJ_txt2nid(string s);
        //ASN1_OBJECT * OBJ_nid2obj(int n);
        [return: DontTakeOwnership]
        SafeAsn1ObjectHandle OBJ_nid2obj(int n);
        //const char *  OBJ_nid2ln(int n);
        IntPtr OBJ_nid2ln(int n);
        //const char *  OBJ_nid2sn(int n);
        IntPtr OBJ_nid2sn(int n);
        //int OBJ_obj2nid(const ASN1_OBJECT *o);
        int OBJ_obj2nid(SafeAsn1ObjectHandle o);
        //ASN1_OBJECT * OBJ_txt2obj(const char *s, int no_name);
        [return: DontTakeOwnership]
        SafeAsn1ObjectHandle OBJ_txt2obj(in byte s, int no_name);
        //int OBJ_ln2nid(const char *ln);
        int OBJ_ln2nid(string s);
        //int OBJ_sn2nid(const char *sn);
        int OBJ_sn2nid(string s);
        //ASN1_OBJECT *OBJ_dup(ASN1_OBJECT *o);
        IntPtr OBJ_dup(SafeAsn1ObjectHandle o);
        //int OBJ_cmp(const ASN1_OBJECT *a,const ASN1_OBJECT *b);
        [DontCheckReturnType]
        int OBJ_cmp(SafeAsn1ObjectHandle a, SafeAsn1ObjectHandle b);
        //void ASN1_OBJECT_free(ASN1_OBJECT *o);
        void ASN1_OBJECT_free(IntPtr o);

        #region STACKOF
        //TODO: WHAT???
        [return: NewSafeHandle]
        SafeStackHandle<TStackable> OPENSSL_sk_new_null<TStackable>()
            where TStackable : SafeBaseHandle, IStackable;
        [DontCheckReturnType]
        int OPENSSL_sk_num<TStackable>(SafeStackHandle<TStackable> stack)
            where TStackable : SafeBaseHandle, IStackable;
        [DontCheckReturnType]
        int OPENSSL_sk_find<TStackable>(SafeStackHandle<TStackable> stack, TStackable data)
            where TStackable : SafeBaseHandle, IStackable;
        int OPENSSL_sk_insert<TStackable>(SafeStackHandle<TStackable> stack, TStackable data, int where)
            where TStackable : SafeBaseHandle, IStackable;
        TStackable OPENSSL_sk_shift<TStackable>(SafeStackHandle<TStackable> stack)
            where TStackable : SafeBaseHandle, IStackable;
        int OPENSSL_sk_unshift<TStackable>(SafeStackHandle<TStackable> stack, TStackable data)
            where TStackable : SafeBaseHandle, IStackable;
        int OPENSSL_sk_push<TStackable>(SafeStackHandle<TStackable> stack, TStackable data)
            where TStackable : SafeBaseHandle, IStackable;
        TStackable OPENSSL_sk_pop<TStackable>(SafeStackHandle<TStackable> stack)
            where TStackable : SafeBaseHandle, IStackable;
        [DontCheckReturnType]
        [return: DontTakeOwnership]
        TStackable OPENSSL_sk_delete<TStackable>(SafeStackHandle<TStackable> stack, int loc)
            where TStackable : SafeBaseHandle, IStackable;
        [DontCheckReturnType]
        [return: DontTakeOwnership]
        TStackable OPENSSL_sk_delete_ptr<TStackable>(SafeStackHandle<TStackable> stack, TStackable p)
            where TStackable : SafeBaseHandle, IStackable;
        TStackable OPENSSL_sk_value<TStackable>(SafeStackHandle<TStackable> stack, int index)
            where TStackable : SafeBaseHandle, IStackable;
        TStackable OPENSSL_sk_set<TStackable>(SafeStackHandle<TStackable> stack, int index, TStackable data)
            where TStackable : SafeBaseHandle, IStackable;
        IntPtr OPENSSL_sk_dup<TStackable>(SafeStackHandle<TStackable> stack)
            where TStackable : SafeBaseHandle, IStackable;
        void OPENSSL_sk_zero<TStackable>(SafeStackHandle<TStackable> stack)
            where TStackable : SafeBaseHandle, IStackable;
        void OPENSSL_sk_free(IntPtr stack);
        //void OPENSSL_sk_pop_free(OPENSSL_STACK* st, OPENSSL_sk_freefunc func)
        void OPENSSL_sk_pop_free<TStackable>(SafeStackHandle<TStackable> st, OPENSSL_sk_freefunc func)
            where TStackable : SafeBaseHandle, IStackable;
        #endregion

        #region ASN1_INTEGER
        [return: NewSafeHandle]
        SafeAsn1IntegerHandle ASN1_INTEGER_new();
        void ASN1_INTEGER_free(IntPtr x);
        IntPtr ASN1_INTEGER_dup(SafeAsn1IntegerHandle x);

        int ASN1_INTEGER_set(SafeAsn1IntegerHandle a, long v);
        int ASN1_INTEGER_get(SafeAsn1IntegerHandle a);
        #endregion

        #region ASN1_TIME
        [return: NewSafeHandle]
        SafeAsn1DateTimeHandle ASN1_TIME_new();
        void ASN1_TIME_free(IntPtr x);

        //ASN1_TIME *ASN1_TIME_set(ASN1_TIME *s, time_t t);
        SafeAsn1DateTimeHandle ASN1_TIME_set(SafeAsn1DateTimeHandle s, long t);
        //ASN1_TIME* ASN1_TIME_adj(ASN1_TIME* s, time_t t, int offset_day, long offset_sec);
        SafeAsn1DateTimeHandle ASN1_TIME_adj(SafeAsn1DateTimeHandle s, long t, int offset_day, long offset_sec);
        //int ASN1_TIME_print(BIO *fp, const ASN1_TIME *a);
        int ASN1_TIME_print(SafeBioHandle bp, SafeAsn1DateTimeHandle a);
        //ASN1_TIME *X509_time_adj_ex(ASN1_TIME *asn1_time, int offset_day, long offset_sec, time_t* in_tm);
        SafeAsn1DateTimeHandle X509_time_adj(SafeAsn1DateTimeHandle asn1_time, int offset_day, long offset_sec, ref long in_tm);
        #endregion

        #region ASN1_STRING
        [return: NewSafeHandle]
        SafeAsn1StringHandle ASN1_STRING_type_new(int type);
        void ASN1_STRING_free(IntPtr a);
        IntPtr ASN1_STRING_dup(SafeAsn1StringHandle a);

        int ASN1_STRING_cmp(SafeAsn1StringHandle a, SafeAsn1StringHandle b);
        int ASN1_STRING_set(SafeAsn1StringHandle str, in byte data, int len);
        IntPtr ASN1_STRING_get0_data(SafeAsn1StringHandle x);
        //int ASN1_STRING_to_UTF8(unsigned char**out, const ASN1_STRING*in)
        [DontCheckReturnType]
        int ASN1_STRING_to_UTF8(out IntPtr strPtr, SafeAsn1StringHandle str);
        int ASN1_STRING_length(SafeAsn1StringHandle x);
        #endregion

        #region ASN1_OCTET_STRING
        [return: NewSafeHandle]
        SafeASN1OctetStringHandle ASN1_OCTET_STRING_new();
        IntPtr ASN1_OCTET_STRING_dup(SafeASN1OctetStringHandle a);
        void ASN1_OCTET_STRING_free(IntPtr a);

        int ASN1_OCTET_STRING_set(SafeASN1OctetStringHandle str, in byte data, int len);
        int ASN1_OCTET_STRING_cmp(SafeASN1OctetStringHandle a, SafeASN1OctetStringHandle b);
        #endregion

        #region ASN1_OCTET_STRING
        [return: NewSafeHandle]
        SafeASN1BitStringHandle ASN1_BIT_STRING_new();
        IntPtr ASN1_BIT_STRING_dup(SafeASN1BitStringHandle a);
        void ASN1_BIT_STRING_free(IntPtr a);

        int ASN1_BIT_STRING_set(SafeASN1BitStringHandle str, in byte data, int len);
        #endregion

        #region X509_NAME
        [return: NewSafeHandle]
        SafeX509NameHandle X509_NAME_new();
        void X509_NAME_free(IntPtr a);
        IntPtr X509_NAME_dup(SafeX509NameHandle xn);
        [DontCheckReturnType]
        int X509_NAME_cmp(SafeX509NameHandle a, SafeX509NameHandle b);

        //int X509_NAME_entry_count(const X509_NAME *name);
        int X509_NAME_entry_count(SafeX509NameHandle name);
        //int X509_NAME_get_text_by_NID(X509_NAME *name, int nid, char *buf, int len);
        int X509_NAME_get_text_by_NID(SafeX509NameHandle name, int nid, ref byte buf, int len);
        int X509_NAME_get_text_by_NID(SafeX509NameHandle name, int nid, IntPtr buf, int len); //with IntPtr to get the length
        //X509_NAME_ENTRY *X509_NAME_get_entry(const X509_NAME *name, int loc);
        IntPtr X509_NAME_get_entry(SafeX509NameHandle name, int loc);

        //int X509_NAME_add_entry_by_NID(X509_NAME *name, int nid, int type, unsigned char *bytes, int len, int loc, int set);
        int X509_NAME_add_entry_by_NID(SafeX509NameHandle name, int nid, int type, in byte bytes, int len, int loc, int set);
        //int X509_NAME_add_entry_by_txt(X509_NAME *name, const char *field, int type, const unsigned char *bytes, int len, int loc, int set);
        int X509_NAME_add_entry_by_txt(SafeX509NameHandle name, in byte field, int type, in byte bytes, int len, int loc, int set);
        //X509_NAME_ENTRY *X509_NAME_delete_entry(X509_NAME *name, int loc);
        IntPtr X509_NAME_delete_entry(SafeX509NameHandle name, int loc);
        //int X509_NAME_get_index_by_NID(X509_NAME *name, int nid, int lastpos);
        int X509_NAME_get_index_by_NID(SafeX509NameHandle name, int nid, int lastpos);

        //int X509_NAME_digest(const X509_NAME *data, const EVP_MD *type, unsigned char* md, unsigned int* len);
        int X509_NAME_digest(SafeX509NameHandle data, IntPtr type, byte[] md, ref uint len);

        //char * X509_NAME_oneline(X509_NAME *a,char *buf,int size);
        IntPtr X509_NAME_oneline(SafeX509NameHandle a, byte[] buf, int size);
        //int X509_NAME_print(BIO *bp, X509_NAME *name, int obase);
        int X509_NAME_print(SafeBioHandle bp, SafeX509NameHandle name, int obase);
        //int X509_NAME_print_ex(BIO *out, X509_NAME *nm, int indent, unsigned long flags);
        int X509_NAME_print_ex(SafeBioHandle bp, SafeX509NameHandle nm, int indent, uint flags);
        #endregion

        #region X509_REQ
        [return: NewSafeHandle]
        SafeX509RequestHandle X509_REQ_new();
        void X509_REQ_free(IntPtr a);
        //X509_REQ *X509_REQ_dup(X509_REQ *req);
        IntPtr X509_REQ_dup(SafeX509RequestHandle req);

        //int X509_REQ_set_version(X509_REQ *x, long version);
        int X509_REQ_set_version(SafeX509RequestHandle x, int version);
        //long X509_REQ_get_version(const X509_REQ* req);
        long X509_REQ_get_version(SafeX509RequestHandle req);

        //int X509_REQ_set_pubkey(X509_REQ *x, EVP_PKEY *pkey);
        int X509_REQ_set_pubkey(SafeX509RequestHandle x, SafeKeyHandle pkey);
        //EVP_PKEY *X509_REQ_get_pubkey(X509_REQ *req);
        SafeKeyHandle X509_REQ_get_pubkey(SafeX509RequestHandle req);

        //int X509_REQ_set_subject_name(X509_REQ *req, X509_NAME *name);
        int X509_REQ_set_subject_name(SafeX509RequestHandle x, SafeX509NameHandle name);
        [return: DontTakeOwnership]
        SafeX509NameHandle X509_REQ_get_subject_name(SafeX509RequestHandle a);

        //int X509_REQ_sign(X509_REQ *x, EVP_PKEY *pkey, const EVP_MD *md);
        int X509_REQ_sign(SafeX509RequestHandle x, SafeKeyHandle pkey, SafeMessageDigestHandle md);

        //int X509_REQ_verify(X509_REQ *a, EVP_PKEY *r);
        int X509_REQ_verify(SafeX509RequestHandle x, SafeKeyHandle pkey);
        //int X509_REQ_check_private_key(X509_REQ *x509, EVP_PKEY *pkey);
        int X509_REQ_check_private_key(SafeX509RequestHandle x509, SafeKeyHandle pkey);

        //int X509_REQ_digest(const X509_REQ *data, const EVP_MD *type, unsigned char* md, unsigned int* len);
        int X509_REQ_digest(SafeX509RequestHandle data, SafeMessageDigestHandle type, ref byte md, ref uint len);

        //X509 *X509_REQ_to_X509(X509_REQ *r, int days, EVP_PKEY *pkey);
        SafeX509CertificateHandle X509_REQ_to_X509(SafeX509RequestHandle r, int days, SafeKeyHandle pkey);

        //int PEM_write_bio_X509_REQ(BIO *bp, X509_REQ *x);
        int PEM_write_bio_X509_REQ(SafeBioHandle bp, SafeX509RequestHandle x);
        //X509_REQ *PEM_read_X509_REQ(FILE *fp, X509_REQ **x, pem_password_cb* cb, void* u);
        [return: NewSafeHandle]
        SafeX509RequestHandle PEM_read_bio_X509_REQ(SafeBioHandle bp, IntPtr x, pem_password_cb cb, IntPtr u);

        //X509 *d2i_X509_REQ_bio(BIO *bp, X509_REQ **x);
        [return: NewSafeHandle]
        SafeX509RequestHandle d2i_X509_REQ_bio(SafeBioHandle bp, IntPtr x); //an IntPtr to pass IntPtr.Zero
        //int i2d_X509_bio(BIO *bp, X509 *x);
        int i2d_X509_REQ_bio(SafeBioHandle bp, SafeX509RequestHandle x509);

        int X509_REQ_print(SafeBioHandle bp, SafeX509RequestHandle x);
        int X509_REQ_print_ex(SafeBioHandle bp, SafeX509RequestHandle x, uint nmflag, uint cflag);
        #endregion

        #region X509
        //X509 *X509_new(void);
        [return: NewSafeHandle]
        SafeX509CertificateHandle X509_new();
        //void X509_free(X509 *a);
        void X509_free(IntPtr x);
        //int X509_up_ref(X509 *a);
        int X509_up_ref(SafeX509CertificateHandle a);
        IntPtr X509_dup(SafeX509CertificateHandle x509);
        [DontCheckReturnType]
        int X509_cmp(SafeX509CertificateHandle a, SafeX509CertificateHandle b);
        //STACK_OF(X509) *X509_chain_up_ref(STACK_OF(X509) *x);
        [return: NewSafeHandle]
        SafeStackHandle<SafeX509CertificateHandle> X509_chain_up_ref(SafeStackHandle<SafeX509CertificateHandle> x);

        //int X509_sign(X509 *x, EVP_PKEY *pkey, const EVP_MD *md);
        int X509_sign(SafeX509CertificateHandle x, SafeKeyHandle pkey, SafeMessageDigestHandle md);

        //int X509_verify(X509 *a, EVP_PKEY *r);
        [DontCheckReturnType]
        int X509_verify(SafeX509CertificateHandle x, SafeKeyHandle pkey);
        //int X509_check_private_key(X509 *x, EVP_PKEY *k);
        [DontCheckReturnType]
        int X509_check_private_key(SafeX509CertificateHandle x509, SafeKeyHandle pkey);

        //int X509_pubkey_digest(const X509 *data, const EVP_MD *type, unsigned char* md, unsigned int* len);
        int X509_pubkey_digest(SafeX509CertificateHandle data, SafeMessageDigestHandle type, ref byte md, out uint len);
        //int X509_digest(const X509 *data, const EVP_MD *type, unsigned char *md, unsigned int* len);
        int X509_digest(SafeX509CertificateHandle data, SafeMessageDigestHandle type, ref byte md, out uint len);

        //int X509_set_version(X509 *x, long version);
        int X509_set_version(SafeX509CertificateHandle x, long version);
        //long X509_get_version(const X509 *x);
        long X509_get_version(SafeX509CertificateHandle x);

        //int X509_set_serialNumber(X509 *x, ASN1_INTEGER *serial);
        int X509_set_serialNumber(SafeX509CertificateHandle x, SafeAsn1IntegerHandle serial);
        //ASN1_INTEGER *X509_get_serialNumber(X509 *x);
        [return: DontTakeOwnership]
        SafeAsn1IntegerHandle X509_get_serialNumber(SafeX509CertificateHandle x);

        //int X509_set_issuer_name(X509 *x, X509_NAME *name);
        int X509_set_issuer_name(SafeX509CertificateHandle x, SafeX509NameHandle name);
        //X509_NAME *X509_get_issuer_name(const X509 *x);
        [return: DontTakeOwnership]
        SafeX509NameHandle X509_get_issuer_name(SafeX509CertificateHandle a);

        //int X509_set_subject_name(X509 *x, X509_NAME *name);
        int X509_set_subject_name(SafeX509CertificateHandle x, SafeX509NameHandle name);
        //X509_NAME *X509_get_subject_name(const X509 *x);
        [return: DontTakeOwnership]
        SafeX509NameHandle X509_get_subject_name(SafeX509CertificateHandle a);

        //const ASN1_TIME *X509_get0_notBefore(const X509 *x);
        [return: DontTakeOwnership]
        SafeAsn1DateTimeHandle X509_get0_notBefore(SafeX509CertificateHandle x);
        //const ASN1_TIME* X509_get0_notAfter(const X509* x);
        [return: DontTakeOwnership]
        SafeAsn1DateTimeHandle X509_get0_notAfter(SafeX509CertificateHandle x);

        //int X509_set1_notBefore(X509 *x, const ASN1_TIME *tm);
        int X509_set1_notBefore(SafeX509CertificateHandle x, SafeAsn1DateTimeHandle tm);
        //int X509_set1_notAfter(X509 *x, const ASN1_TIME *tm);
        int X509_set1_notAfter(SafeX509CertificateHandle x, SafeAsn1DateTimeHandle tm);

        //int X509_set_pubkey(X509 *x, EVP_PKEY *pkey);
        int X509_set_pubkey(SafeX509CertificateHandle x, SafeKeyHandle pkey);
        //EVP_PKEY *X509_get_pubkey(X509 *x);
        SafeKeyHandle X509_get_pubkey(SafeX509CertificateHandle x);

        //const char *X509_verify_cert_error_string(long n);
        IntPtr X509_verify_cert_error_string(int n);

        //X509_REQ *X509_to_X509_REQ(X509 *x, EVP_PKEY *pkey, const EVP_MD *md);
        SafeX509RequestHandle X509_to_X509_REQ(SafeX509CertificateHandle x, SafeKeyHandle pkey, SafeMessageDigestHandle md);

        //X509 *X509_find_by_issuer_and_serial(STACK_OF(X509) *sk, X509_NAME *name, ASN1_INTEGER* serial);
        SafeX509CertificateHandle X509_find_by_issuer_and_serial(SafeStackHandle<SafeX509CertificateHandle> sk, SafeX509NameHandle name, SafeAsn1IntegerHandle serial);
        //X509 *X509_find_by_subject(STACK_OF(X509) *sk, X509_NAME *name);
        SafeX509CertificateHandle X509_find_by_subject(SafeStackHandle<SafeX509CertificateHandle> sk, SafeX509NameHandle name);

        //X509 *d2i_X509_bio(BIO *bp, X509 **x);
        [return: NewSafeHandle]
        SafeX509CertificateHandle d2i_X509_bio(SafeBioHandle bp, IntPtr x); //an IntPtr to pass IntPtr.Zero
        //int i2d_X509_bio(BIO *bp, X509 *x);
        int i2d_X509_bio(SafeBioHandle bp, SafeX509CertificateHandle x509);

        //int PEM_write_bio_X509(BIO *bp, X509 *x);
        int PEM_write_bio_X509(SafeBioHandle bp, SafeX509CertificateHandle x);
        //X509 *PEM_read_bio_X509(BIO *bp, X509 **x, pem_password_cb *cb, void *u);
        [return: NewSafeHandle]
        SafeX509CertificateHandle PEM_read_bio_X509(SafeBioHandle bp, IntPtr x, pem_password_cb cb, IntPtr u); //an IntPtr to pass IntPtr.Zero

        //int X509_get_ext_count(const X509 *x);
        int X509_get_ext_count(SafeX509CertificateHandle x);
        //X509_EXTENSION *X509_get_ext(const X509 *x, int loc);
        [return: DontTakeOwnership]
        SafeX509ExtensionHandle X509_get_ext(SafeX509CertificateHandle x, int loc);

        //void X509_get0_signature(const ASN1_BIT_STRING **psig, const X509_ALGOR** palg, const X509* x);
        void X509_get0_signature([DontTakeOwnership] out SafeASN1BitStringHandle psig, IntPtr palg, SafeX509CertificateHandle x);

        int X509_print_ex(SafeBioHandle bp, SafeX509CertificateHandle x, uint nmflag, uint cflag);
        int X509_print(SafeBioHandle bp, SafeX509CertificateHandle x);
        #endregion

        #region X509_EXTENSION
        [return: NewSafeHandle]
        SafeX509ExtensionHandle X509_EXTENSION_new();
        void X509_EXTENSION_free(IntPtr x);
        IntPtr X509_EXTENSION_dup(SafeX509ExtensionHandle ex);

        //int X509_add_ext(X509 *x, X509_EXTENSION *ex, int loc);
        int X509_add_ext(SafeX509CertificateHandle x, SafeX509ExtensionHandle ex, int loc);
        //X509_EXTENSION *X509_delete_ext(X509 *x, int loc);
        SafeX509ExtensionHandle X509_delete_ext(SafeX509CertificateHandle x, int loc);
        //int X509_add1_ext_i2d(X509 *x, int nid, void *value, int crit, unsigned long flags);
        int X509_add1_ext_i2d(SafeX509CertificateHandle x, int nid, in byte value, int crit, uint flags);

        //X509_EXTENSION *X509_EXTENSION_create_by_NID(X509_EXTENSION **ex, int nid, int crit, ASN1_OCTET_STRING *data);
        [return: NewSafeHandle]
        SafeX509ExtensionHandle X509_EXTENSION_create_by_NID(IntPtr ex, int nid, int crit, SafeASN1OctetStringHandle data);
        [return: NewSafeHandle]
        SafeX509ExtensionHandle X509_EXTENSION_create_by_NID(IntPtr ex, int nid, int crit, IntPtr data);

        //int X509_EXTENSION_set_critical(X509_EXTENSION *ex, int crit);
        int X509_EXTENSION_set_critical(SafeX509ExtensionHandle ex, int crit);
        //int X509_EXTENSION_set_data(X509_EXTENSION *ex, ASN1_OCTET_STRING *data);
        int X509_EXTENSION_set_data(SafeX509ExtensionHandle ex, SafeASN1OctetStringHandle data);
        //ASN1_OBJECT *X509_EXTENSION_get_object(X509_EXTENSION *ex);
        SafeAsn1ObjectHandle X509_EXTENSION_get_object(SafeX509ExtensionHandle ex);
        //int X509_EXTENSION_get_critical(const X509_EXTENSION *ex);
        int X509_EXTENSION_get_critical(SafeX509ExtensionHandle ex);
        //ASN1_OCTET_STRING *X509_EXTENSION_get_data(X509_EXTENSION *ne)
        [return: DontTakeOwnership]
        SafeASN1OctetStringHandle X509_EXTENSION_get_data(SafeX509ExtensionHandle ne);
        #endregion

        //TODO: X509_CRL
        #region X509_EXT_CTX
        //void X509V3_set_ctx(X509V3_CTX *ctx, X509 *issuer, X509 *subj, X509_REQ *req, X509_CRL* crl, int flags)
        void X509V3_set_ctx(SafeX509ExtensionContextHandle ctx, IntPtr issuer, IntPtr subj, IntPtr req, IntPtr crl, int flags);
        //X509_EXTENSION *X509V3_EXT_conf_nid(LHASH_OF(CONF_VALUE) *conf, X509V3_CTX* ctx, int ext_nid, const char* value)
        [return: NewSafeHandle]
        SafeX509ExtensionHandle X509V3_EXT_conf_nid(IntPtr conf, SafeX509ExtensionContextHandle ctx, int ext_nid, in byte value);
        #endregion

        #region X509_OBJECT
        //X509_OBJECT *X509_OBJECT_new(void);
        [return: NewSafeHandle]
        SafeX509ObjectHandle X509_OBJECT_new();
        //void X509_OBJECT_free(X509_OBJECT *a);
        void X509_OBJECT_free(IntPtr a);

        //X509 *X509_OBJECT_get0_X509(const X509_OBJECT *a);
        [DontCheckReturnType]
        SafeX509CertificateHandle X509_OBJECT_get0_X509(SafeX509ObjectHandle a);
        //X509_LOOKUP_TYPE X509_OBJECT_get_type(const X509_OBJECT *a)
        int X509_OBJECT_get_type(SafeX509ObjectHandle a);

        //int X509_OBJECT_up_ref_count(X509_OBJECT *a);
        int X509_OBJECT_up_ref_count(SafeX509ObjectHandle a);
        #endregion

        #region X509_INFO
        //X509_INFO *X509_INFO_new(void);
        SafeX509InfoHandle X509_INFO_new();
        //void X509_INFO_free(X509_INFO* a);
        void X509_INFO_free(IntPtr a);
        //STACK_OF(X509_INFO) *PEM_X509_INFO_read_bio(BIO *bp, STACK_OF(X509_INFO) *sk,  pem_password_cb* cb, void* u)
        [return: NewSafeHandle]
        SafeStackHandle<SafeX509InfoHandle> PEM_X509_INFO_read_bio(SafeBioHandle bp, IntPtr sk, pem_password_cb cb, IntPtr u);
        #endregion

        #region X509_STORE
        //X509_STORE *X509_STORE_new(void);
        [return: NewSafeHandle]
        SafeX509StoreHandle X509_STORE_new();
        //void X509_STORE_free(X509_STORE *v);
        void X509_STORE_free(IntPtr x);
        //int X509_STORE_up_ref(X509_STORE *v);
        int X509_STORE_up_ref(SafeX509StoreHandle x);

        //int X509_STORE_add_cert(X509_STORE *ctx, X509 *x);
        int X509_STORE_add_cert(SafeX509StoreHandle ctx, SafeX509CertificateHandle x);
        //STACK_OF(X509_OBJECT) *X509_STORE_get0_objects(X509_STORE *ctx);
        [return: DontTakeOwnership]
        SafeStackHandle<SafeX509ObjectHandle> X509_STORE_get0_objects(SafeX509StoreHandle ctx);

        //int X509_STORE_load_locations(X509_STORE *ctx, const char* file, const char* dir);
        int X509_STORE_load_locations(SafeX509StoreHandle ctx, in byte file, in byte dir);
        int X509_STORE_load_locations(SafeX509StoreHandle ctx, in byte file, IntPtr dir);
        int X509_STORE_load_locations(SafeX509StoreHandle ctx, IntPtr file, in byte dir);
        #endregion

        #region X509_STORE_CTX
        //X509_STORE_CTX *X509_STORE_CTX_new(void);
        [return: NewSafeHandle]
        SafeX509StoreContextHandle X509_STORE_CTX_new();
        void X509_STORE_CTX_free(IntPtr x);

        //int X509_STORE_CTX_init(X509_STORE_CTX *ctx, X509_STORE *store, X509* x509, STACK_OF(X509) *chain);
        int X509_STORE_CTX_init(SafeX509StoreContextHandle ctx, SafeX509StoreHandle store, SafeX509CertificateHandle x509, SafeStackHandle<SafeX509CertificateHandle> chain);
        //int X509_verify_cert(X509_STORE_CTX *ctx);
        int X509_verify_cert(SafeX509StoreContextHandle ctx);

        //X509 *X509_STORE_CTX_get_current_cert(X509_STORE_CTX *ctx);
        SafeX509CertificateHandle X509_STORE_CTX_get_current_cert(SafeX509StoreContextHandle x509_store_ctx);
        //int   X509_STORE_CTX_get_error_depth(X509_STORE_CTX *ctx);
        int X509_STORE_CTX_get_error_depth(SafeX509StoreContextHandle x509_store_ctx);
        
        //int X509_STORE_CTX_get_error(X509_STORE_CTX *ctx);
        int X509_STORE_CTX_get_error(SafeX509StoreContextHandle x509_store_ctx);
        //void X509_STORE_CTX_set_error(X509_STORE_CTX *ctx, int s);
        void X509_STORE_CTX_set_error(SafeX509StoreContextHandle x509_store_ctx, int error);

        //X509_STORE *X509_STORE_CTX_get0_store(X509_STORE_CTX *ctx);
        SafeX509StoreHandle X509_STORE_CTX_get0_store(SafeX509StoreContextHandle ctx);
        #endregion

        #region RAND_METHOD
        //void RAND_set_rand_method(const RAND_METHOD *meth);
        int RAND_set_rand_method(IntPtr meth);
        //const RAND_METHOD *RAND_get_rand_method(void);
        IntPtr RAND_get_rand_method();
        #endregion

        #region RANDOM
        //void RAND_cleanup(void);
        void RAND_cleanup();
        //void RAND_seed(const void *buf, int num);
        void RAND_seed(in byte buf, int len);
        //void RAND_add(const void *buf, int num, double entropy);
        void RAND_add(in byte buf, int num, double entropy);
        //int  RAND_status(void);
        int RAND_status();
        //int RAND_poll();
        int RAND_poll();

        //int RAND_pseudo_bytes(unsigned char *buf, int num);
        int RAND_pseudo_bytes(ref byte buf, int len);
        //int RAND_bytes(unsigned char *buf, int num);
        int RAND_bytes(ref byte buf, int num);

        //int RAND_load_file(const char* filename, long max_bytes);
        int RAND_load_file(string file, int max_bytes);
        //int RAND_write_file(const char *filename);
        int RAND_write_file(string file);
        //const char *RAND_file_name(char *buf, size_t num);
        IntPtr RAND_file_name(ref byte buf, uint num);

        //int RAND_query_egd_bytes(const char *path, unsigned char *buf, int bytes);
        int RAND_query_egd_bytes(string path, ref byte buf, int bytes);
        //int RAND_egd(const char *path);
        int RAND_egd(string path);
        //int RAND_egd_bytes(const char *path, int bytes);
        int RAND_egd_bytes(string path, int bytes);
        #endregion

        #region RANDOM BIGNUM
        //int BN_rand(BIGNUM *rnd, int bits, int top, int bottom);
        int BN_rand(SafeBigNumberHandle rnd, int bits, int top, int bottom);
        //int BN_pseudo_rand(BIGNUM *rnd, int bits, int top, int bottom);
        int BN_pseudo_rand(SafeBigNumberHandle rnd, int bits, int top, int bottom);
        //int BN_rand_range(BIGNUM *rnd, BIGNUM *range);
        int BN_rand_range(SafeBigNumberHandle rnd, SafeBigNumberHandle range);
        //int BN_pseudo_rand_range(BIGNUM *rnd, BIGNUM *range);
        int BN_pseudo_rand_range(SafeBigNumberHandle rnd, SafeBigNumberHandle range);
        #endregion

        #region DSA
        //DSA* DSA_new(void);
        [return: NewSafeHandle]
        SafeDSAHandle DSA_new();
        //void DSA_free(DSA *dsa);
        void DSA_free(IntPtr dsa);
        int DSA_up_ref(SafeDSAHandle dsa);

        //int DSA_generate_parameters_ex(DSA *dsa, int bits, const unsigned char* seed,int seed_len, int* counter_ret, unsigned long* h_ret, BN_GENCB *cb);
        int DSA_generate_parameters_ex(SafeDSAHandle dsa, int bits, in byte seed, int seed_len, out int counter_ret, out ulong h_ret, bn_gencb_st callback);
        //int DSA_generate_key(DSA *a);
        int DSA_generate_key(SafeDSAHandle dsa);
        //int DSA_size(const DSA *dsa);
        int DSA_size(SafeDSAHandle dsa);

        //int DSA_sign(int type, const unsigned char *dgst, int len, unsigned char* sigret, unsigned int* siglen, DSA *dsa);
        int DSA_sign(int type, in byte dgst, int dlen, ref byte sig, out uint siglen, SafeDSAHandle dsa);
        //int DSA_verify(int type, const unsigned char *dgst, int len, unsigned char* sigbuf, int siglen, DSA *dsa);
        int DSA_verify(int type, in byte dgst, int dgst_len, in byte sigbuf, int siglen, SafeDSAHandle dsa);

        //int DSAparams_print(BIO *bp, DSA *x);
        int DSAparams_print(SafeBioHandle bp, SafeDSAHandle x);
        //int DSA_print(BIO *bp, DSA *x, int offset);
        int DSA_print(SafeBioHandle bp, SafeDSAHandle x, int off);
        #endregion

        #region RSA
        //RSA * RSA_new(void);
        [return: NewSafeHandle]
        SafeRSAHandle RSA_new();
        //void RSA_free(RSA *rsa);
        void RSA_free(IntPtr rsa);
        int RSA_up_ref(SafeRSAHandle rsa);

        //int RSA_generate_key_ex(RSA *rsa, int bits, BIGNUM *e, BN_GENCB *cb);
        int RSA_generate_key_ex(SafeRSAHandle rsa, int bits, SafeBigNumberHandle e, bn_gencb_st cb);
        //int RSA_size(const RSA *rsa);
        int RSA_size(SafeRSAHandle rsa);
        //int RSA_check_key(RSA *rsa);
        int RSA_check_key(SafeRSAHandle rsa);

        //int RSA_public_encrypt(int flen, unsigned char *from, unsigned char* to, RSA *rsa, int padding);
        int RSA_public_encrypt(int flen, in byte from, ref byte to, SafeRSAHandle rsa, int padding);
        //int RSA_private_decrypt(int flen, unsigned char *from, unsigned char* to, RSA *rsa, int padding);
        int RSA_private_decrypt(int flen, in byte from, ref byte to, SafeRSAHandle rsa, int padding);
        //int RSA_private_encrypt(int flen, unsigned char *from, unsigned char* to, RSA *rsa, int padding);
        int RSA_private_encrypt(int flen, in byte from, ref byte to, SafeRSAHandle rsa, int padding);
        //int RSA_public_decrypt(int flen, unsigned char *from, unsigned char* to, RSA *rsa, int padding);
        int RSA_public_decrypt(int flen, in byte from, ref byte to, SafeRSAHandle rsa, int padding);

        //int RSA_sign(int type, const unsigned char *m, unsigned int m_len, unsigned char* sigret, unsigned int* siglen, RSA *rsa);
        int RSA_sign(int type, in byte m, uint m_length, ref byte sigret, out uint siglen, SafeRSAHandle rsa);
        //int RSA_verify(int type, const unsigned char *m, unsigned int m_len, unsigned char* sigbuf, unsigned int siglen, RSA *rsa);
        int RSA_verify(int type, in byte m, uint m_length, in byte sigbuf, uint siglen, SafeRSAHandle rsa);

        //RSA *PEM_read_bio_RSAPrivateKey(BIO *bp, RSA **x, pem_password_cb *cb, void *u);
        SafeRSAHandle PEM_read_bio_RSAPrivateKey(SafeBioHandle bp, IntPtr x, pem_password_cb cb, IntPtr u);
        //int PEM_write_bio_RSAPrivateKey(BIO *bp, RSA *x, const EVP_CIPHER *enc, unsigned char *kstr, int klen, pem_password_cb *cb, void *u);
        int PEM_write_bio_RSAPrivateKey(SafeBioHandle bp, SafeRSAHandle x, SafeCipherHandle enc, IntPtr kstr, int klen, pem_password_cb cb, IntPtr u);

        //RSA *d2i_RSAPrivateKey_bio(BIO *bp, RSA **a);
        SafeRSAHandle d2i_RSAPrivateKey_bio(SafeBioHandle bp, IntPtr a);
        //int i2d_RSAPrivateKey_bio(BIO *bp, SafeRSAHandle *a);
        int i2d_RSAPrivateKey_bio(SafeBioHandle bp, SafeRSAHandle a);

        //int RSA_print(BIO *bp, RSA *x, int offset);
        int RSA_print(SafeBioHandle bp, SafeRSAHandle r, int offset);
        #endregion

        #region DH
        //DH* DH_new(void);
        [return: NewSafeHandle]
        SafeDHHandle DH_new();
        //void DH_free(DH *dh);
        void DH_free(IntPtr dh);
        int DH_up_ref(SafeDHHandle dh);

        //int DH_generate_parameters_ex(DH *dh, int prime_len,int generator, BN_GENCB *cb);
        int DH_generate_parameters_ex(SafeDHHandle dh, int prime_len, int generator, bn_gencb_st cb);
        //int DH_generate_key(DH *dh);
        int DH_generate_key(SafeDHHandle dh);
        //int DH_compute_key(unsigned char *key, BIGNUM *pub_key, DH *dh);
        int DH_compute_key(ref byte key, SafeBigNumberHandle pub_key, SafeDHHandle dh);
        //int DH_size(const DH *dh);
        int DH_size(SafeDHHandle dh);

        //int DH_check(DH *dh, int *codes);
        int DH_check(SafeDHHandle dh, out int codes);

        //int DHparams_print(BIO *bp, DH *x);
        int DHparams_print(SafeBioHandle bp, SafeDHHandle x);

        //DH *d2i_DHparams(DH **a, unsigned char **pp, long length);
        [return: NewSafeHandle]
        SafeDHHandle d2i_DHparams(IntPtr a, IntPtr pp, int length);
        //int i2d_DHparams(DH *a, unsigned char **pp);
        int i2d_DHparams(SafeDHHandle a, IntPtr pp);
        #endregion

        #region BIGNUM
        [return: NewSafeHandle]
        SafeBigNumberHandle BN_new();
        void BN_free(IntPtr a);
        void BN_clear_free(IntPtr a);
        void BN_clear(SafeBigNumberHandle a);
        IntPtr BN_dup(SafeBigNumberHandle a);

        SafeBigNumberHandle BN_value_one();
        //BIGNUM *BN_bin2bn(const unsigned char *s, int len, BIGNUM *ret);
        [return: NewSafeHandle]
        SafeBigNumberHandle BN_bin2bn(in byte s, int len, IntPtr ret);
        //int BN_bn2bin(const BIGNUM *a, unsigned char *to);
        int BN_bn2bin(SafeBigNumberHandle a, ref byte to);
        //BIGNUM *BN_copy(BIGNUM *to, const BIGNUM *from);
        SafeBigNumberHandle BN_copy(SafeBigNumberHandle a, SafeBigNumberHandle b);
        //void BN_swap(BIGNUM *a, BIGNUM *b);
        void BN_swap(SafeBigNumberHandle a, SafeBigNumberHandle b);
        [DontCheckReturnType]
        int BN_cmp(SafeBigNumberHandle a, SafeBigNumberHandle b);

        //int BN_sub(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);
        int BN_sub(SafeBigNumberHandle r, SafeBigNumberHandle a, SafeBigNumberHandle b);
        //int BN_add(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);
        int BN_add(SafeBigNumberHandle r, SafeBigNumberHandle a, SafeBigNumberHandle b);
        //int BN_mul(BIGNUM *r, BIGNUM *a, BIGNUM *b, BN_CTX *ctx);
        int BN_mul(SafeBigNumberHandle r, SafeBigNumberHandle a, SafeBigNumberHandle b, SafeBigNumberContextHandle ctx);
        //int BN_sqr(BIGNUM *r, BIGNUM *a, BN_CTX *ctx);
        int BN_sqr(SafeBigNumberHandle r, SafeBigNumberHandle a, SafeBigNumberContextHandle ctx);
        //int BN_div(BIGNUM *dv, BIGNUM *rem, const BIGNUM *a, const BIGNUM *d, BN_CTX* ctx);
        int BN_div(SafeBigNumberHandle dv, SafeBigNumberHandle rem, SafeBigNumberHandle a, SafeBigNumberHandle d, SafeBigNumberContextHandle ctx);

        //int BN_num_bits(const BIGNUM *a);
        int BN_num_bits(SafeBigNumberHandle a);

        //int BN_print(BIO *fp, const BIGNUM *a);
        int BN_print(SafeBioHandle fp, SafeBigNumberHandle a);

        //char* BN_bn2hex(const BIGNUM* a);
        IntPtr BN_bn2hex(SafeBigNumberHandle a); //The string must be freed later using OPENSSL_free()
        //char *BN_bn2dec(const BIGNUM *a);
        IntPtr BN_bn2dec(SafeBigNumberHandle a);
        //int BN_hex2bn(BIGNUM **a, const char *str);
        int BN_hex2bn([NewSafeHandle] out SafeBigNumberHandle a, in byte str);
        //int BN_dec2bn(BIGNUM **a, const char *str);
        int BN_dec2bn([NewSafeHandle] out SafeBigNumberHandle a, in byte str);

        //BN_ULONG BN_mod_word(const BIGNUM *a, BN_ULONG w);
        uint BN_mod_word(SafeBigNumberHandle a, uint w);
        //BN_ULONG BN_div_word(BIGNUM *a, BN_ULONG w);
        uint BN_div_word(SafeBigNumberHandle a, uint w);
        //int BN_mul_word(BIGNUM *a, BN_ULONG w);
        int BN_mul_word(SafeBigNumberHandle a, uint w);
        //int BN_add_word(BIGNUM *a, BN_ULONG w);
        int BN_add_word(SafeBigNumberHandle a, uint w);
        //int BN_sub_word(BIGNUM *a, BN_ULONG w);
        int BN_sub_word(SafeBigNumberHandle a, uint w);
        //int BN_set_word(BIGNUM *a, BN_ULONG w);
        int BN_set_word(SafeBigNumberHandle a, uint w);
        //BN_ULONG BN_get_word(BIGNUM *a);
        uint BN_get_word(SafeBigNumberHandle a);
        //int BN_set_bit(BIGNUM* a, int n);
        int BN_set_bit(SafeBigNumberHandle a, int n);
        #endregion

        #region BN_CTX
        //BN_CTX *BN_CTX_new(void);
        [return: NewSafeHandle]
        SafeBigNumberContextHandle BN_CTX_new();
        //void BN_CTX_free(BN_CTX *c);
        void BN_CTX_free(IntPtr c);
        //void BN_CTX_start(BN_CTX *ctx);
        void BN_CTX_start(SafeBigNumberContextHandle ctx);
        //BIGNUM *BN_CTX_get(BN_CTX *ctx);
        SafeBigNumberHandle BN_CTX_get(SafeBigNumberContextHandle ctx); //doesn't own the handle on the returned SafeBigNumberHandle
        //void BN_CTX_end(BN_CTX *ctx);
        void BN_CTX_end(SafeBigNumberContextHandle ctx);
        #endregion

        //TODO: PEM to PKCS12 (check tools)
        #region PKCS12
        void PKCS12_free(IntPtr p12);
        //PKCS12 *d2i_PKCS12_bio(BIO *bp, PKCS12 **p12);
        [return: NewSafeHandle]
        SafePKCS12Handle d2i_PKCS12_bio(SafeBioHandle bp, IntPtr ptr);
        //int i2d_PKCS12_bio(BIO *bp, PKCS12 *p12);
        int i2d_PKCS12_bio(SafeBioHandle bp, SafePKCS12Handle p12);

        //PKCS12 *PKCS12_create(char *pass, char *name, EVP_PKEY *pkey, X509 *cert, STACK_OF(X509) *ca, int nid_key, int nid_cert, int iter, int mac_iter, int keytype);
        [return: NewSafeHandle]
        SafePKCS12Handle PKCS12_create(string pass, string name, SafeKeyHandle pkey, SafeX509CertificateHandle cert,
            SafeStackHandle<SafeX509CertificateHandle> ca, int nid_key, int nid_cert, int iter, int mac_iter, int keytype);
        //int PKCS12_parse(PKCS12 *p12, const char *pass, EVP_PKEY **pkey, X509 **cert, STACK_OF(X509) **ca);
        int PKCS12_parse(SafePKCS12Handle p12, string pass, 
            [NewSafeHandle] out SafeKeyHandle pkey,
            [NewSafeHandle] out SafeX509CertificateHandle cert,
            [NewSafeHandle] out SafeStackHandle<SafeX509CertificateHandle> ca);
        #endregion

        #region PKCS7
        void PKCS7_free(IntPtr p7);
        //PKCS7 *PKCS7_dup(PKCS7 *p7);
        IntPtr PKCS7_dup(SafePKCS7Handle p7);

        //PKCS7 *PEM_read_bio_PKCS7(BIO *bp, PKCS7 **x, pem_password_cb *cb, void *u);
        [return: NewSafeHandle]
        SafePKCS7Handle PEM_read_bio_PKCS7(SafeBioHandle bp, IntPtr x, pem_password_cb cb, IntPtr u);
        //PKCS7 *d2i_PKCS7_bio(BIO *bp, PKCS7 **p7);
        [return: NewSafeHandle]
        SafePKCS7Handle d2i_PKCS7_bio(SafeBioHandle bp, IntPtr p7);
        //int i2d_PKCS7_bio(BIO *bp, PKCS7 *p7);
        int i2d_PKCS7_bio(SafeBioHandle bp, SafePKCS7Handle p7);
        #endregion

        //create object from BIO (used for DH)
        IntPtr ASN1_d2i_bio(IntPtr xnew, IntPtr d2i, SafeBioHandle bp, IntPtr x);
        int ASN1_i2d_bio(IntPtr i2d, SafeBioHandle bp, IntPtr x);

        //int PEM_write_bio_PKCS8PrivateKey(BIO *bp, EVP_PKEY *x, const EVP_CIPHER *enc, char* kstr, int klen, pem_password_cb *cb, void* u);
        int PEM_write_bio_PKCS8PrivateKey(SafeBioHandle bp, SafeKeyHandle evp_pkey, SafeCipherHandle evp_cipher, IntPtr kstr, int klen, pem_password_cb cb, IntPtr user_data);

        #region EVP_MD
        //const EVP_MD *EVP_get_digestbyname(const char *name);
        SafeMessageDigestHandle EVP_get_digestbyname(in byte name);
        SafeMessageDigestHandle EVP_get_digestbyname(IntPtr name);

        //const EVP_MD *EVP_md_null(void);
        SafeMessageDigestHandle EVP_md_null();
        SafeMessageDigestHandle EVP_md2();
        SafeMessageDigestHandle EVP_md4();
        SafeMessageDigestHandle EVP_md5();
        SafeMessageDigestHandle EVP_sha();
        SafeMessageDigestHandle EVP_sha1();
        SafeMessageDigestHandle EVP_sha224();
        SafeMessageDigestHandle EVP_sha256();
        SafeMessageDigestHandle EVP_sha384();
        SafeMessageDigestHandle EVP_sha512();
        SafeMessageDigestHandle EVP_dss();
        SafeMessageDigestHandle EVP_dss1();
        SafeMessageDigestHandle EVP_mdc2();
        SafeMessageDigestHandle EVP_ripemd160();
        SafeMessageDigestHandle EVP_ecdsa();

        //int EVP_MD_type(const EVP_MD *md);
        int EVP_MD_type(SafeMessageDigestHandle md);
        //int EVP_MD_pkey_type(const EVP_MD *md); 
        int EVP_MD_pkey_type(SafeMessageDigestHandle md);
        //int EVP_MD_size(const EVP_MD *md);
        int EVP_MD_size(SafeMessageDigestHandle md);
        //int EVP_MD_block_size(const EVP_MD *md);
        int EVP_MD_block_size(SafeMessageDigestHandle md);
        //unsigned long EVP_MD_flags(const EVP_MD *md);
        ulong EVP_MD_flags(SafeMessageDigestHandle md);

        //int EVP_Digest(const void *data, size_t count, unsigned char* md, unsigned int* size, const EVP_MD* type, ENGINE *impl);
        int EVP_Digest(in byte data, uint count, ref byte md, ref uint size, SafeMessageDigestHandle type, SafeEngineHandle impl);
        #endregion

        #region EVP_MD_CTX
        //EVP_MD_CTX *EVP_MD_CTX_new(void);
        [return: NewSafeHandle]
        SafeMessageDigestContextHandle EVP_MD_CTX_new();
        //void EVP_MD_CTX_free(EVP_MD_CTX *ctx);
        void EVP_MD_CTX_free(IntPtr ctx);

        //int EVP_DigestInit_ex(EVP_MD_CTX *ctx, const EVP_MD *type, ENGINE *impl);
        int EVP_DigestInit_ex(SafeMessageDigestContextHandle ctx, SafeMessageDigestHandle type, SafeEngineHandle impl);
        //int EVP_DigestInit(EVP_MD_CTX *ctx, const EVP_MD *type);
        int EVP_DigestInit(SafeMessageDigestContextHandle ctx, SafeMessageDigestHandle type);
        //int EVP_DigestUpdate(EVP_MD_CTX *ctx, const void *d, size_t cnt);
        int EVP_DigestUpdate(SafeMessageDigestContextHandle ctx, in byte d, uint cnt);
        //int EVP_DigestFinal(EVP_MD_CTX* ctx, unsigned char* md, unsigned int* s);
        int EVP_DigestFinal(SafeMessageDigestContextHandle ctx, ref byte md, out uint s);
        //int EVP_DigestFinal_ex(EVP_MD_CTX *ctx, unsigned char *md, unsigned int* s);
        int EVP_DigestFinal_ex(SafeMessageDigestContextHandle ctx, ref byte md, out uint s);

        //int EVP_SignInit_ex(EVP_MD_CTX *ctx, const EVP_MD *type, ENGINE *impl);
        int EVP_SignInit_ex(SafeMessageDigestContextHandle ctx, SafeMessageDigestHandle type, SafeEngineHandle impl);
        int EVP_SignInit(SafeMessageDigestContextHandle ctx, SafeMessageDigestHandle type);
        //int EVP_SignUpdate(EVP_MD_CTX *ctx, const void *d, unsigned int cnt);
        int EVP_SignUpdate(SafeMessageDigestContextHandle ctx, in byte d, uint cnt);
        //int EVP_SignFinal(EVP_MD_CTX *ctx,unsigned char *sig,unsigned int *s, EVP_PKEY *pkey)
        int EVP_SignFinal(SafeMessageDigestContextHandle ctx, ref byte sig, out uint s, SafeKeyHandle pkey);

        //int EVP_VerifyInit_ex(EVP_MD_CTX *ctx, const EVP_MD *type, ENGINE *impl);
        int EVP_VerifyInit_ex(SafeMessageDigestContextHandle ctx, SafeMessageDigestHandle type, SafeEngineHandle impl);
        //int EVP_VerifyUpdate(EVP_MD_CTX *ctx, const void *d, unsigned int cnt);
        int EVP_VerifyUpdate(SafeMessageDigestContextHandle ctx, in byte d, uint cnt);
        //int EVP_VerifyFinal(EVP_MD_CTX *ctx, unsigned char *sigbuf, unsigned int siglen, EVP_PKEY *pkey);
        [DontCheckReturnType]
        int EVP_VerifyFinal(SafeMessageDigestContextHandle ctx, in byte sigbuf, uint siglen, SafeKeyHandle pkey);
        #endregion

        #region HMAC_CTX
        //HMAC_CTX* HMAC_CTX_new(void);
        [return: NewSafeHandle]
        SafeHMACContextHandle HMAC_CTX_new();
        //void HMAC_CTX_free(HMAC_CTX *ctx);
        void HMAC_CTX_free(IntPtr ctx);

        //int HMAC_Init_ex(HMAC_CTX *ctx, const void *key, int key_len, const EVP_MD* md, ENGINE *impl);
        void HMAC_Init_ex(SafeHMACContextHandle ctx, in byte key, int len, SafeMessageDigestHandle md, SafeEngineHandle engine_impl);
        //int HMAC_Update(HMAC_CTX *ctx, const unsigned char *data, int len);
        void HMAC_Update(SafeHMACContextHandle ctx, in byte data, int len);
        //int HMAC_Final(HMAC_CTX *ctx, unsigned char *md, unsigned int *len);
        void HMAC_Final(SafeHMACContextHandle ctx, ref byte md, out uint len);

        //void HMAC_CTX_set_flags(HMAC_CTX *ctx, unsigned long flags);
        void HMAC_CTX_set_flags(SafeHMACContextHandle ctx, uint flags);
        //unsigned char *HMAC(const EVP_MD *evp_md, const void *key, int key_len, const unsigned char* d, int n, unsigned char* md, unsigned int* md_len);
        IntPtr HMAC(SafeMessageDigestHandle evp_md, in byte key, int key_len, in byte d, int n, ref byte md, out uint md_len);
        #endregion

        #region EVP_CIPHER
        //const EVP_CIPHER *EVP_get_cipherbyname(const char *name);
        SafeCipherHandle EVP_get_cipherbyname(in byte name);
        SafeCipherHandle EVP_get_cipherbyname(IntPtr name);

        //const EVP_CIPHER *EVP_enc_null(void);
        SafeCipherHandle EVP_enc_null();
        SafeCipherHandle EVP_des_ecb();
        SafeCipherHandle EVP_des_ede();
        SafeCipherHandle EVP_des_ede3();
        SafeCipherHandle EVP_des_ede_ecb();
        SafeCipherHandle EVP_des_ede3_ecb();
        SafeCipherHandle EVP_des_cfb64();
        SafeCipherHandle EVP_des_cfb1();
        SafeCipherHandle EVP_des_cfb8();
        SafeCipherHandle EVP_des_ede_cfb64();
        SafeCipherHandle EVP_des_ede3_cfb64();
        SafeCipherHandle EVP_des_ede3_cfb1();
        SafeCipherHandle EVP_des_ede3_cfb8();
        SafeCipherHandle EVP_des_ofb();
        SafeCipherHandle EVP_des_ede_ofb();
        SafeCipherHandle EVP_des_ede3_ofb();
        SafeCipherHandle EVP_des_cbc();
        SafeCipherHandle EVP_des_ede_cbc();
        SafeCipherHandle EVP_des_ede3_cbc();
        SafeCipherHandle EVP_desx_cbc();
        SafeCipherHandle EVP_rc4();
        SafeCipherHandle EVP_rc4_40();
        SafeCipherHandle EVP_idea_ecb();
        SafeCipherHandle EVP_idea_cfb64();
        SafeCipherHandle EVP_idea_ofb();
        SafeCipherHandle EVP_idea_cbc();
        SafeCipherHandle EVP_rc2_ecb();
        SafeCipherHandle EVP_rc2_cbc();
        SafeCipherHandle EVP_rc2_40_cbc();
        SafeCipherHandle EVP_rc2_64_cbc();
        SafeCipherHandle EVP_rc2_cfb64();
        SafeCipherHandle EVP_rc2_ofb();
        SafeCipherHandle EVP_bf_ecb();
        SafeCipherHandle EVP_bf_cbc();
        SafeCipherHandle EVP_bf_cfb64();
        SafeCipherHandle EVP_bf_ofb();
        SafeCipherHandle EVP_cast5_ecb();
        SafeCipherHandle EVP_cast5_cbc();
        SafeCipherHandle EVP_cast5_cfb64();
        SafeCipherHandle EVP_cast5_ofb();
        SafeCipherHandle EVP_rc5_32_12_16_cbc();
        SafeCipherHandle EVP_rc5_32_12_16_ecb();
        SafeCipherHandle EVP_rc5_32_12_16_cfb64();
        SafeCipherHandle EVP_rc5_32_12_16_ofb();
        SafeCipherHandle EVP_aes_128_ecb();
        SafeCipherHandle EVP_aes_128_cbc();
        SafeCipherHandle EVP_aes_128_cfb1();
        SafeCipherHandle EVP_aes_128_cfb8();
        SafeCipherHandle EVP_aes_128_cfb128();
        SafeCipherHandle EVP_aes_128_ofb();
        SafeCipherHandle EVP_aes_192_ecb();
        SafeCipherHandle EVP_aes_192_cbc();
        SafeCipherHandle EVP_aes_192_cfb1();
        SafeCipherHandle EVP_aes_192_cfb8();
        SafeCipherHandle EVP_aes_192_cfb128();
        SafeCipherHandle EVP_aes_192_ofb();
        SafeCipherHandle EVP_aes_256_ecb();
        SafeCipherHandle EVP_aes_256_cbc();
        SafeCipherHandle EVP_aes_256_cfb1();
        SafeCipherHandle EVP_aes_256_cfb8();
        SafeCipherHandle EVP_aes_256_cfb128();
        SafeCipherHandle EVP_aes_256_ofb();

        //int EVP_CIPHER_type(const EVP_CIPHER *ctx);
        int EVP_CIPHER_type(SafeCipherHandle ctx);
        //int EVP_CIPHER_iv_length(const EVP_CIPHER *e);
        [DontCheckReturnType]
        int EVP_CIPHER_iv_length(SafeCipherHandle e);
        //int EVP_CIPHER_key_length(const EVP_CIPHER *e);
        int EVP_CIPHER_key_length(SafeCipherHandle e);
        //int EVP_CIPHER_block_size(const EVP_CIPHER *e);
        int EVP_CIPHER_block_size(SafeCipherHandle e);
        
        //int EVP_BytesToKey(const EVP_CIPHER *type,const EVP_MD *md, const unsigned char* salt, const unsigned char* data, int datal, int count, unsigned char* key, unsigned char* iv);
        int EVP_BytesToKey(SafeCipherHandle type, SafeMessageDigestHandle md, in byte salt, in byte data, int datal, int count, ref byte key, ref byte iv);
        #endregion

        #region EVP_CIPHER_CTX
        //EVP_CIPHER_CTX *EVP_CIPHER_CTX_new(void);
        [return: NewSafeHandle]
        SafeCipherContextHandle EVP_CIPHER_CTX_new();
        //void EVP_CIPHER_CTX_free(EVP_CIPHER_CTX *a);
        void EVP_CIPHER_CTX_free(IntPtr a);

        //int EVP_CIPHER_CTX_rand_key(EVP_CIPHER_CTX *ctx, unsigned char *key);
        int EVP_CIPHER_CTX_rand_key(SafeCipherContextHandle ctx, ref byte key);
        //int EVP_CIPHER_CTX_set_padding(EVP_CIPHER_CTX *x, int padding);
        int EVP_CIPHER_CTX_set_padding(SafeCipherContextHandle x, int padding);
        //int EVP_CIPHER_CTX_set_key_length(EVP_CIPHER_CTX *x, int keylen);
        int EVP_CIPHER_CTX_set_key_length(SafeCipherContextHandle x, int keylen);
        //int EVP_CIPHER_CTX_ctrl(EVP_CIPHER_CTX* ctx, int type, int arg, void* ptr);
        int EVP_CIPHER_CTX_ctrl(SafeCipherContextHandle ctx, int type, int arg, IntPtr ptr);
        //int EVP_CIPHER_CTX_reset(EVP_CIPHER_CTX *ctx);
        int EVP_CIPHER_CTX_reset(SafeCipherContextHandle ctx);

        //int EVP_CipherInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type, ENGINE* impl, const unsigned char* key, const unsigned char* iv, int enc);
        int EVP_CipherInit_ex(SafeCipherContextHandle ctx, SafeCipherHandle type, SafeEngineHandle impl, in byte key, in byte iv, int enc);
        int EVP_CipherInit_ex(SafeCipherContextHandle ctx, SafeCipherHandle type, SafeEngineHandle impl, in byte key, IntPtr iv, int enc);
        //int EVP_CipherUpdate(EVP_CIPHER_CTX* ctx, unsigned char*out, int* outl, const unsigned char*in, int inl);
        int EVP_CipherUpdate(SafeCipherContextHandle ctx, ref byte outb, out int outl, in byte inb, int inl);
        //int EVP_CipherFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *outm, int *outl);
        int EVP_CipherFinal_ex(SafeCipherContextHandle ctx, ref byte outm, out int outl);

        //int EVP_OpenInit(EVP_CIPHER_CTX *ctx, EVP_CIPHER *type, unsigned char *ek, int ekl, unsigned char* iv, EVP_PKEY *priv);
        int EVP_OpenInit(SafeCipherContextHandle ctx, SafeCipherHandle type, in byte ek, int ekl, in byte iv, SafeKeyHandle priv);
        int EVP_OpenInit(SafeCipherContextHandle ctx, SafeCipherHandle type, in byte ek, int ekl, IntPtr iv, SafeKeyHandle priv);
        //int EVP_OpenFinal(EVP_CIPHER_CTX *ctx, unsigned char *out, int* outl);
        int EVP_OpenFinal(SafeCipherContextHandle ctx, ref byte outb, out int outl);

        //int EVP_SealInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type, unsigned char** ek, int* ekl, unsigned char* iv, EVP_PKEY **pubk, int npubk);
        int EVP_SealInit(SafeCipherContextHandle ctx, SafeCipherHandle type, IntPtr[] ek, in int ekl, in byte iv, IntPtr[] pubk, int npubk);
        int EVP_SealInit(SafeCipherContextHandle ctx, SafeCipherHandle type, IntPtr[] ek, in int ekl, IntPtr iv, IntPtr[] pubk, int npubk);
        //int EVP_SealFinal(EVP_CIPHER_CTX *ctx, unsigned char *out, int* outl);
        int EVP_SealFinal(SafeCipherContextHandle ctx, ref byte outb, out int outl);

        //int EVP_DecryptInit_ex(EVP_CIPHER_CTX* ctx, const EVP_CIPHER* type, ENGINE *impl, const unsigned char* key, const unsigned char* iv);
        int EVP_DecryptInit_ex(SafeCipherContextHandle ctx, SafeCipherHandle type, SafeEngineHandle impl, in byte key, in byte iv);
        int EVP_DecryptInit_ex(SafeCipherContextHandle ctx, SafeCipherHandle type, SafeEngineHandle impl, in byte key, IntPtr iv);
        //int EVP_DecryptInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type, const unsigned char* key, const unsigned char* iv);
        int EVP_DecryptInit(SafeCipherContextHandle ctx, SafeCipherHandle type, in byte key, in byte iv);
        int EVP_DecryptInit(SafeCipherContextHandle ctx, SafeCipherHandle type, in byte key, IntPtr iv);
        //int EVP_DecryptUpdate(EVP_CIPHER_CTX* ctx, unsigned char*out, int* outl, const unsigned char*in, int inl);
        int EVP_DecryptUpdate(SafeCipherContextHandle ctx, ref byte output, out int outl, in byte input, int inl);
        //int EVP_DecryptFinal_ex(EVP_CIPHER_CTX* ctx, unsigned char* outm, int* outl);
        int EVP_DecryptFinal_ex(SafeCipherContextHandle ctx, ref byte outm, out int outl);

        //int EVP_EncryptInit_ex(EVP_CIPHER_CTX* ctx, const EVP_CIPHER* type, ENGINE *impl, const unsigned char* key, const unsigned char* iv);
        int EVP_EncryptInit_ex(SafeCipherContextHandle ctx, SafeCipherHandle cipher, SafeEngineHandle impl, in byte key, in byte iv);
        int EVP_EncryptInit_ex(SafeCipherContextHandle ctx, SafeCipherHandle cipher, SafeEngineHandle impl, in byte key, IntPtr iv);
        //int EVP_EncryptInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type, const unsigned char* key, const unsigned char* iv);
        int EVP_EncryptInit(SafeCipherContextHandle ctx, SafeCipherHandle type, in byte key, in byte iv);
        int EVP_EncryptInit(SafeCipherContextHandle ctx, SafeCipherHandle type, in byte key, IntPtr iv);
        //int EVP_EncryptUpdate(EVP_CIPHER_CTX* ctx, unsigned char*out, int* outl, const unsigned char*in, int inl);
        int EVP_EncryptUpdate(SafeCipherContextHandle ctx, ref byte output, out int outl, in byte input, int inl);
        //int EVP_EncryptFinal_ex(EVP_CIPHER_CTX* ctx, unsigned char*out, int* outl);
        int EVP_EncryptFinal_ex(SafeCipherContextHandle ctx, ref byte outb, out int outl);
        #endregion

        #region EVP_PKEY
        //EVP_PKEY *EVP_PKEY_new(void);
        [return: NewSafeHandle]
        SafeKeyHandle EVP_PKEY_new();
        //int EVP_PKEY_up_ref(EVP_PKEY *key);
        int EVP_PKEY_up_ref(SafeKeyHandle key);
        //void EVP_PKEY_free(EVP_PKEY *key);
        void EVP_PKEY_free(IntPtr pkey);
        //int EVP_PKEY_cmp(const EVP_PKEY *a, const EVP_PKEY *b);
        [DontCheckReturnType]
        int EVP_PKEY_cmp(SafeKeyHandle a, SafeKeyHandle b);

        //int EVP_PKEY_base_id(const EVP_PKEY *pkey);
        int EVP_PKEY_base_id(SafeKeyHandle pkey);

        //int EVP_PKEY_decrypt_old(unsigned char* dec_key, const unsigned char* enc_key, int enc_key_len, EVP_PKEY *private_key);
        int EVP_PKEY_decrypt_old(ref byte dec_key, in byte enc_key, int enc_key_len, SafeKeyHandle private_key);
        //int EVP_PKEY_encrypt_old(unsigned char *enc_key, const unsigned char* key, int key_len, EVP_PKEY *pub_key);
        int EVP_PKEY_encrypt_old(ref byte enc_key, in byte key, int key_len, SafeKeyHandle pub_key);
        //int EVP_PKEY_type(int type);
        int EVP_PKEY_type(int type);
        //int EVP_PKEY_bits(EVP_PKEY *pkey);
        int EVP_PKEY_bits(SafeKeyHandle pkey);
        //int EVP_PKEY_size(EVP_PKEY *pkey);
        int EVP_PKEY_size(SafeKeyHandle pkey);
        //int EVP_PKEY_assign(EVP_PKEY *pkey, int type, void *key);
        int EVP_PKEY_assign(SafeKeyHandle pkey, int type, IntPtr key);

        //int EVP_PKEY_set1_RSA(EVP_PKEY *pkey,RSA *key);
        int EVP_PKEY_set1_RSA(SafeKeyHandle pkey, SafeRSAHandle key);
        //RSA *EVP_PKEY_get1_RSA(EVP_PKEY *pkey);
        [return: NewSafeHandle]
        SafeRSAHandle EVP_PKEY_get1_RSA(SafeKeyHandle pkey);
        //int EVP_PKEY_set1_DSA(EVP_PKEY *pkey,DSA *key);
        int EVP_PKEY_set1_DSA(SafeKeyHandle pkey, SafeDSAHandle key);
        //DSA *EVP_PKEY_get1_DSA(EVP_PKEY *pkey);
        [return: NewSafeHandle]
        SafeDSAHandle EVP_PKEY_get1_DSA(SafeKeyHandle pkey);
        //int EVP_PKEY_set1_DH(EVP_PKEY *pkey,DH *key);
        int EVP_PKEY_set1_DH(SafeKeyHandle pkey, SafeDHHandle key);
        //DH *EVP_PKEY_get1_DH(EVP_PKEY *pkey);
        [return: NewSafeHandle]
        SafeDHHandle EVP_PKEY_get1_DH(SafeKeyHandle pkey);
        //int EVP_PKEY_set1_EC_KEY(EVP_PKEY *pkey,EC_KEY *key);
        int EVP_PKEY_set1_EC_KEY(SafeKeyHandle pkey, SafeECKeyHandle key);
        //EC_KEY *EVP_PKEY_get1_EC_KEY(EVP_PKEY *pkey);
        [return: NewSafeHandle]
        SafeECKeyHandle EVP_PKEY_get1_EC_KEY(SafeKeyHandle pkey);

        // int EVP_PKEY_assign_RSA(EVP_PKEY *pkey, RSA *key);
        int EVP_PKEY_assign_RSA(SafeKeyHandle pkey, SafeRSAHandle key);
        //int EVP_PKEY_assign_DSA(EVP_PKEY* pkey, DSA* key);
        int EVP_PKEY_assign_DSA(SafeKeyHandle pkey, SafeDSAHandle key);
        //int EVP_PKEY_assign_DH(EVP_PKEY* pkey, DH* key);
        int EVP_PKEY_assign_DH(SafeKeyHandle pkey, SafeDHHandle key);
        //int EVP_PKEY_assign_EC_KEY(EVP_PKEY* pkey, EC_KEY* key);
        int EVP_PKEY_assign_EC_KEY(SafeKeyHandle pkey, SafeECKeyHandle key);

        //int EVP_PKEY_set1_engine(EVP_PKEY* pkey, ENGINE* engine);
        int EVP_PKEY_set1_engine(SafeKeyHandle pkey, SafeEngineHandle engine);

        //int EVP_PKEY_copy_parameters(EVP_PKEY *to, const EVP_PKEY *from);
        int EVP_PKEY_copy_parameters(SafeKeyHandle to, SafeKeyHandle from);
        //int EVP_PKEY_missing_parameters(const EVP_PKEY *pkey);
        int EVP_PKEY_missing_parameters(SafeKeyHandle pkey);
        //int EVP_PKEY_cmp_parameters(const EVP_PKEY *a, const EVP_PKEY *b);
        int EVP_PKEY_cmp_parameters(SafeKeyHandle a, SafeKeyHandle b);
        //int EVP_PKEY_save_parameters(EVP_PKEY *pkey, int mode);
        int EVP_PKEY_save_parameters(SafeKeyHandle pkey, int mode);

        // EVP_PKEY *PEM_read_bio_PrivateKey(BIO *bp, EVP_PKEY **x, pem_password_cb* cb, void* u);
        [return: NewSafeHandle]
        SafeKeyHandle PEM_read_bio_PrivateKey(SafeBioHandle bp, IntPtr x, pem_password_cb cb, IntPtr u);
        //int PEM_write_bio_PrivateKey(BIO* bp, EVP_PKEY* x, const EVP_CIPHER* enc, unsigned char* kstr, int klen, pem_password_cb *cb, void* u);
        int PEM_write_bio_PrivateKey(SafeBioHandle bp, SafeKeyHandle x, SafeCipherHandle enc, IntPtr kstr, int klen, pem_password_cb cb, IntPtr u);

        //EVP_PKEY *d2i_PrivateKey_bio(BIO *bp, EVP_PKEY **a);
        [return: NewSafeHandle]
        SafeKeyHandle d2i_PrivateKey_bio(SafeBioHandle bp, IntPtr a);
        //int i2d_PrivateKey_bio(BIO *bp, EVP_PKEY *pkey);
        int i2d_PrivateKey_bio(SafeBioHandle bp, SafeKeyHandle pkey);

        //int i2d_PUBKEY_bio(BIO *bp, EVP_PKEY *pkey);
        int i2d_PUBKEY_bio(SafeBioHandle bp, SafeKeyHandle pkey);
        //EVP_PKEY *d2i_PUBKEY_bio(BIO *bp, EVP_PKEY **a);
        [return: NewSafeHandle]
        SafeKeyHandle d2i_PUBKEY_bio(SafeBioHandle bp, IntPtr a);
        #endregion

        #region ENGINE
        void ENGINE_free(IntPtr e);
        int ENGINE_up_ref(SafeEngineHandle e);
        //ENGINE *ENGINE_by_id(const char *id);
        [DontCheckReturnType]
        [return: DontTakeOwnership]
        SafeEngineHandle ENGINE_by_id(in byte id);
        //int ENGINE_remove(ENGINE *e);
        int ENGINE_remove(SafeEngineHandle e);

        void ENGINE_load_builtin_engines();
        void ENGINE_register_all_complete();
        //ENGINE* ENGINE_get_default_RSA(void);
        SafeEngineHandle ENGINE_get_default_RSA();
        //ENGINE* ENGINE_get_default_DSA(void);
        SafeEngineHandle ENGINE_get_default_DSA();
        //ENGINE* ENGINE_get_default_ECDH(void);
        SafeEngineHandle ENGINE_get_default_ECDH();
        //ENGINE* ENGINE_get_default_ECDSA(void);
        SafeEngineHandle ENGINE_get_default_ECDSA();
        //ENGINE* ENGINE_get_default_DH(void);
        SafeEngineHandle ENGINE_get_default_DH();
        //ENGINE* ENGINE_get_default_RAND(void);
        SafeEngineHandle ENGINE_get_default_RAND();
        //ENGINE* ENGINE_get_cipher_engine(int nid);
        SafeEngineHandle ENGINE_get_cipher_engine(int nid);
        //ENGINE* ENGINE_get_digest_engine(int nid);
        SafeEngineHandle ENGINE_get_digest_engine(int nid);
        #endregion

        #region EVP_PKEY_CTX
        //EVP_PKEY_CTX* EVP_PKEY_CTX_new(EVP_PKEY* pkey, ENGINE* e);
        [return: NewSafeHandle]
        SafeKeyContextHandle EVP_PKEY_CTX_new(SafeKeyHandle pkey, SafeEngineHandle e);
        //EVP_PKEY_CTX *EVP_PKEY_CTX_new_id(int id, ENGINE *e);
        [return: NewSafeHandle]
        SafeKeyContextHandle EVP_PKEY_CTX_new_id(int id, SafeEngineHandle e);
        SafeKeyContextHandle EVP_PKEY_CTX_new_id(int id, IntPtr e);
        //void EVP_PKEY_CTX_free(EVP_PKEY_CTX* ctx);
        void EVP_PKEY_CTX_free(IntPtr ctx);
        //EVP_PKEY_CTX *EVP_PKEY_CTX_dup(EVP_PKEY_CTX* ctx);
        IntPtr EVP_PKEY_CTX_dup(SafeKeyContextHandle ctx);

        //int EVP_PKEY_keygen_init(EVP_PKEY_CTX* ctx);
        int EVP_PKEY_keygen_init(SafeKeyContextHandle ctx);
        //int EVP_PKEY_keygen(EVP_PKEY_CTX* ctx, EVP_PKEY** ppkey);
        int EVP_PKEY_keygen(SafeKeyContextHandle ctx, [NewSafeHandle] out SafeKeyHandle ppkey);

        //int EVP_PKEY_CTX_set_rsa_keygen_bits(EVP_PKEY_CTX *ctx, int mbits);
        int EVP_PKEY_CTX_set_rsa_keygen_bits(SafeKeyContextHandle ctx, int mbits);

        //int EVP_PKEY_decrypt_init(EVP_PKEY_CTX* ctx);
        int EVP_PKEY_decrypt_init(SafeKeyContextHandle ctx);
        //int EVP_PKEY_decrypt(EVP_PKEY_CTX* ctx, unsigned char *out, size_t* outlen, const unsigned char*in, size_t inlen);
        int EVP_PKEY_decrypt(SafeKeyContextHandle ctx, ref byte output, ref uint outlen, in byte input, uint inlen);
        int EVP_PKEY_decrypt(SafeKeyContextHandle ctx, IntPtr output, ref uint outlen, in byte input, uint inlen); //to pass IntPtr.Zero

        //int EVP_PKEY_encrypt_init(EVP_PKEY_CTX* ctx);
        int EVP_PKEY_encrypt_init(SafeKeyContextHandle ctx);
        //int EVP_PKEY_encrypt(EVP_PKEY_CTX* ctx, unsigned char*out, size_t* outlen, const unsigned char*in, size_t inlen);
        int EVP_PKEY_encrypt(SafeKeyContextHandle ctx, ref byte output, ref uint outlen, in byte input, uint inlen);
        int EVP_PKEY_encrypt(SafeKeyContextHandle ctx, IntPtr output, ref uint outlen, in byte input, uint inlen); //to pass IntPtr.Zero
        #endregion

        #region EC_METHOD
        //const EC_METHOD *EC_GFp_simple_method(void);
        SafeECMethodHandle EC_GFp_simple_method();
        SafeECMethodHandle EC_GFp_mont_method();
        SafeECMethodHandle EC_GFp_nist_method();
        SafeECMethodHandle EC_GF2m_simple_method();
        //int EC_METHOD_get_field_type(const EC_METHOD* meth);
        int EC_METHOD_get_field_type(SafeECMethodHandle meth);
        #endregion

        #region EC_POINT
        //EC_POINT *EC_POINT_new(const EC_GROUP *group);
        [return: NewSafeHandle]
        SafeECPointHandle EC_POINT_new(SafeECGroupHandle group);
        //void EC_POINT_free(EC_POINT *point);
        void EC_POINT_free(IntPtr point);
        //void EC_POINT_clear_free(EC_POINT *point);
        void EC_POINT_clear_free(IntPtr point);
        //int EC_POINT_copy(EC_POINT* dst, const EC_POINT* src);
        int EC_POINT_copy(SafeECPointHandle dst, SafeECPointHandle src);
        //EC_POINT *EC_POINT_dup(const EC_POINT *src, const EC_GROUP *group);
        IntPtr EC_POINT_dup(SafeECPointHandle src, SafeECGroupHandle group);
        //const EC_METHOD *EC_POINT_method_of(const EC_POINT *point);
        SafeECMethodHandle EC_POINT_method_of(SafeECPointHandle point);
        //int EC_POINT_cmp(const EC_GROUP *group, const EC_POINT *a, const EC_POINT *b, BN_CTX *ctx);
        int EC_POINT_cmp(SafeECGroupHandle group, SafeECPointHandle a, SafeECPointHandle b, SafeBigNumberContextHandle ctx);

        //int EC_POINT_set_to_infinity(const EC_GROUP *group, EC_POINT *point);
        int EC_POINT_set_to_infinity(SafeECGroupHandle group, SafeECPointHandle point);

        //int EC_POINT_set_Jprojective_coordinates_GFp(const EC_GROUP *group, EC_POINT *p, const BIGNUM* x, const BIGNUM* y, const BIGNUM* z, BN_CTX *ctx);
        int EC_POINT_set_Jprojective_coordinates_GFp(SafeECGroupHandle group, SafeECPointHandle p, SafeBigNumberHandle x, SafeBigNumberHandle y, SafeBigNumberHandle z, SafeBigNumberContextHandle ctx);
        //int EC_POINT_get_Jprojective_coordinates_GFp(const EC_GROUP *group, const EC_POINT* p, BIGNUM *x, BIGNUM* y, BIGNUM *z, BN_CTX* ctx);
        int EC_POINT_get_Jprojective_coordinates_GFp(SafeECGroupHandle group, SafeECPointHandle p, SafeBigNumberHandle x, SafeBigNumberHandle y, SafeBigNumberHandle z, SafeBigNumberContextHandle ctx);

        //int EC_POINT_set_affine_coordinates_GFp(const EC_GROUP *group, EC_POINT *p, const BIGNUM* x, const BIGNUM* y, BN_CTX *ctx);
        int EC_POINT_set_affine_coordinates_GFp(SafeECGroupHandle group, SafeECPointHandle p, SafeBigNumberHandle x, SafeBigNumberHandle y, SafeBigNumberContextHandle ctx);
        //int EC_POINT_get_affine_coordinates_GFp(const EC_GROUP *group, const EC_POINT* p, BIGNUM *x, BIGNUM* y, BN_CTX *ctx);
        int EC_POINT_get_affine_coordinates_GFp(SafeECGroupHandle group, SafeECPointHandle p, SafeBigNumberHandle x, SafeBigNumberHandle y, SafeBigNumberContextHandle ctx);

        //int EC_POINT_set_affine_coordinates_GF2m(const EC_GROUP *group, EC_POINT *p, const BIGNUM* x, const BIGNUM* y, BN_CTX *ctx);
        int EC_POINT_set_affine_coordinates_GF2m(SafeECGroupHandle group, SafeECPointHandle p, SafeBigNumberHandle x, SafeBigNumberHandle y, SafeBigNumberContextHandle ctx);
        //int EC_POINT_get_affine_coordinates_GF2m(const EC_GROUP *group, const EC_POINT* p, BIGNUM *x, BIGNUM* y, BN_CTX *ctx);
        int EC_POINT_get_affine_coordinates_GF2m(SafeECGroupHandle group, SafeECPointHandle p, SafeBigNumberHandle x, SafeBigNumberHandle y, SafeBigNumberContextHandle ctx);

        //int EC_POINT_set_compressed_coordinates_GFp(const EC_GROUP *group, EC_POINT *p, const BIGNUM* x, int y_bit, BN_CTX *ctx);
        int EC_POINT_set_compressed_coordinates_GFp(SafeECGroupHandle group, SafeECPointHandle p, SafeBigNumberHandle x, int y_bit, SafeBigNumberContextHandle ctx);
        //int EC_POINT_set_compressed_coordinates_GF2m(const EC_GROUP *group, EC_POINT *p, const BIGNUM* x, int y_bit, BN_CTX *ctx);
        int EC_POINT_set_compressed_coordinates_GF2m(SafeECGroupHandle group, SafeECPointHandle p, SafeBigNumberHandle x, int y_bit, SafeBigNumberContextHandle ctx);

        //size_t EC_POINT_point2oct(const EC_GROUP *group, const EC_POINT *p, point_conversion_form_t form, unsigned char* buf, size_t len, BN_CTX* ctx);
        int EC_POINT_point2oct(SafeECGroupHandle group, SafeECPointHandle p, int form, ref byte buf, int len, SafeBigNumberContextHandle ctx);
        //int EC_POINT_oct2point(const EC_GROUP *group, EC_POINT *p, const unsigned char* buf, size_t len, BN_CTX* ctx);
        int EC_POINT_oct2point(SafeECGroupHandle group, SafeECPointHandle p, in byte buf, int len, SafeBigNumberContextHandle ctx);
        //BIGNUM *EC_POINT_point2bn(const EC_GROUP *, const EC_POINT *, point_conversion_form_t form, BIGNUM *, BN_CTX *);
        SafeBigNumberHandle EC_POINT_point2bn(SafeECGroupHandle a, SafeECPointHandle b, int form, SafeBigNumberHandle c, SafeBigNumberContextHandle d);
        //EC_POINT *EC_POINT_bn2point(const EC_GROUP *, const BIGNUM *, EC_POINT*, BN_CTX*);
        SafeECPointHandle EC_POINT_bn2point(SafeECGroupHandle a, SafeBigNumberHandle b, SafeECPointHandle c, SafeBigNumberContextHandle d);
        //char *EC_POINT_point2hex(const EC_GROUP *, const EC_POINT *,  point_conversion_form_t form, BN_CTX *);
        string EC_POINT_point2hex(SafeECGroupHandle a, SafeECPointHandle b, int form, SafeBigNumberContextHandle c);
        //EC_POINT *EC_POINT_hex2point(const EC_GROUP *, const char *, EC_POINT*, BN_CTX*);
        SafeECPointHandle EC_POINT_hex2point(SafeECGroupHandle a, string s, SafeECPointHandle b, SafeBigNumberContextHandle c);

        //int EC_POINT_add(const EC_GROUP *group, EC_POINT *r, const EC_POINT *a, const EC_POINT *b, BN_CTX *ctx);
        int EC_POINT_add(SafeECGroupHandle group, SafeECPointHandle r, SafeECPointHandle a, SafeECPointHandle b, SafeBigNumberContextHandle ctx);
        //int EC_POINT_dbl(const EC_GROUP *group, EC_POINT *r, const EC_POINT *a, BN_CTX *ctx);
        int EC_POINT_dbl(SafeECGroupHandle group, SafeECPointHandle r, SafeECPointHandle a, SafeBigNumberContextHandle ctx);
        //int EC_POINT_invert(const EC_GROUP *group, EC_POINT *a, BN_CTX *ctx);
        int EC_POINT_invert(SafeECGroupHandle group, SafeECPointHandle a, SafeBigNumberContextHandle ctx);
        //int EC_POINT_is_at_infinity(const EC_GROUP *group, const EC_POINT *p);
        int EC_POINT_is_at_infinity(SafeECGroupHandle group, SafeECPointHandle p);
        //int EC_POINT_is_on_curve(const EC_GROUP *group, const EC_POINT *point, BN_CTX *ctx);
        int EC_POINT_is_on_curve(SafeECGroupHandle group, SafeECPointHandle point, SafeBigNumberContextHandle ctx);
        //int EC_POINT_make_affine(const EC_GROUP *group, EC_POINT *point, BN_CTX *ctx);
        int EC_POINT_make_affine(SafeECGroupHandle a, SafeECPointHandle b, SafeBigNumberContextHandle c);
        //int EC_POINTs_make_affine(const EC_GROUP *group, size_t num, EC_POINT *points[], BN_CTX *ctx);
        int EC_POINTs_make_affine(SafeECGroupHandle a, int num, SafeECPointHandle[] b, SafeBigNumberContextHandle c);
        //int EC_POINTs_mul(const EC_GROUP *group, EC_POINT *r, const BIGNUM *n, size_t num, const EC_POINT *p[], const BIGNUM *m[], BN_CTX *ctx);
        int EC_POINTs_mul(SafeECGroupHandle group, SafeECPointHandle r, SafeBigNumberHandle n, int num, SafeECPointHandle[] p, SafeBigNumberHandle[] m, SafeBigNumberContextHandle ctx);
        // int EC_POINT_mul(const EC_GROUP *group, EC_POINT *r, const BIGNUM *n, const EC_POINT *q, const BIGNUM *m, BN_CTX *ctx);
        int EC_POINT_mul(SafeECGroupHandle group, SafeECPointHandle r, SafeBigNumberHandle n, SafeECPointHandle q, SafeBigNumberHandle m, SafeBigNumberContextHandle ctx);
        #endregion

        #region EC_GROUP
        //size_t EC_get_builtin_curves(EC_builtin_curve *r, size_t nitems);
        int EC_get_builtin_curves(IntPtr r, int nitems);

        //EC_GROUP *EC_GROUP_new(const EC_METHOD *meth);
        [return: NewSafeHandle]
        SafeECGroupHandle EC_GROUP_new(SafeECMethodHandle meth);
        //void EC_GROUP_free(EC_GROUP *group);
        void EC_GROUP_free(IntPtr group);
        //void EC_GROUP_clear_free(EC_GROUP *group);
        void EC_GROUP_clear_free(IntPtr group);
        //int EC_GROUP_copy(EC_GROUP *dst, const EC_GROUP *src);
        int EC_GROUP_copy(SafeECGroupHandle dst, SafeECGroupHandle src);
        //EC_GROUP *EC_GROUP_dup(const EC_GROUP *src);
        IntPtr EC_GROUP_dup(SafeECGroupHandle src);
        //const EC_METHOD *EC_GROUP_method_of(const EC_GROUP *group);
        SafeECMethodHandle EC_GROUP_method_of(SafeECGroupHandle group);
        //int EC_GROUP_cmp(const EC_GROUP *a, const EC_GROUP *b, BN_CTX *ctx);
        int EC_GROUP_cmp(SafeECGroupHandle a, SafeECGroupHandle b, SafeBigNumberContextHandle ctx);

        //EC_GROUP *EC_GROUP_new_curve_GFp(const BIGNUM *p, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx);
        [return: NewSafeHandle]
        SafeECGroupHandle EC_GROUP_new_curve_GFp(SafeBigNumberHandle p, SafeBigNumberHandle a, SafeBigNumberHandle b, SafeBigNumberContextHandle ctx);
        //EC_GROUP *EC_GROUP_new_curve_GF2m(const BIGNUM *p, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx);
        [return: NewSafeHandle]
        SafeECGroupHandle EC_GROUP_new_curve_GF2m(SafeBigNumberHandle p, SafeBigNumberHandle a, SafeBigNumberHandle b, SafeBigNumberContextHandle ctx);
        //EC_GROUP *EC_GROUP_new_by_curve_name(int nid);
        [return: NewSafeHandle]
        SafeECGroupHandle EC_GROUP_new_by_curve_name(int nid);

        //int EC_GROUP_set_generator(EC_GROUP *group, const EC_POINT *generator, const BIGNUM *order, const BIGNUM *cofactor);
        int EC_GROUP_set_generator(SafeECGroupHandle group, SafeECPointHandle generator, SafeBigNumberHandle order, SafeBigNumberHandle cofactor);
        //const EC_POINT *EC_GROUP_get0_generator(const EC_GROUP *group);
        SafeECPointHandle EC_GROUP_get0_generator(SafeECGroupHandle group);
        //int EC_GROUP_get_order(const EC_GROUP *group, BIGNUM *order, BN_CTX *ctx);
        int EC_GROUP_get_order(SafeECGroupHandle group, SafeBigNumberHandle order, SafeBigNumberContextHandle ctx);
        //int EC_GROUP_get_cofactor(const EC_GROUP *group, BIGNUM *cofactor, BN_CTX *ctx);
        int EC_GROUP_get_cofactor(SafeECGroupHandle group, SafeBigNumberHandle cofactor, SafeBigNumberContextHandle ctx);
        //void EC_GROUP_set_curve_name(EC_GROUP *group, int nid);
        void EC_GROUP_set_curve_name(SafeECGroupHandle group, int nid);
        //int EC_GROUP_get_curve_name(const EC_GROUP *group);
        int EC_GROUP_get_curve_name(SafeECGroupHandle group);
        //void EC_GROUP_set_asn1_flag(EC_GROUP *group, int flag);
        void EC_GROUP_set_asn1_flag(SafeECGroupHandle group, int flag);
        //int EC_GROUP_get_asn1_flag(const EC_GROUP *group);
        int EC_GROUP_get_asn1_flag(SafeECGroupHandle group);

        //void EC_GROUP_set_point_conversion_form(EC_GROUP *group, point_conversion_form_t form);
        void EC_GROUP_set_point_conversion_form(SafeECGroupHandle x, int y);
        //point_conversion_form_t EC_GROUP_get_point_conversion_form(const EC_GROUP *);
        int EC_GROUP_get_point_conversion_form(SafeECGroupHandle x);

        //unsigned char *EC_GROUP_get0_seed(const EC_GROUP *x);
        ref byte EC_GROUP_get0_seed(SafeECGroupHandle x);
        //size_t EC_GROUP_get_seed_len(const EC_GROUP *);
        int EC_GROUP_get_seed_len(SafeECGroupHandle x);
        //size_t EC_GROUP_set_seed(EC_GROUP *, const unsigned char *, size_t len);
        int EC_GROUP_set_seed(SafeECGroupHandle x, in byte buf, int len);

        //int EC_GROUP_set_curve_GFp(EC_GROUP *group, const BIGNUM *p, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx);
        int EC_GROUP_set_curve_GFp(SafeECGroupHandle group, SafeBigNumberHandle p, SafeBigNumberHandle a, SafeBigNumberHandle b, SafeBigNumberContextHandle ctx);
        //int EC_GROUP_get_curve_GFp(const EC_GROUP *group, BIGNUM *p, BIGNUM *a, BIGNUM *b, BN_CTX *ctx);
        int EC_GROUP_get_curve_GFp(SafeECGroupHandle group, SafeBigNumberHandle p, SafeBigNumberHandle a, SafeBigNumberHandle b, SafeBigNumberContextHandle ctx);
        //int EC_GROUP_set_curve_GF2m(EC_GROUP *group, const BIGNUM *p, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx);
        int EC_GROUP_set_curve_GF2m(SafeECGroupHandle group, SafeBigNumberHandle p, SafeBigNumberHandle a, SafeBigNumberHandle b, SafeBigNumberContextHandle ctx);
        //int EC_GROUP_get_curve_GF2m(const EC_GROUP *group, BIGNUM *p, BIGNUM *a, BIGNUM *b, BN_CTX *ctx);
        int EC_GROUP_get_curve_GF2m(SafeECGroupHandle group, SafeBigNumberHandle p, SafeBigNumberHandle a, SafeBigNumberHandle b, SafeBigNumberContextHandle ctx);

        //int EC_GROUP_get_degree(const EC_GROUP *group);
        int EC_GROUP_get_degree(SafeECGroupHandle group);
        //int EC_GROUP_check(const EC_GROUP *group, BN_CTX *ctx);
        int EC_GROUP_check(SafeECGroupHandle group, SafeBigNumberContextHandle ctx);
        //int EC_GROUP_check_discriminant(const EC_GROUP *group, BN_CTX *ctx);
        int EC_GROUP_check_discriminant(SafeECGroupHandle group, SafeBigNumberContextHandle ctx);

        //int EC_GROUP_precompute_mult(EC_GROUP *group, BN_CTX *ctx);
        int EC_GROUP_precompute_mult(SafeECGroupHandle group, SafeBigNumberContextHandle ctx);
        //int EC_GROUP_have_precompute_mult(const EC_GROUP *group);
        int EC_GROUP_have_precompute_mult(SafeECGroupHandle group);
        #endregion

        #region EC_KEY
        //EC_KEY *EC_KEY_new(void);
        [return: NewSafeHandle]
        SafeECKeyHandle EC_KEY_new();
        //EC_KEY *EC_KEY_new_by_curve_name(int nid);
        [return: NewSafeHandle]
        SafeECKeyHandle EC_KEY_new_by_curve_name(int nid);
        //void EC_KEY_free(EC_KEY *key);
        void EC_KEY_free(IntPtr key);
        //EC_KEY *EC_KEY_copy(EC_KEY *dst, const EC_KEY *src);
        SafeECKeyHandle EC_KEY_copy(SafeECKeyHandle dst, SafeECKeyHandle src);
        //EC_KEY *EC_KEY_dup(const EC_KEY *src);
        IntPtr EC_KEY_dup(SafeECKeyHandle src);
        //int EC_KEY_up_ref(EC_KEY *key);
        int EC_KEY_up_ref(SafeECKeyHandle key);

        //const EC_GROUP *EC_KEY_get0_group(const EC_KEY *key);
        SafeECGroupHandle EC_KEY_get0_group(SafeECKeyHandle key);
        //int EC_KEY_set_group(EC_KEY *key, const EC_GROUP *group);
        int EC_KEY_set_group(SafeECKeyHandle key, SafeECGroupHandle group);

        //const BIGNUM *EC_KEY_get0_private_key(const EC_KEY *key);
        SafeBigNumberHandle EC_KEY_get0_private_key(SafeECKeyHandle key);
        //int EC_KEY_set_private_key(EC_KEY *key, const BIGNUM *prv);
        int EC_KEY_set_private_key(SafeECKeyHandle key, SafeBigNumberHandle prv);

        //const EC_POINT *EC_KEY_get0_public_key(const EC_KEY *key);
        SafeECPointHandle EC_KEY_get0_public_key(SafeECKeyHandle key);
        //int EC_KEY_set_public_key(EC_KEY *key, const EC_POINT *pub);
        int EC_KEY_set_public_key(SafeECKeyHandle key, SafeECPointHandle pub);

        //unsigned int EC_KEY_get_enc_flags(const EC_KEY *key);
        uint EC_KEY_get_enc_flags(SafeECKeyHandle key);
        //void EC_KEY_set_enc_flags(EC_KEY *eckey, unsigned int flags);
        void EC_KEY_set_enc_flags(SafeECKeyHandle x, uint y);

        //point_conversion_form_t EC_KEY_get_conv_form(const EC_KEY *key);
        int EC_KEY_get_conv_form(SafeECKeyHandle x);
        //void EC_KEY_set_conv_form(EC_KEY *eckey, point_conversion_form_t cform);
        void EC_KEY_set_conv_form(SafeECKeyHandle x, int y);

        //void *EC_KEY_get_key_method_data(EC_KEY *key, void* (* dup_func) (void*), void (* free_func) (void*), void (* clear_free_func) (void*));
        SafeECKeyHandle EC_KEY_get_key_method_data(SafeECKeyHandle x, EC_KEY_dup_func dup_func, EC_KEY_free_func free_func, EC_KEY_free_func clear_free_func);
        //void EC_KEY_insert_key_method_data(EC_KEY *key, void *data, void* (* dup_func) (void*), void (* free_func) (void*), void (* clear_free_func) (void*));
        void EC_KEY_insert_key_method_data(SafeECKeyHandle x, IntPtr data, EC_KEY_dup_func dup_func, EC_KEY_free_func free_func, EC_KEY_free_func clear_free_func);

        //void EC_KEY_set_asn1_flag(EC_KEY *eckey, int asn1_flag);
        void EC_KEY_set_asn1_flag(SafeECKeyHandle x, int y);
        //int EC_KEY_precompute_mult(EC_KEY *key, BN_CTX *ctx);
        int EC_KEY_precompute_mult(SafeECKeyHandle key, SafeBigNumberContextHandle ctx);

        //int EC_KEY_generate_key(EC_KEY *key);
        int EC_KEY_generate_key(SafeECKeyHandle key);
        //int EC_KEY_check_key(const EC_KEY *key);
        int EC_KEY_check_key(SafeECKeyHandle key);
        #endregion

        #region ECDSA_SIG
        //ECDSA_SIG* ECDSA_SIG_new(void);
        [return: NewSafeHandle]
        SafeECDSASignatureHandle ECDSA_SIG_new();
        //void ECDSA_SIG_free(ECDSA_SIG *sig);
        void ECDSA_SIG_free(IntPtr sig);

        //int i2d_ECDSA_SIG(const ECDSA_SIG *sig, unsigned char **pp);
        int i2d_ECDSA_SIG(SafeECDSASignatureHandle sig, ref byte pp);
        //ECDSA_SIG* d2i_ECDSA_SIG(ECDSA_SIG **sig, const unsigned char **pp, long len);
        [return: NewSafeHandle]
        SafeECDSASignatureHandle d2i_ECDSA_SIG(IntPtr sig, in byte pp, long len);

        //ECDSA_SIG* ECDSA_do_sign(const unsigned char *dgst, int dgst_len, EC_KEY* eckey);
        [return: NewSafeHandle]
        SafeECDSASignatureHandle ECDSA_do_sign(in byte dgst, int dgst_len, SafeECKeyHandle eckey);
        //ECDSA_SIG* ECDSA_do_sign_ex(const unsigned char *dgst, int dgstlen, const BIGNUM* kinv, const BIGNUM* rp, EC_KEY *eckey);
        [return: NewSafeHandle]
        SafeECDSASignatureHandle ECDSA_do_sign_ex(in byte dgst, int dgstlen, SafeBigNumberHandle kinv, SafeBigNumberHandle rp, SafeECKeyHandle eckey);
        //int ECDSA_do_verify(const unsigned char *dgst, int dgst_len, const ECDSA_SIG* sig, EC_KEY* eckey);
        int ECDSA_do_verify(in byte dgst, int dgst_len, SafeECDSASignatureHandle sig, SafeECKeyHandle eckey);

        //const ECDSA_METHOD* ECDSA_OpenSSL(void);
        IntPtr ECDSA_OpenSSL();
        //void ECDSA_set_default_method(const ECDSA_METHOD *meth);
        void ECDSA_set_default_method(IntPtr meth);
        //const ECDSA_METHOD* ECDSA_get_default_method(void);
        IntPtr ECDSA_get_default_method();
        //int ECDSA_set_method(EC_KEY *eckey,const ECDSA_METHOD *meth);
        int ECDSA_set_method(SafeECKeyHandle eckey, IntPtr meth);

        //int ECDSA_size(const EC_KEY *eckey);
        int ECDSA_size(SafeECKeyHandle eckey);
        //int ECDSA_sign_setup(EC_KEY *eckey, BN_CTX *ctx,  BIGNUM** kinv, BIGNUM **rp);
        int ECDSA_sign_setup(SafeECKeyHandle eckey, SafeBigNumberContextHandle ctx, SafeBigNumberHandle[] kinv, SafeBigNumberHandle[] rp);
        //int ECDSA_sign(int type, const unsigned char *dgst, int dgstlen, unsigned char* sig, unsigned int* siglen, EC_KEY *eckey);
        int ECDSA_sign(int type, in byte dgst, int dgstlen, ref byte sig, out uint siglen, SafeECKeyHandle eckey);
        //int ECDSA_sign_ex(int type, const unsigned char *dgst, int dgstlen, unsigned char* sig, unsigned int* siglen, const BIGNUM* kinv, const BIGNUM* rp, EC_KEY *eckey);
        int ECDSA_sign_ex(int type, in byte dgst, int dgstlen, ref byte sig, out uint siglen, SafeBigNumberHandle kinv, SafeBigNumberHandle rp, SafeECKeyHandle eckey);
        //int ECDSA_verify(int type, const unsigned char *dgst, int dgstlen, const unsigned char* sig, int siglen, EC_KEY *eckey);
        int ECDSA_verify(int type, in byte dgst, int dgstlen, in byte sig, int siglen, SafeECKeyHandle eckey);
        #endregion

        //int ECDH_compute_key(void *out, size_t outlen, const EC_POINT *pub_key, EC_KEY* ecdh, void* (* KDF) (const void*in, size_t inlen, void*out, size_t* outlen));
        int ECDH_compute_key(ref byte pout, int outlen, SafeECPointHandle pub_key, SafeECKeyHandle ecdh, ECDH_KDF kdf);

        #region BIO
        //const BIO_METHOD* BIO_s_mem(void);
        IntPtr BIO_s_mem();
        //const BIO_METHOD *BIO_f_md(void);
        IntPtr BIO_f_md();
        //const BIO_METHOD *BIO_f_null(void);
        IntPtr BIO_f_null();
        //BIO *  BIO_new(const BIO_METHOD *type);
        [return: NewSafeHandle]
        SafeBioHandle BIO_new(IntPtr type);
        //int BIO_up_ref(BIO *a);
        int BIO_up_ref(SafeBioHandle a);

        //BIO *BIO_new_file(const char *filename, const char *mode);
        [return: NewSafeHandle]
        SafeBioHandle BIO_new_file(in byte filename, in byte mode);
        //BIO *BIO_new_mem_buf(const void *buf, int len);
        [return: NewSafeHandle]
        SafeBioHandle BIO_new_mem_buf(ref byte buf, int len);
        //BIO *BIO_new_fp(FILE *stream, int flags);
        [return: NewSafeHandle]
        SafeBioHandle BIO_new_fp(Microsoft.Win32.SafeHandles.SafeFileHandle stream, int flags);

        //BIO *BIO_push(BIO *b, BIO *append);
        SafeBioHandle BIO_push(SafeBioHandle bp, SafeBioHandle append);
        //long BIO_ctrl(BIO *bp, int cmd, long larg, void *parg);
        long BIO_ctrl(SafeBioHandle bp, int cmd, int larg, IntPtr parg);
        //long BIO_int_ctrl(BIO *bp, int cmd, long larg, int iarg);
        long BIO_int_ctrl(SafeBioHandle bp, int cmd, int larg, int parg);
        //# define BIO_flush(b)            (int)BIO_ctrl(b,BIO_CTRL_FLUSH,0,NULL)
        long BIO_flush(SafeBioHandle b);
        //void *BIO_get_data(BIO *a);
        IntPtr BIO_get_data(SafeBioHandle a);

        //int BIO_set_md(BIO* b, EVP_MD* md);
        int BIO_set_md(SafeBioHandle b, SafeMessageDigestHandle md);
        //int BIO_get_md_ctx(BIO *b,EVP_MD_CTX **mdcp);
        int BIO_get_md_ctx(SafeBioHandle b, [NewSafeHandle] out SafeMessageDigestContextHandle mdcp);

        //int BIO_read(BIO* b, void* data, int dlen);
        [DontCheckReturnType]
        int BIO_read(SafeBioHandle b, ref byte buf, int len);
        //int BIO_write(BIO *b, const void *data, int dlen);
        [DontCheckReturnType]
        int BIO_write(SafeBioHandle b, in byte buf, int len);
        //int BIO_puts(BIO *b, const char *buf);
        int BIO_puts(SafeBioHandle b, in byte buf);
        //int BIO_gets(BIO *b, char *buf, int size);
        int BIO_gets(SafeBioHandle b, ref byte buf, int len);

        //int BIO_free(BIO *a);
        int BIO_free(IntPtr bio);
        //void BIO_free_all(BIO* a);
        void BIO_free_all(IntPtr bio);

        //uint64_t BIO_number_read(BIO *bio)
        ulong BIO_number_read(SafeBioHandle bio);
        //uint64_t BIO_number_written(BIO *bio)
        ulong BIO_number_written(SafeBioHandle bio);

        //size_t BIO_ctrl_pending(BIO* b);
        uint BIO_ctrl_pending(SafeBioHandle bio);
        #endregion

        #region ERR
        [DontCheckReturnType]
        ulong ERR_get_error();
        void ERR_error_string_n(ulong e, ref byte buf, int len);
        IntPtr ERR_lib_error_string(ulong e);
        IntPtr ERR_func_error_string(ulong e);
        IntPtr ERR_reason_error_string(ulong e);
        void ERR_clear_error();
        void ERR_print_errors_cb(err_cb cb, IntPtr u);
        #endregion

        //void CRYPTO_free(void *str, const char *file, int line)
        void CRYPTO_free(IntPtr addr, in byte file, int line);
        //void *CRYPTO_malloc(size_t num, const char *file, int line)
        IntPtr CRYPTO_malloc(int size, in byte file, int line);

        //int CRYPTO_set_mem_functions(void* (* m) (size_t, const char*, int), void* (* r) (void*, size_t, const char*, int), void (* f) (void*, const char*, int))
        int CRYPTO_set_mem_functions(MallocFunctionPtr m, ReallocFunctionPtr r, FreeFunctionPtr f);
        //int CRYPTO_mem_leaks(BIO* b);
        int CRYPTO_mem_leaks(SafeBioHandle b);
    }
}
