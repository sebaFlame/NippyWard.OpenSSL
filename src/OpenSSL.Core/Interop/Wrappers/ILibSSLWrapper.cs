using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

using OpenSSL.Core.Interop.Attributes;
using OpenSSL.Core.Interop.SafeHandles;
using OpenSSL.Core.Interop.SafeHandles.SSL;
using OpenSSL.Core.Interop.SafeHandles.Crypto;
using OpenSSL.Core.Interop.SafeHandles.X509;

namespace OpenSSL.Core.Interop.Wrappers
{
    //int (*client_cert_cb)(SSL *ssl, X509 **x509, EVP_PKEY **pkey)
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    internal delegate int ClientCertificateCallback(IntPtr ssl, out IntPtr x509, out IntPtr pkey);

    //int (*verify_callback)(int, X509_STORE_CTX *)
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    internal delegate int VerifyCertificateCallback(int preVerify, IntPtr x509_store_ctx);

    //int (*cb) (struct ssl_st *ssl, SSL_SESSION *sess)
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    internal delegate int SessionCallback(IntPtr ssl, IntPtr sess);

    //callback(SSL *ssl, int where, int ret)
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    internal delegate void SslInfoCallback (IntPtr ssl, int where, int ret);

    internal interface ILibSSLWrapper
    {
        void SSL_load_error_strings();
        //int OPENSSL_init_ssl(uint64_t opts, const OPENSSL_INIT_SETTINGS *settings);
        int OPENSSL_init_ssl(ulong opts, IntPtr settings);

        #region SSL_METHOD
        //const SSL_METHOD* TLS_method(void);
        SafeSslMethodHandle TLS_method();
        //const SSL_METHOD* TLS_server_method(void);
        SafeSslMethodHandle TLS_server_method();
        //const SSL_METHOD* TLS_client_method(void);
        SafeSslMethodHandle TLS_client_method();

        SafeSslMethodHandle TLSv1_method();
        SafeSslMethodHandle TLSv1_client_method();
        SafeSslMethodHandle TLSv1_server_method();

        SafeSslMethodHandle TLSv1_1_method();
        SafeSslMethodHandle TLSv1_1_server_method();
        SafeSslMethodHandle TLSv1_1_client_method();

        SafeSslMethodHandle TLSv1_2_method();
        SafeSslMethodHandle TLSv1_2_server_method();
        SafeSslMethodHandle TLSv1_2_client_method();

        SafeSslMethodHandle DTLSv1_method();
        SafeSslMethodHandle DTLSv1_client_method();
        SafeSslMethodHandle DTLSv1_server_method();

        SafeSslMethodHandle DTLSv1_2_method();
        SafeSslMethodHandle DTLSv1_2_client_method();
        SafeSslMethodHandle DTLSv1_2_server_method();
        #endregion

        #region SSL_CTX 
        //SSL_CTX *SSL_CTX_new(const SSL_METHOD *method);
        [return: TakeOwnership]
        SafeSslContextHandle SSL_CTX_new(SafeSslMethodHandle sslMethod);
        //void SSL_CTX_free(SSL_CTX *ctx);
        void SSL_CTX_free(IntPtr ctx);
        //long SSL_CTX_ctrl(SSL_CTX *ctx, int cmd, long larg, void *parg);
        [return: NativeLong, DontVerifyType]
        long SSL_CTX_ctrl(SafeSslContextHandle ctx, int cmd, [NativeLong] long arg, IntPtr parg);
        //void SSL_CTX_set_verify_depth(SSL_CTX *ctx,int depth);
        void SSL_CTX_set_verify_depth(SafeSslContextHandle ctx, int depth);
        //int SSL_CTX_up_ref(SSL_CTX *ctx);
        int SSL_CTX_up_ref(SafeSslContextHandle ctx);

        //STACK_OF(SSL_CIPHER) *SSL_CTX_get_ciphers(const SSL_CTX *ctx);
        SafeStackHandle<SafeSslCipherHandle> SSL_CTX_get_ciphers(SafeSslContextHandle ctx);
        //long SSL_CTX_set_options(SSL_CTX *ctx, long options);
        [return: NativeLong, DontVerifyType]
        long SSL_CTX_set_options(SafeSslContextHandle ctx, [NativeLong] long options);
        //long SSL_CTX_clear_options(SSL_CTX *ctx, long options);
        [return: NativeLong, DontVerifyType]
        long SSL_CTX_clear_options(SafeSslContextHandle ctx, [NativeLong] long options);
        //void SSL_CTX_set_security_level(SSL_CTX *ctx, int level);
        void SSL_CTX_set_security_level(SafeSslContextHandle ctx, int level);

        //int SSL_CTX_load_verify_locations(SSL_CTX *ctx, const char *CAfile, const char* CApath);
        int SSL_CTX_load_verify_locations(SafeSslContextHandle ctx, string file, string path);
        //int SSL_CTX_set_default_verify_paths(SSL_CTX *ctx);
        int SSL_CTX_set_default_verify_paths(SafeSslContextHandle ctx);
        //int SSL_CTX_set_cipher_list(SSL_CTX *ctx, const char *str);
        int SSL_CTX_set_cipher_list(SafeSslContextHandle ctx, in byte str);
        //int SSL_CTX_set_ciphersuites(SSL_CTX *ctx, const char *str);
        int SSL_CTX_set_ciphersuites(SafeSslContextHandle ctx, in byte str);
        //int SSL_CTX_use_certificate_chain_file(SSL_CTX *ctx, const char *file);
        int SSL_CTX_use_certificate_chain_file(SafeSslContextHandle ctx, string file);
        //int SSL_CTX_use_PrivateKey_file(SSL_CTX *ctx, const char *file, int type);
        int SSL_CTX_use_PrivateKey_file(SafeSslContextHandle ctx, string file, int type);
        //int SSL_CTX_check_private_key(const SSL_CTX *ctx);
        int SSL_CTX_check_private_key(SafeSslContextHandle ctx);
        //void SSL_CTX_set_default_passwd_cb_userdata(SSL_CTX *ctx, void *u);
        void SSL_CTX_set_default_passwd_cb_userdata(SafeSslContextHandle ctx, IntPtr data);
        //void SSL_CTX_set_default_passwd_cb(SSL_CTX *ctx, pem_password_cb *cb);
        void SSL_CTX_set_default_passwd_cb(SafeSslContextHandle ctx, pem_password_cb callback);

        //int SSL_CTX_set_session_id_context(SSL_CTX *ctx, const unsigned char *sid_ctx, unsigned int sid_ctx_len);
        int SSL_CTX_set_session_id_context(SafeSslContextHandle ctx, in byte sid_ctx, uint sid_ctx_len);
        //int SSL_CTX_add_session(SSL_CTX *ctx, SSL_SESSION *c)
        [return: DontVerifyType]
        int SSL_CTX_add_session(SafeSslContextHandle ctx, SafeSslSessionHandle c);
        //void SSL_CTX_sess_set_new_cb(SSL_CTX *ctx, int (*cb) (struct ssl_st *ssl, SSL_SESSION *sess))
        void SSL_CTX_sess_set_new_cb(SafeSslContextHandle ctx, SessionCallback new_session_cb);

        //int SSL_CTX_use_certificate(SSL_CTX *ctx, X509 *x);
        int SSL_CTX_use_certificate(SafeSslContextHandle ctx, SafeX509CertificateHandle cert);
        //X509 *SSL_CTX_get0_certificate(const SSL_CTX *ctx)
        SafeX509CertificateHandle SSL_CTX_get0_certificate(SafeSslContextHandle ctx);
        //int SSL_CTX_use_PrivateKey(SSL_CTX *ctx, EVP_PKEY *pkey);
        int SSL_CTX_use_PrivateKey(SafeSslContextHandle ctx, SafeKeyHandle pkey);
        //EVP_PKEY *SSL_CTX_get0_privatekey(const SSL_CTX *ctx)
        SafeKeyHandle SSL_CTX_get0_privatekey(SafeSslContextHandle ctx);

        //void SSL_CTX_set_cert_store(SSL_CTX *ctx, X509_STORE *store);
        void SSL_CTX_set_cert_store(SafeSslContextHandle ctx, SafeX509StoreHandle cert_store);
        //X509_STORE *SSL_CTX_get_cert_store(const SSL_CTX *ctx);
        SafeX509StoreHandle SSL_CTX_get_cert_store(SafeSslContextHandle ctx);

        //void SSL_CTX_set_client_CA_list(SSL_CTX *ctx, STACK_OF(X509_NAME) *list);
        void SSL_CTX_set_client_CA_list(SafeSslContextHandle ctx, SafeStackHandle<SafeX509NameHandle> name_list);
        //STACK_OF(X509_NAME) *SSL_CTX_get_client_CA_list(const SSL_CTX *ctx);
        SafeStackHandle<SafeX509NameHandle> SSL_CTX_get_client_CA_list(SafeSslContextHandle ctx);
        //int SSL_CTX_add_client_CA(SSL_CTX *ctx, X509 *cacert);
        int SSL_CTX_add_client_CA(SafeSslContextHandle ctx, SafeX509CertificateHandle cacert);
        //void SSL_CTX_set_client_cert_cb(SSL_CTX *ctx, int (*client_cert_cb)(SSL *ssl, X509 **x509, EVP_PKEY **pkey));
        void SSL_CTX_set_client_cert_cb(SafeSslContextHandle ctx, ClientCertificateCallback callback);

        //void SSL_CTX_set_verify(SSL_CTX *ctx, int mode, int (* verify_callback) (int, X509_STORE_CTX*));
        void SSL_CTX_set_verify(SafeSslContextHandle ctx, int mode, VerifyCertificateCallback callback);
        #endregion

        #region STACK_OF(SSL_CIPHER)
        //STACK_OF(SSL_CIPHER) *SSL_get_ciphers(const SSL *s);
        SafeStackHandle<SafeSslCipherHandle> SSL_get_ciphers(SafeSslHandle s);

        //char *SSL_CIPHER_description(const SSL_CIPHER *cipher, char *buf, int size);
        IntPtr SSL_CIPHER_description(SafeSslCipherHandle ssl_cipher, in byte[] buf, int buf_len);
        //const char *SSL_CIPHER_get_name(const SSL_CIPHER *cipher);
        IntPtr SSL_CIPHER_get_name(SafeSslCipherHandle ssl_cipher);
        //int SSL_CIPHER_get_bits(const SSL_CIPHER *cipher, int *alg_bits);
        int SSL_CIPHER_get_bits(SafeSslCipherHandle ssl_cipher, out int alg_bits);
        //char *SSL_CIPHER_get_version(const SSL_CIPHER *cipher);
        IntPtr SSL_CIPHER_get_version(SafeSslCipherHandle ssl_cipher);
        #endregion

        #region STACK_OF(X509_NAME)
        //STACK_OF(X509_NAME) *SSL_load_client_CA_file(const char* file);
        [return: TakeOwnership]
        SafeStackHandle<SafeX509NameHandle> SSL_load_client_CA_file(string file);
        //STACK_OF(X509_NAME) *SSL_get_client_CA_list(const SSL *s);
        SafeStackHandle<SafeX509NameHandle> SSL_get_client_CA_list(SafeSslHandle ssl);
        //void SSL_set_client_CA_list(SSL *s, STACK_OF(X509_NAME) *list);
        void SSL_set_client_CA_list(SafeSslHandle ssl, SafeStackHandle<SafeX509NameHandle> name_list);
        #endregion

        #region SSL
        //long SSL_set_options(SSL *ssl, long options);
        [return: NativeLong, DontVerifyType]
        long SSL_set_options(SafeSslHandle ssl, [NativeLong] long options);
        //void SSL_set_security_level(SSL *s, int level);
        void SSL_set_security_level(SafeSslHandle s, int level);

        //long SSL_get_verify_result(const SSL *ssl);
        [return: NativeLong, DontVerifyType]
        long SSL_get_verify_result(SafeSslHandle ssl);
        //void SSL_set_verify_result(SSL *ssl, long verify_result);
        void SSL_set_verify_result(SafeSslHandle ssl, [NativeLong] long v);

        //SSL_CIPHER *SSL_get_current_cipher(const SSL *ssl);
        SafeSslCipherHandle SSL_get_current_cipher(SafeSslHandle ssl);

        //int SSL_get_error(const SSL *ssl, int ret);
        [return: DontVerifyType]
        int SSL_get_error(SafeSslHandle ssl, int ret_code);
        //int SSL_accept(SSL *ssl);
        int SSL_accept(SafeSslHandle ssl);
        //int SSL_shutdown(SSL *ssl);
        [return: DontVerifyType]
        int SSL_shutdown(SafeSslHandle ssl);
        //int SSL_get_shutdown(const SSL* ssl);
        [return: DontVerifyType]
        int SSL_get_shutdown(SafeSslHandle ssl);

        //int SSL_write(SSL *ssl, const void *buf, int num);
        [return: DontVerifyType]
        int SSL_write(SafeSslHandle ssl, in byte buf, int len);
        //int SSL_read(SSL *ssl, void *buf, int num);
        [return: DontVerifyType]
        int SSL_read(SafeSslHandle ssl, ref byte buf, int len);
        //int SSL_pending(const SSL *ssl);
        [return: DontVerifyType]
        int SSL_pending(SafeSslHandle ssl);
        [return: DontVerifyType]
        int SSL_peek(SafeSslHandle ssl, ref byte buf, int len);
        //void SSL_set_read_ahead(SSL *s, int yes);
        void SSL_set_read_ahead(SafeSslHandle ssl, int yes);

        //int SSL_renegotiate(SSL *s);
        int SSL_renegotiate(SafeSslHandle ssl);
        //int SSL_renegotiate_abbreviated(SSL *s);
        int SSL_renegotiate_abbreviated(SafeSslHandle ssl);
        //int SSL_key_update(SSL *s, int updatetype);
        int SSL_key_update(SafeSslHandle ssl, int updatetype);
        //int SSL_renegotiate_pending(const SSL* s);
        [return: DontVerifyType]
        int SSL_renegotiate_pending(SafeSslHandle ssl);
        //int SSL_get_key_update_type(const SSL *s);
        [return: DontVerifyType]
        int SSL_get_key_update_type(SafeSslHandle ssl);

        //int SSL_set_session_id_context(SSL *ssl, const unsigned char *sid_ctx, unsigned int sid_ctx_len);
        int SSL_set_session_id_context(SafeSslHandle ssl, byte[] sid_ctx, uint sid_ctx_len);
        //int SSL_do_handshake(SSL *ssl);
        [return: DontVerifyType]
        int SSL_do_handshake(SafeSslHandle ssl);
        //void SSL_set_connect_state(SSL *ssl);
        void SSL_set_connect_state(SafeSslHandle ssl);
        //void SSL_set_accept_state(SSL *ssl);
        void SSL_set_accept_state(SafeSslHandle ssl);
        //int SSL_connect(SSL *ssl);
        int SSL_connect(SafeSslHandle ssl);
        //SSL *SSL_new(SSL_CTX *ctx);
        [return: TakeOwnership]
        SafeSslHandle SSL_new(SafeSslContextHandle ctx);
        //void SSL_free(SSL *ssl);
        void SSL_free(IntPtr ssl);
        //int SSL_state(const SSL *ssl);
        int SSL_state(SafeSslHandle ssl);
        //void SSL_set_state(SSL *ssl, int state);
        void SSL_set_state(SafeSslHandle ssl, int state);
        //void SSL_set_bio(SSL *ssl, BIO *rbio, BIO *wbio);
        void SSL_set_bio(SafeSslHandle ssl, SafeBioHandle read_bio, SafeBioHandle write_bio);
        //int SSL_use_certificate_file(SSL* ssl, const char* file, int type);
        int SSL_use_certificate_file(SafeSslHandle ssl, string file, int type);
        //int SSL_CTX_use_PrivateKey_file(SSL_CTX *ctx, const char *file, int type);
        int SSL_use_PrivateKey_file(SafeSslHandle ssl, string file, int type);
        //int SSL_version(const SSL *s);
        int SSL_version(SafeSslHandle ssl);
        //int SSL_clear(SSL *ssl);
        int SSL_clear(SafeSslHandle ssl);
        //const char *SSL_get_servername(const SSL *s, const int type);
        IntPtr SSL_get_servername(SafeSslHandle s, int type);
        //int SSL_get_servername_type(const SSL *s);
        int SSL_get_servername_type(SafeSslHandle s);
        //int SSL_is_init_finished(const SSL *s);
        [return: DontVerifyType]
        int SSL_is_init_finished(SafeSslHandle s);
        //int SSL_up_ref(SSL *s);
        int SSL_up_ref(SafeSslHandle s);
        //void SSL_set_info_callback(SSL *ssl, void (*callback)());
        void SSL_set_info_callback(SafeSslHandle ssl, SslInfoCallback callback);
        //const char *SSL_state_string(const SSL *ssl);
        IntPtr SSL_state_string(SafeSslHandle ssl);
        //long SSL_ctrl(SSL *ssl, int cmd, long larg, char *parg);
        [return: DontVerifyType, NativeLong]
        long SSL_ctrl(SafeSslHandle ssl, int cmd, [NativeLong] long larg, IntPtr parg);

        //X509 *SSL_get_peer_certificate(const SSL *ssl);
        [return: TakeOwnership] //not new, already gets an extra reference in the native code
        SafeX509CertificateHandle SSL_get_peer_certificate(SafeSslHandle ssl);
        //X509 *SSL_get_certificate(const SSL *ssl);
        SafeX509CertificateHandle SSL_get_certificate(SafeSslHandle ssl);
        //int SSL_use_certificate(SSL *ssl, X509 *x);
        int SSL_use_certificate(SafeSslHandle ssl, SafeX509CertificateHandle x509);

        //SSL_SESSION *SSL_get_session(const SSL *ssl);
        SafeSslSessionHandle SSL_get_session(SafeSslHandle s);
        //SSL_SESSION *SSL_get1_session(SSL *ssl);
        SafeSslSessionHandle SSL_get1_session(SafeSslHandle ssl);
        //int SSL_set_session(SSL *ssl, SSL_SESSION *session);
        int SSL_set_session(SafeSslHandle ssl, SafeSslSessionHandle session);
        //int SSL_session_reused(SSL *ssl);
        [return: DontVerifyType]
        int SSL_session_reused(SafeSslHandle ssl);
        //int SSL_SESSION_up_ref(SSL_SESSION *ses);
        int SSL_SESSION_up_ref(SafeSslSessionHandle ses);
        // void SSL_SESSION_free(SSL_SESSION *session);
        void SSL_SESSION_free(IntPtr session);

        //int SSL_use_PrivateKey(SSL *ssl, EVP_PKEY *pkey);
        int SSL_use_PrivateKey(SafeSslHandle ssl, SafeKeyHandle evp_pkey);

        //int SSL_get_ex_data_X509_STORE_CTX_idx(void)
        int SSL_get_ex_data_X509_STORE_CTX_idx();
        #endregion
    }
}
