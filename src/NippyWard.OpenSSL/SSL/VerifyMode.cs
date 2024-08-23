using System;
using System.Collections.Generic;
using System.Text;

namespace NippyWard.OpenSSL.SSL
{
    public enum VerifyMode
    {
        /// <summary>
        /// Server mode: the server will not send a client certificate request to the client, so the client will not send a certificate.
        /// Client mode: if not using an anonymous cipher(by default disabled), the server will send a certificate which will be checked. 
        ///     The result of the certificate verification process can be checked after the TLS/SSL handshake using the SSL_get_verify_result(3) function.
        ///     The handshake will be continued regardless of the verification result.
        /// </summary>
        SSL_VERIFY_NONE = 0x00,
        /// <summary>
        /// Server mode: the server sends a client certificate request to the client. The certificate returned (if any) is checked. 
        ///     If the verification process fails, the TLS/SSL handshake is immediately terminated with an alert message containing the reason for the verification failure. 
        ///     The behaviour can be controlled by the additional SSL_VERIFY_FAIL_IF_NO_PEER_CERT and SSL_VERIFY_CLIENT_ONCE flags.
        /// Client mode: the server certificate is verified. If the verification process fails, 
        ///     the TLS/SSL handshake is immediately terminated with an alert message containing the reason for the verification failure. 
        ///     If no server certificate is sent, because an anonymous cipher is used, SSL_VERIFY_PEER is ignored.
        /// </summary>
        SSL_VERIFY_PEER = 0x01,
        /// <summary>
        /// Server mode: if the client did not return a certificate, the TLS/SSL handshake is immediately terminated with a "handshake failure" alert. 
        ///     This flag must be used together with SSL_VERIFY_PEER.
        /// Client mode: ignored
        /// </summary>
        SSL_VERIFY_FAIL_IF_NO_PEER_CERT = 0x02,
        /// <summary>
        /// Server mode: only request a client certificate on the initial TLS/SSL handshake. 
        ///     Do not ask for a client certificate again in case of a renegotiation. This flag must be used together with SSL_VERIFY_PEER.
        /// Client mode: ignored
        /// </summary>
        SSL_VERIFY_CLIENT_ONCE = 0x04,
        /// <summary>
        /// Server mode: the server will not send a client certificate request during the initial handshake, but will send the request via SSL_verify_client_post_handshake(). 
        /// This allows the SSL_CTX or SSL to be configured for post-handshake peer verification before the handshake occurs. 
        /// This flag must be used together with SSL_VERIFY_PEER. TLSv1.3 only; no effect on pre-TLSv1.3 connections.
        /// Client mode: ignored
        /// </summary>
        SSL_VERIFY_POST_HANDSHAKE = 0x08
    }
}
