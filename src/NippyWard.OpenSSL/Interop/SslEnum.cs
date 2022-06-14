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

namespace NippyWard.OpenSSL.Interop
{
	/// <summary>
	///
	/// </summary>
	public enum CipherAlgorithmType
	{
		/// <summary>
		///
		/// </summary>
		None,
		/// <summary>
		///
		/// </summary>
		Rc2,
		/// <summary>
		///
		/// </summary>
		Rc4,
		/// <summary>
		///
		/// </summary>
		Des,
		/// <summary>
		///
		/// </summary>
		Idea,
		/// <summary>
		///
		/// </summary>
		Fortezza,
		/// <summary>
		///
		/// </summary>
		Camellia128,
		/// <summary>
		///
		/// </summary>
		Camellia256,
		/// <summary>
		///
		/// </summary>
		Seed,
		/// <summary>
		///
		/// </summary>
		TripleDes,
		/// <summary>
		///
		/// </summary>
		Aes,
		/// <summary>
		///
		/// </summary>
		Aes128,
		/// <summary>
		///
		/// </summary>
		Aes192,
		/// <summary>
		///
		/// </summary>
		Aes256
	}

	/// <summary>
	///
	/// </summary>
	public enum HashAlgorithmType
	{
		/// <summary>
		///
		/// </summary>
		None,
		/// <summary>
		///
		/// </summary>
		Md5,
		/// <summary>
		///
		/// </summary>
		Sha1
	}

	/// <summary>
	///
	/// </summary>
	public enum ExchangeAlgorithmType
	{
		/// <summary>
		///
		/// </summary>
		None,
		/// <summary>
		///
		/// </summary>
		RsaSign,
		/// <summary>
		///
		/// </summary>
		RsaKeyX,
		/// <summary>
		///
		/// </summary>
		DiffieHellman,
		/// <summary>
		///
		/// </summary>
		Kerberos,
		/// <summary>
		///
		/// </summary>
		Fortezza,
		/// <summary>
		///
		/// </summary>
		ECDiffieHellman
	}

	/// <summary>
	/// SSL_FILETYPE_*
	/// </summary>
	public enum SslFileType
	{
		/// <summary>
		/// SSL_FILETYPE_PEM
		/// </summary>
		PEM = 1,
		/// <summary>
		/// SSL_FILETYPE_ASN1
		/// </summary>
		ASN1 = 2
	}

	enum AuthenticationMethod
	{
		None,
		Rsa,
		Dss,
		DiffieHellman,
		Kerberos,
		ECDsa
	}

	/// <summary>
	/// Options enumeration for Options property
	/// </summary>
	[Flags]
	internal enum SslOptions : ulong
	{
        /* Allow initial connection to servers that don't support RI */
        SSL_OP_LEGACY_SERVER_CONNECT = 0x00000004U,
        SSL_OP_TLSEXT_PADDING = 0x00000010U,
        SSL_OP_SAFARI_ECDHE_ECDSA_BUG = 0x00000040U,

        /*
         * Disable SSL 3.0/TLS 1.0 CBC vulnerability workaround that was added in
         * OpenSSL 0.9.6d.  Usually (depending on the application protocol) the
         * workaround is not needed.  Unfortunately some broken SSL/TLS
         * implementations cannot handle it at all, which is why we include it in
         * SSL_OP_ALL. Added in 0.9.6e
         */
        SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS = 0x00000800U,

        /* DTLS options */
        SSL_OP_NO_QUERY_MTU = 0x00001000U,
        /* Turn on Cookie Exchange (on relevant for servers) */
        SSL_OP_COOKIE_EXCHANGE = 0x00002000U,
        /* Don't use RFC4507 ticket extension */
        SSL_OP_NO_TICKET = 0x00004000U,

        /* Use Cisco's "speshul" version of DTLS_BAD_VER
         * (only with deprecated DTLSv1_client_method())  */
        SSL_OP_CISCO_ANYCONNECT = 0x00008000U,

        /* As server, disallow session resumption on renegotiation */
        SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION = 0x00010000U,
        /* Don't use compression even if supported */
        SSL_OP_NO_COMPRESSION = 0x00020000U,
        /* Permit unsafe legacy renegotiation */
        SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION = 0x00040000U,
        /* Disable encrypt-then-mac */
        SSL_OP_NO_ENCRYPT_THEN_MAC = 0x00080000U,
        /*
         * Set on servers to choose the cipher according to the server's preferences
         */
        SSL_OP_CIPHER_SERVER_PREFERENCE = 0x00400000U,
        /*
         * If set, a server will allow a client to issue a SSLv3.0 version number as
         * latest version supported in the premaster secret, even when TLSv1.0
         * (version 3.1) was announced in the client hello. Normally this is
         * forbidden to prevent version rollback attacks.
         */
        SSL_OP_TLS_ROLLBACK_BUG = 0x00800000U,

        SSL_OP_NO_SSLv3 = 0x02000000U,
        SSL_OP_NO_TLSv1 = 0x04000000U,
        SSL_OP_NO_TLSv1_2 = 0x08000000U,
        SSL_OP_NO_TLSv1_1 = 0x10000000U,
		SSL_OP_NO_TLSv1_3 = 0x20000000U,

        SSL_OP_NO_DTLSv1 = 0x04000000U,
        SSL_OP_NO_DTLSv1_2 = 0x08000000U,
        SSL_OP_NO_SSL_MASK = (SSL_OP_NO_SSLv3|SSL_OP_NO_TLSv1|SSL_OP_NO_TLSv1_1|SSL_OP_NO_TLSv1_2),
        SSL_OP_NO_DTLS_MASK = (SSL_OP_NO_DTLSv1|SSL_OP_NO_DTLSv1_2),

        /* Disallow all renegotiation */
        SSL_OP_NO_RENEGOTIATION = 0x40000000U,

        /*
         * Make server add server-hello extension from early version of cryptopro
         * draft, when GOST ciphersuite is negotiated. Required for interoperability
         * with CryptoPro CSP 3.x
         */
        SSL_OP_CRYPTOPRO_TLSEXT_BUG = 0x80000000U,

        /*
         * SSL_OP_ALL: various bug workarounds that should be rather harmless.
         * This used to be 0x000FFFFFL before 0.9.7.
         * This used to be 0x80000BFFU before 1.1.1.
         */
        SSL_OP_ALL = (SSL_OP_CRYPTOPRO_TLSEXT_BUG|SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS|SSL_OP_LEGACY_SERVER_CONNECT|SSL_OP_TLSEXT_PADDING|SSL_OP_SAFARI_ECDHE_ECDSA_BUG)
	}

    [Flags]
	internal enum SslMode
	{
		/// <summary>
		/// Allow SSL_write(..., n) to return r with 0 &lt; r &lt; n (i.e. report success
		/// when just a single record has been written):
		/// </summary>
		SSL_MODE_ENABLE_PARTIAL_WRITE = 0x00000001,

		/// <summary>
		/// Make it possible to retry SSL_write() with changed buffer location
		/// (buffer contents must stay the same!); this is not the default to avoid
		/// the misconception that non-blocking SSL_write() behaves like
		/// non-blocking write():
		/// </summary>
		SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER = 0x00000002,

		/// <summary>
		/// Never bother the application with retries if the transport
		/// is blocking:
		/// </summary>
		SSL_MODE_AUTO_RETRY = 0x00000004,

		/// <summary>
		/// Don't attempt to automatically build certificate chain
		/// </summary>
		SSL_MODE_NO_AUTO_CHAIN = 0x00000008
	}

    internal enum SslError
    {
        SSL_ERROR_NONE = 0,
        SSL_ERROR_SSL = 1,
        SSL_ERROR_WANT_READ = 2,
        SSL_ERROR_WANT_WRITE = 3,
        SSL_ERROR_WANT_X509_LOOKUP = 4,
        SSL_ERROR_SYSCALL = 5,
        SSL_ERROR_ZERO_RETURN = 6,
        SSL_ERROR_WANT_CONNECT = 7,
        SSL_ERROR_WANT_ACCEPT = 8
    }

    internal enum SslVersion
    {
        SSL3_VERSION = 0x0300,
        TLS1_VERSION = 0x0301,
        TLS1_1_VERSION = 0x0302,
        TLS1_2_VERSION = 0x0303,
        TLS1_3_VERSION = 0x0304
    }

    internal enum FrameType : byte
    {
        ChangeCipherSpec = 0x14,
        Alert = 0x15,
        Handshake = 0x16,
        Application = 0x17,
    }
}
