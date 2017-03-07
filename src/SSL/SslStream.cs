﻿// Copyright (c) 2009 Ben Henderson
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

using OpenSSL.Core.X509;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Security;
using System.Threading.Tasks;
using System.Threading;

namespace OpenSSL.Core.SSL
{
	/// <summary>
	///
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="cert"></param>
	/// <param name="chain"></param>
	/// <param name="depth"></param>
	/// <param name="result"></param>
	/// <returns></returns>
	public delegate bool RemoteCertificateValidationHandler(
		Object sender,
		X509Certificate cert,
		X509Chain chain,
		int depth,
		VerifyResult result
	);

	/// <summary>
	///
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="targetHost"></param>
	/// <param name="localCerts"></param>
	/// <param name="remoteCert"></param>
	/// <param name="acceptableIssuers"></param>
	/// <returns></returns>
	public delegate X509Certificate LocalCertificateSelectionHandler(
		Object sender,
		string targetHost,
		X509List localCerts,
		X509Certificate remoteCert,
		string[] acceptableIssuers
	);

	/// <summary>
	/// Implements an AuthenticatedStream and is the main interface to the SSL library.
	/// </summary>
	public class SslStream : AuthenticatedStream
	{
		#region Initialization

		/// <summary>
		/// Create an SslStream based on an existing stream.
		/// </summary>
		/// <param name="stream"></param>
		public SslStream(Stream stream) : this(stream, false)
		{
		}

		/// <summary>
		/// Create an SslStream based on an existing stream.
		/// </summary>
		/// <param name="stream"></param>
		/// <param name="leaveInnerStreamOpen"></param>
		public SslStream(Stream stream, bool leaveInnerStreamOpen) : base(stream, leaveInnerStreamOpen)
		{
		}

		/// <summary>
		/// Create an SslStream based on an existing stream.
		/// </summary>
		/// <param name="stream"></param>
		/// <param name="leaveInnerStreamOpen"></param>
		/// <param name="remote_callback"></param>
		public SslStream(Stream stream,
			bool leaveInnerStreamOpen,
			RemoteCertificateValidationHandler remote_callback) : this(
				stream,
				leaveInnerStreamOpen,
				remote_callback,
				null)
		{
		}

		/// <summary>
		/// Create an SslStream based on an existing stream.
		/// </summary>
		/// <param name="stream"></param>
		/// <param name="leaveInnerStreamOpen"></param>
		/// <param name="remote_callback"></param>
		/// <param name="local_callback"></param>
		public SslStream(
			Stream stream,
			bool leaveInnerStreamOpen,
			RemoteCertificateValidationHandler remote_callback,
			LocalCertificateSelectionHandler local_callback) : base(stream, leaveInnerStreamOpen)
		{
			remoteCertificateValidationCallback = remote_callback;
			localCertificateSelectionCallback = local_callback;
		}

		#endregion

		#region AuthenticatedStream Members

		/// <summary>
		/// Returns whether authentication was successful.
		/// </summary>
		public override bool IsAuthenticated
		{
			get { return sslStream != null; }
		}

		/// <summary>
		/// Indicates whether data sent using this SslStream is encrypted.
		/// </summary>
		public override bool IsEncrypted
		{
			get { return IsAuthenticated; }
		}

		/// <summary>
		/// Indicates whether both server and client have been authenticated.
		/// </summary>
		public override bool IsMutuallyAuthenticated
		{
			get
			{
				if (IsAuthenticated &&
				    (IsServer ? Ssl.RemoteCertificate != null :
						Ssl.LocalCertificate != null))
				{
					return true;
				}
				return false;
			}
		}

		/// <summary>
		/// Indicates whether the local side of the connection was authenticated as the server.
		/// </summary>
		public override bool IsServer
		{
			get { return sslStream is SslStreamServer; }
		}

		/// <summary>
		/// Indicates whether the data sent using this stream is signed.
		/// </summary>
		public override bool IsSigned
		{
			get { return IsAuthenticated; }
		}

		#endregion

		#region Stream Members

		/// <summary>
		/// Gets a value indicating whether the current stream supports reading.
		/// </summary>
		public override bool CanRead
		{
			get { return InnerStream.CanRead; }
		}

		/// <summary>
		/// Gets a value indicating whether the current stream supports seeking.
		/// </summary>
		public override bool CanSeek
		{
			get { return InnerStream.CanSeek; }
		}

		/// <summary>
		/// Gets a value indicating whether the current stream supports writing.
		/// </summary>
		public override bool CanWrite
		{
			get { return InnerStream.CanWrite; }
		}

		/// <summary>
		/// Clears all buffers for this stream and causes any buffered data to be written to the underlying device.
		/// </summary>
		public override void Flush()
		{
			InnerStream.Flush();
		}

        public override Task FlushAsync(CancellationToken cancellationToken)
        {
            return InnerStream.FlushAsync(cancellationToken);
        }

        /// <summary>
        /// Gets the length in bytes of the stream.
        /// </summary>
        public override long Length
		{
			get { return InnerStream.Length; }
		}

		/// <summary>
		/// Gets or sets the position within the current stream.
		/// </summary>
		public override long Position
		{
			get { return InnerStream.Position; }
			set { throw new NotSupportedException(); }
		}

		/// <summary>
		/// Gets or sets a value, in milliseconds, that determines how long the stream will attempt to read before timing out.
		/// </summary>
		public override int ReadTimeout
		{
			get { return InnerStream.ReadTimeout; }
			set { InnerStream.ReadTimeout = value; }
		}

		/// <summary>
		/// Gets or sets a value, in milliseconds, that determines how long the stream will attempt to write before timing out.
		/// </summary>
		public override int WriteTimeout
		{
			get { return InnerStream.WriteTimeout; }
			set { InnerStream.WriteTimeout = value; }
		}

        /// <summary>
        /// Reads a sequence of bytes from the current stream and advances the position within the stream by the number of bytes read.
        /// </summary>
        /// <param name="buffer"></param>
        /// <param name="offset"></param>
        /// <param name="count"></param>
        /// <returns></returns>
        public override int Read(byte[] buffer, int offset, int count)
        {
            TestConnectionIsValid();

            Task<int> read = this.ReadAsync(buffer, offset, count);
            read.Wait();

            return read.Result;
        }

        public override async Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            TestConnectionIsValid();

            return await sslStream.ReadAsync(buffer, offset, count, cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// Not supported
        /// </summary>
        /// <param name="offset"></param>
        /// <param name="origin"></param>
        /// <returns></returns>
        public override long Seek(long offset, SeekOrigin origin)
		{
			throw new NotSupportedException();
		}

		/// <summary>
		/// Sets the length of the current stream.
		/// </summary>
		/// <param name="value"></param>
		public override void SetLength(long value)
		{
			InnerStream.SetLength(value);
		}

		/// <summary>
		/// Writes a sequence of bytes to the current stream and advances the current position within this stream by the number of bytes written.
		/// </summary>
		/// <param name="buffer"></param>
		/// <param name="offset"></param>
		/// <param name="count"></param>
		public override void Write(byte[] buffer, int offset, int count)
		{
            TestConnectionIsValid();

            this.WriteAsync(buffer, offset, count).Wait();
		}

        public override async Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            TestConnectionIsValid();

            await sslStream.WriteAsync(buffer, offset, count, cancellationToken).ConfigureAwait(false);
        }

        public override void Close()
        {
            base.Close();
            if (sslStream != null)
            {
                sslStream.Close();
            }
        }
        #endregion

        #region Properties

        /// <summary>
        ///
        /// </summary>
        public bool CheckCertificateRevocationStatus
		{
			get
			{
				if (!IsAuthenticated)
					return false;
				return sslStream.CheckCertificateRevocationStatus;
			}
		}

		/// <summary>
		/// Gets the ssl.
		/// </summary>
		/// <value>The ssl.</value>
		public Ssl Ssl
		{
			get
			{
				if (!IsAuthenticated)
					return null;
				return sslStream.Ssl;
			}
		}


        #endregion

        #region Methods

        public virtual async Task AuthenticateAsClient(string targetHost)
        {
            await AuthenticateAsClient(targetHost, null, null, SslProtocols.Tls, SslStrength.All, false, CancellationToken.None).ConfigureAwait(false);
        }

        public virtual async Task AuthenticateAsClient(string targetHost,
            X509List clientCertificates,
            X509Chain caCertificates,
            SslProtocols enabledSslProtocols,
            SslStrength sslStrength,
            bool checkCertificateRevocation,
            CancellationToken cancellationToken)
        {
            if (IsAuthenticated)
            {
                throw new InvalidOperationException("SslStream is already authenticated");
            }

            End = ConnectionEnd.Client;

            // Create the stream
            var client_stream = new SslStreamClient(
                                    InnerStream,
                                    targetHost,
                                    clientCertificates,
                                    caCertificates,
                                    enabledSslProtocols,
                                    sslStrength,
                                    checkCertificateRevocation,
                                    remoteCertificateValidationCallback,
                                    localCertificateSelectionCallback);

            // set the internal stream
            sslStream = client_stream;

            // start the write operation
            await this.WriteAsync(new byte[0], 0, 0, cancellationToken).ConfigureAwait(false);

            TestConnectionIsValid();
        }

        public virtual async Task AuthenticateAsServer(X509Certificate serverCertificate)
        {
            await AuthenticateAsServer(serverCertificate, false, null, SslProtocols.Tls, SslStrength.All, false, CancellationToken.None).ConfigureAwait(false);
        }

        public virtual async Task AuthenticateAsServer(X509Certificate serverCertificate,
            bool clientCertificateRequired,
            X509Chain caCertificates,
            SslProtocols enabledSslProtocols,
            SslStrength sslStrength,
            bool checkCertificateRevocation,
            CancellationToken cancellationToken)
        {
            if (IsAuthenticated)
            {
                throw new InvalidOperationException("SslStream is already authenticated");
            }

            End = ConnectionEnd.Server;

            // Initialize the server stream
            var server_stream = new SslStreamServer(
                                    InnerStream,
                                    serverCertificate,
                                    clientCertificateRequired,
                                    caCertificates,
                                    enabledSslProtocols,
                                    sslStrength,
                                    checkCertificateRevocation,
                                    remoteCertificateValidationCallback);
            // Set the internal sslStream
            sslStream = server_stream;

            // Start the read operation
            await this.ReadAsync(new byte[0], 0, 0, cancellationToken).ConfigureAwait(false);

            TestConnectionIsValid();
        }

        /// <summary>
        ///
        /// </summary>
        public async Task Renegotiate(CancellationToken cancellationToken)
        {
            TestConnectionIsValid();

            sslStream.Renegotiate();

            if (sslStream is SslStreamClient)
                await this.WriteAsync(new byte[0], 0, 0, cancellationToken).ConfigureAwait(false);
            else
                await this.ReadAsync(new byte[0], 0, 0, cancellationToken).ConfigureAwait(false);
        }

        #endregion

        #region Helpers

        private void TestConnectionIsValid()
		{
			if (sslStream == null)
			{
				throw new InvalidOperationException("SslStream has not been authenticated");
			}
		}

		#endregion

		#region Properties

		/// <summary>
		///
		/// </summary>
		public ConnectionEnd End { get; private set; }

		#endregion

		#region Fields

		SslStreamBase sslStream;
		internal RemoteCertificateValidationHandler remoteCertificateValidationCallback = null;
		internal LocalCertificateSelectionHandler localCertificateSelectionCallback = null;

        #endregion

        #region IDisposable

        private bool disposed;
        protected override void Dispose(bool disposing)
        {
            if (disposed)
                return;

            if (sslStream != null)
                sslStream.Dispose();

            base.Dispose(disposing);
            disposed = true;
        }

        #endregion
    }
}
