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

using OpenSSL.Core.Core;
using OpenSSL.Core.X509;
using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using OpenSSL.Core.Extensions;
using System.Threading.Tasks;

namespace OpenSSL.Core.SSL
{
	internal abstract class SslStreamBase : Stream
	{
		internal Stream innerStream;
		private volatile bool disposed = false;
		internal SslContext sslContext;
		internal Ssl ssl;
		internal BIO read_bio;
		internal BIO write_bio;
		// for reading from the stream
		private byte[] read_buffer = new byte[16384];
		// decrypted data from Ssl.Read
		private MemoryStream cleartext = new MemoryStream();
		private const int SSL3_RT_HEADER_LENGTH = 5;
		private const int SSL3_RT_MAX_PLAIN_LENGTH = 16384;
		private const int SSL3_RT_MAX_COMPRESSED_LENGTH = (1024 + SSL3_RT_MAX_PLAIN_LENGTH);
		private const int SSL3_RT_MAX_ENCRYPTED_LENGTH = (1024 + SSL3_RT_MAX_COMPRESSED_LENGTH);
		private const int SSL3_RT_MAX_PACKET_SIZE = (SSL3_RT_MAX_ENCRYPTED_LENGTH + SSL3_RT_HEADER_LENGTH);
		// 5 minutes
		private const int WaitTimeOut = 300 * 1000;
		protected LocalCertificateSelectionHandler OnLocalCertificate;
		protected RemoteCertificateValidationHandler OnRemoteCertificate;
		protected bool checkCertificateRevocationStatus = false;
		protected HandshakeState handShakeState = HandshakeState.None;
		protected OpenSslException handshakeException = null;

		protected string srvName = "localhost";

        /// <summary>
        /// Override to implement client/server specific handshake processing
        /// </summary>
        /// <returns></returns>
        internal protected abstract bool ProcessHandshake();

        public SslStreamBase(Stream stream)
		{
			if (stream == null)
			{
				throw new ArgumentNullException("stream");
			}
			if (!stream.CanRead || !stream.CanWrite)
			{
				throw new ArgumentException("Stream must allow read and write capabilities", "stream");
			}
			innerStream = stream;
		}

		public bool HandshakeComplete
		{
			get { return handShakeState == HandshakeState.Complete; }
		}

		private bool NeedHandshake
		{
			get { return ((handShakeState == HandshakeState.None) || (handShakeState == HandshakeState.Renegotiate)); }
		}

		public bool CheckCertificateRevocationStatus
		{
			get { return checkCertificateRevocationStatus; }
			set { checkCertificateRevocationStatus = value; }
		}

		public LocalCertificateSelectionHandler LocalCertSelectionCallback
		{
			get { return OnLocalCertificate; }
			set { OnLocalCertificate = value; }
		}

		public RemoteCertificateValidationHandler RemoteCertValidationCallback
		{
			get { return OnRemoteCertificate; }
			set { OnRemoteCertificate = value; }
		}

		public Ssl Ssl
		{
			get { return ssl; }
		}

		#region Stream methods

		public override bool CanRead
		{
			get { return innerStream.CanRead; }
		}

		public override bool CanSeek
		{
			get { return innerStream.CanSeek; }
		}

		public override bool CanWrite
		{
			get { return innerStream.CanWrite; }
		}

		public override void Flush()
		{
			if (disposed)
			{
				throw new ObjectDisposedException("SslStreamBase");
			}
			innerStream.Flush();
		}

        public override Task FlushAsync(CancellationToken cancellationToken)
        {
            if (disposed)
            {
                throw new ObjectDisposedException("SslStreamBase");
            }
            return innerStream.FlushAsync(cancellationToken);
        }

        public override long Length
		{
			get { return innerStream.Length; }
		}

		public override long Position
		{
			get { return innerStream.Position; }
			set { throw new NotSupportedException(); }
		}

		public override int ReadTimeout
		{
			get { return innerStream.ReadTimeout; }
			set { innerStream.ReadTimeout = value; }
		}

		public override int WriteTimeout
		{
			get { return innerStream.WriteTimeout; }
			set { innerStream.WriteTimeout = value; }
		}

		public override long Seek(long offset, SeekOrigin origin)
		{
			throw new NotImplementedException();
		}

		public override void SetLength(long value)
		{
			innerStream.SetLength(value);
		}

        //!! - not implementing blocking read, but using BeginRead with no callbacks
        public override int Read(byte[] buffer, int offset, int count)
        {
            throw new NotImplementedException();
        }

        public void SendShutdownAlert()
		{
			if (disposed)
				return;

			var nShutdownRet = ssl.Shutdown();
			if (nShutdownRet == 0)
			{
				var nBytesToWrite = write_bio.BytesPending;
				if (nBytesToWrite <= 0)
				{
					// unexpected error
					//!!TODO log error
					return;
				}
				var buf = write_bio.ReadBytes((int)nBytesToWrite);
				if (buf.Count <= 0)
				{
					//!!TODO - log error
				}
				else
				{
					// Write the shutdown alert to the stream
					innerStream.Write(buf.Array, 0, buf.Count);
				}
			}
		}

        public override async Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            if (disposed)
                return 0;

            if (buffer == null)
            {
                throw new ArgumentNullException("buffer", "buffer can't be null");
            }
            if (offset < 0)
            {
                throw new ArgumentOutOfRangeException("offset", "offset less than 0");
            }
            if (offset > buffer.Length)
            {
                throw new ArgumentOutOfRangeException("offset", "offset must be less than buffer length");
            }
            if (count < 0)
            {
                throw new ArgumentOutOfRangeException("count", "count less than 0");
            }
            if (count > (buffer.Length - offset))
            {
                throw new ArgumentOutOfRangeException("count", "count is greater than buffer length - offset");
            }

            if (NeedHandshake)
            {
                // Start the handshake
                await HandShake(cancellationToken).ConfigureAwait(false);
            }

            if (cleartext.Position == cleartext.Length)
            {
                cleartext.Seek(0, SeekOrigin.Begin);
                cleartext.SetLength(0);
            }
            // Check to see if we have data waiting in the decrypted data stream
            if (cleartext.Length > 0 && (cleartext.Position != cleartext.Length))
            {
                // Process the pre-existing data
                return await cleartext.ReadAsync(buffer, offset, count, cancellationToken).ConfigureAwait(false);
            }

            bool haveDataToReturn = false;
            int bytesRead = 0;

            if ((bytesRead = await innerStream.ReadAsync(read_buffer, 0, read_buffer.Length, cancellationToken).ConfigureAwait(false)) > 0)
            {
                // Copy encrypted data into the SSL read_bio
                read_bio.Write(read_buffer, bytesRead);
                if (handShakeState == HandshakeState.InProcess ||
                    handShakeState == HandshakeState.RenegotiateInProcess)
                {
                    // We are in the handshake, complete the async operation to fire the async
                    // handshake callback for processing
                    return bytesRead;
                }
                var nBytesPending = read_bio.BytesPending;
                var decrypted_buf = new byte[SSL3_RT_MAX_PACKET_SIZE];
                while (nBytesPending > 0)
                {
                    int decryptedBytesRead = ssl.Read(decrypted_buf, decrypted_buf.Length);
                    if (decryptedBytesRead <= 0)
                    {
                        var lastError = ssl.GetError(decryptedBytesRead);
                        if (lastError == SslError.SSL_ERROR_WANT_READ)
                        {
                            // if we have bytes pending in the write bio.
                            // the client has requested a renegotiation
                            if (write_bio.BytesPending > 0)
                            {
                                // Start the renegotiation by writing the write_bio data, and use the RenegotiationWriteCallback
                                // to handle the rest of the renegotiation
                                var buf = write_bio.ReadBytes((int)write_bio.BytesPending);
                                await innerStream.WriteAsync(buf.Array, 0, buf.Count, cancellationToken).ConfigureAwait(false);
                                return await this.ReadAsync(buffer, offset, count, cancellationToken).ConfigureAwait(false);
                            }
                            // no data in the out bio, we just need more data to complete the record
                            //break;
                        }
                        else if (lastError == SslError.SSL_ERROR_WANT_WRITE)
                        {
                            // unexpected error!
                            //!!TODO debug log
                        }
                        else if (lastError == SslError.SSL_ERROR_ZERO_RETURN)
                        {
                            // Shutdown alert
                            SendShutdownAlert();
                            break;
                        }
                        else
                        {
                            //throw new OpenSslException();
                        }
                    }
                    if (decryptedBytesRead > 0)
                    {
                        // Write decrypted data to memory stream
                        var pos = cleartext.Position;
                        cleartext.Seek(0, SeekOrigin.End);
                        cleartext.Write(decrypted_buf, 0, decryptedBytesRead);
                        cleartext.Seek(pos, SeekOrigin.Begin);
                        haveDataToReturn = true;
                    }

                    // See if we have more data to process
                    nBytesPending = read_bio.BytesPending;
                }
                // Check to see if we have data to return, if not, fire the async read again
                if (!haveDataToReturn)
                {
                    return await this.ReadAsync(buffer, offset, count, cancellationToken).ConfigureAwait(false);
                }
                else
                {
                    // Read the data into the buffer provided by the user (now hosted in the InternalAsyncResult)
                    return await cleartext.ReadAsync(buffer, offset, count, cancellationToken).ConfigureAwait(false);
                }
            }

            return bytesRead;
        }

        //!! - not implmenting blocking Write, use BeginWrite with no callback
        public override void Write(byte[] buffer, int offset, int count)
        {
            throw new NotImplementedException();
        }

        public override async Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            if (disposed)
                return;

            if (buffer == null)
            {
                throw new ArgumentNullException("buffer", "buffer can't be null");
            }
            if (offset < 0)
            {
                throw new ArgumentOutOfRangeException("offset", "offset less than 0");
            }
            if (offset > buffer.Length)
            {
                throw new ArgumentOutOfRangeException("offset", "offset must be less than buffer length");
            }
            if (count < 0)
            {
                throw new ArgumentOutOfRangeException("count", "count less than 0");
            }
            if (count > (buffer.Length - offset))
            {
                throw new ArgumentOutOfRangeException("count", "count is greater than buffer length - offset");
            }

            if (NeedHandshake)
            {
                // Start the handshake
                await HandShake(cancellationToken).ConfigureAwait(false);
            }

            // Only write to the SSL object if we have data
            if (count != 0)
            {
                var bytesWritten = ssl.Write(buffer, count);
                if (bytesWritten < 0)
                {
                    var lastError = ssl.GetError(bytesWritten);
                    if (lastError == SslError.SSL_ERROR_WANT_READ)
                    {
                        //!!TODO - Log - unexpected renogiation request
                    }
                    throw new OpenSslException();
                }
            }

            var bytesPending = write_bio.BytesPending;
            if (bytesPending > 0)
            {
                var buf = write_bio.ReadBytes((int)bytesPending);
                if (buf.Count > 0)
                {
                    await innerStream.WriteAsync(buf.Array, 0, buf.Count, cancellationToken).ConfigureAwait(false);
                }
            }
        }

        private async Task HandShake(CancellationToken cancellationToken)
        {
            if (disposed)
                return;
            int bytesRead = 0;

            if (handShakeState != HandshakeState.Renegotiate)
                handShakeState = HandshakeState.InProcess;

            if (ProcessHandshake())
                handShakeState = HandshakeState.Complete;
            else
            {
                //!! if (readwriteAsyncResult.IsWriteOperation)
                if (write_bio.BytesPending > 0)
                {
                    await this.WriteAsync(new byte[0], 0, 0, cancellationToken).ConfigureAwait(false);

                    if (handShakeState == HandshakeState.Complete)
                        return;

                    // Check to see if we saved an exception from the last Handshake process call
                    // the if the client gets an error code, it needs to send the alert, and then
                    // throw the exception here.
                    if (handshakeException != null)
                        throw new AggregateException(handshakeException);

                    // We wrote out the handshake data, now read to get the response
                    await this.ReadAsync(new byte[0], 0, 0, cancellationToken).ConfigureAwait(false);
                    await this.HandShake(cancellationToken).ConfigureAwait(false);
                }
                else
                {
                    bytesRead = await this.ReadAsync(new byte[0], 0, 0, cancellationToken).ConfigureAwait(false);

                    if (bytesRead > 0)
                    {
                        if (ProcessHandshake())
                        {
                            handShakeState = HandshakeState.Complete;
                            // We have completed the handshake, but need to send the
                            // last response packet.
                            if (write_bio.BytesPending > 0)
                            {
                                await this.WriteAsync(new byte[0], 0, 0, cancellationToken).ConfigureAwait(false);
                                await this.HandShake(cancellationToken).ConfigureAwait(false);
                            }
                            else
                                return;
                        }
                        else
                        {
                            // Not complete with the handshake yet, write the handshake packet out
                            await this.WriteAsync(new byte[0], 0, 0, cancellationToken).ConfigureAwait(false);
                            await this.HandShake(cancellationToken).ConfigureAwait(false);
                        }
                    }
                    else
                    {
                        // Read read 0 bytes, the remote socket has been closed, so complete the operation
                        throw new IOException("The remote stream has been closed");
                    }
                }
            }
        }

        #endregion

        /// <summary>
        /// Renegotiate session keys - calls SSL_renegotiate
        /// </summary>
		/// <summary>
		/// Renegotiate session keys - calls SSL_renegotiate
		/// </summary>
		public void Renegotiate()
        {
            if (ssl != null)
            {
                // Call the SSL_renegotiate to reset the SSL object state
                // to start handshake
                Native.ExpectSuccess(Native.SSL_renegotiate(ssl.Handle));
                handShakeState = HandshakeState.Renegotiate;
            }
        }

        #region IDisposable Members

        protected override void Dispose(bool disposing)
		{
			if (disposed)
				return;

            if (innerStream != null)
            {
                innerStream.Dispose();
                innerStream = null;
            }
            if (ssl != null)
            {
                ssl.Dispose();
                ssl = null;
            }
            if (sslContext != null)
            {
                sslContext.Dispose();
                sslContext = null;
            }
            if (read_bio != null)
            {
                read_bio.FreeAfterSSL();
                read_bio = null;
            }
            if (write_bio != null)
            {
                write_bio.FreeAfterSSL();
                write_bio = null;
            }
            if (cleartext != null)
            {
                cleartext.Dispose();
                cleartext = null;
            }
            read_buffer = null;

            OnLocalCertificate = null;
            OnRemoteCertificate = null;

            base.Dispose(disposing);
            disposed = true;
		}

		#endregion
	}
}
