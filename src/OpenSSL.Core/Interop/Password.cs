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
using System.Runtime.InteropServices;
using System.Text;
using System.Diagnostics;
using OpenSSL.Core.Interop.Wrappers;

namespace OpenSSL.Core.Interop
{
	/// <summary>
	/// Callback prototype. Must return the password or prompt for one.
	/// </summary>
	/// <param name="verify"></param>
	/// <param name="userdata"></param>
	/// <returns></returns>
	public delegate string PasswordHandler(bool verify);

	/// <summary>
	/// Simple password callback that returns the contained password.
	/// </summary>
	public class PasswordCallback
	{
		private string password;
		/// <summary>
		/// Constructs a PasswordCallback
		/// </summary>
		/// <param name="password"></param>
		public PasswordCallback(string password)
		{
			this.password = password;
		}

		/// <summary>
		/// Suitable callback to be used as a PasswordHandler
		/// </summary>
		/// <param name="verify"></param>
		/// <param name="userdata"></param>
		/// <returns></returns>
		public string OnPassword(bool verify)
		{
			return this.password;
		}
	}

	internal class PasswordThunk
	{
		private PasswordHandler OnPassword;

		public pem_password_cb Callback
		{
			get
			{
				if (OnPassword == null)
					return null;

				return OnPasswordThunk;
			}
		}

		public PasswordThunk(PasswordHandler client)
		{
			OnPassword = client;
		}

		internal int OnPasswordThunk(IntPtr buf, int size, int rwflag, IntPtr userdata)
		{
            string password = string.Empty;

            try
			{
				password = OnPassword(rwflag != 0);

                if (password.Length > size)
                    throw new OverflowException("Password too long");

                unsafe
                {
                    ReadOnlySpan<char> passSpan = password.AsSpan();
                    fixed(char* ch = passSpan)
                    {
                        Encoding.ASCII.GetBytes(ch, passSpan.Length, (byte*)buf.ToPointer(), size);
                    }
                }
			}
			catch (Exception ex)
			{
				Debug.WriteLine(ex.Message);
				return -1;
			}

			return password.Length;
		}
	}
}
