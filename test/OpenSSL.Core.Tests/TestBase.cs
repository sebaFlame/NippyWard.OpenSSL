// Copyright (c) 2009 Frank Laub
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
using System.Linq;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;

using Xunit;
using Xunit.Abstractions;

using OpenSSL.Core.Interop;
using OpenSSL.Core.Error;

namespace OpenSSL.Core.Tests
{
	public class TestBase : IDisposable
	{
        protected readonly ITestOutputHelper OutputHelper;

        protected TestBase(ITestOutputHelper outputHelper)
        {
            this.OutputHelper = outputHelper;
            MemoryTracker.Start();
        }

		public virtual void Dispose()
		{
            List<MemoryProblem> lstMemoryProblem = MemoryTracker.Finish();
            foreach (var mem in lstMemoryProblem)
            {
                Debug.WriteLine("MEMORY: {0}", mem);
                this.OutputHelper.WriteLine("MEMORY: {0}", mem);
            }

            List<string> errors = OpenSslError.GetErrors();
            foreach (var err in errors)
            {
                Debug.WriteLine("ERROR: {0}", err);
                this.OutputHelper.WriteLine("ERROR: {0}", err);
            }

            Assert.Empty(errors);
            //TODO: manually check output
            //Assert.Empty(lstMemoryProblem);
        }
	}
}
