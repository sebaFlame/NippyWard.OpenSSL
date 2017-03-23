using System;
using OpenSSL.Core.Core;
using Xunit;

namespace OpenSSL.Core.Tests
{
	public class TestBigNumber
	{
		[Fact]
		public void Basic()
		{
			Console.WriteLine(BigNumber.Options);
		}
	}
}

