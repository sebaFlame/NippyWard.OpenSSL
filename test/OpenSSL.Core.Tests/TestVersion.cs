using Xunit;
using Xunit.Abstractions;

using OpenSSL.Core.Interop;
using Version = OpenSSL.Core.Interop.Version;

namespace OpenSSL.Core.Tests
{
	public class TestVersion : TestBase
	{
        public TestVersion(ITestOutputHelper outputHelper)
            : base(outputHelper) { }

        protected override void Dispose(bool disposing) { }

        [Fact]
        public void CorrectVersion()
        {
            Assert.True(Version.Library >= Version.MinimumOpenSslVersion);
        }

		[Fact]
		public void Zero()
		{
			var version = new Version(0x00000000);
			Assert.Equal((uint)0, version.Major);
			Assert.Equal((uint)0, version.Minor);
			Assert.Equal((uint)0, version.Fix);
			Assert.Null(version.Patch);
			Assert.Equal(Version.StatusType.Development, version.Status);
			Assert.Equal((uint)0, version.Raw);
			Assert.Equal("0.0.0 Development (0x00000000)", version.ToString());
		}

		[Fact]
		public void Basic1()
		{
			var version = new Version(0x102031af);
			Assert.Equal((uint)1, version.Major);
			Assert.Equal((uint)2, version.Minor);
			Assert.Equal((uint)3, version.Fix);
			Assert.Equal('z', version.Patch);
			Assert.Equal(Version.StatusType.Release, version.Status);
			Assert.Equal((uint)0x102031af, version.Raw);
			Assert.Equal("1.2.3z Release (0x102031af)", version.ToString());
		}

		[Fact]
		public void Basic2()
		{
			var version = new Version(0x1000200f);
			Assert.Equal((uint)1, version.Major);
			Assert.Equal((uint)0, version.Minor);
			Assert.Equal((uint)2, version.Fix);
			Assert.Null(version.Patch);
			Assert.Equal(Version.StatusType.Release, version.Status);
			Assert.Equal((uint)0x1000200f, version.Raw);
			Assert.Equal("1.0.2 Release (0x1000200f)", version.ToString());
		}

		[Fact]
		public void Basic3()
		{
			var version = new Version(0x1000201f);
			Assert.Equal((uint)1, version.Major);
			Assert.Equal((uint)0, version.Minor);
			Assert.Equal((uint)2, version.Fix);
			Assert.Equal('a', version.Patch);
			Assert.Equal(Version.StatusType.Release, version.Status);
			Assert.Equal((uint)0x1000201f, version.Raw);
			Assert.Equal("1.0.2a Release (0x1000201f)", version.ToString());
		}
	}
}
