using System;
using System.Collections.Generic;
using System.Text;
using System.Buffers;

namespace OpenSSL.Core.SSL.Pooling
{
    internal sealed class PooledMemoryOwner : IMemoryOwner<byte>
    {
        public Memory<byte> Memory { get; private set; }

        private byte[] buffer;

        public PooledMemoryOwner(int minimumRentSize)
        {
            this.buffer = ArrayPool<byte>.Shared.Rent(minimumRentSize);
            this.Memory = new Memory<byte>(this.buffer);
        }

        public void Dispose()
        {
            ArrayPool<byte>.Shared.Return(this.buffer);
        }
    }
}
