using System;
using System.Collections.Generic;
using System.Buffers;

namespace OpenSSL.Core.SSL.Pooling
{
    internal sealed class PooledMemoryPool : MemoryPool<byte>
    {
        private int maxBufferSize;
        public override int MaxBufferSize => this.maxBufferSize;

        //add one, because of max SSL frame size
        public PooledMemoryPool(int maxBufferSize)
        {
            this.maxBufferSize = ++maxBufferSize;
        }

        public override IMemoryOwner<byte> Rent(int minBufferSize = -1)
        {
            return new PooledMemoryOwner(minBufferSize);
        }

        protected override void Dispose(bool disposing)
        {
            //do nothing
        }
    }
}
