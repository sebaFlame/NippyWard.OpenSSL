using System;
using System.Collections.Generic;
using System.Text;

namespace OpenSSL.Core.SSL.Pipelines
{
    internal struct BufferSequence
    {
        // The read head which is the extent of the IPipelineReader's consumed bytes
        internal BufferSegment ReadHead;
        internal int ReadHeadIndex;

        // The commit head which is the extent of the bytes available to the IPipelineReader to consume
        internal BufferSegment CommitHead;
        internal int CommitHeadIndex;

        // The write head which is the extent of the IPipelineWriter's written bytes
        internal BufferSegment WritingHead;

        internal long Length;
        internal long CurrentWriteLength;

        public void Reset()
        {
            CommitHeadIndex = 0;
            CurrentWriteLength = 0;
            Length = 0;
        }

        public void Copy(ref BufferSequence bufferSequence)
        {
            this.ReadHead = bufferSequence.ReadHead;
            this.ReadHeadIndex = bufferSequence.ReadHeadIndex;
            this.CommitHead = bufferSequence.CommitHead;
            this.CommitHeadIndex = bufferSequence.CommitHeadIndex;
            this.WritingHead = bufferSequence.WritingHead;
            this.Length = bufferSequence.Length;
            this.CurrentWriteLength = bufferSequence.CurrentWriteLength;
        }
    }
}
