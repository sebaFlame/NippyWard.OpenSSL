namespace NippyWard.OpenSSL.Error
{
    public abstract class BaseOpenSslError
    {
        public ulong ErrorCode { get; private set; }

        public int Reason => (int)(this.ErrorCode & 0X7FFFFF);
        public int Library => (int)((this.ErrorCode >> 23) & 0xFF);

        public BaseOpenSslError(ulong errorCode)
        {
            this.ErrorCode = errorCode;
        }

        public abstract string Message { get; }
    }
}
