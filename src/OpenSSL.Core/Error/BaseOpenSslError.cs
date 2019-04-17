namespace OpenSSL.Core.Error
{
    public abstract class BaseOpenSslError
    {
        protected ulong ErrorCode { get; private set; }

        public BaseOpenSslError(ulong errorCode)
        {
            this.ErrorCode = errorCode;
        }

        public abstract string Message { get; }
    }
}
