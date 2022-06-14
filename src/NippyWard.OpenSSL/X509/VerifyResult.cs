// Copyright (c), Ben Henderson
// All rights reserved.

// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
//,. Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
//,. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
//,. The name of the author may not be used to endorse or promote products
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


namespace NippyWard.OpenSSL.X509
{
    /// <summary>
    /// X509_V_*
    /// </summary>
    public enum VerifyResult
    {
        /// <summary>
        /// the operation was successful.
        /// </summary>
        X509_V_OK = 0,
        X509_V_ERR_UNSPECIFIED,
        /// <summary>
        /// the issuer certificate could not be found: this occurs if the issuer certificate of an untrusted certificate cannot be found.
        /// </summary>
        X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT,
        /// <summary>
        /// the CRL of a certificate could not be found.
        /// </summary>
        X509_V_ERR_UNABLE_TO_GET_CRL,
        /// <summary>
        /// the certificate signature could not be decrypted. 
        /// This means that the actual signature value could not be determined rather than it not matching the expected value, this is only meaningful for RSA keys.
        /// </summary>
        X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE,
        /// <summary>
        /// the CRL signature could not be decrypted: this means that the actual signature value could not be determined rather than it not matching the expected value. Unused.
        /// </summary>
        X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE,
        /// <summary>
        /// the public key in the certificate SubjectPublicKeyInfo could not be read.
        /// </summary>
        X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY,
        /// <summary>
        /// the signature of the certificate is invalid.
        /// </summary>
        X509_V_ERR_CERT_SIGNATURE_FAILURE,
        /// <summary>
        /// the signature of the certificate is invalid.
        /// </summary>
        X509_V_ERR_CRL_SIGNATURE_FAILURE,
        /// <summary>
        /// the certificate is not yet valid: the notBefore date is after the current time.
        /// </summary>
        X509_V_ERR_CERT_NOT_YET_VALID,
        /// <summary>
        /// the certificate has expired: that is the notAfter date is before the current time.
        /// </summary>
        X509_V_ERR_CERT_HAS_EXPIRED,
        /// <summary>
        /// the CRL is not yet valid.
        /// </summary>
        X509_V_ERR_CRL_NOT_YET_VALID,
        /// <summary>
        /// the CRL has expired.
        /// </summary>
        X509_V_ERR_CRL_HAS_EXPIRED,
        /// <summary>
        /// the certificate notBefore field contains an invalid time.
        /// </summary>
        X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD,
        /// <summary>
        /// the certificate notAfter field contains an invalid time.
        /// </summary>
        X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD,
        /// <summary>
        /// the CRL lastUpdate field contains an invalid time.
        /// </summary>
        X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD,
        /// <summary>
        /// the CRL nextUpdate field contains an invalid time.
        /// </summary>
        X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD,
        /// <summary>
        /// an error occurred trying to allocate memory. This should never happen.
        /// </summary>
        X509_V_ERR_OUT_OF_MEM,
        /// <summary>
        /// the passed certificate is self signed and the same certificate cannot be found in the list of trusted certificates.
        /// </summary>
        X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT,
        /// <summary>
        /// the certificate chain could be built up using the untrusted certificates but the root could not be found locally.
        /// </summary>
        X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN,
        /// <summary>
        /// the issuer certificate of a locally looked up certificate could not be found. This normally means the list of trusted certificates is not complete.
        /// </summary>
        X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY,
        /// <summary>
        /// no signatures could be verified because the chain contains only one certificate and it is not self signed.
        /// </summary>
        X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE,
        /// <summary>
        /// the certificate chain length is greater than the supplied maximum depth. Unused.
        /// </summary>
        X509_V_ERR_CERT_CHAIN_TOO_LONG,
        /// <summary>
        /// the certificate has been revoked.
        /// </summary>
        X509_V_ERR_CERT_REVOKED,
        /// <summary>
        /// a CA certificate is invalid. Either it is not a CA or its extensions are not consistent with the supplied purpose.
        /// </summary>
        X509_V_ERR_INVALID_CA,
        /// <summary>
        /// the basicConstraints path-length parameter has been exceeded.
        /// </summary>
        X509_V_ERR_PATH_LENGTH_EXCEEDED,
        /// <summary>
        /// the supplied certificate cannot be used for the specified purpose.
        /// </summary>
        X509_V_ERR_INVALID_PURPOSE,
        /// <summary>
        /// the root CA is not marked as trusted for the specified purpose.
        /// </summary>
        X509_V_ERR_CERT_UNTRUSTED,
        /// <summary>
        /// the root CA is marked to reject the specified purpose.
        /// </summary>
        X509_V_ERR_CERT_REJECTED,
        /* These are 'informational' when looking for issuer cert */
        /// <summary>
        /// the current candidate issuer certificate was rejected because its subject name did not match the issuer name of the current certificate. 
        /// This is only set if issuer check debugging is enabled it is used for status notification and is not in itself an error.
        /// </summary>
        X509_V_ERR_SUBJECT_ISSUER_MISMATCH,
        /// <summary>
        /// the current candidate issuer certificate was rejected because its subject key identifier was present and did not match the authority key identifier current certificate. 
        /// This is only set if issuer check debugging is enabled it is used for status notification and is not in itself an error.
        /// </summary>
        X509_V_ERR_AKID_SKID_MISMATCH,
        /// <summary>
        /// the current candidate issuer certificate was rejected because its issuer name and serial number was present and did not match the authority key identifier of the current certificate. 
        /// This is only set if issuer check debugging is enabled it is used for status notification and is not in itself an error.
        /// </summary>
        X509_V_ERR_AKID_ISSUER_SERIAL_MISMATCH,
        /// <summary>
        /// the current candidate issuer certificate was rejected because its keyUsage extension does not permit certificate signing. 
        /// This is only set if issuer check debugging is enabled it is used for status notification and is not in itself an error.
        /// </summary>
        X509_V_ERR_KEYUSAGE_NO_CERTSIGN,
        X509_V_ERR_UNABLE_TO_GET_CRL_ISSUER,
        /// <summary>
        /// A certificate extension had an invalid value (for example an incorrect encoding) or some value inconsistent with other extensions.
        /// </summary>
        X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION,
        X509_V_ERR_KEYUSAGE_NO_CRL_SIGN,
        X509_V_ERR_UNHANDLED_CRITICAL_CRL_EXTENSION,
        X509_V_ERR_INVALID_NON_CA,
        X509_V_ERR_PROXY_PATH_LENGTH_EXCEEDED,
        X509_V_ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE,
        X509_V_ERR_PROXY_CERTIFICATES_NOT_ALLOWED,
        X509_V_ERR_INVALID_EXTENSION,
        /// <summary>
        /// A certificate policies extension had an invalid value (for example an incorrect encoding) or some value inconsistent with other extensions. 
        /// This error only occurs if policy processing is enabled.
        /// </summary>
        X509_V_ERR_INVALID_POLICY_EXTENSION,
        /// <summary>
        /// The verification flags were set to require and explicit policy but none was present.
        /// </summary>
        X509_V_ERR_NO_EXPLICIT_POLICY,
        /// <summary>
        /// The only CRLs that could be found did not match the scope of the certificate.
        /// </summary>
        X509_V_ERR_DIFFERENT_CRL_SCOPE,
        /// <summary>
        /// Some feature of a certificate extension is not supported. Unused.
        /// </summary>
        X509_V_ERR_UNSUPPORTED_EXTENSION_FEATURE,
        X509_V_ERR_UNNESTED_RESOURCE,
        /// <summary>
        /// A name constraint violation occurred in the permitted subtrees.
        /// </summary>
        X509_V_ERR_PERMITTED_VIOLATION,
        /// <summary>
        /// A name constraint violation occurred in the excluded subtrees.
        /// </summary>
        X509_V_ERR_EXCLUDED_VIOLATION,
        /// <summary>
        /// A certificate name constraints extension included a minimum or maximum field: this is not supported.
        /// </summary>
        X509_V_ERR_SUBTREE_MINMAX,
        /* The application is not happy */
        /// <summary>
        /// an application specific error. This will never be returned unless explicitly set by an application.
        /// </summary>
        X509_V_ERR_APPLICATION_VERIFICATION,
        /// <summary>
        /// An unsupported name constraint type was encountered. OpenSSL currently only supports directory name, DNS name, email and URI types.
        /// </summary>
        X509_V_ERR_UNSUPPORTED_CONSTRAINT_TYPE,
        /// <summary>
        /// The format of the name constraint is not recognised: for example an email address format of a form not mentioned in RFC3280. 
        /// This could be caused by a garbage extension or some new feature not currently supported.
        /// </summary>
        X509_V_ERR_UNSUPPORTED_CONSTRAINT_SYNTAX,
        X509_V_ERR_UNSUPPORTED_NAME_SYNTAX,
        /// <summary>
        /// An error occurred when attempting to verify the CRL path. This error can only happen if extended CRL checking is enabled.
        /// </summary>
        X509_V_ERR_CRL_PATH_VALIDATION_ERROR,
        /* Another issuer check debug option */
        X509_V_ERR_PATH_LOOP,
        /* Suite B mode algorithm violation */
        X509_V_ERR_SUITE_B_INVALID_VERSION,
        X509_V_ERR_SUITE_B_INVALID_ALGORITHM,
        X509_V_ERR_SUITE_B_INVALID_CURVE,
        X509_V_ERR_SUITE_B_INVALID_SIGNATURE_ALGORITHM,
        X509_V_ERR_SUITE_B_LOS_NOT_ALLOWED,
        X509_V_ERR_SUITE_B_CANNOT_SIGN_P_384_WITH_P_256,
        /* Host, email and IP check errors */
        X509_V_ERR_HOSTNAME_MISMATCH,
        X509_V_ERR_EMAIL_MISMATCH,
        X509_V_ERR_IP_ADDRESS_MISMATCH,
        /* DANE TLSA errors */
        X509_V_ERR_DANE_NO_MATCH,
        /* security level errors */
        X509_V_ERR_EE_KEY_TOO_SMALL,
        X509_V_ERR_CA_KEY_TOO_SMALL,
        X509_V_ERR_CA_MD_TOO_WEAK,
        /* Caller error */
        X509_V_ERR_INVALID_CALL,
        /* Issuer lookup error */
        X509_V_ERR_STORE_LOOKUP,
        /* Certificate transparency */
        X509_V_ERR_NO_VALID_SCTS,

        X509_V_ERR_PROXY_SUBJECT_NAME_VIOLATION,
    }
}
