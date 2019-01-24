// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Collections.Generic;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using NuGet.Packaging.Signing;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509.Extension;
using X509Extension = System.Security.Cryptography.X509Certificates.X509Extension;
using Org.BouncyCastle.Asn1.Ocsp;
using NuGet.Common;
using GeneralName = Org.BouncyCastle.Asn1.X509.GeneralName;
using HashAlgorithmName = System.Security.Cryptography.HashAlgorithmName;

namespace Test.Utility.Signing
{
    public sealed class CertificateAuthority : HttpResponder
    {
        private readonly Dictionary<string, X509Certificate2> _issuedCertificates;
        private readonly Dictionary<string, RevocationInfo> _revokedCertificates;
        private readonly Lazy<OcspResponder> _ocspResponder;
        private string _nextSerialNumber;

        /// <summary>
        /// This base URI is shared amongst all HTTP responders hosted by the same web host instance.
        /// </summary>
        public Uri SharedUri { get; }

        public X509Certificate2 Certificate { get; }

        /// <summary>
        /// Gets the base URI specific to this HTTP responder.
        /// </summary>
        public override Uri Url { get; }

        public OcspResponder OcspResponder => _ocspResponder.Value;

        public CertificateAuthority Parent { get; }

        public Uri CertificateUri { get; }

        public Uri OcspResponderUri { get; }

        internal RSA KeyPair { get; }

        private CertificateAuthority(
            X509Certificate2 certificate,
            RSA keyPair,
            Uri sharedUri,
            CertificateAuthority parentCa)
        {
            Certificate = certificate;
            KeyPair = keyPair;
            SharedUri = sharedUri;
            Url = GenerateRandomUri();
            var fingerprint = CertificateUtilities.GenerateFingerprint(certificate);
            CertificateUri = new Uri(Url, $"{fingerprint}.cer");
            OcspResponderUri = GenerateRandomUri();
            Parent = parentCa;
            _nextSerialNumber = IncrementSerialByOne(certificate.SerialNumber);
            _issuedCertificates = new Dictionary<string, X509Certificate2>();
            _revokedCertificates = new Dictionary<string, RevocationInfo>();
            _ocspResponder = new Lazy<OcspResponder>(() => OcspResponder.Create(this));
        }

        public X509Certificate2 IssueCertificate(IssueCertificateOptions options)
        {
            if (options == null)
            {
                throw new ArgumentNullException(nameof(options));
            }

            var signatureGenerator = X509SignatureGenerator.CreateForRSA(options.KeyPair, RSASignaturePadding.Pkcs1);

            void customizeCertificate(TestCertificateGenerator generator)
            {
                generator.Extensions.Add(
                    new X509Extension(
                        TestOids.AuthorityInfoAccess,
                        new DerSequence(
                            new AccessDescription(AccessDescription.IdADOcsp,
                                new GeneralName(GeneralName.UniformResourceIdentifier, OcspResponderUri.OriginalString)),
                            new AccessDescription(AccessDescription.IdADCAIssuers,
                                new GeneralName(GeneralName.UniformResourceIdentifier, CertificateUri.OriginalString))).GetDerEncoded(),
                        critical: false));

                var publicKey = DotNetUtilities.GetRsaPublicKey(Certificate.GetRSAPublicKey());

                generator.Extensions.Add(
                    new X509Extension(
                        Oids.AuthorityKeyIdentifier,
                        new AuthorityKeyIdentifierStructure(publicKey).GetEncoded(),
                        critical: false));
                generator.Extensions.Add(
                    new X509SubjectKeyIdentifierExtension(signatureGenerator.PublicKey, critical: false));
                generator.Extensions.Add(
                    new X509BasicConstraintsExtension(certificateAuthority: false, hasPathLengthConstraint: false, pathLengthConstraint: 0, critical: true));

            }

            return IssueCertificate(options, customizeCertificate);
        }

        public CertificateAuthority CreateIntermediateCertificateAuthority(IssueCertificateOptions options = null)
        {
            options = options ?? IssueCertificateOptions.CreateDefaultForIntermediateCertificateAuthority();

            var signatureGenerator = X509SignatureGenerator.CreateForRSA(options.KeyPair, RSASignaturePadding.Pkcs1);

            void customizeCertificate(TestCertificateGenerator generator)
            {
                generator.Extensions.Add(
                    new X509Extension(
                        TestOids.AuthorityInfoAccess,
                        new DerSequence(
                            new AccessDescription(AccessDescription.IdADOcsp,
                                new GeneralName(GeneralName.UniformResourceIdentifier, OcspResponderUri.OriginalString)),
                            new AccessDescription(AccessDescription.IdADCAIssuers,
                                new GeneralName(GeneralName.UniformResourceIdentifier, CertificateUri.OriginalString))).GetDerEncoded(),
                        critical: false));

                var publicKey = DotNetUtilities.GetRsaPublicKey(Certificate.GetRSAPublicKey());

                generator.Extensions.Add(
                    new X509Extension(
                        Oids.AuthorityKeyIdentifier,
                        new AuthorityKeyIdentifierStructure(publicKey).GetEncoded(),
                        critical: false));
                generator.Extensions.Add(
                    new X509SubjectKeyIdentifierExtension(signatureGenerator.PublicKey, critical: false));
                generator.Extensions.Add(
                    new X509BasicConstraintsExtension(certificateAuthority: true, hasPathLengthConstraint: false, pathLengthConstraint: 0, critical: true));
            }

            var certificate = IssueCertificate(options, customizeCertificate);

            return new CertificateAuthority(certificate, options.KeyPair, SharedUri, parentCa: this);
        }

        public void Revoke(X509Certificate2 certificate, RevocationReason reason, DateTimeOffset revocationDate)
        {
            if (certificate == null)
            {
                throw new ArgumentNullException(nameof(certificate));
            }

            if (!_issuedCertificates.ContainsKey(certificate.SerialNumber))
            {
                throw new ArgumentException("Unknown serial number.", nameof(certificate));
            }

            if (_revokedCertificates.ContainsKey(certificate.SerialNumber))
            {
                throw new ArgumentException("Certificate already revoked.", nameof(certificate));
            }

            _revokedCertificates.Add(
                certificate.SerialNumber,
                new RevocationInfo(certificate.SerialNumber, revocationDate, reason));
        }

        public override void Respond(HttpListenerContext context)
        {
            if (context == null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            if (IsGet(context.Request) &&
                string.Equals(context.Request.RawUrl, CertificateUri.AbsolutePath, StringComparison.OrdinalIgnoreCase))
            {
                var bcCert = DotNetUtilities.FromX509Certificate(Certificate);
                WriteResponseBody(context.Response, bcCert.GetEncoded());
            }
            else
            {
                context.Response.StatusCode = 404;
            }
        }

        public static CertificateAuthority Create(Uri sharedUri, IssueCertificateOptions options = null)
        {
            if (sharedUri == null)
            {
                throw new ArgumentNullException(nameof(sharedUri));
            }

            if (!sharedUri.AbsoluteUri.EndsWith("/"))
            {
                sharedUri = new Uri($"{sharedUri.AbsoluteUri}/");
            }

            options = options ?? IssueCertificateOptions.CreateDefaultForRootCertificateAuthority();

            var signatureGenerator = X509SignatureGenerator.CreateForRSA(options.KeyPair, RSASignaturePadding.Pkcs1);

            void customizeCertificate(TestCertificateGenerator generator)
            {
                generator.Extensions.Add(
                    new X509SubjectKeyIdentifierExtension(signatureGenerator.PublicKey, critical: false));
                generator.Extensions.Add(
                    new X509BasicConstraintsExtension(certificateAuthority: true, hasPathLengthConstraint: false, pathLengthConstraint: 0, critical: true));
                generator.Extensions.Add(
                    new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, critical: true));
            }

            var certificate = CreateCertificate(
                options.KeyPair,
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1,
                "1",
                options.SubjectName,
                options.NotBefore,
                options.NotAfter,
                options.CustomizeCertificate ?? customizeCertificate);

            return new CertificateAuthority(certificate, options.KeyPair, sharedUri, parentCa: null);
        }

        internal CertificateStatus GetStatus(CertificateID certificateId)
        {
            if (certificateId == null)
            {
                throw new ArgumentNullException(nameof(certificateId));
            }

            var bcCert = DotNetUtilities.FromX509Certificate(Certificate);

            if (certificateId.MatchesIssuer(bcCert) &&
                _issuedCertificates.ContainsKey(certificateId.SerialNumber.ToString()))
            {
                RevocationInfo revocationInfo;

                if (!_revokedCertificates.TryGetValue(certificateId.SerialNumber.ToString(), out revocationInfo))
                {
                    return CertificateStatus.Good;
                }

                var datetimeString = DerGeneralizedTimeUtility.ToDerGeneralizedTimeString(revocationInfo.RevocationDate);

                // The DateTime constructor truncates fractional seconds;
                // however, the string constructor preserves full accuracy.
                var revocationDate = new DerGeneralizedTime(datetimeString);
                var reason = new CrlReason((int)revocationInfo.Reason);
                var revokedInfo = new RevokedInfo(revocationDate, reason);

                return new RevokedStatus(revokedInfo);
            }

            return new UnknownStatus();
        }

        internal Uri GenerateRandomUri()
        {
            using (var provider = RandomNumberGenerator.Create())
            {
                var bytes = new byte[32];

                provider.GetBytes(bytes);

                var path = BitConverter.ToString(bytes).Replace("-", "");

                return new Uri(SharedUri, $"{path}/");
            }
        }

        private X509Certificate2 IssueCertificate(
            IssueCertificateOptions options,
            Action<TestCertificateGenerator> customizeCertificate)
        {
            var serialNumber = _nextSerialNumber;
            var notAfter = options.NotAfter.UtcDateTime;

            // An issued certificate should not have a validity period beyond the issuer's validity period.
            if (notAfter > Certificate.NotAfter)
            {
                notAfter = Certificate.NotAfter;
            }

            var certificate = CreateCertificate(
                options.KeyPair,
                options.SignatureAlgorithmName,
                RSASignaturePadding.Pkcs1,
                serialNumber,
                options.SubjectName,
                options.NotBefore.UtcDateTime,
                notAfter,
                options.CustomizeCertificate ?? customizeCertificate,
                Certificate);

            _nextSerialNumber = IncrementSerialByOne(_nextSerialNumber);
            _issuedCertificates.Add(certificate.SerialNumber, certificate);

            return certificate;
        }

        private static X509Certificate2 CreateCertificate(
            RSA certificateKey,
            HashAlgorithmName hashAlgorithm,
            RSASignaturePadding padding,
            string serialNumber,
            X500DistinguishedName subjectName,
            DateTimeOffset notBefore,
            DateTimeOffset notAfter,
            Action<TestCertificateGenerator> customizeCertificate,
            X509Certificate2 issuer = null)
        {
            var request = new CertificateRequest(subjectName, certificateKey, hashAlgorithm, padding);

            var generator = new TestCertificateGenerator();

            generator.SetSerialNumber(serialNumber);
            generator.NotBefore = notBefore.UtcDateTime;
            generator.NotAfter = notAfter.UtcDateTime;

            customizeCertificate(generator);

            foreach (var extension in generator.Extensions)
            {
                request.CertificateExtensions.Add(extension);
            }

            X509Certificate2 certResult;

            if (issuer == null)
            {
                certResult = request.CreateSelfSigned(generator.NotBefore, generator.NotAfter);
            }
            else
            {
                using (var temp = request.Create(issuer, generator.NotBefore, generator.NotAfter, generator.SerialNumber))
                {
                    certResult = temp.CopyWithPrivateKey(certificateKey);
                }
            }

            return new X509Certificate2(certResult.Export(X509ContentType.Pkcs12), password: (string)null, keyStorageFlags: X509KeyStorageFlags.Exportable);
        }

        private static string IncrementSerialByOne(string serialNumber)
        {
            var serial = Convert.ToInt64(serialNumber);

            serial += 1;

            return Convert.ToString(serial);
        }

        private sealed class RevocationInfo
        {
            internal string SerialNumber { get; }
            internal DateTimeOffset RevocationDate { get; }
            internal RevocationReason Reason { get; }

            internal RevocationInfo(string serialNumber, DateTimeOffset revocationDate, RevocationReason reason)
            {
                SerialNumber = serialNumber;
                RevocationDate = revocationDate;
                Reason = reason;
            }
        }
    }
}