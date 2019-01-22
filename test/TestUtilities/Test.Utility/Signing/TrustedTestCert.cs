// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using NuGet.Common;
using NuGet.Test.Utility;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;

namespace Test.Utility.Signing
{
    public static class TrustedTestCert
    {
        public static TrustedTestCert<X509Certificate2> Create(
            X509Certificate2 cert,
            StoreName storeName,
            StoreLocation storeLocation,
            TestDirectory dir,
            TimeSpan? maximumValidityPeriod = null,
            bool trustInLinux = false,
            bool trustInMac = false)
        {
            return new TrustedTestCert<X509Certificate2>(
                cert,
                x => x,
                storeName,
                storeLocation,
                dir,
                maximumValidityPeriod,
                trustInLinux,
                trustInMac);
        }
    }

    /// <summary>
    /// Give a certificate full trust for the life of the object.
    /// </summary>
    public class TrustedTestCert<T> : IDisposable
    {
        private X509Store _store;

        public X509Certificate2 TrustedCert { get; }

        public T Source { get; }

        public StoreName StoreName { get; }

        public StoreLocation StoreLocation { get; }

        private bool _isDisposed;

        private string _systemTrustedCertPath;

        private readonly bool _trustedInMac;

        public TrustedTestCert(T source,
            Func<T, X509Certificate2> getCert,
            StoreName storeName,
            StoreLocation storeLocation,
            TestDirectory dir,
            TimeSpan? maximumValidityPeriod = null,
            bool trustInLinux = false,
            bool trustInMac = false)
        {
            Source = source;
            TrustedCert = getCert(source);

            if (!maximumValidityPeriod.HasValue)
            {
                maximumValidityPeriod = TimeSpan.FromHours(2);
            }

            if (TrustedCert.NotAfter - TrustedCert.NotBefore > maximumValidityPeriod.Value)
            {
                throw new InvalidOperationException($"The certificate used is valid for more than {maximumValidityPeriod}.");
            }

            StoreName = storeName;
            StoreLocation = storeLocation;
            AddCertificateToStore();

            if (trustInLinux && RuntimeEnvironmentHelper.IsLinux)
            {
                TrustCertInLinux(dir);
            }
            else if (trustInMac && RuntimeEnvironmentHelper.IsMacOSX)
            {
                _trustedInMac = true;
                TrustCertInMac(dir);
            }

            ExportCrl();
        }

        private void AddCertificateToStore()
        {
            _store = new X509Store(StoreName, StoreLocation);
            _store.Open(OpenFlags.ReadWrite);
            _store.Add(TrustedCert);
        }

        private void ExportCrl()
        {
            var testCertificate = Source as TestCertificate;

            if (testCertificate != null && testCertificate.Crl != null)
            {
                testCertificate.Crl.ExportCrl();
            }
        }

        private void TrustCertInLinux(TestDirectory dir)
        {
            var certDir = @"/usr/share/ca-certificates/nuget";

            var tempCertFileName = "NuGetTest-" + Guid.NewGuid().ToString() + ".crt";
            var tempCertPath = Path.Combine(dir, tempCertFileName);

            var bcCert = DotNetUtilities.FromX509Certificate(TrustedCert);
            var pemWriter = new PemWriter(new StreamWriter(File.Open(tempCertPath, FileMode.Create)));
            pemWriter.WriteObject(bcCert);
            pemWriter.Writer.Flush();
            pemWriter.Writer.Close();

            _systemTrustedCertPath = Path.Combine(certDir, tempCertFileName);

            Process.Start(@"/usr/bin/sudo", $@"cp {tempCertPath} {_systemTrustedCertPath}");
            Process.Start(@"/usr/bin/sudo", @"update-ca-certificates");
        }

        private void TrustCertInMac(TestDirectory dir)
        {
            var exportedCert = TrustedCert.Export(X509ContentType.Cert);

            var tempCertFileName = "NuGetTest-" + Guid.NewGuid().ToString() + ".cer";

            _systemTrustedCertPath = Path.Combine(dir, tempCertFileName);
            File.WriteAllBytes(_systemTrustedCertPath, exportedCert);

            Process.Start(@"/usr/bin/sudo", $@"security -v add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain {_systemTrustedCertPath}");
        }

        private void DisposeCrl()
        {
            var testCertificate = Source as TestCertificate;

            if (testCertificate != null && testCertificate.Crl != null)
            {
                testCertificate.Crl.Dispose();
            }
        }

        public void Dispose()
        {
            if (!_isDisposed)
            {
                using (_store)
                {
                    _store.Remove(TrustedCert);
                }

                if (_systemTrustedCertPath != null && RuntimeEnvironmentHelper.IsLinux)
                {
                    Process.Start(@"/usr/bin/sudo", $@"rm {_systemTrustedCertPath}");
                }

                if (_trustedInMac && RuntimeEnvironmentHelper.IsMacOSX)
                {
                    Process.Start(@"/usr/bin/sudo", $@"security -v remove-trusted-cert -d {_systemTrustedCertPath}");
                }

                DisposeCrl();

                _isDisposed = true;
            }
        }
    }
}