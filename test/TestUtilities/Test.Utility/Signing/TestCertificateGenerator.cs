// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Collections.ObjectModel;
using System.Security.Cryptography.X509Certificates;

namespace Test.Utility.Signing
{
    public sealed class TestCertificateGenerator
    {
        public DateTimeOffset NotBefore { get; set; }

        public DateTimeOffset NotAfter { get; set; }

        public byte[] SerialNumber { get; private set; }

        public Collection<X509Extension> Extensions { get; }

        public TestCertificateGenerator()
        {
            Extensions = new Collection<X509Extension>();
        }

        private void SetSerialNumber(byte[] serialNumber)
        {
            SerialNumber = serialNumber ?? throw new ArgumentNullException(nameof(serialNumber));
        }

        public void SetSerialNumber(long serialNumber)
        {
            if (serialNumber <= 0)
            {
                throw new ArgumentException("serial number cannot be negative");
            }

            var bytes = BitConverter.GetBytes(serialNumber);
            Array.Reverse(bytes);

            SerialNumber = bytes;
        }

        public void SetSerialNumber(string serialNumber)
        {
            if (string.IsNullOrEmpty(serialNumber))
            {
                throw new ArgumentException(nameof(serialNumber));
            }

            var serial = Convert.ToInt64(serialNumber);
            SetSerialNumber(serial);
        }
    }
}
