// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Runtime.InteropServices;

namespace NuGet.SolutionRestoreManager
{
    /// <summary>
    /// Contains target framework metadata needed for restore operation.
    /// </summary>
    [ComImport]
    [Guid("451ACBA6-FE6A-4412-99D2-3882790BF338")]
    public interface IVsTargetFrameworkInfo2
    {
        /// <summary>
        /// Target framework name in full format.
        /// </summary>
        string TargetFrameworkMoniker { get; }

        /// <summary>
        /// Collection of project references.
        /// </summary>
        IVsReferenceItems ProjectReferences { get; }

        /// <summary>
        /// Collection of package references.
        /// </summary>
        IVsReferenceItems PackageReferences { get; }

        /// <summary>
        /// Collection of package downloads.
        /// </summary>
        IVsReferenceItems PackageDownloads { get; }

        /// <summary>
        /// Collection of project level properties evaluated per each Target Framework,
        /// e.g. PackageTargetFallback.
        /// </summary>
        IVsProjectProperties Properties { get; }
    }
}
