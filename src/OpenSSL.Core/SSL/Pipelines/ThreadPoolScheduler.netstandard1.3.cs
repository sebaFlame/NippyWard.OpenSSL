// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Threading;
using System.Threading.Tasks;

namespace OpenSSL.Core.SSL.Pipelines
{
    internal sealed class ThreadPoolScheduler : PipeScheduler
    {
        public override void Schedule(Action<object> action, object state)
        {
            Task.Factory.StartNew(action, state, CancellationToken.None, TaskCreationOptions.DenyChildAttach, TaskScheduler.Default);
        }
    }
}
