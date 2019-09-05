using System;
using System.Runtime.CompilerServices;

namespace Cnaws.Web.Hosting
{
#if (MONO)
    internal static class MonoInternal
    {
        [MethodImpl(MethodImplOptions.InternalCall)]
        internal static extern string GetRequestHeader(IntPtr request);
        [MethodImpl(MethodImplOptions.InternalCall)]
        internal static extern string GetServerVariable(IntPtr request, string name);
        [MethodImpl(MethodImplOptions.InternalCall)]
        internal static extern int GetInputDataType(IntPtr request);
        [MethodImpl(MethodImplOptions.InternalCall)]
        internal static extern byte[] GetInputData(IntPtr request);
        [MethodImpl(MethodImplOptions.InternalCall)]
        internal static extern int ReadInputData(IntPtr request, byte[] buffer, int size, int offset);
        [MethodImpl(MethodImplOptions.InternalCall)]
        internal static extern int SetStatus(IntPtr request, int status);
        [MethodImpl(MethodImplOptions.InternalCall)]
        internal static extern int SetHeader(IntPtr request, int index, string value);
        [MethodImpl(MethodImplOptions.InternalCall)]
        internal static extern int SetUnknownHeader(IntPtr request, string name, string value);
        [MethodImpl(MethodImplOptions.InternalCall)]
        internal static extern int SendContent(IntPtr request, IntPtr response, byte[] content, int size);
        [MethodImpl(MethodImplOptions.InternalCall)]
        internal static extern int SetError(IntPtr request, IntPtr response, int status, string message);
        [MethodImpl(MethodImplOptions.InternalCall)]
        internal static extern int SendFile(IntPtr request, IntPtr response, string file, long offset, long size);
    }
#endif
}
