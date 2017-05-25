using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace HandleLeaker
{
    class ntdll
    {
        #region Structs
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct SYSTEM_HANDLE
        {
            public int ProcessID;
            public char ObjectTypeNumber;
            public char Flags; 
            public ushort Handle;
            public IntPtr Object_Pointer;
            public IntPtr GrantedAccess;
        }
        #endregion
        #region Functions
        [DllImport("ntdll.dll")]
        public static extern int NtSuspendProcess(IntPtr hProcess);
        [DllImport("ntdll.dll")]
        public static extern int NtResumeProcess(IntPtr hProcess);
        [DllImport("ntdll.dll")]
        public static extern int NtQueryInformationProcess(IntPtr ProcessHandle, int ProcessInformationClass, IntPtr[] ProcessInformation, int ProcessInformationLength, ref int ReturnLength);
        [DllImport("ntdll.dll")]
        public static extern int NtQuerySystemInformation(int SystemInformationClass, IntPtr SystemInformation, int SystemInformationLength, ref int ReturnLength);
        [DllImport("ntdll.dll")]
        public static extern int RtlCreateUserThread(IntPtr Process, IntPtr ThreadSecurityDescriptor, Boolean CreateSuspended, IntPtr ZeroBits, IntPtr MaximumStackSize, IntPtr CommittedStackSize, IntPtr StartAddress, IntPtr Parameter, ref IntPtr Thread, IntPtr ClientId);
        #endregion Functions
    }
}
