using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace HandleLeaker
{
    class Service
    {

        #region Structs
        public struct HANDLE_INFO
        {
            public int Pid;
            public IntPtr hProcess;
            public HANDLE_INFO(int Pid, IntPtr hProcess)
            {
                this.Pid = Pid;
                this.hProcess = hProcess;
            }
        }

        private struct HANDLE_IN
        {
            public IntPtr hObject;
            public bool PStatus;
            public bool IStatus;
            public IntPtr Function;
            public HANDLE_IN(IntPtr hObject, bool PStatus, bool IStatus, IntPtr Function)
            {
                this.hObject = hObject;
                this.PStatus = PStatus;
                this.IStatus = IStatus;
                this.Function = Function;
            }
        };

        private struct THREAD_IN
        {
            public IntPtr hProcess;
            public IntPtr _GetProcessId, _ExitThread;
            public THREAD_IN(IntPtr hProcess, IntPtr _GetProcessId, IntPtr _ExitThread)
            {
                this.hProcess = hProcess;
                this._GetProcessId = _GetProcessId;
                this._ExitThread = _ExitThread;
            }
        };

        #endregion Structs

        #region Members
        static IntPtr _ExitThread = IntPtr.Zero, _GetProcessId = IntPtr.Zero, _NtSetInformationObject = IntPtr.Zero;
        #endregion

        /// <summary>
        /// This function starts our target process in the normal session
        /// </summary>
        public static IntPtr ServiceStartProcess(string lpFile, string lpArguments, string lpDir, Boolean Inherit, IntPtr hParent)
        {
            Kernel32.STARTUPINFOEX si = new Kernel32.STARTUPINFOEX();
            Kernel32.PROCESS_INFORMATION pi = new Kernel32.PROCESS_INFORMATION();
            IntPtr processToken = IntPtr.Zero, userToken = IntPtr.Zero, pEnvironment = IntPtr.Zero, cbAttributeListSize = IntPtr.Zero, pAttributeList = IntPtr.Zero;
            Advapi32.SECURITY_ATTRIBUTES sa = new Advapi32.SECURITY_ATTRIBUTES();
            pi.hProcess = IntPtr.Zero;
            if (!Kernel32.OpenProcessToken(Kernel32.GetCurrentProcess(), Kernel32.TOKEN_ALL_ACCESS, ref processToken))
                goto EXIT;
            if (!Advapi32.DuplicateTokenEx(processToken, Kernel32.TOKEN_ALL_ACCESS, out sa, Advapi32.SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation, Advapi32.TOKEN_TYPE.TokenPrimary, out userToken) ||
                !UserEnv.CreateEnvironmentBlock(ref pEnvironment, userToken, false))
                goto EXIT;
            Kernel32.InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref cbAttributeListSize);
            pAttributeList = Kernel32.VirtualAlloc(IntPtr.Zero, (int)cbAttributeListSize, 0x1000, 0x40);
            if (pAttributeList == null)
                goto EXIT;
            if (!Kernel32.InitializeProcThreadAttributeList(pAttributeList, 1, 0, ref cbAttributeListSize))
                goto EXIT;
            if (!Kernel32.UpdateProcThreadAttribute(pAttributeList, 0, (IntPtr)0x00020000, ref hParent, (IntPtr)Marshal.SizeOf(hParent), IntPtr.Zero, IntPtr.Zero))
                goto EXIT;
            si.lpAttributeList = pAttributeList;
            si.StartupInfo = new Kernel32.STARTUPINFO();
            si.StartupInfo.cb = Marshal.SizeOf(typeof(Kernel32.STARTUPINFO));
            if (!Kernel32.CreateProcessAsUserA(userToken, lpFile, lpArguments, IntPtr.Zero, IntPtr.Zero, Inherit, 0x400 | 0x010 |  0x00080000, pEnvironment, lpDir, ref si, ref pi))
                goto EXIT;
            EXIT:
            if(processToken != IntPtr.Zero)
                Kernel32.CloseHandle(processToken);
            if (userToken != IntPtr.Zero)
                Kernel32.CloseHandle(userToken);
            if (pEnvironment != IntPtr.Zero)
                UserEnv.DestroyEnvironmentBlock(pEnvironment);
            if (pAttributeList != IntPtr.Zero)
            {
                Kernel32.DeleteProcThreadAttributeList(pAttributeList);
                Kernel32.VirtualFree(pAttributeList, (int)cbAttributeListSize, 0x4000);
            }
            if(pi.hThread != IntPtr.Zero)
            Kernel32.CloseHandle(pi.hThread);
            return pi.hProcess;
        }

        /// <summary>
        /// This function executes a shellcode to change the handle characteristics
        /// </summary>
        public static Boolean ServiceSetHandleStatus(CProcess Process, IntPtr hObject, bool Protect, bool Inherit)
        {
            bool Is64 = false, Status = false;
            byte[] W64Thread = { 0x48, 0x83, 0xEC, 0x28, 0xF, 0xB6, 0x41, 0x8, 0x4C, 0x8D, 0x44, 0x24, 0x30, 0x41, 0xB9, 0x2, 0x0, 0x0, 0x0, 0x88, 0x44, 0x24, 0x31, 0xF, 0xB6, 0x41, 0xC, 0x4C, 0x8B, 0xD1, 0x48, 0x8B, 0x9, 0x88, 0x44, 0x24, 0x30, 0x41, 0x8D, 0x51, 0x2, 0x41, 0xFF, 0x52, 0x10, 0x33, 0xC9, 0x85, 0xC0, 0xF, 0x94, 0xC1, 0x8B, 0xC1, 0x48, 0x83, 0xC4, 0x28, 0xC3 };
            byte[] W32Thread = { 0x55, 0x8B, 0xEC, 0x8B, 0x4D, 0x8, 0x6A, 0x2, 0xF, 0xB6, 0x41, 0x4, 0x88, 0x45, 0x9, 0xF, 0xB6, 0x41, 0x8, 0x88, 0x45, 0x8, 0x8D, 0x45, 0x8, 0x50, 0x8B, 0x41, 0xC, 0x6A, 0x4, 0xFF, 0x31, 0xFF, 0xD0, 0xF7, 0xD8, 0x1B, 0xC0, 0x40, 0x5D, 0xC2, 0x4, 0x0 };
            HANDLE_IN Args;
            IntPtr hThread = IntPtr.Zero, lpArgs = IntPtr.Zero, lpThread = IntPtr.Zero, WThread = IntPtr.Zero, WArgs = IntPtr.Zero;
            if (hObject == IntPtr.Zero || Process.Is64(ref Is64) != 1)
                goto EXIT;
            if ((IntPtr.Size == 8) ? !Is64 : Is64)
                goto EXIT;
            if (_NtSetInformationObject == IntPtr.Zero)
            {
                _NtSetInformationObject = Kernel32.GetProcAddress(Kernel32.GetModuleHandleA("ntdll.dll"), "NtSetInformationObject");
                if (_NtSetInformationObject == IntPtr.Zero)
                    goto EXIT;
            }
            Args = new HANDLE_IN(hObject, Protect, Inherit, _NtSetInformationObject);
            if (Args.Function == IntPtr.Zero)
                goto EXIT;
            if ((lpThread = Kernel32.VirtualAllocEx(Process.GetHandle(), IntPtr.Zero, Is64 ? W64Thread.Length : W32Thread.Length, 0x1000, 0x40)) == IntPtr.Zero ||
                (lpArgs = Kernel32.VirtualAllocEx(Process.GetHandle(), IntPtr.Zero, Marshal.SizeOf(typeof(HANDLE_IN)), 0x1000, 0x40)) == IntPtr.Zero)
                goto EXIT;
            WArgs = Marshal.AllocHGlobal(Marshal.SizeOf(WArgs));
            WThread = Marshal.AllocHGlobal(Is64 ? W64Thread.Length : W32Thread.Length);
            Marshal.Copy(Is64 ? W64Thread : W32Thread, 0, WThread, Is64 ? W64Thread.Length : W32Thread.Length);
            Marshal.StructureToPtr(Args, WArgs, true);
            if (!Kernel32.WriteProcessMemory(Process.GetHandle(), lpThread, WThread, Is64 ? W64Thread.Length : W32Thread.Length, IntPtr.Zero) ||
                !Kernel32.WriteProcessMemory(Process.GetHandle(), lpArgs, WArgs, Marshal.SizeOf(Args), IntPtr.Zero))
                goto EXIT;

            if (ntdll.RtlCreateUserThread(Process.GetHandle(), IntPtr.Zero, false, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, lpThread, lpArgs, ref hThread, IntPtr.Zero) != 0)
                goto EXIT;
            Kernel32.WaitForSingleObject(hThread, (0xFFFFFFFF));
            Status = true;
            EXIT:
            if ((hThread) != IntPtr.Zero)
                Kernel32.CloseHandle(hThread);
            if (lpThread != null)
                Kernel32.VirtualFreeEx(Process.GetHandle(), lpThread, Is64 ? W64Thread.Length : W32Thread.Length, 0x4000);
            if (lpArgs != null)
                Kernel32.VirtualFreeEx(Process.GetHandle(), lpArgs, Marshal.SizeOf(typeof(HANDLE_IN)), 0x4000);
            return Status;
        }
        /// <summary>
        /// This function executes a shellcode to get the process id of an existing handle
        /// </summary>
        private static Boolean ServiceGetProcessId(CProcess Process, IntPtr Handle, ref uint ProcessId)
        {
            byte[] W32Thread = { 0x55, 0x8B, 0xEC, 0x56, 0x8B, 0x75, 0x08, 0xFF, 0x36, 0x8B, 0x46, 0x04, 0xFF, 0xD0, 0x50, 0x8B, 0x46, 0x08, 0xFF, 0xD0, 0x5E, 0x5D, 0xC3 };
            byte[] W64Thread = { 0x40, 0x53, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x8B, 0xD9, 0x48, 0x8B, 0x09, 0xFF, 0x53, 0x08, 0x8B, 0xC8, 0xFF, 0x53, 0x10, 0xB8, 0x01, 0x00, 0x00, 0x00, 0x48, 0x83, 0xC4, 0x20, 0x5B, 0xC3 };
            bool Is64 = false, Status = false;
            IntPtr hThread = IntPtr.Zero, lpArgs = IntPtr.Zero, lpThread = IntPtr.Zero, WThread = IntPtr.Zero, WArgs = IntPtr.Zero, k32 = IntPtr.Zero;
            THREAD_IN Args;

            if (Handle == IntPtr.Zero || Process.Is64(ref Is64) != 1)
                goto EXIT;
            if ((IntPtr.Size == 8) ? !Is64 : Is64)
                goto EXIT;
            if (_ExitThread == IntPtr.Zero && _GetProcessId == IntPtr.Zero)
            {
                k32 = Kernel32.GetModuleHandleA("kernel32.dll");
                _ExitThread = Kernel32.GetProcAddress(k32, "ExitThread");
                if (_ExitThread == IntPtr.Zero)
                    goto EXIT;

                _GetProcessId = Kernel32.GetProcAddress(k32, "GetProcessId");
                if (_GetProcessId == IntPtr.Zero)
                    goto EXIT;
            }
            Args = new THREAD_IN(Handle, _GetProcessId, _ExitThread);
            if ((lpThread = Kernel32.VirtualAllocEx(Process.GetHandle(), IntPtr.Zero, Is64 ? W64Thread.Length : W32Thread.Length, 0x1000, 0x40)) == IntPtr.Zero ||
                (lpArgs = Kernel32.VirtualAllocEx(Process.GetHandle(), IntPtr.Zero, Marshal.SizeOf(typeof(THREAD_IN)), 0x1000, 0x40)) == IntPtr.Zero)
                goto EXIT;
            WArgs = Marshal.AllocHGlobal(Marshal.SizeOf(Args));
            WThread = Marshal.AllocHGlobal(Is64 ? W64Thread.Length : W32Thread.Length);
            Marshal.Copy(Is64 ? W64Thread : W32Thread, 0, WThread, Is64 ? W64Thread.Length : W32Thread.Length);
            Marshal.StructureToPtr(Args, WArgs, true);
            if (!Kernel32.WriteProcessMemory(Process.GetHandle(), lpThread, WThread, Is64 ? W64Thread.Length : W32Thread.Length, IntPtr.Zero) ||
                !Kernel32.WriteProcessMemory(Process.GetHandle(), lpArgs, WArgs, Marshal.SizeOf(Args), IntPtr.Zero))
                goto EXIT;
            if (ntdll.RtlCreateUserThread(Process.GetHandle(), IntPtr.Zero, false, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, lpThread, lpArgs, ref hThread, IntPtr.Zero) != 0)
                goto EXIT;
            if (Kernel32.WaitForSingleObject(hThread, Options.ObjectTimeout) == 0x00000102)
            {
                Kernel32.TerminateThread(hThread, 0x102);
                goto EXIT;
            }
            Status = Kernel32.GetExitCodeThread(hThread, out ProcessId);
            EXIT:
            if ((hThread) != IntPtr.Zero)
                Kernel32.CloseHandle(hThread);
            if (lpThread != null)
                Kernel32.VirtualFreeEx(Process.GetHandle(), lpThread, Is64 ? W64Thread.Length : W32Thread.Length, 0x4000);
            if (lpArgs != null)
                Kernel32.VirtualFreeEx(Process.GetHandle(), lpArgs, Marshal.SizeOf(typeof(THREAD_IN)), 0x4000);
            return Status;
        }
        /// <summary>
        /// This function enumrates the handles to our target process
        /// </summary>
        public static List<HANDLE_INFO> ServiceEnumHandles(int ProcessId, UInt32 DesiredAccess)
        {

            UInt32 status = 0;
            IntPtr buffer = IntPtr.Zero, ipHandle = IntPtr.Zero;
            int bufferSize = 0;
            uint pId = 0;
            List<HANDLE_INFO> handlelist = new List<HANDLE_INFO>();
            IntPtr ProcessHandle = IntPtr.Zero, ProcessCopy = IntPtr.Zero;
            ntdll.SYSTEM_HANDLE wHandles = new ntdll.SYSTEM_HANDLE();
            HANDLE_INFO hi;
            long lHandleCount = 0;
            CProcess Process = null;
            do
            {
                status = (UInt32)ntdll.NtQuerySystemInformation(0x10, buffer, bufferSize, ref bufferSize);
                if (status != 0)
                {
                    if (status == 0xc0000004)
                    {
                        if (buffer != null)
                            Kernel32.VirtualFree(buffer, bufferSize, 0x8000);
                        buffer = Kernel32.VirtualAlloc(IntPtr.Zero, bufferSize, 0x1000, 0x40);
                        continue;
                    }
                    break;
                }
                else
                {
                    if (IntPtr.Size == 8)
                    {
                        lHandleCount = Marshal.ReadInt64(buffer);
                        ipHandle = new IntPtr(buffer.ToInt64() + 8);
                    }
                    else
                    {
                        lHandleCount = Marshal.ReadInt32(buffer);
                        ipHandle = new IntPtr(buffer.ToInt32() + 4);
                    }

                    for (long i = 0; i < lHandleCount; i++)
                    {
                        wHandles = new ntdll.SYSTEM_HANDLE();
                        if (IntPtr.Size == 8)
                        {
                            wHandles = (ntdll.SYSTEM_HANDLE)Marshal.PtrToStructure(ipHandle, wHandles.GetType());
                            ipHandle = new IntPtr(ipHandle.ToInt64() + Marshal.SizeOf(wHandles));
                        }
                        else
                        {
                            ipHandle = new IntPtr(ipHandle.ToInt64() + Marshal.SizeOf(wHandles));
                            wHandles = (ntdll.SYSTEM_HANDLE)Marshal.PtrToStructure(ipHandle, wHandles.GetType());
                        }
                        if (wHandles.ObjectTypeNumber == 7 &&
                            wHandles.ProcessID != Kernel32.GetCurrentProcessId() &&
                            (((uint)(wHandles.GrantedAccess) & DesiredAccess)) == DesiredAccess)
                        {
                            if (Options.UseDuplicateHandle == true)
                            {
                                ProcessHandle = Kernel32.OpenProcess(0x0040, false, wHandles.ProcessID);
                                if (Kernel32.DuplicateHandle(ProcessHandle, (IntPtr)(wHandles.Handle), Kernel32.GetCurrentProcess(), ref ProcessCopy, 0x0400, false, 0))
                                {
                                    if (Kernel32.GetProcessId(ProcessCopy) == ProcessId &&
                                        wHandles.ProcessID != ProcessId)
                                    {
                                        hi = new HANDLE_INFO(wHandles.ProcessID,(IntPtr)wHandles.Handle);
                                        handlelist.Add(hi);
                                    }
                                }
                                if (ProcessHandle != IntPtr.Zero)
                                    Kernel32.CloseHandle(ProcessHandle);
                                if (ProcessCopy != IntPtr.Zero)
                                    Kernel32.CloseHandle(ProcessCopy);
                            }
                            else
                            {
                                Process = new CProcess(wHandles.ProcessID, 0x1fffff);
                                if (Process.IsValidProcess() && ServiceGetProcessId(Process, (IntPtr)wHandles.Handle, ref pId))
                                {
                                    if (pId == ProcessId)
                                    {
                                        hi = new HANDLE_INFO(wHandles.ProcessID, (IntPtr)wHandles.Handle);
                                        handlelist.Add(hi);
                                    }
                                }
                                if (Process.IsValidProcess())
                                    Process.Close();
                            }
                        }
                            
                    }
                    break;
                }
            } while (true);
            if (buffer != null)
                Kernel32.VirtualFree(buffer, bufferSize, 0x8000);
            return handlelist;
        }
    }
}
