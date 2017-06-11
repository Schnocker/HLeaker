using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace HandleLeaker
{
    public class CProcess
    {

        public CProcess()
        {
            this.ProcessName = "";
            this.hProcess = Kernel32.GetCurrentProcess();
        }

        public CProcess(int dwProcessId, UInt32 DesiredAccess = 0x1fffff)
        {
            this.ProcessName = "";
            this.hProcess = Kernel32.OpenProcess(DesiredAccess, false, dwProcessId);
        }

        public CProcess(string ProcessName)
        {
            this.ProcessName = ProcessName;
            this.hProcess = IntPtr.Zero;
        }
        public CProcess(IntPtr hProcess)
        {
            this.ProcessName = "";
            this.hProcess = hProcess;
        }

        ~CProcess()
        {
        }

        public bool Wait(int Interval)
        {
            if (this.ProcessName.Length == 0)
                return false;
            this.hProcess = IntPtr.Zero;
            while (true)
            {
                this.ProcessList = System.Diagnostics.Process.GetProcessesByName(ProcessName);
                System.Threading.Thread.Sleep(Interval);
                if (this.ProcessList.Length > 0)
                {
                    this.hProcess = Kernel32.OpenProcess(0x1fffff, false, this.ProcessList[0].Id);
                    break;
                }
            }
            return true;
        }

        public bool SetPrivilege(string lpszPrivilege, bool bEnablePrivilege)
        {
            bool Status = true;
            Kernel32.TOKEN_PRIVILEGES priv = new Kernel32.TOKEN_PRIVILEGES();
            IntPtr hToken = IntPtr.Zero;
            Kernel32.LUID luid = new Kernel32.LUID();
            int RetLength = 0;

            if (!Kernel32.OpenProcessToken(this.hProcess, 0x0020, ref hToken))
            {
                Status = false;
                goto EXIT;
            }

            if (!Advapi32.LookupPrivilegeValueA(null, lpszPrivilege, ref luid))
            {
                Status = false;
                goto EXIT;
            }

            priv.PrivilegeCount = 1;
            priv.Privileges = new Kernel32.LUID_AND_ATTRIBUTES();
            priv.Privileges.Luid = luid;
            priv.Privileges.Attributes = (int)((bEnablePrivilege == true) ? 0x00000002L : 0x00000004L);

            if (!Kernel32.AdjustTokenPrivileges(hToken, false, ref priv, 0, IntPtr.Zero, ref RetLength))
            {
                Status = false;
                goto EXIT;
            }
            EXIT:
            if(hToken != IntPtr.Zero)
                Kernel32.CloseHandle(hToken);
            return Status;
        }

        public bool Suspend()
        {
            return (ntdll.NtSuspendProcess(this.hProcess) == 0);
        }

        public bool Resume()
        {
            return (ntdll.NtResumeProcess(this.hProcess) == 0);
        }

        public bool Kill()
        {
            return Kernel32.TerminateProcess(this.hProcess, 0);
        }

        public bool Open(UInt32 DesiredAccess = 0x1fffff)
        {
            if (this.ProcessName.Length == 0)
                return false;
            this.hProcess = IntPtr.Zero;
            this.ProcessList = System.Diagnostics.Process.GetProcessesByName(ProcessName);
            if (this.ProcessList.Length > 0)
                this.hProcess = Kernel32.OpenProcess(DesiredAccess, false, this.ProcessList[0].Id);
            return IsValidProcess();
        }

        public bool Close()
        {
            return Kernel32.CloseHandle(this.hProcess);
        }

        public IntPtr GetHandle()
        {
            return this.hProcess;
        }

        public int GetPid()
        {
            return Kernel32.GetProcessId(this.hProcess);
        }
        public int GetParentPid()
        {
            IntPtr[] pbi = new IntPtr[6];
            int ulSize = 0;
            if (ntdll.NtQueryInformationProcess(this.hProcess, 0, pbi, Marshal.SizeOf(pbi),  ref ulSize) >= 0)
                return (int)pbi[5];
            return 0;
        }

        public int Is64(ref bool Is64)
        {
            int Status = 1;
            IntPtr hFile = (IntPtr)(-1);
            IntPtr lpFile = (IntPtr)0;
            int dwFileSize = 0, dwReaded = 0, dwSize = 255;
            Kernel32.IMAGE_DOS_HEADER DosHeader;
            byte[] Path = new byte[255];
            byte[] FileCopy = null;
            string lpFileName = "";
            int machineUint = 0;

            if (!Kernel32.QueryFullProcessImageNameA(this.hProcess, 0, Path, ref dwSize))
            {
                Status = 2;
                goto EXIT;
            }
            lpFileName = System.Text.Encoding.Default.GetString(Path);
            hFile = Kernel32.CreateFileA(lpFileName, (0x80000000), 0, IntPtr.Zero, 3, 0, IntPtr.Zero);
            if (hFile == (IntPtr)(-1))
            {
                Status = 3;
                goto EXIT;
            }
            dwFileSize = Kernel32.GetFileSize(hFile, IntPtr.Zero);
            lpFile = Kernel32.VirtualAlloc(IntPtr.Zero, dwFileSize, 0x1000, 0x40);
            if (lpFile == IntPtr.Zero)
            {
                Status = 4;
                goto EXIT;
            }
            if (!Kernel32.ReadFile(hFile, lpFile, dwFileSize, ref dwReaded, IntPtr.Zero))
            {
                Status = 5;
                goto EXIT;
            }
            DosHeader = new Kernel32.IMAGE_DOS_HEADER();
            DosHeader = (Kernel32.IMAGE_DOS_HEADER)Marshal.PtrToStructure(lpFile, typeof(Kernel32.IMAGE_DOS_HEADER));
            if (!DosHeader.isValid)
            {
                Status = 6;
                goto EXIT;
            }
            FileCopy = new byte[dwFileSize];
            Marshal.Copy(lpFile, FileCopy, 0, dwFileSize);
            machineUint = BitConverter.ToUInt16(FileCopy, BitConverter.ToInt32(FileCopy, 60) + 4);
            if (machineUint == 0x8664 ||
                machineUint == 0x0200)
            {
                Is64 = true;
                goto EXIT;
            }
            if (machineUint == 0x014c)
            {
                Is64 = false;
                goto EXIT;
            }
            EXIT:
            if (hFile != IntPtr.Zero)
                Kernel32.CloseHandle(hFile);
            if (lpFile != IntPtr.Zero)
                Kernel32.VirtualFree(lpFile, dwFileSize, 0x4000);
            return Status;
        }

        public bool IsValidProcess()
        {
            if (hProcess == (IntPtr)(-1))
                return false;
            return (Kernel32.WaitForSingleObject(this.hProcess, 0) == 258L);
        }



        System.Diagnostics.Process[] ProcessList; 
        private string ProcessName;
        private IntPtr hProcess;

    }
}
