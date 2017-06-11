using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace HandleLeaker
{
    static class Program
    {
        /// <summary>
        /// The main entry point for the application.
        /// </summary>
        [STAThread]
        static void Main(string[] args)
        {
            CProcess CurrentProcess = new CProcess(), TargetProcess = new CProcess(Options.TargetProcess), ServProcess;
            int counter = 0, maxCount = 1;
            List<Service.HANDLE_INFO> HandleList = new List<Service.HANDLE_INFO>();
            IntPtr hProcess = IntPtr.Zero;
            switch (args.Length)
            {
                case 0:
                    CurrentProcess.SetPrivilege("SeDebugPrivilege", true);
                    CurrentProcess.SetPrivilege("SeTcbPrivilege", true);
                    TargetProcess.Wait(Options.DelayToWait);
                    if (TargetProcess.IsValidProcess())
                    {
                        HandleList = Service.ServiceEnumHandles(TargetProcess.GetPid(), Options.DesiredAccess);
                        if (HandleList.Count > 0)
                        {
                            foreach (Service.HANDLE_INFO enumerator in HandleList)
                            {
                                if (counter == maxCount)
                                    break;
                                if (enumerator.Pid == Kernel32.GetCurrentProcessId()) continue;
                                ServProcess = new CProcess(enumerator.Pid);
                                if (Service.ServiceSetHandleStatus(ServProcess, (IntPtr)enumerator.hProcess, true, true) == true)
                                {
                                    hProcess = Service.ServiceStartProcess(null, Directory.GetCurrentDirectory() + "\\" + Options.YourProcess + " " + enumerator.hProcess, null, true, ServProcess.GetHandle());
                                    Service.ServiceSetHandleStatus(ServProcess, (IntPtr)enumerator.hProcess, false, false);
                                    counter++;
                                }
                                if (hProcess != null)
                                    Kernel32.CloseHandle(hProcess);
                                ServProcess.Close();
                            }
                        }
                        TargetProcess.Close();
                    }
                    CurrentProcess.SetPrivilege("SeDebugPrivilege", false);
                    CurrentProcess.SetPrivilege("SeTcbPrivilege", false);
                    break;
                case 1:
                    Application.EnableVisualStyles();
                    Application.SetCompatibleTextRenderingDefault(false);
                    Application.Run(new HLeaker_GUI((IntPtr)(Convert.ToInt32(args[args.Length - 1]))));
                    break;
                default:
                    break;

            }
        }
    }
}
