#include "Service.hpp"
#include "Options.hpp"

int main(int argc, char** argv)
{
	HMODULE hMods[1024];
	char CLine[1024], ModuleName[MAX_PATH];
	DWORD dwcbNeeded = 0, dwCounter = 0, dwMaxCount = 1;
	PROCESS_INFORMATION pi = { 0,0,0,0 };
	Process::CProcess *CurrentProcess = nullptr,  *TargetProcess = nullptr, *AttachedProcess = nullptr;
	std::vector<Service::HANDLE_INFO> Handles;
	ZeroMemory(CLine, _countof(CLine));
	ZeroMemory(hMods, _countof(hMods));
	ZeroMemory(ModuleName, MAX_PATH);

	switch (argc)
	{
	case 1:
		CurrentProcess = new Process::CProcess();
		CurrentProcess->SetPrivilege(SE_DEBUG_NAME, true);
		CurrentProcess->SetPrivilege(SE_TCB_NAME, true);
		TargetProcess = new Process::CProcess(std::string(TARGET_PROCESS));
		TargetProcess->Wait(DELAY_TO_WAIT);
		TargetProcess->Open();
		if (TargetProcess->IsValidProcess())
		{
			Handles = Service::ServiceEnumHandles(TargetProcess->GetPid(), DESIRED_ACCESS);
			if (!GetFullPathNameA(YOUR_PROCESS, MAX_PATH, ModuleName, 0))
			{
				std::cout << "GetFullPathNameA failed with errorcode " << GetLastError() << std::endl;
				goto EXIT;
			}
			for (auto Handle : Handles)
			{
				if (dwCounter == dwMaxCount)
					break;
				AttachedProcess = new Process::CProcess(Handle.dwPid, PROCESS_ALL_ACCESS);
				if (!Service::ServiceSetHandleStatus(AttachedProcess, Handle.hProcess, TRUE, TRUE))
				{
					std::cout << "ServiceSetHandleStatus failed with errorcode " << GetLastError() << std::endl;

					if (AttachedProcess)
					{
						AttachedProcess->Close();
						delete AttachedProcess;
					}
					continue;
				}
				sprintf_s(CLine, "%s %d", ModuleName, Handle.hProcess);
				if (!Service::ServiceRunProgram(0, CLine, 0, &pi, true, AttachedProcess->GetHandle()))
				{
					std::cout << "ServiceRunProgram failed with errorcode " << GetLastError() << std::endl;
				}
				if (!Service::ServiceSetHandleStatus(AttachedProcess, Handle.hProcess, FALSE, FALSE))
				{
					std::cout << "ServiceSetHandleStatus failed with errorcode " << GetLastError() << std::endl;
				}
				AttachedProcess->Close();
				delete AttachedProcess;
				dwCounter++;
			}
		}
	EXIT:
		CurrentProcess->SetPrivilege(SE_TCB_NAME, false);
		CurrentProcess->SetPrivilege(SE_DEBUG_NAME, false);
		TargetProcess->Close();
		if(CurrentProcess)
			delete CurrentProcess;
		if(TargetProcess)
			delete TargetProcess;
		break;
	case 2:
		TargetProcess = new Process::CProcess(reinterpret_cast<void*>(atoi(argv[1])));
		std::cout << "Process Handle : " << TargetProcess->GetHandle() << std::endl;
		if (EnumProcessModulesEx(TargetProcess->GetHandle(), hMods, sizeof(hMods), &dwcbNeeded, LIST_MODULES_ALL))
		{
			for (int i = 0;i < dwcbNeeded / sizeof(HMODULE);i++)
			{
				if (GetModuleFileNameExA(TargetProcess->GetHandle(), hMods[i], ModuleName, MAX_PATH))
				{
					std::cout << hMods[i] << " : " << ModuleName << std::endl;
				}
			}
		}
		TargetProcess->Close();
		delete TargetProcess;
		std::cin.get();
		break;
	default:
		break;
	}
	return true;
}


