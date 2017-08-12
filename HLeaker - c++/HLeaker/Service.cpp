#include "Service.hpp"
#include "Options.hpp"

namespace Service
{
#pragma region Members
	typedef NTSTATUS(NTAPI*_RtlCreateUserThread)(HANDLE Process, PSECURITY_DESCRIPTOR ThreadSecurityDescriptor, BOOLEAN CreateSuspended, ULONG_PTR ZeroBits, SIZE_T MaximumStackSize, SIZE_T CommittedStackSize, PVOID StartAddress, PVOID Parameter, PHANDLE Thread, PVOID ClientId);
	static _RtlCreateUserThread RtlCreateUserThread = reinterpret_cast<_RtlCreateUserThread>(GetProcAddress(GetModuleHandle("ntdll.dll"), "RtlCreateUserThread"));
	typedef NTSTATUS(NTAPI*_NtQuerySystemInformation)(ULONG, PVOID, ULONG, PULONG);
	static _NtQuerySystemInformation NtQuerySystemInformation = reinterpret_cast<_NtQuerySystemInformation>(GetProcAddress(GetModuleHandle("ntdll.dll"), "NtQuerySystemInformation"));
	static void *_ExitThread = GetProcAddress(GetModuleHandle("kernel32.dll"), "ExitThread"), *_GetProcessId = GetProcAddress(GetModuleHandle("kernel32.dll"), "GetProcessId"), *_NtSetInformationObject = GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtSetInformationObject");
#pragma endregion Members

	HANDLE WINAPI ServiceRunProgram(LPCSTR lpFilename, LPCSTR lpArguments, LPCSTR lpDir, LPPROCESS_INFORMATION ProcessInformation, BOOL Inherit, HANDLE hParent)
	{
		HANDLE processToken = NULL, userToken = NULL;
		LPVOID pEnvironment = NULL;
		STARTUPINFOEXA  si = { 0 };
		SIZE_T cbAttributeListSize = 0;
		PPROC_THREAD_ATTRIBUTE_LIST pAttributeList = NULL;
		BOOL Status = TRUE;
		ZeroMemory(&si, sizeof(si));
		si.StartupInfo.cb = sizeof(STARTUPINFOEXA);

		if (!ProcessInformation)
		{
			Status = false;
			goto EXIT;
		}

		if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &processToken))
		{
			Status = false;
			goto EXIT;
		}
		if (!DuplicateTokenEx(processToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &userToken) ||
			!CreateEnvironmentBlock(&pEnvironment, userToken, TRUE))
		{
			Status = false;
			goto EXIT;
		}
		InitializeProcThreadAttributeList(NULL, 1, 0, &cbAttributeListSize);
		pAttributeList = reinterpret_cast<PPROC_THREAD_ATTRIBUTE_LIST>(HeapAlloc(GetProcessHeap(), 0, cbAttributeListSize));
		if (!pAttributeList)
		{
			Status = false;
			goto EXIT;
		}
		if (!InitializeProcThreadAttributeList(pAttributeList, 1, 0, &cbAttributeListSize))
		{
			Status = false;
			goto EXIT;
		}
		if (!UpdateProcThreadAttribute(pAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hParent, sizeof(HANDLE), NULL, NULL))
		{
			Status = false;
			goto EXIT;
		}
		si.lpAttributeList = pAttributeList;
		if (!CreateProcessAsUserA(userToken, lpFilename, const_cast<LPSTR>(lpArguments), NULL, NULL, TRUE, CREATE_UNICODE_ENVIRONMENT | CREATE_NEW_CONSOLE | EXTENDED_STARTUPINFO_PRESENT, pEnvironment, lpDir, reinterpret_cast<LPSTARTUPINFOA>(&si), ProcessInformation))
		{
			Status = false;
			goto EXIT;
		}
	EXIT:
		if (pEnvironment)
			DestroyEnvironmentBlock(pEnvironment);
		CloseHandle(userToken);
		if (ProcessInformation->hThread)
			CloseHandle(ProcessInformation->hThread);
		if (processToken)
			CloseHandle(processToken);
		if (pAttributeList)
		{
			DeleteProcThreadAttributeList(pAttributeList);
			HeapFree(GetProcessHeap(), 0, pAttributeList);
		}
		return Status ? ProcessInformation->hProcess : 0;
	}
	BOOLEAN WINAPI ServiceSetHandleStatus(Process::CProcess* Process, HANDLE hObject, BOOL Protect, BOOL Inherit)
	{
		typedef struct _CLIENT_ID
		{
			HANDLE UniqueProcess;
			HANDLE UniqueThread;

		} CLIENT_ID, *PCLIENT_ID;

		struct HANDLE_IN
		{
			HANDLE hObject;
			BOOL PStatus;
			BOOL IStatus;
			PVOID Function;
		};
#ifdef _WIN64
		static BYTE WThread[] = { 0x48, 0x83, 0xEC, 0x28, 0xF, 0xB6, 0x41, 0x8, 0x4C, 0x8D, 0x44, 0x24, 0x30, 0x41, 0xB9, 0x2, 0x0, 0x0, 0x0, 0x88, 0x44, 0x24, 0x31, 0xF, 0xB6, 0x41, 0xC, 0x4C, 0x8B, 0xD1, 0x48, 0x8B, 0x9, 0x88, 0x44, 0x24, 0x30, 0x41, 0x8D, 0x51, 0x2, 0x41, 0xFF, 0x52, 0x10, 0x33, 0xC9, 0x85, 0xC0, 0xF, 0x94, 0xC1, 0x8B, 0xC1, 0x48, 0x83, 0xC4, 0x28, 0xC3};
#elif _WIN32
		static BYTE WThread[] = { 0x55, 0x8B, 0xEC, 0x8B, 0x4D, 0x8, 0x6A, 0x2, 0xF, 0xB6, 0x41, 0x4, 0x88, 0x45, 0x9, 0xF, 0xB6, 0x41, 0x8, 0x88, 0x45, 0x8, 0x8D, 0x45, 0x8, 0x50, 0x8B, 0x41, 0xC, 0x6A, 0x4, 0xFF, 0x31, 0xFF, 0xD0, 0xF7, 0xD8, 0x1B, 0xC0, 0x40, 0x5D, 0xC2, 0x4, 0x0 };
#endif
		BOOL IsTarget64 = false, Status = false;
		HANDLE_IN Args = { 0,0,0,0 };
		LPVOID lpThread = nullptr, lpArg = nullptr;
		HANDLE hProcess = Process->GetHandle(), hThread = 0;
		int ThreadSize = _countof(WThread);
		if (!RtlCreateUserThread || !_NtSetInformationObject || hProcess == INVALID_HANDLE_VALUE)
			goto EXIT;

		if (!Process->Is64(&IsTarget64))
			goto EXIT;

#ifdef _WIN64
		if (!IsTarget64)
			goto EXIT;
#elif _WIN32
		if (IsTarget64)
			goto EXIT;
#endif
		lpThread = VirtualAllocEx(hProcess, 0, ThreadSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (lpThread == nullptr)
			goto EXIT;

		lpArg = VirtualAllocEx(hProcess, 0, sizeof(HANDLE_IN), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (lpArg == nullptr)
			goto EXIT;

		Args.Function = _NtSetInformationObject;
		Args.hObject = hObject;
		Args.IStatus = Inherit;
		Args.PStatus = Protect;
		if (!WriteProcessMemory(hProcess, lpThread, reinterpret_cast<LPCVOID>(WThread), ThreadSize, 0) ||
			!WriteProcessMemory(hProcess, lpArg, reinterpret_cast<LPCVOID>(&Args), sizeof(HANDLE_IN), 0))
			goto EXIT;

		if (RtlCreateUserThread(hProcess, 0, 0, 0, 0, 0, reinterpret_cast<PVOID>(lpThread), lpArg, &hThread, 0))
			goto EXIT;

		WaitForSingleObject(hThread, INFINITE);
		Status = true;
	EXIT:
		if (hThread)
			CloseHandle(hThread);
		if (lpThread)
			VirtualFreeEx(hProcess, lpThread, ThreadSize, MEM_RELEASE);
		if (lpArg)
			VirtualFreeEx(hProcess, lpArg, sizeof(HANDLE_IN), MEM_RELEASE);
		return Status;
	}

	BOOLEAN WINAPI ServiceGetProcessId(Process::CProcess* Process, HANDLE hTarget, PDWORD ProcessId)
	{
		struct THREAD_IN
		{
			HANDLE hProcess;
			void* _GetProcessId, *_ExitThread;
		};
#ifdef _WIN64
		static BYTE WThread[] = { 0x40, 0x53, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x8B, 0xD9, 0x48, 0x8B, 0x09, 0xFF, 0x53, 0x08, 0x8B, 0xC8, 0xFF, 0x53, 0x10, 0xB8, 0x01, 0x00, 0x00, 0x00, 0x48, 0x83, 0xC4, 0x20, 0x5B, 0xC3 };
#elif _WIN32
		static BYTE WThread[] = { 0x55, 0x8B, 0xEC, 0x56, 0x8B, 0x75, 0x08, 0xFF, 0x36, 0x8B, 0x46, 0x04, 0xFF, 0xD0, 0x50, 0x8B, 0x46, 0x08, 0xFF, 0xD0, 0x5E, 0x5D, 0xC3 };
#endif
		BOOL IsTarget64 = false, Status = false;
		THREAD_IN Args = { 0,0,0 };
		LPVOID lpThread = nullptr, lpArg = nullptr;
		HANDLE hProcess = Process->GetHandle(), hThread = 0;
		int ThreadSize = _countof(WThread);
		if (!RtlCreateUserThread || !_ExitThread || !_GetProcessId || !ProcessId)
			goto EXIT;

		if (!Process->Is64(&IsTarget64))
			goto EXIT;

#ifdef _WIN64
		if (!IsTarget64)
			goto EXIT;
#elif _WIN32
		if (IsTarget64)
			goto EXIT;
#endif
		lpThread = VirtualAllocEx(hProcess, 0, ThreadSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (lpThread == nullptr)
			goto EXIT;

		lpArg = VirtualAllocEx(hProcess, 0, sizeof(THREAD_IN), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (lpArg == nullptr)
			goto EXIT;

		Args.hProcess = hTarget;
		Args._ExitThread = _ExitThread;
		Args._GetProcessId = _GetProcessId;
		if (!WriteProcessMemory(hProcess, lpThread, reinterpret_cast<LPCVOID>(WThread), ThreadSize, 0) ||
			!WriteProcessMemory(hProcess, lpArg, reinterpret_cast<LPCVOID>(&Args), sizeof(THREAD_IN), 0))
			goto EXIT;

		if (RtlCreateUserThread(hProcess, 0, 0, 0, 0, 0, reinterpret_cast<PVOID>(lpThread), lpArg, &hThread, 0))
			goto EXIT;
		if (WaitForSingleObject(hThread, OBJECTTIMEOUT) == WAIT_TIMEOUT)
			goto EXIT;
		if (!GetExitCodeThread(hThread, ProcessId))
			goto EXIT;
		Status = true;
	EXIT:
		if (hThread)
			CloseHandle(hThread);
		if (lpThread)
			VirtualFreeEx(hProcess, lpThread, ThreadSize, MEM_RELEASE);
		if (lpArg)
			VirtualFreeEx(hProcess, lpArg, sizeof(THREAD_IN), MEM_RELEASE);
		return Status;
	}

	std::vector<HANDLE_INFO> ServiceEnumHandles(ULONG ProcessId, DWORD dwDesiredAccess)
	{
		typedef struct _SYSTEM_HANDLE
		{
			ULONG ProcessId;
			BYTE ObjectTypeNumber;
			BYTE Flags;
			USHORT Handle;
			PVOID Object;
			ACCESS_MASK GrantedAccess;
		} SYSTEM_HANDLE, *PSYSTEM_HANDLE;

		typedef struct _SYSTEM_HANDLE_INFORMATION
		{
			ULONG HandleCount;
			SYSTEM_HANDLE Handles[1];
		} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

		PSYSTEM_HANDLE_INFORMATION handleInfo = 0;
		NTSTATUS status = -1;
		PVOID buffer = 0;
		ULONG bufferSize = 0, pId = 0;
		std::vector<HANDLE_INFO> handlelist;
		HANDLE ProcessHandle = 0, ProcessCopy = 0;
		HANDLE_INFO hi = { 0,0 };
		Process::CProcess* Process = 0;

		if (!NtQuerySystemInformation)
			goto EXIT;

		do {
			status = NtQuerySystemInformation(0x10, buffer, bufferSize, &bufferSize);
			if (status) {
				if (status == 0xc0000004) {
					if (buffer != NULL)
						VirtualFree(buffer, bufferSize, MEM_DECOMMIT);
					buffer = VirtualAlloc(0, bufferSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
					continue;
				}
				break;
			}
			else {
				handleInfo = reinterpret_cast<PSYSTEM_HANDLE_INFORMATION>(buffer);
				for (int i = 0; i < handleInfo->HandleCount; i++) {
					auto handle = &handleInfo->Handles[i];
					if (handle->ObjectTypeNumber == 7 && (handle->GrantedAccess & dwDesiredAccess) == dwDesiredAccess)
					{
#if (USE_DUPLICATE_HANDLE == 1)
						ProcessHandle = OpenProcess(PROCESS_DUP_HANDLE, false, handle->ProcessId);
						if (DuplicateHandle(ProcessHandle, reinterpret_cast<HANDLE>(handle->Handle), GetCurrentProcess(), &ProcessCopy, PROCESS_QUERY_INFORMATION, 0, 0))
						{
							if (GetProcessId(ProcessCopy) == ProcessId)
								handlelist.push_back(HANDLE_INFO(handle->ProcessId, reinterpret_cast<HANDLE>(handle->Handle)));
							
						}
						if (ProcessHandle)
							CloseHandle(ProcessHandle);
						if (ProcessCopy)
							CloseHandle(ProcessCopy);
#else
						Process = new Process::CProcess(handle->ProcessId, PROCESS_ALL_ACCESS);
						if (Process->IsValidProcess() && ServiceGetProcessId(Process, reinterpret_cast<HANDLE>(handle->Handle), &pId))
						{
							if (pId == ProcessId)
								handlelist.push_back(HANDLE_INFO(handle->ProcessId, reinterpret_cast<HANDLE>(handle->Handle)));
							
						}
						if (Process->IsValidProcess())
							Process->Close();
						delete Process;
#endif

					}
				}
				break;
			}
		} 
		while (true);
	EXIT:
		if (buffer != NULL)
			VirtualFree(buffer, bufferSize, MEM_DECOMMIT);
		return handlelist;
	}
}
		
