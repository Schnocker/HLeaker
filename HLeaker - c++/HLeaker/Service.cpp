#include "Service.hpp"

namespace Service
{
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
		si.StartupInfo.lpDesktop = "winsta0\\default";

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
		if(pEnvironment)
			DestroyEnvironmentBlock(pEnvironment);
		CloseHandle(userToken);
		if(ProcessInformation->hThread)
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
		typedef NTSTATUS(NTAPI*_RtlCreateUserThread)(HANDLE Process, PSECURITY_DESCRIPTOR ThreadSecurityDescriptor, BOOLEAN CreateSuspended, ULONG_PTR ZeroBits, SIZE_T MaximumStackSize, SIZE_T CommittedStackSize, PVOID StartAddress, PVOID Parameter, PHANDLE Thread, PCLIENT_ID ClientId);
		static _RtlCreateUserThread RtlCreateUserThread = reinterpret_cast<_RtlCreateUserThread>(GetProcAddress(GetModuleHandle("ntdll.dll"),"RtlCreateUserThread"));
		
		struct HANDLE_IN
		{
			HANDLE hObject;
			BOOL PStatus;
			BOOL IStatus;
			PVOID Function;
		};

#ifdef _WIN64
		static BYTE WThread[] = { 0xC, 0xC7, 0xA8, 0x6C, 0x4B, 0xF2, 0x5, 0x4C, 0x8, 0xC9, 0x0, 0x60, 0x74, 0x5, 0xFD, 0x46, 0x44, 0x44, 0x44, 0xCC, 0x0, 0x60, 0x75, 0x4B, 0xF2, 0x5, 0x48, 0x8, 0xCF, 0x95, 0xC, 0xCF, 0x4D, 0xCC, 0x0, 0x60, 0x74, 0x5, 0xC9, 0x15, 0x46, 0x5, 0xBB, 0x16, 0x54, 0x77, 0x8D, 0xC1, 0x84, 0x4B, 0xD0, 0x85, 0xCF, 0x85, 0xC, 0xC7, 0x80, 0x6C, 0x87}; 
#elif _WIN32
		static BYTE WThread[] = { 0x11, 0xCF, 0xA8, 0xCF, 0x9, 0x4C, 0x2E, 0x46, 0x4B, 0xF2, 0x5, 0x40, 0xCC, 0x1, 0x4D, 0x4B, 0xF2, 0x5, 0x4C, 0xCC, 0x1, 0x4C, 0xC9, 0x1, 0x4C, 0x14, 0xCF, 0x5, 0x48, 0x2E, 0x40, 0xBB, 0x75, 0xBB, 0x94, 0xB3, 0x9C, 0x5F, 0x84, 0x4, 0x19, 0x86, 0x40, 0x44 };
#endif
		
		BOOL Is64 = false, Status = true;
		HANDLE_IN Args = { 0,0,0,0 };
		LPVOID lpThread = nullptr, lpArg = nullptr;
		HANDLE hProcess = Process->GetHandle(), hThread = 0;
		int ThreadSize = _countof(WThread);

		if (!RtlCreateUserThread || hProcess == INVALID_HANDLE_VALUE)
		{
			Status = false;
			goto EXIT;
		}

		if (!Process->Is64(&Is64))
		{
			Status = false;
			goto EXIT;
		}

#ifdef _WIN64
		if (!Is64)
		{
			Status = false;
			goto EXIT;
		}
#elif _WIN32
		if (Is64)
		{
			Status = false;
			goto EXIT;
		}
#endif

		lpThread = VirtualAllocEx(hProcess, 0, ThreadSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (lpThread == nullptr)
		{
			Status = false;
			goto EXIT;
		}

		lpArg = VirtualAllocEx(hProcess, 0, sizeof(HANDLE_IN), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (lpArg == nullptr)
		{
			Status = false;
			goto EXIT;
		}

		Args.Function = reinterpret_cast<PVOID>(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtSetInformationObject"));

		if (!Args.Function)
		{
			Status = false;
			goto EXIT;
		}

		Args.hObject = hObject;
		Args.PStatus = Protect;
		Args.IStatus = Inherit;

		for (int i = 0;i < ThreadSize;i++)
			WThread[i] ^= 0x44;

		if (!WriteProcessMemory(hProcess, lpThread, reinterpret_cast<LPCVOID>(WThread), ThreadSize, 0) ||
			!WriteProcessMemory(hProcess, lpArg, reinterpret_cast<LPCVOID>(&Args), sizeof(HANDLE_IN), 0))
		{
			for (int i = 0;i < ThreadSize;i++)
				WThread[i] ^= 0x44;
			Status = false;
			goto EXIT;
		}

		for (int i = 0;i < ThreadSize;i++)
			WThread[i] ^= 0x44;

		if (RtlCreateUserThread(hProcess, 0, 0, 0, 0, 0, reinterpret_cast<PVOID>(lpThread), lpArg, &hThread, 0))
		{
			Status = false;
			goto EXIT;
		}
		WaitForSingleObject(hThread, INFINITE);
	EXIT:
		if(hThread)
			CloseHandle(hThread);
		if(lpThread)
		VirtualFreeEx(hProcess, lpThread, ThreadSize, MEM_RELEASE);
		if(lpArg)
		VirtualFreeEx(hProcess, lpArg, sizeof(HANDLE_IN), MEM_RELEASE);
		return Status;
	}
	std::vector<HANDLE_INFO> ServiceEnumHandles(ULONG ProcessId, DWORD dwDesiredAccess)
	{
		typedef NTSTATUS(NTAPI*_NtQuerySystemInformation)(ULONG, PVOID, ULONG, PULONG);
		static _NtQuerySystemInformation NtQuerySystemInformation = reinterpret_cast<_NtQuerySystemInformation>(GetProcAddress(GetModuleHandle("ntdll.dll"),"NtQuerySystemInformation"));

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
		ULONG bufferSize = 0;
		std::vector<HANDLE_INFO> handlelist;
		HANDLE ProcessHandle = 0, ProcessCopy = 0;
		HANDLE_INFO hi = { 0,0 };

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
					ProcessHandle = OpenProcess(PROCESS_DUP_HANDLE, false, handle->ProcessId);
					if (DuplicateHandle(ProcessHandle, reinterpret_cast<HANDLE>(handle->Handle), GetCurrentProcess(), &ProcessCopy, PROCESS_QUERY_INFORMATION, 0, 0))
					{
						if (GetProcessId(ProcessCopy) == ProcessId)
						{
							if ((handle->GrantedAccess & dwDesiredAccess) == dwDesiredAccess)
							{
								hi.dwPid = handle->ProcessId;
								hi.hProcess = reinterpret_cast<HANDLE>(handle->Handle);
								handlelist.push_back(hi);
							}
						}
					}
					if (ProcessHandle)
						CloseHandle(ProcessHandle);
					if (ProcessCopy)
						CloseHandle(ProcessCopy);
				}
				break;
			}
		} while (true);
	EXIT:
		if (buffer != NULL)
			VirtualFree(buffer, bufferSize, MEM_DECOMMIT);
		return handlelist;
	}
}
