#pragma once

#include "CProcess.hpp"
#include "Includes.hpp"

namespace Service
{

	struct HANDLE_INFO
	{
		DWORD dwPid;
		HANDLE hProcess;
		HANDLE_INFO() : dwPid(0), hProcess(0) {}
		HANDLE_INFO(DWORD dwPid, HANDLE hProcess) : dwPid(dwPid), hProcess(hProcess){}
	};

	HANDLE WINAPI ServiceRunProgram(LPCSTR lpFilename, LPCSTR lpArguments, LPCSTR lpDir, LPPROCESS_INFORMATION ProcessInformation, BOOL Inherit, HANDLE hParent);
	BOOLEAN WINAPI ServiceSetHandleStatus(Process::CProcess* Process, HANDLE hObject, BOOL Protect, BOOL Inherit);
	std::vector<HANDLE_INFO> ServiceEnumHandles(ULONG ProcessId, DWORD dwDesiredAccess = PROCESS_ALL_ACCESS);
}