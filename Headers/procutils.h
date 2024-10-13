#pragma once

#include "natives.h"
#include "syscalls.h"
#include "External/obfuscate.h"

extern "C" PVOID GetPebAddress(); // GEt the address of the current processes PEB.

namespace ProcessUtilities
{

	/*
		Commonly used WINAPI function pointers types within
		internal process utility functions. For example,
		getting the Windows Service Control Manager.
 	*/
	namespace PPROCFN
	{
		typedef NTSTATUS  (WINAPI *_NtQueryInfo)( HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG );
		typedef NTSTATUS  (WINAPI *_NtOpenProcessToken)( HANDLE, ACCESS_MASK, PHANDLE );
		typedef NTSTATUS  (WINAPI *_NtDuplicateToken)( HANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, BOOLEAN, TOKEN_TYPE, PHANDLE );
		typedef NTSTATUS  (WINAPI *_LdrLoadDll)( PWCHAR, ULONG, PUNICODE_STRING, PHANDLE );
		typedef BOOL      (WINAPI *_FreeLibrary)( HANDLE );
		typedef BOOL      (WINAPI *_ImpersonateLoggedOnUser)( HANDLE );
		typedef HANDLE    (WINAPI *_CreateToolhelp32Snapshot)( DWORD, DWORD );
		typedef SC_HANDLE (WINAPI *_OpenServiceA)( SC_HANDLE, LPCSTR, DWORD );
		typedef SC_HANDLE (WINAPI *_OpenSCManagerW)( LPCWSTR, LPCWSTR, DWORD );
		typedef BOOL      (WINAPI *_QueryServiceStatusEx)( SC_HANDLE, SC_STATUS_TYPE, LPBYTE, DWORD, LPDWORD );
		typedef BOOL      (WINAPI *_StartService)( SC_HANDLE, DWORD, LPCWSTR );
		typedef BOOL      (WINAPI *_CreateProcessWithTokenW)( HANDLE, DWORD, LPCWSTR, LPWSTR, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION );
		typedef BOOL	  (WINAPI *_Process32FirstW)( HANDLE, LPPROCESSENTRY32W );
		typedef BOOL      (WINAPI *_Process32NextW)( HANDLE, LPPROCESSENTRY32W );
		typedef HMODULE	  (WINAPI *_LoadLibrary)( LPCSTR );
		typedef BOOL	  (WINAPI *_SetThreadToken)( PHANDLE, HANDLE );
		typedef BOOL	  (WINAPI *_GetComputerNameA)( LPSTR, LPDWORD );
	}
	
	// Frequently loaded and used dll names.
	namespace freqDLLS
	{
		static const std::string kernel32 = std::string(HIDE("kernel32.dll"));
		static const std::string ntdll    = std::string(HIDE("ntdll.dll"));
		static const std::string advapi32 = std::string(HIDE("advapi32.dll"));
	}

	inline ProcessUtilities::PPROCFN::_SetThreadToken _SetThreadToken = nullptr;

	// 'constructors and destructors'
	BOOL               Init(); // Load frequently used dlls for the future. Load important function pointers.
	BOOL               Clean(); // Free all loaded libraries.

	static std::string _lower(std::string inp); // Convert input string to all lowercase.
	static BOOL        _sub(std::string libPath, std::string s2); // check if s2 is in libPath. Used to find if DLL name is in path
	FARPROC            _GetFuncAddress(HMODULE lib, std::string procedure); // Get a function pointer to an export function 'procedure' located in 'lib'

	std::string        PWSTRToString(PWSTR inp); // convert wide character string to std::string
	HMODULE            GetModHandle(std::string libName); // Get the handle of a dll 'libname'
	HMODULE            GetLoadedLib(std::string libName); // Return a handle of an already loaded dll from 'loadedDlls'
	BOOL               FreeUsedLibrary(std::string lib); // Free a loaded library 'lib'
	DWORD              PIDFromName(const char* name); // Get the process ID from a process name.
	HANDLE			   ImpersonateWithToken(HANDLE token);
	HANDLE             CreateProcessAccessToken(DWORD processID); // Duplicate a process security token from the process id
	void               HaltProcessExecution(); // Delay the current processes execution forever.
	DWORD              StartWindowsService(std::string serviceName); // Start a Windows service 'serviceName'—return process id.
	HANDLE             GetSystemToken(); // Get a SYSTEM permissions security token from winlogon.exe.
	HANDLE			   GetTrustedInstallerToken(); // Obtain a Trusted Installer security token.
	BOOL               CheckNoDebugger(); // Check if the current process is being debugged.

	// Wrapper that uses function pointer for CreateProcessWithTokenW
	BOOL OpenProcessAsImposter(
		HANDLE token,
		DWORD dwLogonFlags,
		LPCWSTR lpApplicationName,
		LPWSTR lpCommandLine,
		DWORD dwCreationFlags,
		LPVOID lpEnvironment,
		LPCWSTR lpCurrentDirectory,
		LPSTARTUPINFOW lpStartupInfo,
		LPPROCESS_INFORMATION lpProcessInformation
	);

	// Get the address of a function and cast it to a function pointer type.
	template <typename fpType>
	inline fpType GetFunctionAddress(HMODULE lib, std::string proc) {
		return reinterpret_cast< fpType >( _GetFuncAddress(lib, proc) );
	}
}