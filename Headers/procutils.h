#ifndef _PROCUTILS_
#define _PROCUTILS_

#include "datatypes.h"
#include "syscalls.h"
#include "obfuscate.h"

extern "C" PVOID GetPebAddress();

namespace ProcessUtilities
{
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
	}
	
	namespace freqDLLS 
	{
		static const std::string kernel32 = std::string(HIDE("kernel32.dll"));	
		static const std::string ntdll    = std::string(HIDE("ntdll.dll"));
		static const std::string advapi32 = std::string(HIDE("advapi32.dll"));
	}

	BOOL               Clean();
	BOOL               Init();

	static std::string _lower(std::string inp);
	static BOOL        _sub(std::string libPath, std::string s2);
	FARPROC            _GetFuncAddress(HMODULE lib, std::string procedure);
	
	std::string        PWSTRToString(PWSTR inp);
	HMODULE            GetModHandle(std::string libName);
	HMODULE            GetLoadedLib(std::string libName);
	BOOL               FreeUsedLibrary(std::string lib);
	DWORD              PIDFromName(const char* name);
	HANDLE             CreateProcessAccessToken(DWORD processID);
	void               HaltProcessExecution();
	DWORD              StartWindowsService(std::string serviceName);
	HANDLE             GetSystemToken();
	BOOL               CheckNoDebugger();

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

	template <typename fpType>
	fpType GetFunctionAddress(HMODULE lib, std::string proc) {
		return reinterpret_cast< fpType >( _GetFuncAddress(lib, proc) );
	}
}

#endif