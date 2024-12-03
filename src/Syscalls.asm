.data
    _SSN DWORD 0

.code
    InsertSyscall PROC
        mov [_SSN], ecx
        ret
    InsertSyscall ENDP

    SysNtOpenProcess PROC
        mov r10, rcx
        mov eax, [_SSN]        
        syscall       
        ret
    SysNtOpenProcess ENDP

    SysNtDuplicateToken PROC
        mov r10, rcx
        mov eax, [_SSN]
        syscall
        ret
    SysNtDuplicateToken ENDP
    
    SysNtClose PROC
        mov r10, rcx
        mov eax, [_SSN]
        syscall
        ret
    SysNtClose ENDP

    SysNtQueryValueKey PROC
        mov r10, rcx
        mov eax, [_SSN]
        syscall
        ret
    SysNtQueryValueKey ENDP

    SysNtOpenKey PROC
        mov r10, rcx
        mov eax, [_SSN]
        syscall
        ret
    SysNtOpenKey ENDP

    SysNtOpenProcessTokenEx PROC
        mov r10, rcx
        mov eax, [_SSN]
        syscall
        ret
    SysNtOpenProcessTokenEx ENDP

    SysRtlAdjustPrivilege PROC
        mov r10, rcx
        mov eax, [_SSN]
        syscall
        ret
    SysRtlAdjustPrivilege ENDP

    SysNtRaiseHardError PROC
        mov r10, rcx
        mov eax, [_SSN]
        syscall
        ret
    SysNtRaiseHardError ENDP

    SysNtRevertContainerImpersonation PROC
        mov eax, [_SSN]
        syscall
        ret
    SysNtRevertContainerImpersonation ENDP

    SysNtCreateKey PROC
        mov r10, rcx
        mov eax, [_SSN]
        syscall
        ret
    SysNtCreateKey ENDP

    SysNtSetValueKey PROC
        mov r10, rcx
        mov eax, [_SSN]
        syscall
        ret
    SysNtSetValueKey ENDP

    SysNtDelayExecution PROC
        mov r10, rcx
        mov eax, [_SSN]
        syscall
        ret
    SysNtDelayExecution ENDP

    SysNtAdjustPrivilegesToken PROC
        mov r10, rcx
        mov eax, [_SSN]
        syscall
        ret
    SysNtAdjustPrivilegesToken ENDP

    SysNtShutdownSystem PROC
        mov r10, rcx
        mov eax, [_SSN]
        syscall
        ret
    SysNtShutdownSystem ENDP

    SysNtReadFile PROC
        mov r10, rcx
        mov eax, [_SSN]
        syscall
        ret
    SysNtReadFile ENDP
end
