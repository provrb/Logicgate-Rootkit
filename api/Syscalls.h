#pragma once

extern "C" NTSTATUS SysNtOpenProcess(
    PHANDLE            ProcessHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID         ClientId
);

extern "C" NTSTATUS SysNtClose(
    HANDLE handle
);

extern "C" NTSTATUS SysNtOpenKey(
    PHANDLE KeyHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes
);

extern "C" NTSTATUS SysNtQueryValueKey(
    HANDLE KeyHandle,
    PUNICODE_STRING ValueName,
    KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
    PVOID KeyValueInformation,
    ULONG Length,
    PULONG ResultLength
);

extern "C" NTSTATUS SysNtDuplicateToken(
    HANDLE ExistingTokenHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    BOOLEAN EffectiveOnly,
    TOKEN_TYPE Type,
    PHANDLE NewTokenHandle
);

extern "C" NTSTATUS SysNtOpenProcessTokenEx(
    HANDLE processHandle,
    ACCESS_MASK desiredAccess,
    ULONG handleAttributes,
    PHANDLE tokenHandle
);

extern "C" NTSTATUS SysRtlAdjustPrivilege(
    ULONG, 
    BOOLEAN,
    BOOLEAN,
    PBOOLEAN
);

extern "C" NTSTATUS SysNtRaiseHardError(
    NTSTATUS,
    ULONG,
    ULONG,
    PULONG_PTR,
    ULONG,
    PULONG
);
