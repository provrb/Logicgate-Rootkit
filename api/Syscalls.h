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

extern "C" NTSTATUS SysNtRevertContainerImpersonation(
    VOID
);

extern "C" NTSTATUS SysNtCreateKey(
    PHANDLE KeyHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    ULONG TitleIndex,
    PUNICODE_STRING Class,
    ULONG CreateOptions,
    PULONG Disposition
);

extern "C" NTSTATUS SysNtAdjustPrivilegesToken(
    HANDLE TokenHandle,
    BOOLEAN DisableAllPrivileges,
    PTOKEN_PRIVILEGES NewState,
    ULONG BufferLength,
    PTOKEN_PRIVILEGES PreviousState,
    PULONG ReturnLength
);

extern "C" NTSTATUS SysNtSetValueKey(
    HANDLE          KeyHandle,
    PUNICODE_STRING ValueName,
    ULONG           TitleIndex,
    ULONG           Type,
    PVOID           Data,
    ULONG           DataSize
);

extern "C" NTSTATUS SysNtDelayExecution(
    BOOLEAN Alertable,
    PLARGE_INTEGER DelayInterval
);

extern "C" NTSTATUS SysNtShutdownSystem(
    SHUTDOWN_ACTION action
);

extern "C" NTSTATUS SysNtReadFile(
    HANDLE FileHandle,
    HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID Buffer,
    ULONG Length,
    PLARGE_INTEGER ByteOffset,
    PULONG Key
);

extern "C" NTSTATUS SysNtCreateNamedPipeFile(
    PHANDLE            FileHandle,
    ULONG              DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK   IoStatusBlock,
    ULONG              ShareAccess,
    ULONG              CreateDisposition,
    ULONG              CreateOptions,
    ULONG              NamedPipeType,
    ULONG              ReadMode,
    ULONG              CompletionMode,
    ULONG              MaximumInstances,
    ULONG              InboundQuota,
    ULONG              OutboundQuota,
    PLARGE_INTEGER     DefaultTimeout
);