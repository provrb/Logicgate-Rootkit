#pragma once
#include "framework.h"

extern "C" NTSTATUS SysNtOpenProcess(
	PHANDLE            ProcessHandle,
	ACCESS_MASK        DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PCLIENT_ID         ClientId
);

extern "C" NTSTATUS SysNtClose(
	HANDLE handle
);

extern "C" NTSTATUS SysNtDuplicateToken(
	HANDLE ExistingTokenHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	BOOLEAN EffectiveOnly,
	TOKEN_TYPE Type,
	PHANDLE NewTokenHandle
);

extern "C" NTSTATUS	SysNtOpenProcessTokenEx(
	HANDLE processHandle,
	ACCESS_MASK desiredAccess,
	ULONG handleAttributes,
	PHANDLE tokenHandle
);
