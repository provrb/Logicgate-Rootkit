.data
	_SSN DWORD 0

.code

	SysNtOpenProcess PROC
		mov r10, rcx  ; syscall arguments
		mov eax, 26h		
		syscall       ; invoke
		ret
	SysNtOpenProcess ENDP

	SysNtDuplicateToken PROC
		mov r10, rcx
		mov eax, 42h
		syscall
		ret
	SysNtDuplicateToken ENDP
	
	SysNtClose PROC
		mov r10, rcx
		mov eax, 0Fh
		syscall
		ret
	SysNtClose ENDP

	SysNtOpenProcessTokenEx PROC
		mov r10, rcx
		mov eax, 30h
		syscall
		ret
	SysNtOpenProcessTokenEx ENDP

end