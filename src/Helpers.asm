.code

GetPebAddress PROC
    mov rax, gs:[60h]
    ret
GetPebAddress ENDP

END 