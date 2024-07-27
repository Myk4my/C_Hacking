BITS 32
; execve(const char *file, char *const argv[], char *const envp[])

	xor eax, eax
	push eax
	push 0x68737a2f
	push 0x6e69622f
	mov ebx, esp
	push eax
	mov edx, esp
	push ecx
	mov edx, esp
	mov al, 11
	int 0x80