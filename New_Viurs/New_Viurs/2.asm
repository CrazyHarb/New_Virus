.386
.model flat,stdcall
option casemap:none

include windows.inc
include  Macro.inc


.code


CODE_START   equ    this byte
    lpLoadLibrary     dd      0
    lpGetProcAddress  dd      0
	_CodeThread    proc
	    jmp @F
		    lpdll    db   "user32.dll",0
			lpAPI    db   "MessageBoxA",0
		@@:
	        call @F
		@@:
		    pop  ebx
			sub  ebx,offset @B
			mov  eax,offset lpdll
	        add  eax,ebx
			_invoke [ebx + lpLoadLibrary],eax
			mov  esi,eax
			mov  eax,offset lpAPI
			add  eax,ebx
			_invoke [ebx + lpGetProcAddress],esi,eax
			mov  esi,eax
			mov  [eax],eax
			_invoke esi,NULL,NULL,NULL,NULL
			ret
	_CodeThread   endp
	
CODE_END    equ   this byte

CODE_LENGTH  equ  offset CODE_END - offset CODE_START

end