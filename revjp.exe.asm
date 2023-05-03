; ---------------------------------------------------------------------------

GUID            struc ; (sizeof=0x10, align=0x4, copyof_2)
                                        ; XREF: .rdata:00797738/r
Data1           dd ?
Data2           dw ?
Data3           dw ?
Data4           db 8 dup(?)
GUID            ends

; ---------------------------------------------------------------------------

FuncInfo        struc ; (sizeof=0x24, mappedto_5)
                                        ; XREF: .rdata:stru_797A80/r
                                        ; .rdata:stru_797AAC/r ...
magicNumber     dd ?                    ; base 16
maxState        dd ?                    ; base 10
pUnwindMap      dd ?                    ; offset
nTryBlocks      dd ?                    ; base 10
pTryBlockMap    dd ?                    ; offset
nIPMapEntries   dd ?                    ; base 10
pIPtoStateMap   dd ?                    ; offset
pESTypeList     dd ?                    ; offset
EHFlags         dd ?                    ; base 16
FuncInfo        ends

; ---------------------------------------------------------------------------

UnwindMapEntry  struc ; (sizeof=0x8, mappedto_6)
                                        ; XREF: .rdata:stru_797AA4/r
                                        ; .rdata:stru_797AF4/r ...
toState         dd ?                    ; base 10
action          dd ?                    ; offset
UnwindMapEntry  ends

; ---------------------------------------------------------------------------

TryBlockMapEntry struc ; (sizeof=0x14, mappedto_7)
                                        ; XREF: .rdata:stru_797C50/r
                                        ; .rdata:stru_797CA8/r
tryLow          dd ?                    ; base 10
tryHigh         dd ?                    ; base 10
catchHigh       dd ?                    ; base 10
nCatches        dd ?                    ; base 10
pHandlerArray   dd ?                    ; offset
TryBlockMapEntry ends

; ---------------------------------------------------------------------------

HandlerType     struc ; (sizeof=0x10, mappedto_8)
                                        ; XREF: .rdata:stru_797C64/r
                                        ; .rdata:stru_797CBC/r
adjectives      dd ?                    ; base 16
pType           dd ?                    ; offset
dispCatchObj    dd ?                    ; base 10
addressOfHandler dd ?                   ; offset
HandlerType     ends

; ---------------------------------------------------------------------------

_EH4_SCOPETABLE struc ; (sizeof=0x10, align=0x4, copyof_10, variable size)
                                        ; XREF: .rdata:stru_797D50/r
                                        ; .rdata:stru_797D70/r
GSCookieOffset  dd ?
GSCookieXOROffset dd ?
EHCookieOffset  dd ?
EHCookieXOROffset dd ?
ScopeRecord     _EH4_SCOPETABLE_RECORD 0 dup(?)
_EH4_SCOPETABLE ends

; ---------------------------------------------------------------------------

_EH4_SCOPETABLE_RECORD struc ; (sizeof=0xC, align=0x4, copyof_9)
                                        ; XREF: _EH4_SCOPETABLE/r
EnclosingLevel  dd ?
FilterFunc      dd ?                    ; offset
HandlerFunc     dd ?                    ; offset
_EH4_SCOPETABLE_RECORD ends

; ---------------------------------------------------------------------------

CPPEH_RECORD    struc ; (sizeof=0x18, align=0x4, copyof_15)
                                        ; XREF: ___scrt_is_nonwritable_in_current_image/r
                                        ; ?__scrt_common_main_seh@@YAHXZ/r
old_esp         dd ?                    ; XREF: ___scrt_is_nonwritable_in_current_image:loc_79526F/r
                                        ; __scrt_common_main_seh(void):loc_795543/r
exc_ptr         dd ?                    ; XREF: ___scrt_is_nonwritable_in_current_image:loc_79525C/r
                                        ; __scrt_common_main_seh(void):loc_79552F/r ; offset
registration    _EH3_EXCEPTION_REGISTRATION ?
                                        ; XREF: ___scrt_is_nonwritable_in_current_image+C/w
                                        ; ___scrt_is_nonwritable_in_current_image+5A/w ...
CPPEH_RECORD    ends

; ---------------------------------------------------------------------------

_EH3_EXCEPTION_REGISTRATION struc ; (sizeof=0x10, align=0x4, copyof_12)
                                        ; XREF: CPPEH_RECORD/r
Next            dd ?                    ; XREF: ___scrt_is_nonwritable_in_current_image:loc_79527B/r
                                        ; __scrt_common_main_seh(void):loc_795564/r ; offset
ExceptionHandler dd ?                   ; offset
ScopeTable      dd ?                    ; offset
TryLevel        dd ?                    ; XREF: ___scrt_is_nonwritable_in_current_image+C/w
                                        ; ___scrt_is_nonwritable_in_current_image+5A/w ...
_EH3_EXCEPTION_REGISTRATION ends

; ---------------------------------------------------------------------------

_ThrowInfo      struc ; (sizeof=0x10, align=0x4, copyof_16)
attributes      dd ?
pmfnUnwind      dd ?                    ; offset
pForwardCompat  dd ?                    ; offset
pCatchableTypeArray dd ?                ; offset
_ThrowInfo      ends

; ---------------------------------------------------------------------------

xtime           struc ; (sizeof=0x10, align=0x8, copyof_26)
                                        ; XREF: sub_793230/r
sec             dq ?
nsec            dd ?
                db ? ; undefined
                db ? ; undefined
                db ? ; undefined
                db ? ; undefined
xtime           ends

; ---------------------------------------------------------------------------

_onexit_table_t struc ; (sizeof=0xC, align=0x4, copyof_28)
                                        ; XREF: .data:Table/r
                                        ; .data:stru_7990D8/r
_first          dd ?                    ; XREF: ___scrt_initialize_onexit_tables+4F/w
                                        ; ___scrt_initialize_onexit_tables+61/w ... ; offset
_last           dd ?                    ; XREF: ___scrt_initialize_onexit_tables+55/w
                                        ; ___scrt_initialize_onexit_tables+67/w ; offset
_end            dd ?                    ; XREF: ___scrt_initialize_onexit_tables+5B/w
                                        ; ___scrt_initialize_onexit_tables+6D/w ; offset
_onexit_table_t ends

; ---------------------------------------------------------------------------

_EXCEPTION_POINTERS struc ; (sizeof=0x8, align=0x4, copyof_30)
                                        ; XREF: .rdata:ExceptionInfo/r
                                        ; ___scrt_fastfail/r
ExceptionRecord dd ?                    ; XREF: ___scrt_fastfail+E7/w ; offset
ContextRecord   dd ?                    ; XREF: ___scrt_fastfail+F2/w ; offset
_EXCEPTION_POINTERS ends

; ---------------------------------------------------------------------------

_FILETIME       struc ; (sizeof=0x8, align=0x4, copyof_43)
                                        ; XREF: ___get_entropy/r
dwLowDateTime   dd ?                    ; XREF: ___get_entropy+6/w
                                        ; ___get_entropy+1B/r
dwHighDateTime  dd ?                    ; XREF: ___get_entropy+D/w
                                        ; ___get_entropy+18/r
_FILETIME       ends

; ---------------------------------------------------------------------------

LARGE_INTEGER   union ; (sizeof=0x8, align=0x8, copyof_44)
                                        ; XREF: ___get_entropy+3D/r
                                        ; ___get_entropy+43/r ...
anonymous_0     _LARGE_INTEGER::$837407842DC9087486FDFA5FEB63B74E ?
u               _LARGE_INTEGER::$837407842DC9087486FDFA5FEB63B74E ?
QuadPart        dq ?
LARGE_INTEGER   ends

; ---------------------------------------------------------------------------

_LARGE_INTEGER::$837407842DC9087486FDFA5FEB63B74E struc ; (sizeof=0x8, align=0x4, copyof_46)
                                        ; XREF: LARGE_INTEGER/r
                                        ; LARGE_INTEGER/r
LowPart         dd ?
HighPart        dd ?
_LARGE_INTEGER::$837407842DC9087486FDFA5FEB63B74E ends

; ---------------------------------------------------------------------------

_SLIST_HEADER   union ; (sizeof=0x8, align=0x8, copyof_49)
                                        ; XREF: .data:ListHead/r
Alignment       dq ?
anonymous_0     _SLIST_HEADER::$B36A5591D671C64BFB448D01F8D237E7 ?
_SLIST_HEADER   ends

; ---------------------------------------------------------------------------

_SLIST_HEADER::$04C3B4B3818F1694974352AE64BF5082 struc ; (sizeof=0x8, align=0x4, copyof_51)
Next            SLIST_ENTRY ?
Depth           dw ?
CpuId           dw ?
_SLIST_HEADER::$04C3B4B3818F1694974352AE64BF5082 ends

; ---------------------------------------------------------------------------

SLIST_ENTRY     struc ; (sizeof=0x4, align=0x4, copyof_52)
                                        ; XREF: _SLIST_HEADER::$04C3B4B3818F1694974352AE64BF5082/r
                                        ; _SLIST_HEADER::$B36A5591D671C64BFB448D01F8D237E7/r
Next            dd ?                    ; offset
SLIST_ENTRY     ends

; ---------------------------------------------------------------------------

_SLIST_HEADER::$B36A5591D671C64BFB448D01F8D237E7 struc ; (sizeof=0x8, align=0x4, copyof_62)
                                        ; XREF: _SLIST_HEADER/r
Next            SLIST_ENTRY ?
Depth           dw ?
CpuId           dw ?
_SLIST_HEADER::$B36A5591D671C64BFB448D01F8D237E7 ends

; ---------------------------------------------------------------------------

; enum __TI_flags, copyof_3, bitfield
TI_IsConst       = 1
TI_IsVolatile    = 2
TI_IsUnaligned   = 4
TI_IsPure        = 8
TI_IsWinRT       = 10h

; ---------------------------------------------------------------------------

; enum __CT_flags, copyof_4, bitfield
CT_IsSimpleType  = 1
CT_ByReferenceOnly  = 2
CT_HasVirtualBase  = 4
CT_IsWinRTHandle  = 8
CT_IsStdBadAlloc  = 10h                 ; XREF: .rdata:__CT??_R0?AVbad_alloc@std@@@8_40156F/s

; ---------------------------------------------------------------------------

; enum _crt_argv_mode, copyof_55
_crt_argv_no_arguments  = 0
_crt_argv_unexpanded_arguments  = 1
_crt_argv_expanded_arguments  = 2

; ---------------------------------------------------------------------------

; enum _crt_app_type, copyof_56
_crt_unknown_app  = 0
_crt_console_app  = 1
_crt_gui_app     = 2
                .686p
                .mmx
                .model flat

; ===========================================================================

; Segment type: Pure code
; Segment permissions: Read/Execute
_text           segment para public 'CODE' use32
                assume cs:_text
                ;org 791000h
                assume es:nothing, ss:nothing, ds:_data, fs:nothing, gs:nothing

; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int sub_791000()
sub_791000      proc near               ; DATA XREF: .rdata:00797160↓o

var_24          = byte ptr -24h
var_C           = dword ptr -0Ch
var_4           = dword ptr -4

; FUNCTION CHUNK AT 007964E2 SIZE 00000008 BYTES
; FUNCTION CHUNK AT 007964EF SIZE 0000000C BYTES

; __unwind { // SEH_401000
                push    ebp
                mov     ebp, esp
                push    0FFFFFFFFh
                push    offset SEH_401000
                mov     eax, large fs:0
                push    eax
                mov     large fs:0, esp
                sub     esp, 18h
                push    offset aHttpsDiscordGg ; "https://discord.gg/fmhw85T5zM"
                lea     ecx, [ebp+var_24]
                call    sub_7920BA
;   try {
                and     [ebp+var_4], 0
                lea     eax, [ebp+var_24]
                push    eax
                mov     ecx, offset dword_79944C
                call    sub_7918BC
;   } // starts at 791028
                or      [ebp+var_4], 0FFFFFFFFh
                lea     ecx, [ebp+var_24]
                call    Process_Input
                push    offset sub_796612 ; void (__cdecl *)()
                call    _atexit
                pop     ecx
                mov     ecx, [ebp+var_C]
                mov     large fs:0, ecx
                leave
                retn
; } // starts at 791000
sub_791000      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int sub_79105D()
sub_79105D      proc near               ; DATA XREF: .rdata:00797164↓o

var_24          = byte ptr -24h
var_C           = dword ptr -0Ch
var_4           = dword ptr -4

; FUNCTION CHUNK AT 007964E2 SIZE 00000008 BYTES
; FUNCTION CHUNK AT 007964EF SIZE 0000000C BYTES

; __unwind { // SEH_401000
                push    ebp
                mov     ebp, esp
                push    0FFFFFFFFh
                push    offset SEH_401000
                mov     eax, large fs:0
                push    eax
                mov     large fs:0, esp
                sub     esp, 18h
                push    offset aV1rtu4lall0c ; "V1rtu4lAll0c"
                lea     ecx, [ebp+var_24]
                call    sub_7920BA
;   try {
                and     [ebp+var_4], 0
                lea     eax, [ebp+var_24]
                push    eax
                mov     ecx, offset dword_799458
                call    sub_7918BC
;   } // starts at 791085
                or      [ebp+var_4], 0FFFFFFFFh
                lea     ecx, [ebp+var_24]
                call    Process_Input
                push    offset sub_796621 ; void (__cdecl *)()
                call    _atexit
                pop     ecx
                mov     ecx, [ebp+var_C]
                mov     large fs:0, ecx
                leave
                retn
; } // starts at 79105D
sub_79105D      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int sub_7910BA()
sub_7910BA      proc near               ; DATA XREF: .rdata:00797168↓o

var_24          = byte ptr -24h
var_C           = dword ptr -0Ch
var_4           = dword ptr -4

; FUNCTION CHUNK AT 007964E2 SIZE 00000008 BYTES
; FUNCTION CHUNK AT 007964EF SIZE 0000000C BYTES

; __unwind { // SEH_401000
                push    ebp
                mov     ebp, esp
                push    0FFFFFFFFh
                push    offset SEH_401000
                mov     eax, large fs:0
                push    eax
                mov     large fs:0, esp
                sub     esp, 18h
                push    offset aJpofwejfdslfkj ; "jpofwejfdslfkjdslkfghiphap332oiu"
                lea     ecx, [ebp+var_24]
                call    sub_7920BA
;   try {
                and     [ebp+var_4], 0
                lea     eax, [ebp+var_24]
                push    eax
                mov     ecx, offset dword_7994A0
                call    sub_7918BC
;   } // starts at 7910E2
                or      [ebp+var_4], 0FFFFFFFFh
                lea     ecx, [ebp+var_24]
                call    Process_Input
                push    offset sub_796630 ; void (__cdecl *)()
                call    _atexit
                pop     ecx
                mov     ecx, [ebp+var_C]
                mov     large fs:0, ecx
                leave
                retn
; } // starts at 7910BA
sub_7910BA      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int sub_791117()
sub_791117      proc near               ; DATA XREF: .rdata:0079716C↓o

var_24          = byte ptr -24h
var_C           = dword ptr -0Ch
var_4           = dword ptr -4

; FUNCTION CHUNK AT 007964E2 SIZE 00000008 BYTES
; FUNCTION CHUNK AT 007964EF SIZE 0000000C BYTES

; __unwind { // SEH_401000
                push    ebp
                mov     ebp, esp
                push    0FFFFFFFFh
                push    offset SEH_401000
                mov     eax, large fs:0
                push    eax
                mov     large fs:0, esp
                sub     esp, 18h
                push    offset aOhu3mndslwoxfe ; "Ohu3mNdslwoxfedlo34"
                lea     ecx, [ebp+var_24]
                call    sub_7920BA
;   try {
                and     [ebp+var_4], 0
                lea     eax, [ebp+var_24]
                push    eax
                mov     ecx, offset dword_799440
                call    sub_7918BC
;   } // starts at 79113F
                or      [ebp+var_4], 0FFFFFFFFh
                lea     ecx, [ebp+var_24]
                call    Process_Input
                push    offset sub_79663F ; void (__cdecl *)()
                call    _atexit
                pop     ecx
                mov     ecx, [ebp+var_C]
                mov     large fs:0, ecx
                leave
                retn
; } // starts at 791117
sub_791117      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int sub_791174()
sub_791174      proc near               ; DATA XREF: .rdata:00797170↓o

var_24          = byte ptr -24h
var_C           = dword ptr -0Ch
var_4           = dword ptr -4

; FUNCTION CHUNK AT 007964E2 SIZE 00000008 BYTES
; FUNCTION CHUNK AT 007964EF SIZE 0000000C BYTES

; __unwind { // SEH_401000
                push    ebp
                mov     ebp, esp
                push    0FFFFFFFFh
                push    offset SEH_401000
                mov     eax, large fs:0
                push    eax
                mov     large fs:0, esp
                sub     esp, 18h
                push    offset a2Mk43xxy01k ; "2-mk43xxy0.1k"
                lea     ecx, [ebp+var_24]
                call    sub_7920BA
;   try {
                and     [ebp+var_4], 0
                lea     eax, [ebp+var_24]
                push    eax
                mov     ecx, offset dword_799464
                call    sub_7918BC
;   } // starts at 79119C
                or      [ebp+var_4], 0FFFFFFFFh
                lea     ecx, [ebp+var_24]
                call    Process_Input
                push    offset sub_79664E ; void (__cdecl *)()
                call    _atexit
                pop     ecx
                mov     ecx, [ebp+var_C]
                mov     large fs:0, ecx
                leave
                retn
; } // starts at 791174
sub_791174      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int sub_7911D1()
sub_7911D1      proc near               ; DATA XREF: .rdata:00797174↓o

var_24          = byte ptr -24h
var_C           = dword ptr -0Ch
var_4           = dword ptr -4

; FUNCTION CHUNK AT 007964E2 SIZE 00000008 BYTES
; FUNCTION CHUNK AT 007964EF SIZE 0000000C BYTES

; __unwind { // SEH_401000
                push    ebp
                mov     ebp, esp
                push    0FFFFFFFFh
                push    offset SEH_401000
                mov     eax, large fs:0
                push    eax
                mov     large fs:0, esp
                sub     esp, 18h
                push    offset a324265339152 ; ";32;42;65;33;91;52"
                lea     ecx, [ebp+var_24]
                call    sub_7920BA
;   try {
                and     [ebp+var_4], 0
                lea     eax, [ebp+var_24]
                push    eax
                mov     ecx, offset dword_799494
                call    sub_7918BC
;   } // starts at 7911F9
                or      [ebp+var_4], 0FFFFFFFFh
                lea     ecx, [ebp+var_24]
                call    Process_Input
                push    offset sub_79665D ; void (__cdecl *)()
                call    _atexit
                pop     ecx
                mov     ecx, [ebp+var_C]
                mov     large fs:0, ecx
                leave
                retn
; } // starts at 7911D1
sub_7911D1      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int sub_79122E()
sub_79122E      proc near               ; DATA XREF: .rdata:00797178↓o

var_24          = byte ptr -24h
var_C           = dword ptr -0Ch
var_4           = dword ptr -4

; FUNCTION CHUNK AT 007964E2 SIZE 00000008 BYTES
; FUNCTION CHUNK AT 007964EF SIZE 0000000C BYTES

; __unwind { // SEH_401000
                push    ebp
                mov     ebp, esp
                push    0FFFFFFFFh
                push    offset SEH_401000
                mov     eax, large fs:0
                push    eax
                mov     large fs:0, esp
                sub     esp, 18h
                push    offset aSDY9DVk ; "S`=d`Y9{]D}_vK$#."
                lea     ecx, [ebp+var_24]
                call    sub_7920BA
;   try {
                and     [ebp+var_4], 0
                lea     eax, [ebp+var_24]
                push    eax
                mov     ecx, offset dword_799434
                call    sub_7918BC
;   } // starts at 791256
                or      [ebp+var_4], 0FFFFFFFFh
                lea     ecx, [ebp+var_24]
                call    Process_Input
                push    offset sub_79666C ; void (__cdecl *)()
                call    _atexit
                pop     ecx
                mov     ecx, [ebp+var_C]
                mov     large fs:0, ecx
                leave
                retn
; } // starts at 79122E
sub_79122E      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int sub_79128B()
sub_79128B      proc near               ; DATA XREF: .rdata:0079717C↓o

var_24          = byte ptr -24h
var_C           = dword ptr -0Ch
var_4           = dword ptr -4

; FUNCTION CHUNK AT 007964E2 SIZE 00000008 BYTES
; FUNCTION CHUNK AT 007964EF SIZE 0000000C BYTES

; __unwind { // SEH_401000
                push    ebp
                mov     ebp, esp
                push    0FFFFFFFFh
                push    offset SEH_401000
                mov     eax, large fs:0
                push    eax
                mov     large fs:0, esp
                sub     esp, 18h
                push    offset aXxxxxgot75Huh9 ; "xxxxxGot7.5_HUH?98rjoi2r3oifjdsoigfogdf"...
                lea     ecx, [ebp+var_24]
                call    sub_7920BA
;   try {
                and     [ebp+var_4], 0
                lea     eax, [ebp+var_24]
                push    eax
                mov     ecx, offset dword_799488
                call    sub_7918BC
;   } // starts at 7912B3
                or      [ebp+var_4], 0FFFFFFFFh
                lea     ecx, [ebp+var_24]
                call    Process_Input
                push    offset sub_79667B ; void (__cdecl *)()
                call    _atexit
                pop     ecx
                mov     ecx, [ebp+var_C]
                mov     large fs:0, ecx
                leave
                retn
; } // starts at 79128B
sub_79128B      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int sub_7912E8()
sub_7912E8      proc near               ; DATA XREF: .rdata:00797180↓o
                push    ebp
                mov     ebp, esp
                push    offset aH4ndy51mpl30bf ; "H4ndy51mpL30bFusC4tI0NL1bR4RybYM3mB3R_T"...
                mov     ecx, offset dword_799470
                call    sub_7920BA
                push    offset sub_79668A ; void (__cdecl *)()
                call    _atexit
                pop     ecx
                pop     ebp
                retn
sub_7912E8      endp


; =============== S U B R O U T I N E =======================================


; int sub_791307()
sub_791307      proc near               ; DATA XREF: .rdata:0079715C↓o
                push    offset sub_796699 ; void (__cdecl *)()
                call    _atexit
                pop     ecx
                retn
sub_791307      endp

; ---------------------------------------------------------------------------
                align 10h
; [00000008 BYTES: COLLAPSED FUNCTION operator new(uint,void *). PRESS CTRL-NUMPAD+ TO EXPAND]

; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; char sub_791328()
sub_791328      proc near               ; CODE XREF: sub_792565+4↓p
                                        ; sub_7926F2+7↓p
                push    ebp
                mov     ebp, esp
                xor     al, al
                pop     ebp
                retn
sub_791328      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; void *sub_79132F()
sub_79132F      proc near               ; CODE XREF: sub_791339+F↓p
                                        ; ___scrt_initialize_default_local_stdio_options↓p
                push    ebp
                mov     ebp, esp
                mov     eax, offset unk_799428
                pop     ebp
                retn
sub_79132F      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int __cdecl sub_791339(FILE *Stream, char *Format, _locale_t Locale, va_list ArgList)
sub_791339      proc near               ; CODE XREF: printf+29↓p

Stream          = dword ptr  8
Format          = dword ptr  0Ch
Locale          = dword ptr  10h
ArgList         = dword ptr  14h

                push    ebp
                mov     ebp, esp
                push    [ebp+ArgList]   ; ArgList
                push    [ebp+Locale]    ; Locale
                push    [ebp+Format]    ; Format
                push    [ebp+Stream]    ; Stream
                call    sub_79132F
                push    dword ptr [eax+4]
                push    dword ptr [eax] ; Options
                call    ds:__stdio_common_vfprintf
                add     esp, 18h
                pop     ebp
                retn
sub_791339      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int printf(char *, ...)
printf          proc near               ; CODE XREF: sub_7919EF+24↓p
                                        ; _main+2D↓p ...

var_10          = dword ptr -10h
Stream          = dword ptr -0Ch
Format          = dword ptr -8
ArgList         = dword ptr -4
arg_0           = dword ptr  8
arg_4           = byte ptr  0Ch

                push    ebp
                mov     ebp, esp
                sub     esp, 10h
                lea     eax, [ebp+arg_4]
                mov     [ebp+ArgList], eax
                mov     eax, [ebp+arg_0]
                mov     [ebp+Format], eax
                push    1               ; Ix
                call    ds:__acrt_iob_func
                pop     ecx
                mov     [ebp+Stream], eax
                push    [ebp+ArgList]   ; ArgList
                push    0               ; Locale
                push    [ebp+Format]    ; Format
                push    [ebp+Stream]    ; Stream
                call    sub_791339
                add     esp, 10h
                mov     [ebp+var_10], eax
                and     [ebp+ArgList], 0
                mov     eax, [ebp+var_10]
                leave
                retn
printf          endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _DWORD *__thiscall sub_79139A(_DWORD *this, int, int)
sub_79139A      proc near               ; CODE XREF: sub_791473+F↓p
                                        ; sub_791674+11↓p

var_4           = dword ptr -4
arg_0           = dword ptr  8

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+var_4], ecx
                mov     eax, [ebp+var_4]
                mov     dword ptr [eax], offset ??_7exception@std@@6B@ ; const std::exception::`vftable'
                xor     eax, eax
                mov     ecx, [ebp+var_4]
                add     ecx, 4
                mov     [ecx], eax
                mov     [ecx+4], eax
                mov     eax, [ebp+var_4]
                mov     ecx, [ebp+arg_0]
                mov     [eax+4], ecx
                mov     eax, [ebp+var_4]
                leave
                retn    8
sub_79139A      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _DWORD *__thiscall sub_7913C7(_DWORD *this, int)
sub_7913C7      proc near               ; CODE XREF: sub_79156F+D↓p
                                        ; sub_7916B6+D↓p
                                        ; DATA XREF: ...

var_4           = dword ptr -4
arg_0           = dword ptr  8

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+var_4], ecx
                mov     eax, [ebp+var_4]
                mov     dword ptr [eax], offset ??_7exception@std@@6B@ ; const std::exception::`vftable'
                xor     eax, eax
                mov     ecx, [ebp+var_4]
                add     ecx, 4
                mov     [ecx], eax
                mov     [ecx+4], eax
                mov     eax, [ebp+var_4]
                add     eax, 4
                push    eax
                mov     eax, [ebp+arg_0]
                add     eax, 4
                push    eax
                call    ds:__std_exception_copy
                pop     ecx
                pop     ecx
                mov     eax, [ebp+var_4]
                leave
                retn    4
sub_7913C7      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int __thiscall sub_791401(_DWORD *this)
sub_791401      proc near               ; CODE XREF: sub_791449+A↓p
                                        ; sub_7914C1+A↓p

var_4           = dword ptr -4

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+var_4], ecx
                mov     eax, [ebp+var_4]
                mov     dword ptr [eax], offset ??_7exception@std@@6B@ ; const std::exception::`vftable'
                mov     eax, [ebp+var_4]
                add     eax, 4
                push    eax
                call    ds:__std_exception_destroy
                pop     ecx
                leave
                retn
sub_791401      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; const char *__thiscall sub_791421(_DWORD *this)
sub_791421      proc near               ; DATA XREF: .rdata:007971C0↓o
                                        ; .rdata:007971CC↓o ...

var_8           = dword ptr -8
var_4           = dword ptr -4

                push    ebp
                mov     ebp, esp
                push    ecx
                push    ecx
                mov     [ebp+var_4], ecx
                mov     eax, [ebp+var_4]
                cmp     dword ptr [eax+4], 0
                jz      short loc_79143D
                mov     eax, [ebp+var_4]
                mov     eax, [eax+4]
                mov     [ebp+var_8], eax
                jmp     short loc_791444
; ---------------------------------------------------------------------------

loc_79143D:                             ; CODE XREF: sub_791421+F↑j
                mov     [ebp+var_8], offset aUnknownExcepti ; "Unknown exception"

loc_791444:                             ; CODE XREF: sub_791421+1A↑j
                mov     eax, [ebp+var_8]
                leave
                retn
sub_791421      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _DWORD *__thiscall sub_791449(_DWORD *this, char)
sub_791449      proc near               ; DATA XREF: .rdata:const std::exception::`vftable'↓o

Block           = dword ptr -4
arg_0           = dword ptr  8

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+Block], ecx
                mov     ecx, [ebp+Block]
                call    sub_791401
                mov     eax, [ebp+arg_0]
                and     eax, 1
                jz      short loc_79146C
                push    0Ch
                push    [ebp+Block]     ; Block
                call    sub_795312
                pop     ecx
                pop     ecx

loc_79146C:                             ; CODE XREF: sub_791449+15↑j
                mov     eax, [ebp+Block]
                leave
                retn    4
sub_791449      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _DWORD *__thiscall sub_791473(_DWORD *this, int)
sub_791473      proc near               ; CODE XREF: sub_7914D2+F↓p

var_4           = dword ptr -4
arg_0           = dword ptr  8

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+var_4], ecx
                push    1
                push    [ebp+arg_0]
                mov     ecx, [ebp+var_4]
                call    sub_79139A
                mov     eax, [ebp+var_4]
                mov     dword ptr [eax], offset ??_7bad_alloc@std@@6B@ ; const std::bad_alloc::`vftable'
                mov     eax, [ebp+var_4]
                leave
                retn    4
sub_791473      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _DWORD *__thiscall sub_791497(_DWORD *this, char)
sub_791497      proc near               ; DATA XREF: .rdata:const std::bad_alloc::`vftable'↓o
                                        ; .rdata:const std::bad_cast::`vftable'↓o

Block           = dword ptr -4
arg_0           = dword ptr  8

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+Block], ecx
                mov     ecx, [ebp+Block]
                call    sub_7914C1
                mov     eax, [ebp+arg_0]
                and     eax, 1
                jz      short loc_7914BA
                push    0Ch
                push    [ebp+Block]     ; Block
                call    sub_795312
                pop     ecx
                pop     ecx

loc_7914BA:                             ; CODE XREF: sub_791497+15↑j
                mov     eax, [ebp+Block]
                leave
                retn    4
sub_791497      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int __thiscall sub_7914C1(_DWORD *this)
sub_7914C1      proc near               ; CODE XREF: sub_791497+A↑p
                                        ; sub_79151E+A↓p
                                        ; DATA XREF: ...

var_4           = dword ptr -4

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+var_4], ecx
                mov     ecx, [ebp+var_4]
                call    sub_791401
                leave
                retn
sub_7914C1      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _DWORD *__thiscall sub_7914D2(_DWORD *this)
sub_7914D2      proc near               ; CODE XREF: sub_79152F+9↓p
                                        ; sub_7955CC+9↓p

var_4           = dword ptr -4

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+var_4], ecx
                push    offset aBadArrayNewLen ; "bad array new length"
                mov     ecx, [ebp+var_4]
                call    sub_791473
                mov     eax, [ebp+var_4]
                mov     dword ptr [eax], offset ??_7bad_array_new_length@std@@6B@ ; const std::bad_array_new_length::`vftable'
                mov     eax, [ebp+var_4]
                leave
                retn
sub_7914D2      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _DWORD *__thiscall sub_7914F4(_DWORD *this, char)
sub_7914F4      proc near               ; DATA XREF: .rdata:const std::bad_array_new_length::`vftable'↓o

Block           = dword ptr -4
arg_0           = dword ptr  8

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+Block], ecx
                mov     ecx, [ebp+Block]
                call    sub_79151E
                mov     eax, [ebp+arg_0]
                and     eax, 1
                jz      short loc_791517
                push    0Ch
                push    [ebp+Block]     ; Block
                call    sub_795312
                pop     ecx
                pop     ecx

loc_791517:                             ; CODE XREF: sub_7914F4+15↑j
                mov     eax, [ebp+Block]
                leave
                retn    4
sub_7914F4      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int __thiscall sub_79151E(_DWORD *this)
sub_79151E      proc near               ; CODE XREF: sub_7914F4+A↑p
                                        ; DATA XREF: .rdata:00797E2C↓o

var_4           = dword ptr -4

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+var_4], ecx
                mov     ecx, [ebp+var_4]
                call    sub_7914C1
                leave
                retn
sub_79151E      endp


; =============== S U B R O U T I N E =======================================

; Attributes: noreturn bp-based frame

; void __cdecl __noreturn sub_79152F()
sub_79152F      proc near               ; CODE XREF: sub_792D4A+19↓p
                                        ; sub_793533+17↓p

pExceptionObject= dword ptr -0Ch

                push    ebp
                mov     ebp, esp
                sub     esp, 0Ch
                lea     ecx, [ebp+pExceptionObject]
                call    sub_7914D2
                push    offset __TI3?AVbad_array_new_length@std@@ ; pThrowInfo
                lea     eax, [ebp+pExceptionObject]
                push    eax             ; pExceptionObject
                call    _CxxThrowException
sub_79152F      endp

; ---------------------------------------------------------------------------
                leave
                retn

; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _DWORD *__thiscall sub_79154D(_DWORD *this, int)
sub_79154D      proc near               ; DATA XREF: .rdata:00797E50↓o

var_4           = dword ptr -4
arg_0           = dword ptr  8

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+var_4], ecx
                push    [ebp+arg_0]
                mov     ecx, [ebp+var_4]
                call    sub_79156F
                mov     eax, [ebp+var_4]
                mov     dword ptr [eax], offset ??_7bad_array_new_length@std@@6B@ ; const std::bad_array_new_length::`vftable'
                mov     eax, [ebp+var_4]
                leave
                retn    4
sub_79154D      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _DWORD *__thiscall sub_79156F(_DWORD *this, int)
sub_79156F      proc near               ; CODE XREF: sub_79154D+D↑p
                                        ; DATA XREF: .rdata:00797DD0↓o

var_4           = dword ptr -4
arg_0           = dword ptr  8

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+var_4], ecx
                push    [ebp+arg_0]
                mov     ecx, [ebp+var_4]
                call    sub_7913C7
                mov     eax, [ebp+var_4]
                mov     dword ptr [eax], offset ??_7bad_alloc@std@@6B@ ; const std::bad_alloc::`vftable'
                mov     eax, [ebp+var_4]
                leave
                retn    4
sub_79156F      endp

; [0000000A BYTES: COLLAPSED FUNCTION std::numeric_limits<int>::min(void). PRESS CTRL-NUMPAD+ TO EXPAND]
; [0000000A BYTES: COLLAPSED FUNCTION unknown_libname_1. PRESS CTRL-NUMPAD+ TO EXPAND]
; [00000007 BYTES: COLLAPSED FUNCTION ___scrt_stub_for_initialize_mta. PRESS CTRL-NUMPAD+ TO EXPAND]
; [0000000A BYTES: COLLAPSED FUNCTION unknown_libname_2. PRESS CTRL-NUMPAD+ TO EXPAND]

; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; __int64 sub_7915B6()
sub_7915B6      proc near               ; CODE XREF: sub_79296C+11↓p
                push    ebp
                mov     ebp, esp
                xor     eax, eax
                xor     edx, edx
                pop     ebp
                retn
sub_7915B6      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; __int64 sub_7915BF()
sub_7915BF      proc near               ; CODE XREF: sub_79296C+6↓p
                push    ebp
                mov     ebp, esp
                or      eax, 0FFFFFFFFh
                or      edx, 0FFFFFFFFh
                pop     ebp
                retn
sub_7915BF      endp

; [0000000E BYTES: COLLAPSED FUNCTION operator new(uint,int,char const *,int). PRESS CTRL-NUMPAD+ TO EXPAND]

; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _DWORD *__cdecl sub_7915D8(_DWORD *, _DWORD *)
sub_7915D8      proc near               ; CODE XREF: sub_792D9C+29↓p

var_10          = dword ptr -10h
var_C           = dword ptr -0Ch
var_8           = dword ptr -8
var_4           = dword ptr -4
arg_0           = dword ptr  8
arg_4           = dword ptr  0Ch

                push    ebp
                mov     ebp, esp
                sub     esp, 10h
                mov     eax, [ebp+arg_4]
                mov     eax, [eax]
                add     eax, 23h ; '#'
                mov     ecx, [ebp+arg_4]
                mov     [ecx], eax
                mov     eax, [ebp+arg_0]
                mov     eax, [eax]
                mov     [ebp+var_C], eax
                push    4
                pop     eax
                imul    eax, -1
                mov     ecx, [ebp+var_C]
                mov     eax, [ecx+eax]
                mov     [ebp+var_8], eax
                mov     [ebp+var_10], 4
                mov     eax, [ebp+arg_0]
                mov     eax, [eax]
                sub     eax, [ebp+var_8]
                mov     [ebp+var_4], eax

loc_791614:                             ; CODE XREF: sub_7915D8+56↓j
                cmp     [ebp+var_4], 4
                jb      short loc_791622
                cmp     [ebp+var_4], 23h ; '#'
                ja      short loc_791622
                jmp     short loc_79162C
; ---------------------------------------------------------------------------

loc_791622:                             ; CODE XREF: sub_7915D8+40↑j
                                        ; sub_7915D8+46↑j ...
                call    ds:_invalid_parameter_noinfo_noreturn
; ---------------------------------------------------------------------------
                xor     eax, eax
                jnz     short loc_791622

loc_79162C:                             ; CODE XREF: sub_7915D8+48↑j
                xor     eax, eax
                jnz     short loc_791614
                mov     eax, [ebp+arg_0]
                mov     ecx, [ebp+var_8]
                mov     [eax], ecx
                leave
                retn
sub_7915D8      endp

; [00000008 BYTES: COLLAPSED FUNCTION unknown_libname_3. PRESS CTRL-NUMPAD+ TO EXPAND]

; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; void sub_791642()
sub_791642      proc near               ; CODE XREF: sub_791E6C+D0↓p
                                        ; sub_7920BA+5D↓p ...

var_4           = dword ptr -4

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+var_4], ecx
                leave
                retn
sub_791642      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; void __stdcall sub_79164B(int)
sub_79164B      proc near               ; CODE XREF: sub_791F52+27↓p

var_4           = dword ptr -4

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+var_4], ecx
                leave
                retn    4
sub_79164B      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; void *__thiscall sub_791656(void *this, int, int)
sub_791656      proc near               ; CODE XREF: sub_791E6C+7B↓p
                                        ; sub_7920BA+42↓p

var_4           = dword ptr -4

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+var_4], ecx
                mov     eax, [ebp+var_4]
                leave
                retn    8
sub_791656      endp


; =============== S U B R O U T I N E =======================================

; Attributes: noreturn bp-based frame

; void __noreturn sub_791664()
sub_791664      proc near               ; CODE XREF: sub_792B4B+28↓p
                                        ; sub_792C68+16↓p
                push    ebp
                mov     ebp, esp
                push    offset aStringTooLong ; "string too long"
                call    ds:?_Xlength_error@std@@YAXPBD@Z ; std::_Xlength_error(char const *)
sub_791664      endp

; ---------------------------------------------------------------------------
                pop     ebp
                retn

; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _DWORD *__thiscall sub_791674(_DWORD *this)
sub_791674      proc near               ; CODE XREF: sub_791698+9↓p

var_4           = dword ptr -4

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+var_4], ecx
                push    1
                push    offset aBadCast ; "bad cast"
                mov     ecx, [ebp+var_4]
                call    sub_79139A
                mov     eax, [ebp+var_4]
                mov     dword ptr [eax], offset ??_7bad_cast@std@@6B@ ; const std::bad_cast::`vftable'
                mov     eax, [ebp+var_4]
                leave
                retn
sub_791674      endp


; =============== S U B R O U T I N E =======================================

; Attributes: noreturn bp-based frame

; void __noreturn sub_791698()
sub_791698      proc near               ; CODE XREF: sub_792823+77↓p

pExceptionObject= dword ptr -0Ch

                push    ebp
                mov     ebp, esp
                sub     esp, 0Ch
                lea     ecx, [ebp+pExceptionObject]
                call    sub_791674
                push    offset __TI2?AVbad_cast@std@@ ; pThrowInfo
                lea     eax, [ebp+pExceptionObject]
                push    eax             ; pExceptionObject
                call    _CxxThrowException
sub_791698      endp

; ---------------------------------------------------------------------------
                leave
                retn

; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _DWORD *__thiscall sub_7916B6(_DWORD *this, int)
sub_7916B6      proc near               ; DATA XREF: .rdata:00797DF8↓o

var_4           = dword ptr -4
arg_0           = dword ptr  8

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+var_4], ecx
                push    [ebp+arg_0]
                mov     ecx, [ebp+var_4]
                call    sub_7913C7
                mov     eax, [ebp+var_4]
                mov     dword ptr [eax], offset ??_7bad_cast@std@@6B@ ; const std::bad_cast::`vftable'
                mov     eax, [ebp+var_4]
                leave
                retn    4
sub_7916B6      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int (__thiscall ***__thiscall sub_7916D8(_DWORD **this))(_DWORD, int)
sub_7916D8      proc near               ; CODE XREF: sub_792F66+89↓p
                                        ; sub_792F66+363F↓j

var_10          = dword ptr -10h
var_C           = dword ptr -0Ch
var_8           = dword ptr -8
var_4           = dword ptr -4

                push    ebp
                mov     ebp, esp
                sub     esp, 10h
                mov     [ebp+var_4], ecx
                mov     eax, [ebp+var_4]
                cmp     dword ptr [eax+4], 0
                jz      short locret_79171F
                mov     eax, [ebp+var_4]
                mov     eax, [eax+4]
                mov     ecx, [ebp+var_4]
                mov     eax, [eax]
                mov     ecx, [ecx+4]
                call    dword ptr [eax+8]
                mov     [ebp+var_8], eax
                cmp     [ebp+var_8], 0
                jz      short loc_79171B
                mov     eax, [ebp+var_8]
                mov     eax, [eax]
                mov     eax, [eax]
                mov     [ebp+var_C], eax
                push    1
                mov     ecx, [ebp+var_8]
                call    [ebp+var_C]
                mov     [ebp+var_10], eax
                jmp     short locret_79171F
; ---------------------------------------------------------------------------

loc_79171B:                             ; CODE XREF: sub_7916D8+2A↑j
                and     [ebp+var_10], 0

locret_79171F:                          ; CODE XREF: sub_7916D8+10↑j
                                        ; sub_7916D8+41↑j
                leave
                retn
sub_7916D8      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int __thiscall sub_791721(_DWORD *this, unsigned int)
sub_791721      proc near               ; CODE XREF: sub_792823+47↓p

var_10          = dword ptr -10h
var_C           = dword ptr -0Ch
var_8           = dword ptr -8
var_4           = dword ptr -4
arg_0           = dword ptr  8

                push    ebp
                mov     ebp, esp
                sub     esp, 10h
                mov     [ebp+var_4], ecx
                mov     eax, [ebp+var_4]
                mov     eax, [eax+4]
                mov     ecx, [ebp+arg_0]
                cmp     ecx, [eax+0Ch]
                jnb     short loc_79174C
                mov     eax, [ebp+var_4]
                mov     eax, [eax+4]
                mov     eax, [eax+8]
                mov     ecx, [ebp+arg_0]
                mov     eax, [eax+ecx*4]
                mov     [ebp+var_8], eax
                jmp     short loc_791750
; ---------------------------------------------------------------------------

loc_79174C:                             ; CODE XREF: sub_791721+15↑j
                and     [ebp+var_8], 0

loc_791750:                             ; CODE XREF: sub_791721+29↑j
                mov     eax, [ebp+var_8]
                mov     [ebp+var_C], eax
                cmp     [ebp+var_C], 0
                jnz     short loc_79176A
                mov     eax, [ebp+var_4]
                mov     eax, [eax+4]
                movzx   eax, byte ptr [eax+14h]
                test    eax, eax
                jnz     short loc_79176F

loc_79176A:                             ; CODE XREF: sub_791721+39↑j
                mov     eax, [ebp+var_C]
                jmp     short locret_791793
; ---------------------------------------------------------------------------

loc_79176F:                             ; CODE XREF: sub_791721+47↑j
                call    ds:?_Getgloballocale@locale@std@@CAPAV_Locimp@12@XZ ; std::locale::_Getgloballocale(void)
                mov     [ebp+var_10], eax
                mov     eax, [ebp+var_10]
                mov     ecx, [ebp+arg_0]
                cmp     ecx, [eax+0Ch]
                jnb     short loc_791791
                mov     eax, [ebp+var_10]
                mov     eax, [eax+8]
                mov     ecx, [ebp+arg_0]
                mov     eax, [eax+ecx*4]
                jmp     short locret_791793
; ---------------------------------------------------------------------------

loc_791791:                             ; CODE XREF: sub_791721+60↑j
                xor     eax, eax

locret_791793:                          ; CODE XREF: sub_791721+4C↑j
                                        ; sub_791721+6E↑j
                leave
                retn    4
sub_791721      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _DWORD *__cdecl sub_791797(_DWORD *)
sub_791797      proc near               ; CODE XREF: sub_793C80+26↓p

var_10          = dword ptr -10h
var_8           = qword ptr -8
arg_0           = dword ptr  8

                push    ebp
                mov     ebp, esp
                sub     esp, 10h
                call    ds:_Xtime_get_ticks
                mov     dword ptr [ebp+var_8], eax
                mov     dword ptr [ebp+var_8+4], edx
                lea     eax, [ebp+var_8]
                push    eax
                lea     ecx, [ebp+var_10]
                call    sub_791864
                push    eax
                mov     ecx, [ebp+arg_0]
                call    sub_791F83
                mov     eax, [ebp+arg_0]
                leave
                retn
sub_791797      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _DWORD *__cdecl sub_7917C3(_DWORD *)
sub_7917C3      proc near               ; CODE XREF: sub_792943+D↓p
                                        ; sub_793230+A↓p

var_30          = dword ptr -30h
var_28          = qword ptr -28h
var_20          = qword ptr -20h
var_18          = qword ptr -18h
var_10          = qword ptr -10h
var_8           = qword ptr -8
arg_0           = dword ptr  8

                push    ebp
                mov     ebp, esp
                sub     esp, 30h
                call    ds:_Query_perf_frequency
                mov     dword ptr [ebp+var_8], eax
                mov     dword ptr [ebp+var_8+4], edx
                call    ds:_Query_perf_counter
                mov     dword ptr [ebp+var_10], eax
                mov     dword ptr [ebp+var_10+4], edx
                push    dword ptr [ebp+var_8+4]
                push    dword ptr [ebp+var_8]
                push    dword ptr [ebp+var_10+4]
                push    dword ptr [ebp+var_10]
                call    __alldiv
                push    0
                push    3B9ACA00h
                push    edx
                push    eax
                call    __allmul
                mov     dword ptr [ebp+var_18], eax
                mov     dword ptr [ebp+var_18+4], edx
                push    dword ptr [ebp+var_8+4]
                push    dword ptr [ebp+var_8]
                push    dword ptr [ebp+var_10+4]
                push    dword ptr [ebp+var_10]
                call    __allrem
                push    0
                push    3B9ACA00h
                push    edx
                push    eax
                call    __allmul
                push    dword ptr [ebp+var_8+4]
                push    dword ptr [ebp+var_8]
                push    edx
                push    eax
                call    __alldiv
                mov     dword ptr [ebp+var_20], eax
                mov     dword ptr [ebp+var_20+4], edx
                mov     eax, dword ptr [ebp+var_18]
                add     eax, dword ptr [ebp+var_20]
                mov     ecx, dword ptr [ebp+var_18+4]
                adc     ecx, dword ptr [ebp+var_20+4]
                mov     dword ptr [ebp+var_28], eax
                mov     dword ptr [ebp+var_28+4], ecx
                lea     eax, [ebp+var_28]
                push    eax
                lea     ecx, [ebp+var_30]
                call    sub_791864
                push    eax
                mov     ecx, [ebp+arg_0]
                call    sub_791F83
                mov     eax, [ebp+arg_0]
                leave
                retn
sub_7917C3      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _DWORD *__thiscall sub_791864(_DWORD *this, _DWORD *)
sub_791864      proc near               ; CODE XREF: sub_791797+19↑p
                                        ; sub_7917C3+8E↑p ...

var_4           = dword ptr -4
arg_0           = dword ptr  8

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+var_4], ecx
                mov     eax, [ebp+var_4]
                mov     ecx, [ebp+arg_0]
                mov     edx, [ecx]
                mov     ecx, [ecx+4]
                mov     [eax], edx
                mov     [eax+4], ecx
                mov     eax, [ebp+var_4]
                leave
                retn    4
sub_791864      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; __int64 __thiscall sub_791882(void *this)
sub_791882      proc near               ; CODE XREF: sub_793BCB+19↓p
                                        ; sub_793BCB+2F↓p ...

var_4           = dword ptr -4

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+var_4], ecx
                mov     ecx, [ebp+var_4]
                mov     eax, [ecx]
                mov     edx, [ecx+4]
                leave
                retn
sub_791882      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; double __thiscall sub_791893(void *this)
sub_791893      proc near               ; CODE XREF: sub_794061+13↓p
                                        ; sub_794061+32↓p ...

var_4           = dword ptr -4

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+var_4], ecx
                mov     eax, [ebp+var_4]
                fld     qword ptr [eax]
                leave
                retn
sub_791893      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; void *__thiscall sub_7918A1(void *this)
sub_7918A1      proc near               ; CODE XREF: sub_792205+A↓p
                                        ; sub_792B03+A↓p ...

var_4           = dword ptr -4

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+var_4], ecx
                mov     eax, [ebp+var_4]
                leave
                retn
sub_7918A1      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; unsigned int sub_7918AD()
sub_7918AD      proc near               ; CODE XREF: sub_793285+18↓p
                                        ; sub_7932D3+18↓p ...

var_4           = dword ptr -4

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+var_4], ecx
                call    ds:?_Random_device@std@@YAIXZ ; std::_Random_device(void)
                leave
                retn
sub_7918AD      endp


; =============== S U B R O U T I N E =======================================

; Attributes: fuzzy-sp

; int *__userpurge sub_7918BC@<eax>(int *@<ecx>, int@<ebp>, _DWORD *)
sub_7918BC      proc near               ; CODE XREF: sub_791000+35↑p
                                        ; sub_79105D+35↑p ...

anonymous_0     = dword ptr -0Ch
var_8           = dword ptr -8

; FUNCTION CHUNK AT 007964BD SIZE 00000008 BYTES
; FUNCTION CHUNK AT 007964CA SIZE 0000000C BYTES

; __unwind { // loc_7964CA
                push    ebx
                mov     ebx, esp
                push    ecx
                push    ecx
                and     esp, 0FFFFFFF8h
                add     esp, 4
                push    ebp
                mov     ebp, [ebx+4]
                mov     [esp+0Ch+var_8], ebp
                mov     ebp, esp
                push    0FFFFFFFFh
                push    offset loc_7964CA
                mov     eax, large fs:0
                push    eax
                mov     large fs:0, esp
                push    ebx
                sub     esp, 20h
                mov     [ebp-18h], ecx
                mov     ecx, [ebp-18h]
                call    sub_791F52
;   try {
                and     dword ptr [ebp-4], 0
                mov     eax, [ebp-18h]
                mov     [ebp-1Ch], eax
                mov     ecx, [ebx+8]
                call    sub_791FBF
                push    eax
                mov     ecx, [ebp-1Ch]
                call    sub_791E40
                and     dword ptr [ebp-14h], 0
                jmp     short loc_79191D
; ---------------------------------------------------------------------------

loc_791916:                             ; CODE XREF: sub_7918BC+AC↓j
                mov     eax, [ebp-14h]
                inc     eax
                mov     [ebp-14h], eax

loc_79191D:                             ; CODE XREF: sub_7918BC+58↑j
                mov     ecx, [ebx+8]
                call    sub_791FBF
                cmp     [ebp-14h], eax
                jnb     short loc_79196A
                push    dword ptr [ebp-14h]
                mov     ecx, [ebx+8]
                call    sub_79208B
                movsx   eax, byte ptr [eax]
                push    eax
                lea     ecx, [ebp-30h]
                call    sub_791DDF
                mov     ecx, [eax]
                mov     eax, [eax+4]
                mov     [ebp-28h], ecx
                mov     [ebp-24h], eax
                mov     eax, [ebp-18h]
                mov     [ebp-20h], eax
                push    dword ptr [ebp-14h]
                mov     ecx, [ebp-20h]
                call    sub_791E05
                mov     ecx, [ebp-28h]
                mov     edx, [ebp-24h]
                mov     [eax], ecx
                mov     [eax+4], edx
                jmp     short loc_791916
;   } // starts at 7918F5
; ---------------------------------------------------------------------------

loc_79196A:                             ; CODE XREF: sub_7918BC+6C↑j
                or      dword ptr [ebp-4], 0FFFFFFFFh
                mov     eax, [ebp-18h]
                mov     ecx, [ebp-0Ch]
                mov     large fs:0, ecx
                mov     esp, ebp
                pop     ebp
                mov     esp, ebx
                pop     ebx
                retn    4
; } // starts at 7918BC
sub_7918BC      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int __thiscall sub_791984(_DWORD *this, int)
sub_791984      proc near               ; CODE XREF: Process_Input3+109↓p
                                        ; Process_Input3+133↓p

var_8           = dword ptr -8
var_4           = dword ptr -4
arg_0           = dword ptr  8

                push    ebp
                mov     ebp, esp
                push    ecx
                push    ecx
                mov     [ebp+var_4], ecx
                mov     eax, [ebp+var_4]
                mov     [ebp+var_8], eax
                push    [ebp+arg_0]
                mov     ecx, [ebp+var_8]
                call    sub_791E05
                leave
                retn    4
sub_791984      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int *__thiscall BProcessor(int *this, int *)
BProcessor      proc near               ; CODE XREF: Process_Input3+24↓p
                                        ; Process_Input3+35↓p ...

var_10          = dword ptr -10h
var_C           = dword ptr -0Ch
arg_0           = dword ptr  8

; FUNCTION CHUNK AT 007964D6 SIZE 0000000C BYTES

; __unwind { // SEH_403751
                push    ebp
                mov     ebp, esp
                push    0FFFFFFFFh
                push    offset SEH_402D9C
                mov     eax, large fs:0
                push    eax
                mov     large fs:0, esp
                push    ecx
                mov     [ebp+var_10], ecx
                push    [ebp+var_10]
                mov     ecx, [ebp+arg_0]
                call    sub_791E6C
                mov     eax, [ebp+arg_0]
                mov     ecx, [ebp+var_C]
                mov     large fs:0, ecx
                leave
                retn    4
; } // starts at 7919A1
BProcessor      endp

; ---------------------------------------------------------------------------
                db 5 dup(0CCh)

; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int *__thiscall sub_7919DE(int *this)
sub_7919DE      proc near               ; CODE XREF: _main+6A↓p
                                        ; _main+B0↓p ...

var_4           = dword ptr -4

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+var_4], ecx
                mov     ecx, [ebp+var_4]
                call    sub_791E5B
                leave
                retn
sub_7919DE      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int *__cdecl sub_7919EF(int *)
sub_7919EF      proc near               ; CODE XREF: _main+48↓p

GETInput_Coordinates= byte ptr -28h
var_10          = dword ptr -10h
var_C           = dword ptr -0Ch
var_4           = dword ptr -4
arg_0           = dword ptr  8

; FUNCTION CHUNK AT 007964FB SIZE 00000008 BYTES
; FUNCTION CHUNK AT 00796508 SIZE 0000000C BYTES

; __unwind { // SEH_4019EF
                push    ebp
                mov     ebp, esp
                push    0FFFFFFFFh
                push    offset SEH_4019EF
                mov     eax, large fs:0
                push    eax
                mov     large fs:0, esp
                sub     esp, 1Ch
                and     [ebp+var_10], 0
                push    offset aCoordinates ; "Coordinates: "
                call    printf
                pop     ecx
                push    offset aV2      ; "v2"
                lea     ecx, [ebp+GETInput_Coordinates]
                call    sub_7920BA
;   try {
                and     [ebp+var_4], 0
                lea     eax, [ebp+GETInput_Coordinates]
                push    eax
                push    ds:?cin@std@@3V?$basic_istream@DU?$char_traits@D@std@@@1@A ; std::istream std::cin
                call    sub_79290E
                pop     ecx
                pop     ecx
                lea     eax, [ebp+GETInput_Coordinates]
                push    eax
                mov     ecx, [ebp+arg_0]
                call    sub_7918BC
                mov     eax, [ebp+var_10]
                or      eax, 1
                mov     [ebp+var_10], eax
;   } // starts at 791A26
                or      [ebp+var_4], 0FFFFFFFFh
                lea     ecx, [ebp+GETInput_Coordinates]
                call    Process_Input
                mov     eax, [ebp+arg_0]
                mov     ecx, [ebp+var_C]
                mov     large fs:0, ecx
                leave
                retn
; } // starts at 7919EF
sub_7919EF      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; char __cdecl Process_Input3(int *)
Process_Input3  proc near               ; CODE XREF: _main+56↓p

var_54          = dword ptr -54h
var_48          = dword ptr -48h
var_3C          = dword ptr -3Ch
Processed2      = word ptr -30h
var_2C          = dword ptr -2Ch
var_28          = dword ptr -28h
var_24          = dword ptr -24h
var_20          = dword ptr -20h
var_1C          = word ptr -1Ch
var_18          = dword ptr -18h
Processed1      = word ptr -14h
LastBool        = byte ptr -0Eh
Failure1        = byte ptr -0Dh
var_C           = dword ptr -0Ch
var_4           = dword ptr -4
arg_0           = dword ptr  8

; FUNCTION CHUNK AT 00796514 SIZE 00000008 BYTES
; FUNCTION CHUNK AT 00796521 SIZE 0000000C BYTES

; __unwind { // SEH_401A6B
                push    ebp
                mov     ebp, esp
                push    0FFFFFFFFh
                push    offset SEH_401A6B
                mov     eax, large fs:0
                push    eax
                mov     large fs:0, esp
                sub     esp, 48h
                push    esi
                push    edi
                lea     eax, [ebp+var_48]
                push    eax
                mov     ecx, [ebp+arg_0]
                call    BProcessor
                mov     [ebp+var_24], eax
                lea     eax, [ebp+var_3C]
                push    eax
                mov     ecx, offset dword_799434
                call    BProcessor
                mov     [ebp+var_20], eax
                mov     ecx, [ebp+var_20]
                call    AProcessor
                mov     esi, eax
                mov     ecx, [ebp+var_24]
                call    AProcessor
                cmp     eax, esi
                jz      short loc_791AC7
                mov     [ebp+var_18], 1
                jmp     short loc_791ACB
; ---------------------------------------------------------------------------

loc_791AC7:                             ; CODE XREF: Process_Input3+51↑j
                and     [ebp+var_18], 0

loc_791ACB:                             ; CODE XREF: Process_Input3+5A↑j
                mov     al, byte ptr [ebp+var_18]
                mov     [ebp+Failure1], al
                lea     ecx, [ebp+var_3C]
                call    sub_791E5B
                lea     ecx, [ebp+var_48]
                call    sub_791E5B
                movzx   eax, [ebp+Failure1]
                test    eax, eax
                jnz     short loc_791AF0 ; jz original
                xor     al, al
                jmp     loc_791BBB
; ---------------------------------------------------------------------------

loc_791AF0:                             ; CODE XREF: Process_Input3+7C↑j
                push    0
                lea     ecx, [ebp+Processed1]
                call    sub_791D9F
                push    7
                lea     ecx, [ebp+var_1C]
                call    sub_791D9F
                jmp     short loc_791B16
; ---------------------------------------------------------------------------

loc_791B06:                             ; CODE XREF: Process_Input3:loc_791BB4↓j
                lea     ecx, [ebp+Processed1]
                call    sub_791D73
                lea     ecx, [ebp+var_1C]
                call    sub_791D73

loc_791B16:                             ; CODE XREF: Process_Input3+99↑j
                lea     eax, [ebp+var_54]
                push    eax
                mov     ecx, offset dword_799434
                call    BProcessor
                mov     [ebp+var_28], eax
                mov     eax, [ebp+var_28]
                mov     [ebp+var_2C], eax
;   try {
                and     [ebp+var_4], 0
                mov     ecx, [ebp+var_2C]
                call    AProcessor
                push    eax
                lea     ecx, [ebp+Processed2]
                call    sub_791D9F      ; see if Processed2 change with input.
                lea     eax, [ebp+Processed2]
                push    eax
                lea     ecx, [ebp+Processed1]
                call    Process_Input2
                mov     [ebp+LastBool], al
;   } // starts at 791B2D
                or      [ebp+var_4], 0FFFFFFFFh
                lea     ecx, [ebp+var_54]
                call    sub_791E5B
                movzx   eax, [ebp+LastBool]
                test    eax, eax
                jz      short loc_791BB9
                lea     ecx, [ebp+Processed1]
                call    sub_791D23
                movzx   eax, ax
                push    eax
                mov     ecx, [ebp+arg_0]
                call    sub_791984
                mov     ecx, eax
                call    sub_791DCB
                mov     esi, eax
                lea     ecx, [ebp+var_1C]
                call    sub_791D23
                movzx   edi, ax
                lea     ecx, [ebp+Processed1]
                call    sub_791D23
                movzx   eax, ax
                push    eax
                mov     ecx, offset dword_799434
                call    sub_791984
                mov     ecx, eax
                call    sub_791DCB
                xor     edi, eax
                cmp     esi, edi
                jz      short loc_791BB4
                xor     al, al
                jmp     short loc_791BBB
; ---------------------------------------------------------------------------

loc_791BB4:                             ; CODE XREF: Process_Input3+143↑j
                jmp     loc_791B06
; ---------------------------------------------------------------------------

loc_791BB9:                             ; CODE XREF: Process_Input3+F8↑j
                mov     al, 1

loc_791BBB:                             ; CODE XREF: Process_Input3+80↑j
                                        ; Process_Input3+147↑j
                mov     ecx, [ebp+var_C]
                mov     large fs:0, ecx
                pop     edi
                pop     esi
                leave
                retn
; } // starts at 791A6B
Process_Input3  endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int __cdecl main(int argc, const char **argv, const char **envp)
_main           proc near               ; CODE XREF: __scrt_common_main_seh(void)+F5↓p

var_34          = dword ptr -34h
Input_Coordinates  = dword ptr -24h
var_18          = qword ptr -18h
var_10          = dword ptr -10h
var_C           = dword ptr -0Ch
var_4           = dword ptr -4
argc            = dword ptr  8
argv            = dword ptr  0Ch
envp            = dword ptr  10h

; FUNCTION CHUNK AT 0079652D SIZE 00000008 BYTES
; FUNCTION CHUNK AT 0079653A SIZE 0000000C BYTES

; __unwind { // _main_SEH
                push    ebp
                mov     ebp, esp
                push    0FFFFFFFFh
                push    offset _main_SEH
                mov     eax, large fs:0
                push    eax
                mov     large fs:0, esp
                sub     esp, 28h
                lea     ecx, [ebp+var_34]
                call    sub_791CF9
                push    offset aMain    ; "main"
                push    offset aS       ; "%s()\n"
                call    printf
                pop     ecx
                pop     ecx
                push    offset aFindCorrectPas ; "Find correct Coordinates\n"
                call    printf
                pop     ecx

loc_791C08:                             ; CODE XREF: _main+B5↓j
                xor     eax, eax
                inc     eax
                jz      short loc_791C80
                lea     eax, [ebp+Input_Coordinates]
                push    eax
                call    sub_7919EF
                pop     ecx
;   try {
                and     [ebp+var_4], 0
                lea     eax, [ebp+Input_Coordinates]
                push    eax
                call    Process_Input3
                pop     ecx
                movzx   eax, al
                test    eax, eax
                jz      short loc_791C3A
;   } // starts at 791C17
                or      [ebp+var_4], 0FFFFFFFFh
                lea     ecx, [ebp+Input_Coordinates]
                call    sub_7919DE
                jmp     short loc_791C80
; ---------------------------------------------------------------------------

loc_791C3A:                             ; CODE XREF: _main+61↑j
                lea     ecx, [ebp+var_34]
                call    sub_791CC5
                mov     ecx, eax
                call    sub_791CA5
                push    edx
                push    eax
                push    offset aIncorrectLlu ; "Incorrect!(%llu)\n"
                call    printf
                add     esp, 0Ch
                mov     [ebp+var_10], 0C8h
                lea     eax, [ebp+var_10]
                push    eax
                lea     ecx, [ebp+var_18]
                call    sub_792927
                push    eax
                call    sub_792943
                pop     ecx
                or      [ebp+var_4], 0FFFFFFFFh
                lea     ecx, [ebp+Input_Coordinates]
                call    sub_7919DE
                jmp     short loc_791C08
; ---------------------------------------------------------------------------

loc_791C80:                             ; CODE XREF: _main+42↑j
                                        ; _main+6F↑j
                push    offset aCorrectPleaseS ; "Correct!\nPlease send DM with PW.\n"
                call    printf
                pop     ecx
                call    ds:getchar
                call    ds:getchar
                xor     eax, eax
                mov     ecx, [ebp+var_C]
                mov     large fs:0, ecx
                leave
                retn
; } // starts at 791BC9
_main           endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; __int64 __thiscall sub_791CA5(_QWORD *this)
sub_791CA5      proc near               ; CODE XREF: _main+7B↑p
                                        ; sub_79216E+C↓p ...

var_4           = dword ptr -4

                push    ebp
                mov     ebp, esp
                push    ecx
                push    esi
                mov     [ebp+var_4], ecx
                mov     eax, [ebp+var_4]
                mov     ecx, [ebp+var_4]
                mov     edx, [eax+8]
                xor     edx, [ecx]
                mov     esi, [eax+0Ch]
                xor     esi, [ecx+4]
                mov     eax, edx
                mov     edx, esi
                pop     esi
                leave
                retn
sub_791CA5      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _QWORD *__thiscall sub_791CC5(_QWORD *this)
sub_791CC5      proc near               ; CODE XREF: _main+74↑p

var_24          = dword ptr -24h
var_14          = dword ptr -14h
var_4           = dword ptr -4

                push    ebp
                mov     ebp, esp
                sub     esp, 24h
                push    esi
                push    edi
                mov     [ebp+var_4], ecx
                push    0
                push    1
                lea     ecx, [ebp+var_14]
                call    sub_7921A2
                push    eax
                lea     eax, [ebp+var_24]
                push    eax
                mov     ecx, [ebp+var_4]
                call    sub_79216E
                mov     esi, eax
                mov     edi, [ebp+var_4]
                movsd
                movsd
                movsd
                movsd
                mov     eax, [ebp+var_4]
                pop     edi
                pop     esi
                leave
                retn
sub_791CC5      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int *__thiscall sub_791CF9(int *this)
sub_791CF9      proc near               ; CODE XREF: _main+1E↑p

var_4           = dword ptr -4

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+var_4], ecx
                call    sub_79296C
                mov     ecx, [ebp+var_4]
                mov     [ecx], eax
                mov     [ecx+4], edx
                mov     eax, [ebp+var_4]
                mov     ecx, [ebp+var_4]
                mov     edx, [ecx]
                mov     ecx, [ecx+4]
                mov     [eax+8], edx
                mov     [eax+0Ch], ecx
                mov     eax, [ebp+var_4]
                leave
                retn
sub_791CF9      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int __thiscall sub_791D23(unsigned __int16 *this)
sub_791D23      proc near               ; CODE XREF: Process_Input3+FD↑p
                                        ; Process_Input3+11A↑p ...

var_4           = dword ptr -4

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp-4], ecx
                mov     eax, [ebp-4]
                movzx   eax, word ptr [eax+2]
                mov     ecx, [ebp-4]
                movzx   ecx, word ptr [ecx] ; check ecx
                xor     eax, ecx
                leave
                retn
sub_791D23      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; bool __thiscall Process_Input2(unsigned __int16 *this, unsigned __int16 *)
Process_Input2  proc near               ; CODE XREF: Process_Input3+DE↑p

var_8           = dword ptr -8
var_4           = dword ptr -4
arg_0           = dword ptr  8

                push    ebp
                mov     ebp, esp
                push    ecx
                push    ecx
                push    esi
                mov     [ebp-8], ecx
                mov     ecx, [ebp-8]
                call    sub_791D23
                movzx   esi, ax
                mov     ecx, [ebp+8]
                call    sub_791D23
                movzx   eax, ax
                cmp     esi, eax        ; esi needs to be bigger than eax
                jge     short loc_791D67
                mov     dword ptr [ebp-4], 1
                jmp     short loc_791D6B
; ---------------------------------------------------------------------------

loc_791D67:                             ; CODE XREF: Process_Input2+21↑j
                and     dword ptr [ebp-4], 0

loc_791D6B:                             ; CODE XREF: Process_Input2+2A↑j
                mov     al, [ebp-4]
                pop     esi
                leave
                retn    4
Process_Input2  endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; unsigned __int16 *__thiscall sub_791D73(unsigned __int16 *this)
sub_791D73      proc near               ; CODE XREF: Process_Input3+9E↑p
                                        ; Process_Input3+A6↑p

var_C           = word ptr -0Ch
var_8           = word ptr -8
var_4           = dword ptr -4

                push    ebp
                mov     ebp, esp
                sub     esp, 0Ch
                mov     [ebp+var_4], ecx
                push    1
                lea     ecx, [ebp+var_8]
                call    sub_791D9F
                push    eax
                lea     eax, [ebp+var_C]
                push    eax
                mov     ecx, [ebp+var_4]
                call    sub_7921D4
                mov     eax, [eax]
                mov     ecx, [ebp+var_4]
                mov     [ecx], eax
                mov     eax, [ebp+var_4]
                leave
                retn
sub_791D73      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; __int16 *__thiscall sub_791D9F(__int16 *this, __int16)
sub_791D9F      proc near               ; CODE XREF: Process_Input3+8A↑p
                                        ; Process_Input3+94↑p ...

var_4           = dword ptr -4
arg_0           = word ptr  8

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+var_4], ecx
                call    sub_79299E
                mov     ecx, [ebp+var_4]
                mov     [ecx], ax
                movzx   eax, [ebp+arg_0]
                mov     ecx, [ebp+var_4]
                movzx   ecx, word ptr [ecx]
                xor     eax, ecx
                mov     ecx, [ebp+var_4]
                mov     [ecx+2], ax
                mov     eax, [ebp+var_4]
                leave
                retn    4
sub_791D9F      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int __thiscall sub_791DCB(_DWORD *this)
sub_791DCB      proc near               ; CODE XREF: Process_Input3+110↑p
                                        ; Process_Input3+13A↑p

var_4           = dword ptr -4

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+var_4], ecx
                mov     eax, [ebp+var_4]
                mov     ecx, [ebp+var_4]
                mov     eax, [eax+4]
                xor     eax, [ecx]
                leave
                retn
sub_791DCB      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int *__thiscall sub_791DDF(int *this, int)
sub_791DDF      proc near               ; CODE XREF: sub_7918BC+80↑p

var_4           = dword ptr -4
arg_0           = dword ptr  8

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+var_4], ecx
                call    sub_7929C4
                mov     ecx, [ebp+var_4]
                mov     [ecx], eax
                mov     eax, [ebp+var_4]
                mov     ecx, [ebp+arg_0]
                xor     ecx, [eax]
                mov     eax, [ebp+var_4]
                mov     [eax+4], ecx
                mov     eax, [ebp+var_4]
                leave
                retn    4
sub_791DDF      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int __thiscall sub_791E05(_DWORD *this, int)
sub_791E05      proc near               ; CODE XREF: sub_7918BC+9C↑p
                                        ; sub_791984+14↑p

var_8           = dword ptr -8
var_4           = dword ptr -4
arg_0           = dword ptr  8

                push    ebp
                mov     ebp, esp
                push    ecx
                push    ecx
                mov     [ebp+var_4], ecx
                mov     eax, [ebp+var_4]
                mov     [ebp+var_8], eax
                mov     eax, [ebp+var_8]
                mov     eax, [eax]
                mov     ecx, [ebp+arg_0]
                lea     eax, [eax+ecx*8]
                leave
                retn    4
sub_791E05      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int __thiscall AProcessor(_DWORD *this)
AProcessor      proc near               ; CODE XREF: Process_Input3+40↑p
                                        ; Process_Input3+4A↑p ...

var_8           = dword ptr -8
var_4           = dword ptr -4

                push    ebp
                mov     ebp, esp
                push    ecx
                push    ecx
                mov     [ebp+var_8], ecx
                mov     eax, [ebp+var_8]
                mov     [ebp+var_4], eax
                mov     eax, [ebp+var_4]
                mov     ecx, [ebp+var_4]
                mov     eax, [eax+4]
                sub     eax, [ecx]
                sar     eax, 3
                leave
                retn
AProcessor      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; void __thiscall sub_791E40(int *this, unsigned int)
sub_791E40      proc near               ; CODE XREF: sub_7918BC+4F↑p

var_8           = dword ptr -8
var_1           = byte ptr -1
arg_0           = dword ptr  8

                push    ebp
                mov     ebp, esp
                push    ecx
                push    ecx
                mov     [ebp+var_8], ecx
                lea     eax, [ebp+var_1]
                push    eax
                push    [ebp+arg_0]
                mov     ecx, [ebp+var_8]
                call    sub_7929E8
                leave
                retn    4
sub_791E40      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int *__thiscall sub_791E5B(int *this)
sub_791E5B      proc near               ; CODE XREF: sub_7919DE+A↑p
                                        ; Process_Input3+69↑p ...

var_4           = dword ptr -4

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+var_4], ecx
                mov     ecx, [ebp+var_4]
                call    sub_792216
                leave
                retn
sub_791E5B      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int *__thiscall sub_791E6C(int *this, int *)
sub_791E6C      proc near               ; CODE XREF: BProcessor+22↑p

var_38          = dword ptr -38h
var_34          = dword ptr -34h
var_30          = dword ptr -30h
var_2C          = dword ptr -2Ch
var_28          = dword ptr -28h
var_24          = dword ptr -24h
var_20          = dword ptr -20h
var_1C          = dword ptr -1Ch
var_18          = dword ptr -18h
var_14          = dword ptr -14h
var_10          = byte ptr -10h
var_F           = byte ptr -0Fh
var_E           = byte ptr -0Eh
var_D           = byte ptr -0Dh
var_C           = dword ptr -0Ch
var_4           = dword ptr -4
arg_0           = dword ptr  8

; FUNCTION CHUNK AT 00796546 SIZE 00000008 BYTES
; FUNCTION CHUNK AT 00796553 SIZE 0000000C BYTES

; __unwind { // SEH_401E6C
                push    ebp
                mov     ebp, esp
                push    0FFFFFFFFh
                push    offset SEH_401E6C
                mov     eax, large fs:0
                push    eax
                mov     large fs:0, esp
                sub     esp, 2Ch
                mov     [ebp+var_14], ecx
                mov     eax, [ebp+var_14]
                mov     [ebp+var_34], eax
                mov     ecx, [ebp+arg_0]
                call    sub_792205
                push    eax
                lea     eax, [ebp+var_E]
                push    eax
                call    unknown_libname_3 ; Microsoft VisualC 14/net runtime
                pop     ecx
                pop     ecx
                mov     [ebp+var_2C], eax
                mov     al, [ebp+var_F]
                mov     byte ptr [ebp+var_30], al
                push    [ebp+var_2C]
                push    [ebp+var_30]
                mov     ecx, [ebp+var_34]
                call    sub_792ABF
                lea     eax, [ebp+var_10]
                mov     [ebp+var_38], eax
                mov     eax, [ebp+var_14]
                mov     [ebp+var_20], eax
                mov     eax, [ebp+arg_0]
                mov     [ebp+var_24], eax
                mov     eax, [ebp+var_24]
                mov     eax, [eax]
                mov     [ebp+var_1C], eax
                mov     eax, [ebp+var_24]
                mov     eax, [eax+4]
                mov     [ebp+var_18], eax
                push    [ebp+var_20]
                push    [ebp+var_38]
                lea     ecx, [ebp+var_D]
                call    sub_791656
                mov     eax, [ebp+var_1C]
                cmp     eax, [ebp+var_18]
                jz      short loc_791F39
                mov     eax, [ebp+var_18]
                sub     eax, [ebp+var_1C]
                sar     eax, 3
                push    eax
                mov     ecx, [ebp+var_14]
                call    sub_7922C8
                mov     eax, [ebp+var_14]
                mov     [ebp+var_28], eax
;   try {
                and     [ebp+var_4], 0
                mov     eax, [ebp+var_20]
                push    dword ptr [eax]
                push    [ebp+var_18]
                push    [ebp+var_1C]
                mov     ecx, [ebp+var_14]
                call    sub_792ADE
                mov     ecx, [ebp+var_20]
                mov     [ecx+4], eax
                and     [ebp+var_28], 0
;   } // starts at 791F0C
                or      [ebp+var_4], 0FFFFFFFFh
                lea     ecx, [ebp+var_28]
                call    sub_792153

loc_791F39:                             ; CODE XREF: sub_791E6C+86↑j
                lea     ecx, [ebp+var_D]
                call    sub_791642
                mov     eax, [ebp+var_14]
                mov     ecx, [ebp+var_C]
                mov     large fs:0, ecx
                leave
                retn    4
; } // starts at 791E6C
sub_791E6C      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _DWORD *__thiscall sub_791F52(_DWORD *this)
sub_791F52      proc near               ; CODE XREF: sub_7918BC+34↑p

var_14          = dword ptr -14h
var_10          = dword ptr -10h
var_C           = dword ptr -0Ch
var_8           = dword ptr -8
var_1           = byte ptr -1

                push    ebp
                mov     ebp, esp
                sub     esp, 14h
                mov     [ebp+var_8], ecx
                mov     eax, [ebp+var_8]
                mov     [ebp+var_C], eax
                push    [ebp+var_14]
                mov     ecx, [ebp+var_C]
                call    sub_792B03
                mov     eax, [ebp+var_8]
                mov     [ebp+var_10], eax
                lea     eax, [ebp+var_1]
                push    eax
                mov     ecx, [ebp+var_10]
                call    sub_79164B
                mov     eax, [ebp+var_8]
                leave
                retn
sub_791F52      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _DWORD *__thiscall sub_791F83(_DWORD *this, _DWORD *)
sub_791F83      proc near               ; CODE XREF: sub_791797+22↑p
                                        ; sub_7917C3+97↑p ...

var_4           = dword ptr -4
arg_0           = dword ptr  8

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+var_4], ecx
                mov     eax, [ebp+arg_0]
                mov     ecx, [eax]
                mov     eax, [eax+4]
                mov     edx, [ebp+var_4]
                mov     [edx], ecx
                mov     [edx+4], eax
                mov     eax, [ebp+var_4]
                leave
                retn    4
sub_791F83      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _DWORD *__thiscall sub_791FA1(_DWORD *this, _DWORD *)
sub_791FA1      proc near               ; CODE XREF: sub_793200+10↓p
                                        ; sub_793C46+D↓p ...

var_4           = dword ptr -4
arg_0           = dword ptr  8

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+var_4], ecx
                mov     eax, [ebp+var_4]
                mov     ecx, [eax]
                mov     eax, [eax+4]
                mov     edx, [ebp+arg_0]
                mov     [edx], ecx
                mov     [edx+4], eax
                mov     eax, [ebp+arg_0]
                leave
                retn    4
sub_791FA1      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int __thiscall sub_791FBF(_DWORD *this)
sub_791FBF      proc near               ; CODE XREF: sub_7918BC+46↑p
                                        ; sub_7918BC+64↑p

var_4           = dword ptr -4

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+var_4], ecx
                mov     eax, [ebp+var_4]
                mov     eax, [eax+10h]
                leave
                retn
sub_791FBF      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; unsigned int *__thiscall sub_791FCE(size_t *this, char)
sub_791FCE      proc near               ; CODE XREF: sub_792F66+1CE↓p

var_14          = dword ptr -14h
var_10          = dword ptr -10h
var_C           = dword ptr -0Ch
var_8           = dword ptr -8
var_1           = byte ptr -1
arg_0           = dword ptr  8

                push    ebp
                mov     ebp, esp
                sub     esp, 14h
                mov     [ebp+var_8], ecx
                mov     eax, [ebp+var_8]
                mov     eax, [eax+10h]
                mov     [ebp+var_C], eax
                mov     eax, [ebp+var_8]
                mov     ecx, [ebp+var_C]
                cmp     ecx, [eax+14h]
                jnb     short loc_79202E
                mov     eax, [ebp+var_C]
                inc     eax
                mov     ecx, [ebp+var_8]
                mov     [ecx+10h], eax
                mov     ecx, [ebp+var_8]
                call    sub_7924C0
                mov     [ebp+var_10], eax
                lea     eax, [ebp+arg_0]
                push    eax
                mov     eax, [ebp+var_10]
                add     eax, [ebp+var_C]
                push    eax
                call    sub_792524
                pop     ecx
                pop     ecx
                mov     [ebp+var_1], 0
                lea     eax, [ebp+var_1]
                push    eax
                mov     eax, [ebp+var_C]
                mov     ecx, [ebp+var_10]
                lea     eax, [ecx+eax+1]
                push    eax
                call    sub_792524
                pop     ecx
                pop     ecx
                jmp     short locret_79203E
; ---------------------------------------------------------------------------

loc_79202E:                             ; CODE XREF: sub_791FCE+1B↑j
                push    [ebp+arg_0]
                push    [ebp+var_14]
                push    1
                mov     ecx, [ebp+var_8]
                call    sub_792B4B

locret_79203E:                          ; CODE XREF: sub_791FCE+5E↑j
                leave
                retn    4
sub_791FCE      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _BYTE *__stdcall sub_792042(_BYTE *, _BYTE *Src, size_t Size, char)
sub_792042      proc near               ; CODE XREF: sub_792B4B+B2↓p
                                        ; sub_792B4B+E0↓p

var_8           = dword ptr -8
var_1           = byte ptr -1
arg_0           = dword ptr  8
Src             = dword ptr  0Ch
Size            = dword ptr  10h
arg_C           = byte ptr  14h

                push    ebp
                mov     ebp, esp
                push    ecx
                push    ecx
                mov     [ebp+var_8], ecx
                push    [ebp+Size]      ; Size
                push    [ebp+Src]       ; Src
                push    [ebp+arg_0]     ; void *
                call    sub_792565
                add     esp, 0Ch
                lea     eax, [ebp+arg_C]
                push    eax
                mov     eax, [ebp+arg_0]
                add     eax, [ebp+Size]
                push    eax
                call    sub_792524
                pop     ecx
                pop     ecx
                mov     [ebp+var_1], 0
                lea     eax, [ebp+var_1]
                push    eax
                mov     eax, [ebp+Size]
                mov     ecx, [ebp+arg_0]
                lea     eax, [ecx+eax+1]
                push    eax
                call    sub_792524
                pop     ecx
                pop     ecx
                leave
                retn    10h
sub_792042      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; char *__thiscall sub_79208B(_DWORD *this, int)
sub_79208B      proc near               ; CODE XREF: sub_7918BC+74↑p

var_4           = dword ptr -4
arg_0           = dword ptr  8

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+var_4], ecx
                mov     ecx, [ebp+var_4]
                call    sub_7924C0
                add     eax, [ebp+arg_0]
                leave
                retn    4
sub_79208B      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; void __thiscall Process_Input(void **this)
Process_Input   proc near               ; CODE XREF: sub_791000+41↑p
                                        ; sub_79105D+41↑p ...

var_4           = dword ptr -4

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+var_4], ecx
                mov     ecx, [ebp+var_4]
                call    sub_79232A
                mov     ecx, [ebp+var_4]
                call    sub_792131
                leave
                retn
Process_Input   endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; unsigned int *__thiscall sub_7920BA(unsigned int *this, char *Src)
sub_7920BA      proc near               ; CODE XREF: sub_791000+23↑p
                                        ; sub_79105D+23↑p ...

var_20          = dword ptr -20h
var_1C          = dword ptr -1Ch
var_18          = dword ptr -18h
var_14          = dword ptr -14h
var_E           = byte ptr -0Eh
var_D           = byte ptr -0Dh
var_C           = dword ptr -0Ch
var_4           = dword ptr -4
Src             = dword ptr  8

; FUNCTION CHUNK AT 0079655F SIZE 00000008 BYTES
; FUNCTION CHUNK AT 0079656C SIZE 0000000C BYTES

; __unwind { // SEH_4020BA
                push    ebp
                mov     ebp, esp
                push    0FFFFFFFFh
                push    offset SEH_4020BA
                mov     eax, large fs:0
                push    eax
                mov     large fs:0, esp
                sub     esp, 14h
                mov     [ebp+var_14], ecx
                mov     eax, [ebp+var_14]
                mov     [ebp+var_18], eax
                push    [ebp+var_20]
                mov     ecx, [ebp+var_18]
                call    sub_792C45
;   try {
                and     [ebp+var_4], 0
                lea     eax, [ebp+var_E]
                mov     [ebp+var_1C], eax
                push    [ebp+var_14]
                push    [ebp+var_1C]
                lea     ecx, [ebp+var_D]
                call    sub_791656
                mov     ecx, [ebp+var_14]
                call    sub_7923C9
                push    [ebp+Src]       ; Src
                mov     ecx, [ebp+var_14]
                call    sub_7923FD
                lea     ecx, [ebp+var_D]
                call    sub_791642
;   } // starts at 7920E9
                or      [ebp+var_4], 0FFFFFFFFh
                mov     eax, [ebp+var_14]
                mov     ecx, [ebp+var_C]
                mov     large fs:0, ecx
                leave
                retn    4
; } // starts at 7920BA
sub_7920BA      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; void sub_792131()
sub_792131      proc near               ; CODE XREF: Process_Input+12↑p
                                        ; sub_7920BA+44A8↓j

var_4           = dword ptr -4

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+var_4], ecx
                mov     ecx, [ebp+var_4]
                call    sub_792142
                leave
                retn
sub_792131      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; void sub_792142()
sub_792142      proc near               ; CODE XREF: sub_792131+A↑p

var_4           = dword ptr -4

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+var_4], ecx
                mov     ecx, [ebp+var_4]
                call    sub_791642
                leave
                retn
sub_792142      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int *__thiscall sub_792153(int **this)
sub_792153      proc near               ; CODE XREF: sub_791E6C+C8↑p
                                        ; sub_791E6C+46DD↓j

var_4           = dword ptr -4

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+var_4], ecx
                mov     eax, [ebp+var_4]
                cmp     dword ptr [eax], 0
                jz      short locret_79216C
                mov     eax, [ebp+var_4]
                mov     ecx, [eax]
                call    sub_792216

locret_79216C:                          ; CODE XREF: sub_792153+D↑j
                leave
                retn
sub_792153      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int *__thiscall sub_79216E(_QWORD *this, int *, _QWORD *)
sub_79216E      proc near               ; CODE XREF: sub_791CC5+1F↑p

var_4           = dword ptr -4
arg_0           = dword ptr  8
arg_4           = dword ptr  0Ch

                push    ebp
                mov     ebp, esp
                push    ecx
                push    esi
                push    edi
                mov     [ebp+var_4], ecx
                mov     ecx, [ebp+var_4]
                call    sub_791CA5
                mov     esi, eax
                mov     edi, edx
                mov     ecx, [ebp+arg_4]
                call    sub_791CA5
                add     esi, eax
                adc     edi, edx
                push    edi
                push    esi
                mov     ecx, [ebp+arg_0]
                call    sub_7921A2
                mov     eax, [ebp+arg_0]
                pop     edi
                pop     esi
                leave
                retn    8
sub_79216E      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int *__thiscall sub_7921A2(int *this, int, int)
sub_7921A2      proc near               ; CODE XREF: sub_791CC5+12↑p
                                        ; sub_79216E+26↑p

var_4           = dword ptr -4
arg_0           = dword ptr  8
arg_4           = dword ptr  0Ch

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+var_4], ecx
                call    sub_79296C
                mov     ecx, [ebp+var_4]
                mov     [ecx], eax
                mov     [ecx+4], edx
                mov     eax, [ebp+var_4]
                mov     ecx, [ebp+arg_0]
                xor     ecx, [eax]
                mov     edx, [ebp+arg_4]
                xor     edx, [eax+4]
                mov     eax, [ebp+var_4]
                mov     [eax+8], ecx
                mov     [eax+0Ch], edx
                mov     eax, [ebp+var_4]
                leave
                retn    8
sub_7921A2      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; __int16 *__thiscall sub_7921D4(unsigned __int16 *this, __int16 *, unsigned __int16 *)
sub_7921D4      proc near               ; CODE XREF: sub_791D73+1B↑p

var_4           = dword ptr -4
arg_0           = dword ptr  8
arg_4           = dword ptr  0Ch

                push    ebp
                mov     ebp, esp
                push    ecx
                push    esi
                mov     [ebp+var_4], ecx
                mov     ecx, [ebp+var_4]
                call    sub_791D23
                movzx   esi, ax
                mov     ecx, [ebp+arg_4]
                call    sub_791D23
                movzx   eax, ax
                add     esi, eax
                push    esi
                mov     ecx, [ebp+arg_0]
                call    sub_791D9F
                mov     eax, [ebp+arg_0]
                pop     esi
                leave
                retn    8
sub_7921D4      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; void *__thiscall sub_792205(void *this)
sub_792205      proc near               ; CODE XREF: sub_791E6C+27↑p
                                        ; sub_792216+61↓p ...

var_4           = dword ptr -4

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+var_4], ecx
                mov     ecx, [ebp+var_4]
                call    sub_7918A1
                leave
                retn
sub_792205      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int *__thiscall sub_792216(int *this)
sub_792216      proc near               ; CODE XREF: sub_791E5B+A↑p
                                        ; sub_792153+14↑p

var_2C          = dword ptr -2Ch
Block           = dword ptr -28h
var_24          = dword ptr -24h
var_20          = dword ptr -20h
var_1C          = dword ptr -1Ch
var_18          = dword ptr -18h
var_14          = dword ptr -14h
var_10          = dword ptr -10h
var_C           = dword ptr -0Ch

; FUNCTION CHUNK AT 007964D6 SIZE 0000000C BYTES

; __unwind { // SEH_403751
                push    ebp
                mov     ebp, esp
                push    0FFFFFFFFh
                push    offset SEH_402D9C
                mov     eax, large fs:0
                push    eax
                mov     large fs:0, esp
                sub     esp, 20h
                mov     [ebp+var_18], ecx
                mov     eax, [ebp+var_18]
                mov     [ebp+var_14], eax
                mov     eax, [ebp+var_14]
                mov     [ebp+var_10], eax
                mov     eax, [ebp+var_14]
                add     eax, 4
                mov     [ebp+var_1C], eax
                mov     eax, [ebp+var_14]
                add     eax, 8
                mov     [ebp+var_20], eax
                mov     ecx, [ebp+var_14]
                call    sub_791642
                mov     eax, [ebp+var_10]
                cmp     dword ptr [eax], 0
                jz      short loc_7922B7
                mov     eax, [ebp+var_1C]
                push    dword ptr [eax]
                mov     eax, [ebp+var_10]
                push    dword ptr [eax]
                mov     ecx, [ebp+var_18]
                call    sub_7925B7
                mov     ecx, [ebp+var_18]
                call    sub_792205
                mov     [ebp+var_2C], eax
                mov     eax, [ebp+var_20]
                mov     ecx, [ebp+var_10]
                mov     eax, [eax]
                sub     eax, [ecx]
                sar     eax, 3
                mov     [ebp+var_24], eax
                mov     eax, [ebp+var_10]
                mov     eax, [eax]
                mov     [ebp+Block], eax
                push    [ebp+var_24]    ; int
                push    [ebp+Block]     ; Block
                mov     ecx, [ebp+var_2C]
                call    sub_79261E
                mov     eax, [ebp+var_10]
                and     dword ptr [eax], 0
                mov     eax, [ebp+var_1C]
                and     dword ptr [eax], 0
                mov     eax, [ebp+var_20]
                and     dword ptr [eax], 0

loc_7922B7:                             ; CODE XREF: sub_792216+4A↑j
                mov     ecx, [ebp+var_C]
                mov     large fs:0, ecx
                leave
                retn
; } // starts at 792216
sub_792216      endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int __thiscall sub_7922C8(int *this, unsigned int)
sub_7922C8      proc near               ; CODE XREF: sub_791E6C+95↑p

var_1C          = dword ptr -1Ch
var_18          = dword ptr -18h
var_14          = dword ptr -14h
var_10          = dword ptr -10h
var_C           = dword ptr -0Ch
var_8           = dword ptr -8
var_4           = dword ptr -4
arg_0           = dword ptr  8

                push    ebp
                mov     ebp, esp
                sub     esp, 1Ch
                mov     [ebp+var_C], ecx
                mov     eax, [ebp+var_C]
                mov     [ebp+var_4], eax
                mov     eax, [ebp+var_4]
                mov     [ebp+var_14], eax
                mov     eax, [ebp+var_4]
                add     eax, 4
                mov     [ebp+var_18], eax
                mov     eax, [ebp+var_4]
                add     eax, 8
                mov     [ebp+var_1C], eax
                mov     ecx, [ebp+var_C]
                call    sub_792205
                mov     [ebp+var_10], eax
                push    [ebp+arg_0]
                mov     ecx, [ebp+var_10]
                call    sub_7925D9
                mov     [ebp+var_8], eax
                mov     eax, [ebp+var_14]
                mov     ecx, [ebp+var_8]
                mov     [eax], ecx
                mov     eax, [ebp+var_18]
                mov     ecx, [ebp+var_8]
                mov     [eax], ecx
                mov     eax, [ebp+arg_0]
                mov     ecx, [ebp+var_8]
                lea     eax, [ecx+eax*8]
                mov     ecx, [ebp+var_1C]
                mov     [ecx], eax
                leave
                retn    4
sub_7922C8      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _BYTE *__thiscall sub_79232A(void **this)
sub_79232A      proc near               ; CODE XREF: Process_Input+A↑p

var_1C          = dword ptr -1Ch
Block           = dword ptr -18h
var_14          = dword ptr -14h
var_D           = byte ptr -0Dh
var_C           = dword ptr -0Ch

; FUNCTION CHUNK AT 007964D6 SIZE 0000000C BYTES

; __unwind { // SEH_403751
                push    ebp
                mov     ebp, esp
                push    0FFFFFFFFh
                push    offset SEH_402D9C
                mov     eax, large fs:0
                push    eax
                mov     large fs:0, esp
                sub     esp, 10h
                mov     [ebp+var_14], ecx
                mov     ecx, [ebp+var_14]
                call    sub_791642
                mov     ecx, [ebp+var_14]
                call    sub_7926CF
                movzx   eax, al
                test    eax, eax
                jz      short loc_79238E
                mov     eax, [ebp+var_14]
                mov     eax, [eax]
                mov     [ebp+Block], eax
                mov     ecx, [ebp+var_14]
                call    sub_792205
                mov     [ebp+var_1C], eax
                push    [ebp+var_14]
                call    sub_792C63
                pop     ecx
                mov     eax, [ebp+var_14]
                mov     eax, [eax+14h]
                inc     eax
                push    eax             ; int
                push    [ebp+Block]     ; Block
                mov     ecx, [ebp+var_1C]
                call    sub_7927E0

loc_79238E:                             ; CODE XREF: sub_79232A+33↑j
                mov     eax, [ebp+var_14]
                and     dword ptr [eax+10h], 0
                mov     eax, [ebp+var_14]
                mov     dword ptr [eax+14h], 0Fh
                mov     [ebp+var_D], 0
                lea     eax, [ebp+var_D]
                push    eax
                xor     eax, eax
                inc     eax
                imul    eax, 0
                add     eax, [ebp+var_14]
                push    eax
                call    sub_792524
                pop     ecx
                pop     ecx
                mov     ecx, [ebp+var_C]
                mov     large fs:0, ecx
                leave
                retn
; } // starts at 79232A
sub_79232A      endp

; ---------------------------------------------------------------------------
                db 5 dup(0CCh)

; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _BYTE *__thiscall sub_7923C9(int this)
sub_7923C9      proc near               ; CODE XREF: sub_7920BA+4A↑p

var_8           = dword ptr -8
var_1           = byte ptr -1

                push    ebp
                mov     ebp, esp
                push    ecx
                push    ecx
                mov     [ebp+var_8], ecx
                mov     eax, [ebp+var_8]
                and     dword ptr [eax+10h], 0
                mov     eax, [ebp+var_8]
                mov     dword ptr [eax+14h], 0Fh
                mov     [ebp+var_1], 0
                lea     eax, [ebp+var_1]
                push    eax
                xor     eax, eax
                inc     eax
                imul    eax, 0
                add     eax, [ebp+var_8]
                push    eax
                call    sub_792524
                pop     ecx
                pop     ecx
                leave
                retn
sub_7923C9      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; unsigned int *__thiscall sub_7923FD(unsigned int *this, char *Src)
sub_7923FD      proc near               ; CODE XREF: sub_7920BA+55↑p

var_4           = dword ptr -4
Src             = dword ptr  8

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+var_4], ecx
                push    [ebp+Src]
                call    sub_792533
                pop     ecx
                push    eax
                call    unknown_libname_3 ; Microsoft VisualC 14/net runtime
                pop     ecx
                push    eax             ; Size
                push    [ebp+Src]       ; Src
                mov     ecx, [ebp+var_4]
                call    sub_792424
                leave
                retn    4
sub_7923FD      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; unsigned int *__thiscall sub_792424(unsigned int *this, char *Src, size_t Size)
sub_792424      proc near               ; CODE XREF: sub_7923FD+1E↑p

var_10          = byte ptr -10h
var_C           = dword ptr -0Ch
var_8           = dword ptr -8
var_1           = byte ptr -1
Src             = dword ptr  8
Size            = dword ptr  0Ch

                push    ebp
                mov     ebp, esp
                sub     esp, 10h
                mov     [ebp+var_8], ecx
                mov     eax, [ebp+var_8]
                mov     ecx, [ebp+Size]
                cmp     ecx, [eax+14h]
                ja      short loc_792478
                mov     ecx, [ebp+var_8]
                call    sub_7924C0
                mov     [ebp+var_C], eax
                mov     eax, [ebp+var_8]
                mov     ecx, [ebp+Size]
                mov     [eax+10h], ecx
                push    [ebp+Size]      ; Size
                push    [ebp+Src]       ; Src
                push    [ebp+var_C]     ; void *
                call    sub_7926F2
                add     esp, 0Ch
                mov     [ebp+var_1], 0
                lea     eax, [ebp+var_1]
                push    eax
                mov     eax, [ebp+var_C]
                add     eax, [ebp+Size]
                push    eax
                call    sub_792524
                pop     ecx
                pop     ecx
                mov     eax, [ebp+var_8]
                jmp     short locret_792489
; ---------------------------------------------------------------------------

loc_792478:                             ; CODE XREF: sub_792424+12↑j
                push    [ebp+Src]       ; Src
                push    dword ptr [ebp+var_10] ; char
                push    [ebp+Size]      ; Size
                mov     ecx, [ebp+var_8]
                call    sub_792C68

locret_792489:                          ; CODE XREF: sub_792424+52↑j
                leave
                retn    8
sub_792424      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _BYTE *__stdcall sub_79248D(_BYTE *, size_t Size, _BYTE *Src)
sub_79248D      proc near               ; CODE XREF: sub_792C68+7A↓p

var_8           = dword ptr -8
var_1           = byte ptr -1
arg_0           = dword ptr  8
Size            = dword ptr  0Ch
Src             = dword ptr  10h

                push    ebp
                mov     ebp, esp
                push    ecx
                push    ecx
                mov     [ebp+var_8], ecx
                push    [ebp+Size]      ; Size
                push    [ebp+Src]       ; Src
                push    [ebp+arg_0]     ; void *
                call    sub_792565
                add     esp, 0Ch
                mov     [ebp+var_1], 0
                lea     eax, [ebp+var_1]
                push    eax
                mov     eax, [ebp+arg_0]
                add     eax, [ebp+Size]
                push    eax
                call    sub_792524
                pop     ecx
                pop     ecx
                leave
                retn    0Ch
sub_79248D      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int *__thiscall sub_7924C0(int *this)
sub_7924C0      proc near               ; CODE XREF: sub_791FCE+2A↑p
                                        ; sub_79208B+A↑p ...

var_8           = dword ptr -8
var_4           = dword ptr -4

                push    ebp
                mov     ebp, esp
                push    ecx
                push    ecx
                mov     [ebp+var_4], ecx
                mov     eax, [ebp+var_4]
                mov     [ebp+var_8], eax
                mov     ecx, [ebp+var_4]
                call    sub_7926CF
                movzx   eax, al
                test    eax, eax
                jz      short loc_7924EB
                mov     eax, [ebp+var_4]
                push    dword ptr [eax]
                call    unknown_libname_3 ; Microsoft VisualC 14/net runtime
                pop     ecx
                mov     [ebp+var_8], eax

loc_7924EB:                             ; CODE XREF: sub_7924C0+1B↑j
                mov     eax, [ebp+var_8]
                leave
                retn
sub_7924C0      endp

; [00000008 BYTES: COLLAPSED FUNCTION std::numeric_limits<uint>::max(void). PRESS CTRL-NUMPAD+ TO EXPAND]

; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; bool __cdecl sub_7924F8(_DWORD *, _DWORD *)
sub_7924F8      proc near               ; CODE XREF: sub_792F66+17A↓p

var_4           = dword ptr -4
arg_0           = dword ptr  8
arg_4           = dword ptr  0Ch

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     eax, [ebp+arg_0]
                mov     ecx, [ebp+arg_4]
                mov     eax, [eax]
                cmp     eax, [ecx]
                jnz     short loc_792511
                mov     [ebp+var_4], 1
                jmp     short loc_792515
; ---------------------------------------------------------------------------

loc_792511:                             ; CODE XREF: sub_7924F8+E↑j
                and     [ebp+var_4], 0

loc_792515:                             ; CODE XREF: sub_7924F8+17↑j
                mov     al, byte ptr [ebp+var_4]
                leave
                retn
sub_7924F8      endp

; [0000000A BYTES: COLLAPSED FUNCTION std::_Narrow_char_traits<char,int>::to_char_type(int const &). PRESS CTRL-NUMPAD+ TO EXPAND]

; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _BYTE *__cdecl sub_792524(_BYTE *, _BYTE *)
sub_792524      proc near               ; CODE XREF: sub_791FCE+3D↑p
                                        ; sub_791FCE+57↑p ...

arg_0           = dword ptr  8
arg_4           = dword ptr  0Ch

                push    ebp
                mov     ebp, esp
                mov     eax, [ebp+arg_0]
                mov     ecx, [ebp+arg_4]
                mov     cl, [ecx]
                mov     [eax], cl
                pop     ebp
                retn
sub_792524      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; unsigned int __cdecl sub_792533(const char *)
sub_792533      proc near               ; CODE XREF: sub_7923FD+A↑p

var_10          = dword ptr -10h
var_C           = dword ptr -0Ch
var_8           = dword ptr -8
var_1           = byte ptr -1
arg_0           = dword ptr  8

                push    ebp
                mov     ebp, esp
                sub     esp, 10h
                mov     eax, [ebp+arg_0]
                mov     [ebp+var_8], eax
                mov     eax, [ebp+var_8]
                inc     eax
                mov     [ebp+var_C], eax

loc_792546:                             ; CODE XREF: sub_792533+22↓j
                mov     eax, [ebp+var_8]
                mov     al, [eax]
                mov     [ebp+var_1], al
                inc     [ebp+var_8]
                cmp     [ebp+var_1], 0
                jnz     short loc_792546
                mov     eax, [ebp+var_8]
                sub     eax, [ebp+var_C]
                mov     [ebp+var_10], eax
                mov     eax, [ebp+var_10]
                leave
                retn
sub_792533      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _BYTE *__cdecl sub_792565(_BYTE *, _BYTE *Src, size_t Size)
sub_792565      proc near               ; CODE XREF: sub_792042+11↑p
                                        ; sub_79248D+11↑p

var_4           = dword ptr -4
arg_0           = dword ptr  8
Src             = dword ptr  0Ch
Size            = dword ptr  10h

                push    ebp
                mov     ebp, esp
                push    ecx
                call    sub_791328
                movzx   eax, al
                test    eax, eax
                jz      short loc_7925A1
                and     [ebp+var_4], 0
                jmp     short loc_792582
; ---------------------------------------------------------------------------

loc_79257B:                             ; CODE XREF: sub_792565+35↓j
                mov     eax, [ebp+var_4]
                inc     eax
                mov     [ebp+var_4], eax

loc_792582:                             ; CODE XREF: sub_792565+14↑j
                mov     eax, [ebp+var_4]
                cmp     eax, [ebp+Size]
                jnb     short loc_79259C
                mov     eax, [ebp+arg_0]
                add     eax, [ebp+var_4]
                mov     ecx, [ebp+Src]
                add     ecx, [ebp+var_4]
                mov     cl, [ecx]
                mov     [eax], cl
                jmp     short loc_79257B
; ---------------------------------------------------------------------------

loc_79259C:                             ; CODE XREF: sub_792565+23↑j
                mov     eax, [ebp+arg_0]
                jmp     short locret_7925B5
; ---------------------------------------------------------------------------

loc_7925A1:                             ; CODE XREF: sub_792565+E↑j
                push    [ebp+Size]      ; Size
                push    [ebp+Src]       ; Src
                push    [ebp+arg_0]     ; void *
                call    memcpy
                add     esp, 0Ch
                mov     eax, [ebp+arg_0]

locret_7925B5:                          ; CODE XREF: sub_792565+3A↑j
                leave
                retn
sub_792565      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; void __thiscall sub_7925B7(void *this, int, int)
sub_7925B7      proc near               ; CODE XREF: sub_792216+59↑p
                                        ; sub_7929E8+5F↓p ...

var_4           = dword ptr -4
arg_0           = dword ptr  8
arg_4           = dword ptr  0Ch

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+var_4], ecx
                mov     ecx, [ebp+var_4]
                call    sub_792205
                push    eax
                push    [ebp+arg_4]
                push    [ebp+arg_0]
                call    sub_792C63
                add     esp, 0Ch
                leave
                retn    8
sub_7925B7      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int __stdcall sub_7925D9(unsigned int)
sub_7925D9      proc near               ; CODE XREF: sub_7922C8+38↑p
                                        ; sub_793363+7B↓p

var_4           = dword ptr -4
arg_0           = dword ptr  8

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+var_4], ecx
                push    [ebp+arg_0]
                call    sub_792D4A
                pop     ecx
                push    eax
                call    sub_792D70
                pop     ecx
                leave
                retn    4
sub_7925D9      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _DWORD *__cdecl sub_7925F4(_DWORD *, _DWORD *)
sub_7925F4      proc near               ; CODE XREF: sub_792677+2A↓p
                                        ; sub_792F19+42↓p

var_8           = dword ptr -8
var_4           = dword ptr -4
arg_0           = dword ptr  8
arg_4           = dword ptr  0Ch

                push    ebp
                mov     ebp, esp
                push    ecx
                push    ecx
                mov     eax, [ebp+arg_0]
                mov     ecx, [ebp+arg_4]
                mov     eax, [eax]
                cmp     eax, [ecx]
                jnb     short loc_79260D
                mov     eax, [ebp+arg_4]
                mov     [ebp+var_4], eax
                jmp     short loc_792613
; ---------------------------------------------------------------------------

loc_79260D:                             ; CODE XREF: sub_7925F4+F↑j
                mov     eax, [ebp+arg_0]
                mov     [ebp+var_4], eax

loc_792613:                             ; CODE XREF: sub_7925F4+17↑j
                mov     eax, [ebp+var_4]
                mov     [ebp+var_8], eax
                mov     eax, [ebp+var_8]
                leave
                retn
sub_7925F4      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; void __stdcall sub_79261E(void *Block, int)
sub_79261E      proc near               ; CODE XREF: sub_792216+8A↑p
                                        ; sub_793363+F4↓p ...

var_4           = dword ptr -4
Block           = dword ptr  8
arg_4           = dword ptr  0Ch

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+var_4], ecx
                mov     eax, [ebp+arg_4]
                shl     eax, 3
                push    eax             ; int
                push    [ebp+Block]     ; Block
                call    sub_792D9C
                pop     ecx
                pop     ecx
                leave
                retn    8
sub_79261E      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _BYTE *__thiscall sub_79263A(int *this, int)
sub_79263A      proc near               ; CODE XREF: sub_79392C+1F↓p

var_10          = dword ptr -10h
var_C           = dword ptr -0Ch
var_8           = dword ptr -8
var_1           = byte ptr -1
arg_0           = dword ptr  8

                push    ebp
                mov     ebp, esp
                sub     esp, 10h
                mov     [ebp+var_8], ecx
                mov     [ebp+var_1], 0
                mov     ecx, [ebp+var_8]
                call    sub_7924C0
                mov     [ebp+var_C], eax
                mov     eax, [ebp+var_8]
                mov     ecx, [ebp+arg_0]
                mov     [eax+10h], ecx
                mov     eax, [ebp+arg_0]
                mov     [ebp+var_10], eax
                lea     eax, [ebp+var_1]
                push    eax
                mov     eax, [ebp+var_C]
                add     eax, [ebp+var_10]
                push    eax
                call    sub_792524
                pop     ecx
                pop     ecx
                leave
                retn    4
sub_79263A      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int __thiscall sub_792677(void *this)
sub_792677      proc near               ; CODE XREF: sub_792B4B+1B↓p
                                        ; sub_792C68+C↓p ...

var_18          = dword ptr -18h
var_14          = dword ptr -14h
var_10          = dword ptr -10h
var_C           = dword ptr -0Ch
var_8           = dword ptr -8
var_4           = dword ptr -4

                push    ebp
                mov     ebp, esp
                sub     esp, 18h
                mov     [ebp+var_4], ecx
                mov     ecx, [ebp+var_4]
                call    sub_792205
                push    eax
                call    ?max@?$numeric_limits@I@std@@SAIXZ ; std::numeric_limits<uint>::max(void)
                pop     ecx
                mov     [ebp+var_C], eax
                mov     [ebp+var_8], 10h
                lea     eax, [ebp+var_8]
                push    eax
                lea     eax, [ebp+var_C]
                push    eax
                call    sub_7925F4
                pop     ecx
                pop     ecx
                mov     eax, [eax]
                mov     [ebp+var_10], eax
                mov     eax, [ebp+var_10]
                dec     eax
                mov     [ebp+var_14], eax
                call    unknown_libname_1 ; Microsoft VisualC 14/net runtime
                mov     [ebp+var_18], eax
                lea     eax, [ebp+var_14]
                push    eax
                lea     eax, [ebp+var_18]
                push    eax
                call    sub_792B21
                pop     ecx
                pop     ecx
                mov     eax, [eax]
                leave
                retn
sub_792677      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; bool __thiscall sub_7926CF(_DWORD *this)
sub_7926CF      proc near               ; CODE XREF: sub_79232A+29↑p
                                        ; sub_7924C0+11↑p

var_8           = dword ptr -8
var_4           = dword ptr -4

                push    ebp
                mov     ebp, esp
                push    ecx
                push    ecx
                mov     [ebp+var_8], ecx
                mov     eax, [ebp+var_8]
                cmp     dword ptr [eax+14h], 10h ; check digits?
                jb      short loc_7926E9
                mov     [ebp+var_4], 1
                jmp     short loc_7926ED
; ---------------------------------------------------------------------------

loc_7926E9:                             ; CODE XREF: sub_7926CF+F↑j
                and     [ebp+var_4], 0

loc_7926ED:                             ; CODE XREF: sub_7926CF+18↑j
                mov     al, byte ptr [ebp+var_4]
                leave
                retn
sub_7926CF      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; char *__cdecl sub_7926F2(char *, char *Src, size_t Size)
sub_7926F2      proc near               ; CODE XREF: sub_792424+31↑p

var_10          = dword ptr -10h
var_C           = dword ptr -0Ch
var_8           = dword ptr -8
var_1           = byte ptr -1
arg_0           = dword ptr  8
Src             = dword ptr  0Ch
Size            = dword ptr  10h

                push    ebp
                mov     ebp, esp
                sub     esp, 10h
                push    esi
                call    sub_791328
                movzx   eax, al
                test    eax, eax
                jz      loc_7927AE
                mov     eax, [ebp+arg_0]
                cmp     eax, [ebp+Src]
                jnz     short loc_792719
                mov     eax, [ebp+arg_0]
                jmp     loc_7927C2
; ---------------------------------------------------------------------------

loc_792719:                             ; CODE XREF: sub_7926F2+1D↑j
                mov     [ebp+var_1], 1
                mov     eax, [ebp+Src]
                mov     [ebp+var_10], eax
                jmp     short loc_79272C
; ---------------------------------------------------------------------------

loc_792725:                             ; CODE XREF: sub_7926F2:loc_792745↓j
                mov     eax, [ebp+var_10]
                inc     eax
                mov     [ebp+var_10], eax

loc_79272C:                             ; CODE XREF: sub_7926F2+31↑j
                mov     eax, [ebp+Src]
                add     eax, [ebp+Size]
                cmp     [ebp+var_10], eax
                jz      short loc_792747
                mov     eax, [ebp+arg_0]
                cmp     eax, [ebp+var_10]
                jnz     short loc_792745
                mov     [ebp+var_1], 0
                jmp     short loc_792747
; ---------------------------------------------------------------------------

loc_792745:                             ; CODE XREF: sub_7926F2+4B↑j
                jmp     short loc_792725
; ---------------------------------------------------------------------------

loc_792747:                             ; CODE XREF: sub_7926F2+43↑j
                                        ; sub_7926F2+51↑j
                movzx   eax, [ebp+var_1]
                test    eax, eax
                jz      short loc_792778
                and     [ebp+var_8], 0
                jmp     short loc_79275C
; ---------------------------------------------------------------------------

loc_792755:                             ; CODE XREF: sub_7926F2+82↓j
                mov     eax, [ebp+var_8]
                inc     eax
                mov     [ebp+var_8], eax

loc_79275C:                             ; CODE XREF: sub_7926F2+61↑j
                mov     eax, [ebp+var_8]
                cmp     eax, [ebp+Size]
                jnb     short loc_792776
                mov     eax, [ebp+arg_0]
                add     eax, [ebp+var_8]
                mov     ecx, [ebp+Src]
                add     ecx, [ebp+var_8]
                mov     cl, [ecx]
                mov     [eax], cl
                jmp     short loc_792755
; ---------------------------------------------------------------------------

loc_792776:                             ; CODE XREF: sub_7926F2+70↑j
                jmp     short loc_7927A9
; ---------------------------------------------------------------------------

loc_792778:                             ; CODE XREF: sub_7926F2+5B↑j
                and     [ebp+var_C], 0
                jmp     short loc_792785
; ---------------------------------------------------------------------------

loc_79277E:                             ; CODE XREF: sub_7926F2+B5↓j
                mov     eax, [ebp+var_C]
                inc     eax
                mov     [ebp+var_C], eax

loc_792785:                             ; CODE XREF: sub_7926F2+8A↑j
                mov     eax, [ebp+var_C]
                cmp     eax, [ebp+Size]
                jnb     short loc_7927A9
                mov     eax, [ebp+Size]
                dec     eax
                sub     eax, [ebp+var_C]
                mov     ecx, [ebp+Size]
                dec     ecx
                sub     ecx, [ebp+var_C]
                mov     edx, [ebp+arg_0]
                mov     esi, [ebp+Src]
                mov     al, [esi+eax]
                mov     [edx+ecx], al
                jmp     short loc_79277E
; ---------------------------------------------------------------------------

loc_7927A9:                             ; CODE XREF: sub_7926F2:loc_792776↑j
                                        ; sub_7926F2+99↑j
                mov     eax, [ebp+arg_0]
                jmp     short loc_7927C2
; ---------------------------------------------------------------------------

loc_7927AE:                             ; CODE XREF: sub_7926F2+11↑j
                push    [ebp+Size]      ; Size
                push    [ebp+Src]       ; Src
                push    [ebp+arg_0]     ; void *
                call    memmove
                add     esp, 0Ch
                mov     eax, [ebp+arg_0]

loc_7927C2:                             ; CODE XREF: sub_7926F2+22↑j
                                        ; sub_7926F2+BA↑j
                pop     esi
                leave
                retn
sub_7926F2      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; void *__stdcall sub_7927C5(int)
sub_7927C5      proc near               ; CODE XREF: sub_792B4B+60↓p
                                        ; sub_792C68+45↓p

var_4           = dword ptr -4
arg_0           = dword ptr  8

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+var_4], ecx
                push    [ebp+arg_0]
                call    sub_792DEA
                pop     ecx
                push    eax
                call    sub_792D70
                pop     ecx
                leave
                retn    4
sub_7927C5      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; void __stdcall sub_7927E0(void *Block, int)
sub_7927E0      proc near               ; CODE XREF: sub_79232A+5F↑p
                                        ; sub_792B4B+C2↓p ...

var_4           = dword ptr -4
Block           = dword ptr  8
arg_4           = dword ptr  0Ch

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+var_4], ecx
                push    [ebp+arg_4]     ; int
                push    [ebp+Block]     ; Block
                call    sub_792D9C
                pop     ecx
                pop     ecx
                leave
                retn    8
sub_7927E0      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; void __thiscall sub_7927F8(_DWORD *this, unsigned int)
sub_7927F8      proc near               ; CODE XREF: sub_79392C+14↓p

var_4           = dword ptr -4
arg_0           = dword ptr  8

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+var_4], ecx
                mov     eax, [ebp+var_4]
                mov     eax, [eax+10h]
                cmp     eax, [ebp+arg_0]
                jnb     short locret_79280F
                call    sub_792813

locret_79280F:                          ; CODE XREF: sub_7927F8+10↑j
                leave
                retn    4
sub_7927F8      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; void sub_792813()
sub_792813      proc near               ; CODE XREF: sub_7927F8+12↑p
                push    ebp
                mov     ebp, esp
                push    offset aInvalidStringP ; "invalid string position"
                call    ds:?_Xout_of_range@std@@YAXPBD@Z ; std::_Xout_of_range(char const *)
                pop     ebp
                retn
sub_792813      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; struct std::_Facet_base *__cdecl sub_792823(_DWORD *)
sub_792823      proc near               ; CODE XREF: sub_792F66+79↓p

var_28          = dword ptr -28h
var_24          = byte ptr -24h
var_20          = dword ptr -20h
var_1C          = dword ptr -1Ch
var_18          = dword ptr -18h
var_14          = dword ptr -14h
var_10          = dword ptr -10h
var_C           = dword ptr -0Ch
var_4           = dword ptr -4
arg_0           = dword ptr  8

; FUNCTION CHUNK AT 00796578 SIZE 00000011 BYTES
; FUNCTION CHUNK AT 0079658E SIZE 0000000C BYTES

; __unwind { // SEH_402823
                push    ebp
                mov     ebp, esp
                push    0FFFFFFFFh
                push    offset SEH_402823
                mov     eax, large fs:0
                push    eax
                mov     large fs:0, esp
                sub     esp, 1Ch
                push    0
                lea     ecx, [ebp+var_24]
                call    ds:??0_Lockit@std@@QAE@H@Z ; std::_Lockit::_Lockit(int)
;   try {
                and     [ebp+var_4], 0
                mov     eax, dword_799430
                mov     [ebp+var_10], eax
                mov     ecx, ds:?id@?$ctype@D@std@@2V0locale@2@A ; std::locale::id std::ctype<char>::id
                call    ds:??Bid@locale@std@@QAEIXZ ; std::locale::id::operator uint(void)
                mov     [ebp+var_20], eax
                push    [ebp+var_20]
                mov     ecx, [ebp+arg_0]
                call    sub_791721
                mov     [ebp+var_18], eax
                cmp     [ebp+var_18], 0
                jnz     short loc_7928EC
                cmp     [ebp+var_10], 0
                jz      short loc_792886
                mov     eax, [ebp+var_10]
                mov     [ebp+var_18], eax
                jmp     short loc_7928EC
; ---------------------------------------------------------------------------

loc_792886:                             ; CODE XREF: sub_792823+59↑j
                push    [ebp+arg_0]
                lea     eax, [ebp+var_10]
                push    eax
                call    ds:?_Getcat@?$ctype@D@std@@SAIPAPBVfacet@locale@2@PBV42@@Z ; std::ctype<char>::_Getcat(std::locale::facet const * *,std::locale const *)
                pop     ecx
                pop     ecx
                cmp     eax, 0FFFFFFFFh
                jnz     short loc_7928A1
                call    sub_791698
; ---------------------------------------------------------------------------
                jmp     short loc_7928EC
; ---------------------------------------------------------------------------

loc_7928A1:                             ; CODE XREF: sub_792823+75↑j
                mov     eax, [ebp+var_10]
                mov     [ebp+var_14], eax
                push    [ebp+var_14]
                lea     ecx, [ebp+var_1C]
                call    sub_7931DB
;   } // starts at 792849
;   try {
                mov     byte ptr [ebp+var_4], 1
                push    [ebp+var_14]    ; struct std::_Facet_base *
                call    ?_Facet_Register@std@@YAXPAV_Facet_base@1@@Z ; std::_Facet_Register(std::_Facet_base *)
                pop     ecx
                mov     eax, [ebp+var_14]
                mov     eax, [eax]
                mov     ecx, [ebp+var_14]
                call    dword ptr [eax+4]
                mov     eax, [ebp+var_10]
                mov     dword_799430, eax
                mov     eax, [ebp+var_10]
                mov     [ebp+var_18], eax
                lea     ecx, [ebp+var_1C]
                call    sub_792DF7
;   } // starts at 7928B2
;   try {
                mov     byte ptr [ebp+var_4], 0
                lea     ecx, [ebp+var_1C]
                call    sub_792E13

loc_7928EC:                             ; CODE XREF: sub_792823+53↑j
                                        ; sub_792823+61↑j ...
                mov     eax, [ebp+var_18]
                mov     [ebp+var_28], eax
;   } // starts at 7928E0
                or      [ebp+var_4], 0FFFFFFFFh
                lea     ecx, [ebp+var_24]
                call    ds:??1_Lockit@std@@QAE@XZ ; std::_Lockit::~_Lockit(void)
                mov     eax, [ebp+var_28]
                mov     ecx, [ebp+var_C]
                mov     large fs:0, ecx
                leave
                retn
; } // starts at 792823
sub_792823      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int __cdecl sub_79290E(int, _DWORD *)
sub_79290E      proc near               ; CODE XREF: sub_7919EF+45↑p

arg_0           = dword ptr  8
arg_4           = dword ptr  0Ch

                push    ebp
                mov     ebp, esp
                push    [ebp+arg_0]
                call    unknown_libname_3 ; Microsoft VisualC 14/net runtime
                pop     ecx
                push    [ebp+arg_4]
                push    eax
                call    sub_792F66
                pop     ecx
                pop     ecx
                pop     ebp
                retn
sub_79290E      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _QWORD *__thiscall sub_792927(_QWORD *this, int *)
sub_792927      proc near               ; CODE XREF: _main+9D↑p

var_4           = dword ptr -4
arg_0           = dword ptr  8

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+var_4], ecx
                mov     eax, [ebp+arg_0]
                mov     eax, [eax]
                cdq
                mov     ecx, [ebp+var_4]
                mov     [ecx], eax
                mov     [ecx+4], edx
                mov     eax, [ebp+var_4]
                leave
                retn    4
sub_792927      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; BOOL __cdecl sub_792943(void *)
sub_792943      proc near               ; CODE XREF: _main+A3↑p

var_10          = dword ptr -10h
var_8           = dword ptr -8
arg_0           = dword ptr  8

                push    ebp
                mov     ebp, esp
                sub     esp, 10h
                push    [ebp+arg_0]
                lea     eax, [ebp+var_8]
                push    eax
                call    sub_7917C3
                pop     ecx
                push    eax
                lea     eax, [ebp+var_10]
                push    eax
                call    sub_793200
                add     esp, 0Ch
                push    eax
                call    sub_793230
                pop     ecx
                leave
                retn
sub_792943      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int sub_79296C()
sub_79296C      proc near               ; CODE XREF: sub_791CF9+7↑p
                                        ; sub_7921A2+7↑p

var_10          = dword ptr -10h
var_C           = dword ptr -0Ch
var_8           = dword ptr -8
var_4           = dword ptr -4

                push    ebp
                mov     ebp, esp
                sub     esp, 10h
                call    sub_7915BF
                mov     [ebp+var_8], eax
                mov     [ebp+var_4], edx
                call    sub_7915B6
                mov     [ebp+var_10], eax
                mov     [ebp+var_C], edx
                push    [ebp+var_4]
                push    [ebp+var_8]
                push    [ebp+var_C]
                push    [ebp+var_10]
                call    sub_793285
                add     esp, 10h
                leave
                retn
sub_79296C      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; __int16 sub_79299E()
sub_79299E      proc near               ; CODE XREF: sub_791D9F+7↑p

var_8           = dword ptr -8
var_4           = dword ptr -4

                push    ebp
                mov     ebp, esp
                push    ecx
                push    ecx
                call    unknown_libname_2 ; Microsoft VisualC 14/net runtime
                mov     word ptr [ebp+var_4], ax
                call    ___scrt_stub_for_initialize_mta
                mov     word ptr [ebp+var_8], ax
                push    [ebp+var_4]
                push    [ebp+var_8]
                call    sub_7932D3
                pop     ecx
                pop     ecx
                leave
                retn
sub_79299E      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int sub_7929C4()
sub_7929C4      proc near               ; CODE XREF: sub_791DDF+7↑p
                                        ; sub_794802+7↓p

var_8           = dword ptr -8
var_4           = dword ptr -4

                push    ebp
                mov     ebp, esp
                push    ecx
                push    ecx
                call    unknown_libname_1 ; Microsoft VisualC 14/net runtime
                mov     [ebp+var_4], eax
                call    ?min@?$numeric_limits@H@std@@SAHXZ ; std::numeric_limits<int>::min(void)
                mov     [ebp+var_8], eax
                push    [ebp+var_4]
                push    [ebp+var_8]
                call    sub_79331B
                pop     ecx
                pop     ecx
                leave
                retn
sub_7929C4      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; void __thiscall sub_7929E8(int *this, unsigned int, unsigned __int8 *)
sub_7929E8      proc near               ; CODE XREF: sub_791E40+12↑p

var_20          = dword ptr -20h
var_1C          = dword ptr -1Ch
var_18          = dword ptr -18h
var_14          = dword ptr -14h
var_10          = dword ptr -10h
var_C           = dword ptr -0Ch
var_8           = dword ptr -8
var_4           = dword ptr -4
arg_0           = dword ptr  8
arg_4           = dword ptr  0Ch

                push    ebp
                mov     ebp, esp
                sub     esp, 20h
                mov     [ebp+var_8], ecx
                mov     eax, [ebp+var_8]
                mov     [ebp+var_10], eax
                mov     eax, [ebp+var_10]
                mov     [ebp+var_14], eax
                mov     eax, [ebp+var_10]
                add     eax, 4
                mov     [ebp+var_4], eax
                mov     eax, [ebp+var_4]
                mov     ecx, [ebp+var_14]
                mov     eax, [eax]
                sub     eax, [ecx]
                sar     eax, 3
                mov     [ebp+var_18], eax
                mov     eax, [ebp+arg_0]
                cmp     eax, [ebp+var_18]
                jnb     short loc_792A56
                mov     eax, [ebp+var_14]
                mov     eax, [eax]
                mov     ecx, [ebp+arg_0]
                lea     eax, [eax+ecx*8]
                mov     [ebp+var_C], eax
                mov     eax, [ebp+var_4]
                push    dword ptr [eax]
                push    [ebp+var_C]
                mov     ecx, [ebp+var_8]
                call    sub_792E64
                mov     eax, [ebp+var_4]
                push    dword ptr [eax]
                push    [ebp+var_C]
                mov     ecx, [ebp+var_8]
                call    sub_7925B7
                mov     eax, [ebp+var_4]
                mov     ecx, [ebp+var_C]
                mov     [eax], ecx
                jmp     short locret_792ABB
; ---------------------------------------------------------------------------

loc_792A56:                             ; CODE XREF: sub_7929E8+34↑j
                mov     eax, [ebp+arg_0]
                cmp     eax, [ebp+var_18]
                jbe     short locret_792ABB
                mov     eax, [ebp+var_10]
                mov     ecx, [ebp+var_14]
                mov     eax, [eax+8]
                sub     eax, [ecx]
                sar     eax, 3
                mov     [ebp+var_20], eax
                mov     eax, [ebp+arg_0]
                cmp     eax, [ebp+var_20]
                jbe     short loc_792A87
                push    [ebp+arg_4]
                push    [ebp+arg_0]
                mov     ecx, [ebp+var_8]
                call    sub_793363
                jmp     short locret_792ABB
; ---------------------------------------------------------------------------

loc_792A87:                             ; CODE XREF: sub_7929E8+8D↑j
                mov     eax, [ebp+var_4]
                mov     eax, [eax]
                mov     [ebp+var_1C], eax
                mov     eax, [ebp+arg_4]
                movzx   eax, byte ptr [eax]
                push    eax
                mov     eax, [ebp+arg_0]
                sub     eax, [ebp+var_18]
                push    eax
                push    [ebp+var_1C]
                mov     ecx, [ebp+var_8]
                call    sub_792E6F
                mov     ecx, [ebp+var_4]
                mov     [ecx], eax
                push    [ebp+var_1C]
                push    [ebp+var_1C]
                mov     ecx, [ebp+var_8]
                call    sub_792E64

locret_792ABB:                          ; CODE XREF: sub_7929E8+6C↑j
                                        ; sub_7929E8+74↑j ...
                leave
                retn    8
sub_7929E8      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _DWORD *__thiscall sub_792ABF(_DWORD *this, int, int)
sub_792ABF      proc near               ; CODE XREF: sub_791E6C+4A↑p

var_4           = dword ptr -4
arg_4           = dword ptr  0Ch

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+var_4], ecx
                push    [ebp+arg_4]
                call    unknown_libname_3 ; Microsoft VisualC 14/net runtime
                pop     ecx
                mov     ecx, [ebp+var_4]
                call    sub_792E44
                mov     eax, [ebp+var_4]
                leave
                retn    8
sub_792ABF      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int __thiscall sub_792ADE(void *this, int, int, int)
sub_792ADE      proc near               ; CODE XREF: sub_791E6C+B2↑p

var_4           = dword ptr -4
arg_0           = dword ptr  8
arg_4           = dword ptr  0Ch
arg_8           = dword ptr  10h

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+var_4], ecx
                mov     ecx, [ebp+var_4]
                call    sub_792205
                push    eax
                push    [ebp+arg_8]
                push    [ebp+arg_4]
                push    [ebp+arg_0]
                call    sub_79349C
                add     esp, 10h
                leave
                retn    0Ch
sub_792ADE      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _DWORD *__thiscall sub_792B03(_DWORD *this, int)
sub_792B03      proc near               ; CODE XREF: sub_791F52+15↑p

var_4           = dword ptr -4

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+var_4], ecx
                mov     ecx, [ebp+var_4]
                call    sub_7918A1
                mov     ecx, [ebp+var_4]
                call    sub_792E44
                mov     eax, [ebp+var_4]
                leave
                retn    4
sub_792B03      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _DWORD *__cdecl sub_792B21(_DWORD *, _DWORD *)
sub_792B21      proc near               ; CODE XREF: sub_792677+4D↑p
                                        ; sub_7938D6+2B↓p

var_8           = dword ptr -8
var_4           = dword ptr -4
arg_0           = dword ptr  8
arg_4           = dword ptr  0Ch

                push    ebp
                mov     ebp, esp
                push    ecx
                push    ecx
                mov     eax, [ebp+arg_4]
                mov     ecx, [ebp+arg_0]
                mov     eax, [eax]
                cmp     eax, [ecx]
                jnb     short loc_792B3A
                mov     eax, [ebp+arg_4]
                mov     [ebp+var_4], eax
                jmp     short loc_792B40
; ---------------------------------------------------------------------------

loc_792B3A:                             ; CODE XREF: sub_792B21+F↑j
                mov     eax, [ebp+arg_0]
                mov     [ebp+var_4], eax

loc_792B40:                             ; CODE XREF: sub_792B21+17↑j
                mov     eax, [ebp+var_4]
                mov     [ebp+var_8], eax
                mov     eax, [ebp+var_8]
                leave
                retn
sub_792B21      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; unsigned int *__thiscall sub_792B4B(size_t *this, size_t, char, char)
sub_792B4B      proc near               ; CODE XREF: sub_791FCE+6B↑p

var_28          = dword ptr -28h
var_24          = dword ptr -24h
Block           = dword ptr -20h
var_1C          = dword ptr -1Ch
var_18          = dword ptr -18h
var_14          = dword ptr -14h
var_10          = dword ptr -10h
Size            = dword ptr -0Ch
var_8           = dword ptr -8
Src             = dword ptr -4
arg_0           = dword ptr  8
arg_4           = byte ptr  0Ch
arg_8           = byte ptr  10h

                push    ebp
                mov     ebp, esp
                sub     esp, 28h
                mov     [ebp+var_8], ecx
                mov     eax, [ebp+var_8]
                mov     [ebp+Src], eax
                mov     eax, [ebp+Src]
                mov     eax, [eax+10h]
                mov     [ebp+Size], eax
                mov     ecx, [ebp+var_8]
                call    sub_792677
                sub     eax, [ebp+Size]
                cmp     eax, [ebp+arg_0]
                jnb     short loc_792B78
                call    sub_791664
; ---------------------------------------------------------------------------

loc_792B78:                             ; CODE XREF: sub_792B4B+26↑j
                mov     eax, [ebp+Size]
                add     eax, [ebp+arg_0]
                mov     [ebp+var_14], eax
                mov     eax, [ebp+Src]
                mov     eax, [eax+14h]
                mov     [ebp+var_1C], eax
                push    [ebp+var_14]
                mov     ecx, [ebp+var_8]
                call    sub_792E91
                mov     [ebp+var_18], eax
                mov     ecx, [ebp+var_8]
                call    sub_792205
                mov     [ebp+var_24], eax
                mov     eax, [ebp+var_18]
                inc     eax
                push    eax
                mov     ecx, [ebp+var_24]
                call    sub_7927C5
                mov     [ebp+var_10], eax
                mov     ecx, [ebp+Src]
                call    sub_791642
                mov     eax, [ebp+Src]
                mov     ecx, [ebp+var_14]
                mov     [eax+10h], ecx
                mov     eax, [ebp+Src]
                mov     ecx, [ebp+var_18]
                mov     [eax+14h], ecx
                push    [ebp+var_10]
                call    unknown_libname_3 ; Microsoft VisualC 14/net runtime
                pop     ecx
                mov     [ebp+var_28], eax
                cmp     [ebp+var_1C], 10h
                jb      short loc_792C1C
                mov     eax, [ebp+Src]
                mov     eax, [eax]
                mov     [ebp+Block], eax
                push    dword ptr [ebp+arg_8] ; char
                push    [ebp+Size]      ; Size
                push    [ebp+Block]
                call    unknown_libname_3 ; Microsoft VisualC 14/net runtime
                pop     ecx
                push    eax             ; Src
                push    [ebp+var_28]    ; void *
                lea     ecx, [ebp+arg_4]
                call    sub_792042
                mov     eax, [ebp+var_1C]
                inc     eax
                push    eax             ; int
                push    [ebp+Block]     ; Block
                mov     ecx, [ebp+var_24]
                call    sub_7927E0
                mov     eax, [ebp+Src]
                mov     ecx, [ebp+var_10]
                mov     [eax], ecx
                jmp     short loc_792C3E
; ---------------------------------------------------------------------------

loc_792C1C:                             ; CODE XREF: sub_792B4B+92↑j
                push    dword ptr [ebp+arg_8] ; char
                push    [ebp+Size]      ; Size
                push    [ebp+Src]       ; Src
                push    [ebp+var_28]    ; void *
                lea     ecx, [ebp+arg_4]
                call    sub_792042
                lea     eax, [ebp+var_10]
                push    eax
                push    [ebp+Src]
                call    sub_792D1E
                pop     ecx
                pop     ecx

loc_792C3E:                             ; CODE XREF: sub_792B4B+CF↑j
                mov     eax, [ebp+var_8]
                leave
                retn    0Ch
sub_792B4B      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _DWORD *__thiscall sub_792C45(_DWORD *this, int)
sub_792C45      proc near               ; CODE XREF: sub_7920BA+2A↑p

var_4           = dword ptr -4

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+var_4], ecx
                mov     ecx, [ebp+var_4]
                call    sub_7918A1
                mov     ecx, [ebp+var_4]
                call    sub_792EC3
                mov     eax, [ebp+var_4]
                leave
                retn    4
sub_792C45      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; void sub_792C63()
sub_792C63      proc near               ; CODE XREF: sub_79232A+4B↑p
                                        ; sub_7925B7+16↑p ...
                push    ebp
                mov     ebp, esp
                pop     ebp
                retn
sub_792C63      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; unsigned int *__thiscall sub_792C68(unsigned int *this, size_t Size, char, _BYTE *Src)
sub_792C68      proc near               ; CODE XREF: sub_792424+60↑p

var_14          = dword ptr -14h
var_10          = dword ptr -10h
var_C           = dword ptr -0Ch
var_8           = dword ptr -8
var_4           = dword ptr -4
Size            = dword ptr  8
arg_4           = byte ptr  0Ch
Src             = dword ptr  10h

                push    ebp
                mov     ebp, esp
                sub     esp, 14h
                mov     [ebp+var_4], ecx
                mov     ecx, [ebp+var_4]
                call    sub_792677
                cmp     [ebp+Size], eax
                jbe     short loc_792C83
                call    sub_791664
; ---------------------------------------------------------------------------

loc_792C83:                             ; CODE XREF: sub_792C68+14↑j
                mov     eax, [ebp+var_4]
                mov     eax, [eax+14h]
                mov     [ebp+var_10], eax
                push    [ebp+Size]
                mov     ecx, [ebp+var_4]
                call    sub_792E91
                mov     [ebp+var_C], eax
                mov     ecx, [ebp+var_4]
                call    sub_792205
                mov     [ebp+var_14], eax
                mov     eax, [ebp+var_C]
                inc     eax
                push    eax
                mov     ecx, [ebp+var_14]
                call    sub_7927C5
                mov     [ebp+var_8], eax
                mov     ecx, [ebp+var_4]
                call    sub_791642
                mov     eax, [ebp+var_4]
                mov     ecx, [ebp+Size]
                mov     [eax+10h], ecx
                mov     eax, [ebp+var_4]
                mov     ecx, [ebp+var_C]
                mov     [eax+14h], ecx
                push    [ebp+Src]       ; Src
                push    [ebp+Size]      ; Size
                push    [ebp+var_8]
                call    unknown_libname_3 ; Microsoft VisualC 14/net runtime
                pop     ecx
                push    eax             ; void *
                lea     ecx, [ebp+arg_4]
                call    sub_79248D
                cmp     [ebp+var_10], 10h
                jb      short loc_792D09
                mov     eax, [ebp+var_10]
                inc     eax
                push    eax             ; int
                mov     eax, [ebp+var_4]
                push    dword ptr [eax] ; Block
                mov     ecx, [ebp+var_14]
                call    sub_7927E0
                mov     eax, [ebp+var_4]
                mov     ecx, [ebp+var_8]
                mov     [eax], ecx
                jmp     short loc_792D17
; ---------------------------------------------------------------------------

loc_792D09:                             ; CODE XREF: sub_792C68+83↑j
                lea     eax, [ebp+var_8]
                push    eax
                push    [ebp+var_4]
                call    sub_792D1E
                pop     ecx
                pop     ecx

loc_792D17:                             ; CODE XREF: sub_792C68+9F↑j
                mov     eax, [ebp+var_4]
                leave
                retn    0Ch
sub_792C68      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int __cdecl sub_792D1E(int, int)
sub_792D1E      proc near               ; CODE XREF: sub_792B4B+EC↑p
                                        ; sub_792C68+A8↑p

var_4           = dword ptr -4
arg_0           = dword ptr  8
arg_4           = dword ptr  0Ch

                push    ebp
                mov     ebp, esp
                push    ecx
                push    [ebp+arg_0]
                call    unknown_libname_3 ; Microsoft VisualC 14/net runtime
                pop     ecx
                push    eax             ; void *
                push    4               ; unsigned int
                call    ??2@YAPAXIPAX@Z ; operator new(uint,void *)
                pop     ecx
                pop     ecx
                mov     [ebp+var_4], eax
                push    [ebp+arg_4]
                call    unknown_libname_3 ; Microsoft VisualC 14/net runtime
                pop     ecx
                mov     ecx, [ebp+var_4]
                mov     eax, [eax]
                mov     [ecx], eax
                leave
                retn
sub_792D1E      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; unsigned int __cdecl sub_792D4A(unsigned int)
sub_792D4A      proc near               ; CODE XREF: sub_7925D9+A↑p

var_8           = dword ptr -8
var_1           = byte ptr -1
arg_0           = dword ptr  8

                push    ebp
                mov     ebp, esp
                push    ecx
                push    ecx
                mov     [ebp+var_1], 1
                mov     [ebp+var_8], 1FFFFFFFh
                cmp     [ebp+arg_0], 1FFFFFFFh
                jbe     short loc_792D68
                call    sub_79152F
; ---------------------------------------------------------------------------

loc_792D68:                             ; CODE XREF: sub_792D4A+17↑j
                mov     eax, [ebp+arg_0]
                shl     eax, 3
                leave
                retn
sub_792D4A      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; void *__cdecl sub_792D70(unsigned int Size)
sub_792D70      proc near               ; CODE XREF: sub_7925D9+11↑p
                                        ; sub_7927C5+11↑p

Size            = dword ptr  8

                push    ebp             ; int
                mov     ebp, esp
                cmp     [ebp+Size], 1000h
                jb      short loc_792D87
                push    [ebp+Size]
                call    sub_793533
                pop     ecx
                jmp     short loc_792D9A
; ---------------------------------------------------------------------------

loc_792D87:                             ; CODE XREF: sub_792D70+A↑j
                cmp     [ebp+Size], 0
                jz      short loc_792D98
                push    [ebp+Size]      ; Size
                call    ??2@YAPAXIHPBDH@Z ; operator new(uint,int,char const *,int)
                pop     ecx
                jmp     short loc_792D9A
; ---------------------------------------------------------------------------

loc_792D98:                             ; CODE XREF: sub_792D70+1B↑j
                xor     eax, eax

loc_792D9A:                             ; CODE XREF: sub_792D70+15↑j
                                        ; sub_792D70+26↑j
                pop     ebp
                retn
sub_792D70      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; void __cdecl sub_792D9C(void *Block, unsigned int)
sub_792D9C      proc near               ; CODE XREF: sub_79261E+11↑p
                                        ; sub_7927E0+D↑p

var_C           = dword ptr -0Ch
Block           = dword ptr  8
arg_4           = dword ptr  0Ch

; FUNCTION CHUNK AT 007964D6 SIZE 0000000C BYTES

; __unwind { // SEH_403751
                push    ebp
                mov     ebp, esp
                push    0FFFFFFFFh
                push    offset SEH_402D9C
                mov     eax, large fs:0
                push    eax
                mov     large fs:0, esp
                cmp     [ebp+arg_4], 1000h
                jb      short loc_792DCC
                lea     eax, [ebp+arg_4]
                push    eax
                lea     eax, [ebp+Block]
                push    eax
                call    sub_7915D8
                pop     ecx
                pop     ecx

loc_792DCC:                             ; CODE XREF: sub_792D9C+1F↑j
                push    [ebp+arg_4]
                push    [ebp+Block]     ; Block
                call    sub_795312
                pop     ecx
                pop     ecx
                mov     ecx, [ebp+var_C]
                mov     large fs:0, ecx
                leave
                retn
; } // starts at 792D9C
sub_792D9C      endp

; ---------------------------------------------------------------------------
                db 5 dup(0CCh)

; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int __cdecl sub_792DEA(int)
sub_792DEA      proc near               ; CODE XREF: sub_7927C5+A↑p

var_1           = byte ptr -1
arg_0           = dword ptr  8

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+var_1], 0
                mov     eax, [ebp+arg_0]
                leave
                retn
sub_792DEA      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int __thiscall sub_792DF7(int *this)
sub_792DF7      proc near               ; CODE XREF: sub_792823+B8↑p

var_8           = dword ptr -8
var_4           = dword ptr -4

                push    ebp
                mov     ebp, esp
                push    ecx
                push    ecx
                mov     [ebp+var_8], ecx
                and     [ebp+var_4], 0
                lea     eax, [ebp+var_4]
                push    eax
                push    [ebp+var_8]
                call    sub_793591
                pop     ecx
                pop     ecx
                leave
                retn
sub_792DF7      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int (__thiscall ***__thiscall sub_792E13(int (__thiscall ****this)(_DWORD, int)))(_DWORD, int)
sub_792E13      proc near               ; CODE XREF: sub_792823+C4↑p
                                        ; sub_792823+3D61↓j

var_C           = dword ptr -0Ch
var_8           = dword ptr -8
var_4           = dword ptr -4

                push    ebp
                mov     ebp, esp
                sub     esp, 0Ch
                mov     [ebp+var_4], ecx
                mov     eax, [ebp+var_4]
                cmp     dword ptr [eax], 0
                jz      short locret_792E42
                mov     ecx, [ebp+var_4]
                call    sub_7918A1
                mov     [ebp+var_C], eax
                mov     eax, [ebp+var_4]
                mov     eax, [eax]
                mov     [ebp+var_8], eax
                push    [ebp+var_8]
                mov     ecx, [ebp+var_C]
                call    sub_792EE5

locret_792E42:                          ; CODE XREF: sub_792E13+F↑j
                leave
                retn
sub_792E13      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _DWORD *__thiscall sub_792E44(_DWORD *this)
sub_792E44      proc near               ; CODE XREF: sub_792ABF+13↑p
                                        ; sub_792B03+12↑p

var_4           = dword ptr -4

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+var_4], ecx
                mov     eax, [ebp+var_4]
                and     dword ptr [eax], 0
                mov     eax, [ebp+var_4]
                and     dword ptr [eax+4], 0
                mov     eax, [ebp+var_4]
                and     dword ptr [eax+8], 0
                mov     eax, [ebp+var_4]
                leave
                retn
sub_792E44      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; void __stdcall sub_792E64(int, int)
sub_792E64      proc near               ; CODE XREF: sub_7929E8+4F↑p
                                        ; sub_7929E8+CE↑p

var_4           = dword ptr -4

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+var_4], ecx
                leave
                retn    8
sub_792E64      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int __thiscall sub_792E6F(void *this, int, int, int)
sub_792E6F      proc near               ; CODE XREF: sub_7929E8+BB↑p
                                        ; sub_793363+AD↓p

var_4           = dword ptr -4
arg_0           = dword ptr  8
arg_4           = dword ptr  0Ch

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+var_4], ecx
                mov     ecx, [ebp+var_4]
                call    sub_792205
                push    eax
                push    [ebp+arg_4]
                push    [ebp+arg_0]
                call    sub_7935AC
                add     esp, 0Ch
                leave
                retn    0Ch
sub_792E6F      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; unsigned int __thiscall sub_792E91(unsigned int *this, int)
sub_792E91      proc near               ; CODE XREF: sub_792B4B+45↑p
                                        ; sub_792C68+2A↑p

var_C           = dword ptr -0Ch
var_8           = dword ptr -8
var_4           = dword ptr -4
arg_0           = dword ptr  8

                push    ebp
                mov     ebp, esp
                sub     esp, 0Ch
                mov     [ebp+var_4], ecx
                mov     ecx, [ebp+var_4]
                call    sub_792677
                mov     [ebp+var_8], eax
                mov     eax, [ebp+var_4]
                mov     eax, [eax+14h]
                mov     [ebp+var_C], eax
                push    [ebp+var_8]
                push    [ebp+var_C]
                push    [ebp+arg_0]
                call    sub_792F19
                add     esp, 0Ch
                leave
                retn    4
sub_792E91      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _DWORD *__thiscall sub_792EC3(_DWORD *this)
sub_792EC3      proc near               ; CODE XREF: sub_792C45+12↑p

var_4           = dword ptr -4

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+var_4], ecx
                mov     ecx, [ebp+var_4]
                call    sub_7918A1
                mov     eax, [ebp+var_4]
                and     dword ptr [eax+10h], 0
                mov     eax, [ebp+var_4]
                and     dword ptr [eax+14h], 0
                mov     eax, [ebp+var_4]
                leave
                retn
sub_792EC3      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int (__thiscall ***__stdcall sub_792EE5(int (__thiscall ***)(_DWORD, int)))(_DWORD, int)
sub_792EE5      proc near               ; CODE XREF: sub_792E13+2A↑p

var_10          = dword ptr -10h
var_C           = dword ptr -0Ch
var_8           = dword ptr -8
var_4           = dword ptr -4
arg_0           = dword ptr  8

                push    ebp
                mov     ebp, esp
                sub     esp, 10h
                mov     [ebp+var_10], ecx
                mov     eax, [ebp+arg_0]
                mov     [ebp+var_4], eax
                cmp     [ebp+var_4], 0
                jz      short loc_792F11
                mov     eax, [ebp+var_4]
                mov     eax, [eax]
                mov     eax, [eax]
                mov     [ebp+var_8], eax
                push    1
                mov     ecx, [ebp+var_4]
                call    [ebp+var_8]
                mov     [ebp+var_C], eax
                jmp     short locret_792F15
; ---------------------------------------------------------------------------

loc_792F11:                             ; CODE XREF: sub_792EE5+13↑j
                and     [ebp+var_C], 0

locret_792F15:                          ; CODE XREF: sub_792EE5+2A↑j
                leave
                retn    4
sub_792EE5      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; unsigned int __cdecl sub_792F19(int, unsigned int, unsigned int)
sub_792F19      proc near               ; CODE XREF: sub_792E91+26↑p

var_8           = dword ptr -8
var_4           = dword ptr -4
arg_0           = dword ptr  8
arg_4           = dword ptr  0Ch
arg_8           = dword ptr  10h

                push    ebp
                mov     ebp, esp
                push    ecx
                push    ecx
                mov     eax, [ebp+arg_0]
                or      eax, 0Fh
                mov     [ebp+var_4], eax
                mov     eax, [ebp+var_4]
                cmp     eax, [ebp+arg_8]
                jbe     short loc_792F34
                mov     eax, [ebp+arg_8]
                jmp     short locret_792F64
; ---------------------------------------------------------------------------

loc_792F34:                             ; CODE XREF: sub_792F19+14↑j
                mov     eax, [ebp+arg_4]
                shr     eax, 1
                mov     ecx, [ebp+arg_8]
                sub     ecx, eax
                cmp     [ebp+arg_4], ecx
                jbe     short loc_792F48
                mov     eax, [ebp+arg_8]
                jmp     short locret_792F64
; ---------------------------------------------------------------------------

loc_792F48:                             ; CODE XREF: sub_792F19+28↑j
                mov     eax, [ebp+arg_4]
                shr     eax, 1
                add     eax, [ebp+arg_4]
                mov     [ebp+var_8], eax
                lea     eax, [ebp+var_8]
                push    eax
                lea     eax, [ebp+var_4]
                push    eax
                call    sub_7925F4
                pop     ecx
                pop     ecx
                mov     eax, [eax]

locret_792F64:                          ; CODE XREF: sub_792F19+19↑j
                                        ; sub_792F19+2D↑j
                leave
                retn
sub_792F19      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int __cdecl sub_792F66(int, _DWORD *)
sub_792F66      proc near               ; CODE XREF: sub_79290E+10↑p

anonymous_0     = dword ptr -88h
anonymous_1     = dword ptr -84h
anonymous_2     = dword ptr -80h
var_7C          = byte ptr -7Ch
var_74          = dword ptr -74h
var_6C          = qword ptr -6Ch
var_64          = qword ptr -64h
var_5C          = qword ptr -5Ch
var_54          = dword ptr -54h
var_50          = dword ptr -50h
var_4C          = dword ptr -4Ch
var_48          = dword ptr -48h
var_44          = dword ptr -44h
var_40          = dword ptr -40h
var_3C          = dword ptr -3Ch
var_38          = dword ptr -38h
var_34          = dword ptr -34h
var_30          = dword ptr -30h
var_2C          = dword ptr -2Ch
var_28          = dword ptr -28h
var_24          = dword ptr -24h
var_20          = dword ptr -20h
var_1C          = dword ptr -1Ch
var_18          = dword ptr -18h
var_12          = byte ptr -12h
var_11          = byte ptr -11h
var_10          = dword ptr -10h
var_C           = dword ptr -0Ch
anonymous_3     = dword ptr -8
var_4           = dword ptr -4
arg_0           = dword ptr  8
arg_4           = dword ptr  0Ch

; FUNCTION CHUNK AT 0079659A SIZE 00000010 BYTES
; FUNCTION CHUNK AT 007965AF SIZE 0000000C BYTES

; __unwind { // SEH_402F66
                push    ebp
                mov     ebp, esp
                push    0FFFFFFFFh
                push    offset SEH_402F66
                mov     eax, large fs:0
                push    eax
                mov     large fs:0, esp
                push    ecx
                sub     esp, 6Ch
                push    ebx
                push    esi
                push    edi
                mov     [ebp+var_10], esp
                and     [ebp+var_18], 0
                mov     [ebp+var_11], 0
                push    0
                push    [ebp+arg_0]
                lea     ecx, [ebp+var_74]
                call    sub_7936F6
;   try {
                and     [ebp+var_4], 0
                lea     ecx, [ebp+var_74]
                call    sub_7936E7
                movzx   eax, al
                test    eax, eax
                jz      loc_79316F
                mov     eax, [ebp+arg_0]
                mov     eax, [eax]
                mov     ecx, [ebp+arg_0]
                add     ecx, [eax+4]
                mov     [ebp+var_24], ecx
                lea     eax, [ebp+var_7C]
                push    eax
                mov     ecx, [ebp+var_24]
                call    ds:?getloc@ios_base@std@@QBE?AVlocale@2@XZ ; std::ios_base::getloc(void)
                mov     [ebp+var_28], eax
                mov     eax, [ebp+var_28]
                mov     [ebp+var_2C], eax
;   } // starts at 792F9D
;   try {
                mov     byte ptr [ebp+var_4], 1
                push    [ebp+var_2C]
                call    sub_792823
                pop     ecx
                mov     [ebp+var_44], eax
;   } // starts at 792FD8
;   try {
                mov     byte ptr [ebp+var_4], 0
                lea     ecx, [ebp+var_7C]
                call    sub_7916D8
                push    0
                mov     ecx, [ebp+arg_4]
                call    sub_79392C
;   } // starts at 792FE8
;   try {
                mov     byte ptr [ebp+var_4], 2
                mov     eax, [ebp+arg_0]
                mov     eax, [eax]
                mov     ecx, [ebp+arg_0]
                add     ecx, [eax+4]
                call    ds:?width@ios_base@std@@QBE_JXZ ; std::ios_base::width(void)
                mov     dword ptr [ebp+var_5C], eax
                mov     dword ptr [ebp+var_5C+4], edx
                cmp     dword ptr [ebp+var_5C+4], 0
                jl      short loc_79306A
                jg      short loc_793027
                cmp     dword ptr [ebp+var_5C], 0
                jbe     short loc_79306A

loc_793027:                             ; CODE XREF: sub_792F66+B9↑j
                mov     eax, [ebp+arg_0]
                mov     eax, [eax]
                mov     ecx, [ebp+arg_0]
                add     ecx, [eax+4]
                call    ds:?width@ios_base@std@@QBE_JXZ ; std::ios_base::width(void)
                mov     dword ptr [ebp+var_64], eax
                mov     dword ptr [ebp+var_64+4], edx
                mov     ecx, [ebp+arg_4]
                call    sub_792677
                cmp     dword ptr [ebp+var_64], eax
                jnb     short loc_79306A
                mov     eax, [ebp+arg_0]
                mov     eax, [eax]
                mov     ecx, [ebp+arg_0]
                add     ecx, [eax+4]
                call    ds:?width@ios_base@std@@QBE_JXZ ; std::ios_base::width(void)
                mov     dword ptr [ebp+var_6C], eax
                mov     dword ptr [ebp+var_6C+4], edx
                mov     eax, dword ptr [ebp+var_6C]
                mov     [ebp+var_1C], eax
                jmp     short loc_793075
; ---------------------------------------------------------------------------

loc_79306A:                             ; CODE XREF: sub_792F66+B7↑j
                                        ; sub_792F66+BF↑j ...
                mov     ecx, [ebp+arg_4]
                call    sub_792677
                mov     [ebp+var_1C], eax

loc_793075:                             ; CODE XREF: sub_792F66+102↑j
                mov     eax, [ebp+arg_0]
                mov     eax, [eax]
                mov     ecx, [ebp+arg_0]
                add     ecx, [eax+4]
                call    ds:?rdbuf@?$basic_ios@DU?$char_traits@D@std@@@std@@QBEPAV?$basic_streambuf@DU?$char_traits@D@std@@@2@XZ ; std::ios::rdbuf(void)
                mov     [ebp+var_30], eax
                mov     ecx, [ebp+var_30]
                call    ds:?sgetc@?$basic_streambuf@DU?$char_traits@D@std@@@std@@QAEHXZ ; std::streambuf::sgetc(void)
                mov     [ebp+var_34], eax
                mov     eax, [ebp+var_34]
                mov     [ebp+var_20], eax
                jmp     short loc_7930CA
; ---------------------------------------------------------------------------

loc_79309D:                             ; CODE XREF: sub_792F66:loc_79313D↓j
                mov     eax, [ebp+var_1C]
                dec     eax
                mov     [ebp+var_1C], eax
                mov     eax, [ebp+arg_0]
                mov     eax, [eax]
                mov     ecx, [ebp+arg_0]
                add     ecx, [eax+4]
                call    ds:?rdbuf@?$basic_ios@DU?$char_traits@D@std@@@std@@QBEPAV?$basic_streambuf@DU?$char_traits@D@std@@@2@XZ ; std::ios::rdbuf(void)
                mov     [ebp+var_38], eax
                mov     ecx, [ebp+var_38]
                call    ds:?snextc@?$basic_streambuf@DU?$char_traits@D@std@@@std@@QAEHXZ ; std::streambuf::snextc(void)
                mov     [ebp+var_3C], eax
                mov     eax, [ebp+var_3C]
                mov     [ebp+var_20], eax

loc_7930CA:                             ; CODE XREF: sub_792F66+135↑j
                cmp     [ebp+var_1C], 0
                jbe     short loc_793142
                call    ?max@?$numeric_limits@I@std@@SAIXZ ; std::numeric_limits<uint>::max(void)
                mov     [ebp+var_40], eax
                lea     eax, [ebp+var_20]
                push    eax
                lea     eax, [ebp+var_40]
                push    eax
                call    sub_7924F8
                pop     ecx
                pop     ecx
                movzx   eax, al
                test    eax, eax
                jz      short loc_7930FB
                mov     eax, [ebp+var_18]
                or      eax, 1
                mov     [ebp+var_18], eax
                jmp     short loc_793142
; ---------------------------------------------------------------------------
                jmp     short loc_79313D
; ---------------------------------------------------------------------------

loc_7930FB:                             ; CODE XREF: sub_792F66+186↑j
                lea     eax, [ebp+var_20]
                push    eax
                call    ?to_char_type@?$_Narrow_char_traits@DH@std@@SADABH@Z ; std::_Narrow_char_traits<char,int>::to_char_type(int const &)
                pop     ecx
                movzx   eax, al
                push    eax
                push    48h ; 'H'
                mov     ecx, [ebp+var_44]
                call    ds:?is@?$ctype@D@std@@QBE_NFD@Z ; std::ctype<char>::is(short,char)
                mov     [ebp+var_12], al
                movzx   eax, [ebp+var_12]
                test    eax, eax
                jz      short loc_793123
                jmp     short loc_793142
; ---------------------------------------------------------------------------
                jmp     short loc_79313D
; ---------------------------------------------------------------------------

loc_793123:                             ; CODE XREF: sub_792F66+1B7↑j
                lea     eax, [ebp+var_20]
                push    eax
                call    ?to_char_type@?$_Narrow_char_traits@DH@std@@SADABH@Z ; std::_Narrow_char_traits<char,int>::to_char_type(int const &)
                pop     ecx
                movzx   eax, al
                push    eax
                mov     ecx, [ebp+arg_4]
                call    sub_791FCE
                mov     [ebp+var_11], 1

loc_79313D:                             ; CODE XREF: sub_792F66+193↑j
                                        ; sub_792F66+1BB↑j
                jmp     loc_79309D
; ---------------------------------------------------------------------------

loc_793142:                             ; CODE XREF: sub_792F66+168↑j
                                        ; sub_792F66+191↑j ...
                jmp     short loc_793165
; ---------------------------------------------------------------------------

loc_793144:                             ; DATA XREF: .rdata:stru_797C64↓o
;   catch(...) // owned by 792FFE
                mov     eax, [ebp+arg_0]
                mov     eax, [eax]
                mov     ecx, [ebp+arg_0]
                add     ecx, [eax+4]
                mov     [ebp+var_48], ecx
                push    1
                push    4
                mov     ecx, [ebp+var_48]
                call    ds:?setstate@?$basic_ios@DU?$char_traits@D@std@@@std@@QAEXH_N@Z ; std::ios::setstate(int,bool)
                mov     eax, offset loc_79316B
                retn
;   } // starts at 792FFE
; ---------------------------------------------------------------------------

loc_793165:                             ; CODE XREF: sub_792F66:loc_793142↑j
;   try {
                and     [ebp+var_4], 0
                jmp     short loc_79316F
;   } // starts at 793165
; ---------------------------------------------------------------------------

loc_79316B:                             ; CODE XREF: sub_792F66+1FE↑j
                                        ; DATA XREF: sub_792F66+1F9↑o
;   try {
                and     [ebp+var_4], 0

loc_79316F:                             ; CODE XREF: sub_792F66+48↑j
                                        ; sub_792F66+203↑j
                mov     eax, [ebp+arg_0]
                mov     eax, [eax]
                mov     ecx, [ebp+arg_0]
                add     ecx, [eax+4]
                mov     [ebp+var_4C], ecx
                push    0
                push    0
                mov     ecx, [ebp+var_4C]
                call    ds:?width@ios_base@std@@QAE_J_J@Z ; std::ios_base::width(__int64)
                movzx   eax, [ebp+var_11]
                test    eax, eax
                jnz     short loc_79319B
                mov     eax, [ebp+var_18]
                or      eax, 2
                mov     [ebp+var_18], eax

loc_79319B:                             ; CODE XREF: sub_792F66+22A↑j
                mov     eax, [ebp+arg_0]
                mov     eax, [eax]
                mov     ecx, [ebp+arg_0]
                add     ecx, [eax+4]
                mov     [ebp+var_50], ecx
                push    0
                push    [ebp+var_18]
                mov     ecx, [ebp+var_50]
                call    ds:?setstate@?$basic_ios@DU?$char_traits@D@std@@@std@@QAEXH_N@Z ; std::ios::setstate(int,bool)
                mov     eax, [ebp+arg_0]
                mov     [ebp+var_54], eax
;   } // starts at 79316B
                or      [ebp+var_4], 0FFFFFFFFh
                lea     ecx, [ebp+var_74]
                call    sub_793618
                mov     eax, [ebp+var_54]
                mov     ecx, [ebp+var_C]
                mov     large fs:0, ecx
                pop     edi
                pop     esi
                pop     ebx
                leave
                retn
; } // starts at 792F66
sub_792F66      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _DWORD *__thiscall sub_7931DB(_DWORD *this, char)
sub_7931DB      proc near               ; CODE XREF: sub_792823+8A↑p

var_C           = dword ptr -0Ch
var_8           = dword ptr -8
var_4           = dword ptr -4
arg_0           = byte ptr  8

                push    ebp
                mov     ebp, esp
                sub     esp, 0Ch
                mov     [ebp+var_4], ecx
                mov     eax, [ebp+var_4]
                mov     [ebp+var_8], eax
                lea     eax, [ebp+arg_0]
                push    eax
                push    [ebp+var_C]
                mov     ecx, [ebp+var_8]
                call    sub_793BAD
                mov     eax, [ebp+var_4]
                leave
                retn    4
sub_7931DB      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _DWORD *__cdecl sub_793200(_DWORD *, _DWORD *, void *)
sub_793200      proc near               ; CODE XREF: sub_792943+18↑p

var_10          = dword ptr -10h
var_8           = dword ptr -8
arg_0           = dword ptr  8
arg_4           = dword ptr  0Ch
arg_8           = dword ptr  10h

                push    ebp
                mov     ebp, esp
                sub     esp, 10h
                push    [ebp+arg_8]
                lea     eax, [ebp+var_8]
                push    eax
                mov     ecx, [ebp+arg_4]
                call    sub_791FA1
                push    eax
                lea     eax, [ebp+var_10]
                push    eax
                call    sub_793BCB
                add     esp, 0Ch
                push    eax
                mov     ecx, [ebp+arg_0]
                call    sub_791F83
                mov     eax, [ebp+arg_0]
                leave
                retn
sub_793200      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; BOOL __cdecl sub_793230(_DWORD *)
sub_793230      proc near               ; CODE XREF: sub_792943+21↑p

var_20          = xtime ptr -20h
var_10          = dword ptr -10h
var_8           = dword ptr -8
arg_0           = dword ptr  8

                push    ebp
                mov     ebp, esp
                sub     esp, 20h

loc_793236:                             ; CODE XREF: sub_793230+51↓j
                lea     eax, [ebp+var_8]
                push    eax
                call    sub_7917C3
                pop     ecx
                lea     eax, [ebp+var_8]
                push    eax
                push    [ebp+arg_0]
                call    sub_793C1C
                pop     ecx
                pop     ecx
                movzx   eax, al
                test    eax, eax
                jz      short loc_793257
                jmp     short locret_793283
; ---------------------------------------------------------------------------

loc_793257:                             ; CODE XREF: sub_793230+23↑j
                lea     eax, [ebp+var_8]
                push    eax
                push    [ebp+arg_0]
                lea     eax, [ebp+var_10]
                push    eax
                call    sub_793C46
                add     esp, 0Ch
                push    eax
                lea     eax, [ebp+var_20]
                push    eax
                call    sub_793C80
                pop     ecx
                pop     ecx
                lea     eax, [ebp+var_20]
                push    eax             ; xtime *
                call    ds:_Thrd_sleep
                pop     ecx
                jmp     short loc_793236
; ---------------------------------------------------------------------------

locret_793283:                          ; CODE XREF: sub_793230+25↑j
                leave
                retn
sub_793230      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int __cdecl sub_793285(int, int, int, int)
sub_793285      proc near               ; CODE XREF: sub_79296C+28↑p

var_139C        = dword ptr -139Ch
var_14          = dword ptr -14h
var_1           = byte ptr -1
arg_0           = dword ptr  8
arg_4           = dword ptr  0Ch
arg_8           = dword ptr  10h
arg_C           = dword ptr  14h

                push    ebp
                mov     ebp, esp
                mov     eax, 139Ch
                call    __alloca_probe
                lea     ecx, [ebp+var_1]
                call    sub_7918A1
                lea     ecx, [ebp+var_1]
                call    sub_7918AD
                push    eax
                lea     ecx, [ebp+var_139C]
                call    sub_79390C
                push    [ebp+arg_C]
                push    [ebp+arg_8]
                push    [ebp+arg_4]
                push    [ebp+arg_0]
                lea     ecx, [ebp+var_14]
                call    sub_7936C5
                lea     eax, [ebp+var_139C]
                push    eax
                lea     ecx, [ebp+var_14]
                call    sub_793D4C
                leave
                retn
sub_793285      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; __int16 __cdecl sub_7932D3(__int16, __int16)
sub_7932D3      proc near               ; CODE XREF: sub_79299E+1D↑p

var_1390        = dword ptr -1390h
var_8           = word ptr -8
var_1           = byte ptr -1
arg_0           = dword ptr  8
arg_4           = dword ptr  0Ch

                push    ebp
                mov     ebp, esp
                mov     eax, 1390h
                call    __alloca_probe
                lea     ecx, [ebp+var_1]
                call    sub_7918A1
                lea     ecx, [ebp+var_1]
                call    sub_7918AD
                push    eax
                lea     ecx, [ebp+var_1390]
                call    sub_79390C
                push    [ebp+arg_4]
                push    [ebp+arg_0]
                lea     ecx, [ebp+var_8]
                call    sub_7936A9
                lea     eax, [ebp+var_1390]
                push    eax
                lea     ecx, [ebp+var_8]
                call    sub_793D73
                leave
                retn
sub_7932D3      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int __cdecl sub_79331B(int, int)
sub_79331B      proc near               ; CODE XREF: sub_7929C4+1B↑p

var_1394        = dword ptr -1394h
var_C           = byte ptr -0Ch
var_1           = byte ptr -1
arg_0           = dword ptr  8
arg_4           = dword ptr  0Ch

                push    ebp
                mov     ebp, esp
                mov     eax, 1394h
                call    __alloca_probe
                lea     ecx, [ebp+var_1]
                call    sub_7918A1
                lea     ecx, [ebp+var_1]
                call    sub_7918AD
                push    eax
                lea     ecx, [ebp+var_1394]
                call    sub_79390C
                push    [ebp+arg_4]
                push    [ebp+arg_0]
                lea     ecx, [ebp+var_C]
                call    sub_79368D
                lea     eax, [ebp+var_1394]
                push    eax
                lea     ecx, [ebp+var_C]
                call    sub_793D98
                leave
                retn
sub_79331B      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int __thiscall sub_793363(int *this, unsigned int, unsigned __int8 *)
sub_793363      proc near               ; CODE XREF: sub_7929E8+98↑p

var_40          = dword ptr -40h
var_3C          = dword ptr -3Ch
var_38          = dword ptr -38h
var_34          = dword ptr -34h
var_30          = dword ptr -30h
var_2C          = dword ptr -2Ch
var_28          = dword ptr -28h
var_24          = dword ptr -24h
var_20          = dword ptr -20h
var_1C          = dword ptr -1Ch
Block           = dword ptr -18h
var_14          = dword ptr -14h
var_10          = dword ptr -10h
var_C           = dword ptr -0Ch
var_4           = dword ptr -4
arg_0           = dword ptr  8
arg_4           = dword ptr  0Ch

; FUNCTION CHUNK AT 007965BB SIZE 0000000C BYTES

; __unwind { // SEH_403363
                push    ebp
                mov     ebp, esp
                push    0FFFFFFFFh
                push    offset SEH_403363
                mov     eax, large fs:0
                push    eax
                mov     large fs:0, esp
                push    ecx
                sub     esp, 30h
                push    ebx
                push    esi
                push    edi
                mov     [ebp+var_10], esp
                mov     [ebp+var_14], ecx
                mov     ecx, [ebp+var_14]
                call    sub_7938D6
                cmp     [ebp+arg_0], eax
                jbe     short loc_79339A
                call    sub_7937AD
; ---------------------------------------------------------------------------

loc_79339A:                             ; CODE XREF: sub_793363+30↑j
                mov     eax, [ebp+var_14]
                mov     [ebp+var_24], eax
                mov     eax, [ebp+var_24]
                mov     [ebp+var_30], eax
                mov     eax, [ebp+var_24]
                add     eax, 4
                mov     [ebp+var_2C], eax
                mov     eax, [ebp+var_2C]
                mov     ecx, [ebp+var_30]
                mov     eax, [eax]
                sub     eax, [ecx]
                sar     eax, 3
                mov     [ebp+var_28], eax
                push    [ebp+arg_0]
                mov     ecx, [ebp+var_14]
                call    sub_79385F
                mov     [ebp+var_20], eax
                mov     ecx, [ebp+var_14]
                call    sub_792205
                mov     [ebp+var_38], eax
                push    [ebp+var_20]
                mov     ecx, [ebp+var_38]
                call    sub_7925D9
                mov     [ebp+Block], eax
                mov     eax, [ebp+var_28]
                mov     ecx, [ebp+Block]
                lea     eax, [ecx+eax*8]
                mov     [ebp+var_1C], eax
                mov     eax, [ebp+var_1C]
                mov     [ebp+var_34], eax
;   try {
                and     [ebp+var_4], 0
                mov     eax, [ebp+arg_4]
                movzx   eax, byte ptr [eax]
                push    eax
                mov     eax, [ebp+arg_0]
                sub     eax, [ebp+var_28]
                push    eax
                push    [ebp+var_1C]
                mov     ecx, [ebp+var_14]
                call    sub_792E6F
                mov     [ebp+var_3C], eax
                mov     eax, [ebp+var_3C]
                mov     [ebp+var_34], eax
                push    [ebp+Block]
                mov     eax, [ebp+var_2C]
                push    dword ptr [eax]
                mov     eax, [ebp+var_30]
                push    dword ptr [eax]
                mov     ecx, [ebp+var_14]
                call    sub_7938B1
                jmp     short loc_79346B
; ---------------------------------------------------------------------------

loc_793435:                             ; DATA XREF: .rdata:stru_797CBC↓o
;   catch(...) // owned by 7933F8
                push    [ebp+var_34]
                push    [ebp+var_1C]
                mov     ecx, [ebp+var_14]
                call    sub_7925B7
                mov     ecx, [ebp+var_14]
                call    sub_792205
                mov     [ebp+var_40], eax
                push    [ebp+var_20]    ; int
                push    [ebp+Block]     ; Block
                mov     ecx, [ebp+var_40]
                call    sub_79261E
                push    0               ; pThrowInfo
                push    0               ; pExceptionObject
                call    _CxxThrowException
; ---------------------------------------------------------------------------
                mov     eax, offset loc_793471
                retn
;   } // starts at 7933F8
; ---------------------------------------------------------------------------

loc_79346B:                             ; CODE XREF: sub_793363+D0↑j
                or      [ebp+var_4], 0FFFFFFFFh
                jmp     short loc_793475
; ---------------------------------------------------------------------------

loc_793471:                             ; DATA XREF: sub_793363+102↑o
                or      [ebp+var_4], 0FFFFFFFFh

loc_793475:                             ; CODE XREF: sub_793363+10C↑j
                push    [ebp+var_20]
                push    [ebp+arg_0]
                push    [ebp+Block]
                mov     ecx, [ebp+var_14]
                call    sub_7937BD
                mov     ecx, [ebp+var_C]
                mov     large fs:0, ecx
                pop     edi
                pop     esi
                pop     ebx
                leave
                retn    8
; } // starts at 793363
sub_793363      endp

; ---------------------------------------------------------------------------
                db 5 dup(0CCh)

; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int __cdecl sub_79349C(int, int, int, int)
sub_79349C      proc near               ; CODE XREF: sub_792ADE+19↑p
                                        ; sub_793A0B+19↓p

var_20          = dword ptr -20h
var_14          = dword ptr -14h
var_10          = dword ptr -10h
var_C           = dword ptr -0Ch
var_4           = dword ptr -4
arg_0           = byte ptr  8
arg_4           = byte ptr  0Ch
arg_8           = dword ptr  10h
arg_C           = dword ptr  14h

; FUNCTION CHUNK AT 007965C7 SIZE 00000008 BYTES
; FUNCTION CHUNK AT 007965D4 SIZE 0000000C BYTES

; __unwind { // SEH_40349C
                push    ebp
                mov     ebp, esp
                push    0FFFFFFFFh
                push    offset SEH_40349C
                mov     eax, large fs:0
                push    eax
                mov     large fs:0, esp
                sub     esp, 14h
                lea     eax, [ebp+arg_0]
                push    eax
                call    unknown_libname_4 ; Microsoft VisualC 14/net runtime
                pop     ecx
                mov     [ebp+var_10], eax
                lea     eax, [ebp+arg_4]
                push    eax
                call    unknown_libname_4 ; Microsoft VisualC 14/net runtime
                pop     ecx
                mov     [ebp+var_14], eax
                push    [ebp+arg_C]
                push    [ebp+arg_8]
                lea     ecx, [ebp+var_20]
                call    sub_793665
;   try {
                and     [ebp+var_4], 0
                jmp     short loc_7934EE
; ---------------------------------------------------------------------------

loc_7934E5:                             ; CODE XREF: sub_79349C+65↓j
                mov     eax, [ebp+var_10]
                add     eax, 8
                mov     [ebp+var_10], eax

loc_7934EE:                             ; CODE XREF: sub_79349C+47↑j
                mov     eax, [ebp+var_10]
                cmp     eax, [ebp+var_14]
                jz      short loc_793503
                push    [ebp+var_10]
                lea     ecx, [ebp+var_20]
                call    sub_793DB9
                jmp     short loc_7934E5
; ---------------------------------------------------------------------------

loc_793503:                             ; CODE XREF: sub_79349C+58↑j
                lea     ecx, [ebp+var_20]
                call    sub_793629
                mov     [ebp+arg_8], eax
;   } // starts at 7934DF
                or      [ebp+var_4], 0FFFFFFFFh
                lea     ecx, [ebp+var_20]
                call    sub_793643
                mov     eax, [ebp+arg_8]
                mov     ecx, [ebp+var_C]
                mov     large fs:0, ecx
                leave
                retn
; } // starts at 79349C
sub_79349C      endp

; [0000000A BYTES: COLLAPSED FUNCTION unknown_libname_4. PRESS CTRL-NUMPAD+ TO EXPAND]

; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; unsigned int __cdecl sub_793533(unsigned int)
sub_793533      proc near               ; CODE XREF: sub_792D70+F↑p

var_C           = dword ptr -0Ch
Size            = dword ptr -8
var_4           = dword ptr -4
arg_0           = dword ptr  8

                push    ebp
                mov     ebp, esp
                sub     esp, 0Ch
                mov     eax, [ebp+arg_0]
                add     eax, 23h ; '#'
                mov     [ebp+Size], eax
                mov     eax, [ebp+Size]
                cmp     eax, [ebp+arg_0]
                ja      short loc_79354F
                call    sub_79152F
; ---------------------------------------------------------------------------

loc_79354F:                             ; CODE XREF: sub_793533+15↑j
                push    [ebp+Size]      ; Size
                call    ??2@YAPAXIHPBDH@Z ; operator new(uint,int,char const *,int)
                pop     ecx
                mov     [ebp+var_4], eax

loc_79355B:                             ; CODE XREF: sub_793533+3C↓j
                cmp     [ebp+var_4], 0
                jz      short loc_793563
                jmp     short loc_79356D
; ---------------------------------------------------------------------------

loc_793563:                             ; CODE XREF: sub_793533+2C↑j
                                        ; sub_793533+38↓j
                call    ds:_invalid_parameter_noinfo_noreturn
; ---------------------------------------------------------------------------
                xor     eax, eax
                jnz     short loc_793563

loc_79356D:                             ; CODE XREF: sub_793533+2E↑j
                xor     eax, eax
                jnz     short loc_79355B
                mov     eax, [ebp+var_4]
                add     eax, 23h ; '#'
                and     eax, 0FFFFFFE0h
                mov     [ebp+var_C], eax
                push    4
                pop     eax
                imul    eax, -1
                mov     ecx, [ebp+var_C]
                mov     edx, [ebp+var_4]
                mov     [ecx+eax], edx
                mov     eax, [ebp+var_C]
                leave
                retn
sub_793533      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int __cdecl sub_793591(int *, int *)
sub_793591      proc near               ; CODE XREF: sub_792DF7+13↑p

var_4           = dword ptr -4
arg_0           = dword ptr  8
arg_4           = dword ptr  0Ch

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     eax, [ebp+arg_0]
                mov     eax, [eax]
                mov     [ebp+var_4], eax
                mov     eax, [ebp+arg_0]
                mov     ecx, [ebp+arg_4]
                mov     ecx, [ecx]
                mov     [eax], ecx
                mov     eax, [ebp+var_4]
                leave
                retn
sub_793591      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int __cdecl sub_7935AC(int, int, int)
sub_7935AC      proc near               ; CODE XREF: sub_792E6F+16↑p

var_1C          = dword ptr -1Ch
var_10          = dword ptr -10h
var_C           = dword ptr -0Ch
var_4           = dword ptr -4
arg_0           = dword ptr  8
arg_4           = dword ptr  0Ch
arg_8           = dword ptr  10h

; FUNCTION CHUNK AT 007965E0 SIZE 00000008 BYTES
; FUNCTION CHUNK AT 007965ED SIZE 0000000C BYTES

; __unwind { // SEH_4035AC
                push    ebp
                mov     ebp, esp
                push    0FFFFFFFFh
                push    offset SEH_4035AC
                mov     eax, large fs:0
                push    eax
                mov     large fs:0, esp
                sub     esp, 10h
                push    [ebp+arg_8]
                push    [ebp+arg_0]
                lea     ecx, [ebp+var_1C]
                call    sub_793665
;   try {
                and     [ebp+var_4], 0
                jmp     short loc_7935E2
; ---------------------------------------------------------------------------

loc_7935DB:                             ; CODE XREF: sub_7935AC+44↓j
                mov     eax, [ebp+arg_4]
                dec     eax
                mov     [ebp+arg_4], eax

loc_7935E2:                             ; CODE XREF: sub_7935AC+2D↑j
                cmp     [ebp+arg_4], 0
                jbe     short loc_7935F2
                lea     ecx, [ebp+var_1C]
                call    sub_793E0A
                jmp     short loc_7935DB
; ---------------------------------------------------------------------------

loc_7935F2:                             ; CODE XREF: sub_7935AC+3A↑j
                lea     ecx, [ebp+var_1C]
                call    sub_793629
                mov     [ebp+var_10], eax
;   } // starts at 7935D5
                or      [ebp+var_4], 0FFFFFFFFh
                lea     ecx, [ebp+var_1C]
                call    sub_793643
                mov     eax, [ebp+var_10]
                mov     ecx, [ebp+var_C]
                mov     large fs:0, ecx
                leave
                retn
; } // starts at 7935AC
sub_7935AC      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int __thiscall sub_793618(_DWORD *this)
sub_793618      proc near               ; CODE XREF: sub_792F66+25E↑p
                                        ; sub_792F66+3637↓j

var_4           = dword ptr -4

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+var_4], ecx
                mov     ecx, [ebp+var_4]
                call    sub_793751
                leave
                retn
sub_793618      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int __thiscall sub_793629(_DWORD *this)
sub_793629      proc near               ; CODE XREF: sub_79349C+6A↑p
                                        ; sub_7935AC+49↑p

var_4           = dword ptr -4

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+var_4], ecx
                mov     eax, [ebp+var_4]
                mov     ecx, [ebp+var_4]
                mov     ecx, [ecx+4]
                mov     [eax], ecx
                mov     eax, [ebp+var_4]
                mov     eax, [eax+4]
                leave
                retn
sub_793629      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; void sub_793643()
sub_793643      proc near               ; CODE XREF: sub_79349C+79↑p
                                        ; sub_7935AC+58↑p ...

var_4           = dword ptr -4

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+var_4], ecx
                mov     eax, [ebp+var_4]
                push    dword ptr [eax+8]
                mov     eax, [ebp+var_4]
                push    dword ptr [eax+4]
                mov     eax, [ebp+var_4]
                push    dword ptr [eax]
                call    sub_792C63
                add     esp, 0Ch
                leave
                retn
sub_793643      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _DWORD *__thiscall sub_793665(_DWORD *this, int, int)
sub_793665      proc near               ; CODE XREF: sub_79349C+3E↑p
                                        ; sub_7935AC+24↑p

var_4           = dword ptr -4
arg_0           = dword ptr  8
arg_4           = dword ptr  0Ch

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+var_4], ecx
                mov     eax, [ebp+var_4]
                mov     ecx, [ebp+arg_0]
                mov     [eax], ecx
                mov     eax, [ebp+var_4]
                mov     ecx, [ebp+arg_0]
                mov     [eax+4], ecx
                mov     eax, [ebp+var_4]
                mov     ecx, [ebp+arg_4]
                mov     [eax+8], ecx
                mov     eax, [ebp+var_4]
                leave
                retn    8
sub_793665      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _DWORD *__thiscall sub_79368D(_DWORD *this, int, int)
sub_79368D      proc near               ; CODE XREF: sub_79331B+32↑p

var_4           = dword ptr -4
arg_0           = dword ptr  8
arg_4           = dword ptr  0Ch

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+var_4], ecx
                push    [ebp+arg_4]
                push    [ebp+arg_0]
                mov     ecx, [ebp+var_4]
                call    sub_793957
                mov     eax, [ebp+var_4]
                leave
                retn    8
sub_79368D      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _WORD *__thiscall sub_7936A9(_WORD *this, __int16, __int16)
sub_7936A9      proc near               ; CODE XREF: sub_7932D3+32↑p

var_4           = dword ptr -4
arg_0           = dword ptr  8
arg_4           = dword ptr  0Ch

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+var_4], ecx
                push    [ebp+arg_4]
                push    [ebp+arg_0]
                mov     ecx, [ebp+var_4]
                call    sub_79397A
                mov     eax, [ebp+var_4]
                leave
                retn    8
sub_7936A9      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _DWORD *__thiscall sub_7936C5(_DWORD *this, int, int, int, int)
sub_7936C5      proc near               ; CODE XREF: sub_793285+38↑p

var_4           = dword ptr -4
arg_0           = dword ptr  8
arg_4           = dword ptr  0Ch
arg_8           = dword ptr  10h
arg_C           = dword ptr  14h

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+var_4], ecx
                push    [ebp+arg_C]
                push    [ebp+arg_8]
                push    [ebp+arg_4]
                push    [ebp+arg_0]
                mov     ecx, [ebp+var_4]
                call    sub_79399D
                mov     eax, [ebp+var_4]
                leave
                retn    10h
sub_7936C5      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; char __thiscall sub_7936E7(_BYTE *this)
sub_7936E7      proc near               ; CODE XREF: sub_792F66+3E↑p

var_4           = dword ptr -4

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+var_4], ecx
                mov     eax, [ebp+var_4]
                mov     al, [eax+4]
                leave
                retn
sub_7936E7      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _DWORD *__thiscall sub_7936F6(_DWORD *this, int, int)
sub_7936F6      proc near               ; CODE XREF: sub_792F66+32↑p

var_14          = dword ptr -14h
var_10          = dword ptr -10h
var_C           = dword ptr -0Ch
var_4           = dword ptr -4
arg_0           = dword ptr  8
arg_4           = dword ptr  0Ch

; FUNCTION CHUNK AT 007965F9 SIZE 00000008 BYTES
; FUNCTION CHUNK AT 00796606 SIZE 0000000C BYTES

; __unwind { // SEH_4036F6
                push    ebp
                mov     ebp, esp
                push    0FFFFFFFFh
                push    offset SEH_4036F6
                mov     eax, large fs:0
                push    eax
                mov     large fs:0, esp
                push    ecx
                push    ecx
                mov     [ebp+var_10], ecx
                push    [ebp+arg_0]
                mov     ecx, [ebp+var_10]
                call    sub_7939C6
;   try {
                and     [ebp+var_4], 0
                mov     eax, [ebp+var_10]
                mov     eax, [eax]
                mov     [ebp+var_14], eax
                push    [ebp+arg_4]
                mov     ecx, [ebp+var_14]
                call    ds:?_Ipfx@?$basic_istream@DU?$char_traits@D@std@@@std@@QAE_N_N@Z ; std::istream::_Ipfx(bool)
                mov     ecx, [ebp+var_10]
                mov     [ecx+4], al
;   } // starts at 79371E
                or      [ebp+var_4], 0FFFFFFFFh
                mov     eax, [ebp+var_10]
                mov     ecx, [ebp+var_C]
                mov     large fs:0, ecx
                leave
                retn    8
; } // starts at 7936F6
sub_7936F6      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int __thiscall sub_793751(_DWORD *this)
sub_793751      proc near               ; CODE XREF: sub_793618+A↑p
                                        ; sub_7936F6+2F06↓j

var_18          = dword ptr -18h
var_14          = dword ptr -14h
var_10          = dword ptr -10h
var_C           = dword ptr -0Ch

; FUNCTION CHUNK AT 007964D6 SIZE 0000000C BYTES

; __unwind { // SEH_403751
                push    ebp
                mov     ebp, esp
                push    0FFFFFFFFh
                push    offset SEH_402D9C
                mov     eax, large fs:0
                push    eax
                mov     large fs:0, esp
                sub     esp, 0Ch
                mov     [ebp+var_18], ecx
                mov     eax, [ebp+var_18]
                mov     eax, [eax]
                mov     [ebp+var_14], eax
                mov     eax, [ebp+var_14]
                mov     eax, [eax]
                mov     ecx, [ebp+var_14]
                add     ecx, [eax+4]
                call    ds:?rdbuf@?$basic_ios@DU?$char_traits@D@std@@@std@@QBEPAV?$basic_streambuf@DU?$char_traits@D@std@@@2@XZ ; std::ios::rdbuf(void)
                mov     [ebp+var_10], eax
                cmp     [ebp+var_10], 0
                jz      short loc_79379C
                mov     eax, [ebp+var_10]
                mov     eax, [eax]
                mov     ecx, [ebp+var_10]
                call    dword ptr [eax+8]

loc_79379C:                             ; CODE XREF: sub_793751+3E↑j
                mov     ecx, [ebp+var_C]
                mov     large fs:0, ecx
                leave
                retn
; } // starts at 793751
sub_793751      endp

; ---------------------------------------------------------------------------
                db 5 dup(0CCh)

; =============== S U B R O U T I N E =======================================

; Attributes: noreturn bp-based frame

; void __noreturn sub_7937AD()
sub_7937AD      proc near               ; CODE XREF: sub_793363+32↑p
                push    ebp
                mov     ebp, esp
                push    offset aVectorTooLong ; "vector too long"
                call    ds:?_Xlength_error@std@@YAXPBD@Z ; std::_Xlength_error(char const *)
sub_7937AD      endp

; ---------------------------------------------------------------------------
                pop     ebp
                retn

; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int __thiscall sub_7937BD(void **this, void *, int, int)
sub_7937BD      proc near               ; CODE XREF: sub_793363+11E↑p

var_20          = dword ptr -20h
Block           = dword ptr -1Ch
var_18          = dword ptr -18h
var_14          = dword ptr -14h
var_10          = dword ptr -10h
var_C           = dword ptr -0Ch
var_8           = dword ptr -8
var_4           = dword ptr -4
arg_0           = dword ptr  8
arg_4           = dword ptr  0Ch
arg_8           = dword ptr  10h

                push    ebp
                mov     ebp, esp
                sub     esp, 20h
                mov     [ebp+var_C], ecx
                mov     eax, [ebp+var_C]
                mov     [ebp+var_8], eax
                mov     eax, [ebp+var_8]
                mov     [ebp+var_4], eax
                mov     eax, [ebp+var_8]
                add     eax, 4
                mov     [ebp+var_10], eax
                mov     eax, [ebp+var_8]
                add     eax, 8
                mov     [ebp+var_14], eax
                mov     ecx, [ebp+var_8]
                call    sub_791642
                mov     eax, [ebp+var_4]
                cmp     dword ptr [eax], 0
                jz      short loc_793837
                mov     eax, [ebp+var_10]
                push    dword ptr [eax]
                mov     eax, [ebp+var_4]
                push    dword ptr [eax]
                mov     ecx, [ebp+var_C]
                call    sub_7925B7
                mov     ecx, [ebp+var_C]
                call    sub_792205
                mov     [ebp+var_20], eax
                mov     eax, [ebp+var_14]
                mov     ecx, [ebp+var_4]
                mov     eax, [eax]
                sub     eax, [ecx]
                sar     eax, 3
                mov     [ebp+var_18], eax
                mov     eax, [ebp+var_4]
                mov     eax, [eax]
                mov     [ebp+Block], eax
                push    [ebp+var_18]    ; int
                push    [ebp+Block]     ; Block
                mov     ecx, [ebp+var_20]
                call    sub_79261E

loc_793837:                             ; CODE XREF: sub_7937BD+35↑j
                mov     eax, [ebp+var_4]
                mov     ecx, [ebp+arg_0]
                mov     [eax], ecx
                mov     eax, [ebp+arg_4]
                mov     ecx, [ebp+arg_0]
                lea     eax, [ecx+eax*8]
                mov     ecx, [ebp+var_10]
                mov     [ecx], eax
                mov     eax, [ebp+arg_8]
                mov     ecx, [ebp+arg_0]
                lea     eax, [ecx+eax*8]
                mov     ecx, [ebp+var_14]
                mov     [ecx], eax
                leave
                retn    0Ch
sub_7937BD      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; unsigned int __thiscall sub_79385F(_DWORD *this, unsigned int)
sub_79385F      proc near               ; CODE XREF: sub_793363+62↑p

var_10          = dword ptr -10h
var_C           = dword ptr -0Ch
var_8           = dword ptr -8
var_4           = dword ptr -4
arg_0           = dword ptr  8

                push    ebp
                mov     ebp, esp
                sub     esp, 10h
                mov     [ebp+var_8], ecx
                mov     ecx, [ebp+var_8]
                call    sub_793A30
                mov     [ebp+var_4], eax
                mov     ecx, [ebp+var_8]
                call    sub_7938D6
                mov     [ebp+var_C], eax
                mov     eax, [ebp+var_4]
                shr     eax, 1
                mov     ecx, [ebp+var_C]
                sub     ecx, eax
                cmp     [ebp+var_4], ecx
                jbe     short loc_793892
                mov     eax, [ebp+var_C]
                jmp     short locret_7938AD
; ---------------------------------------------------------------------------

loc_793892:                             ; CODE XREF: sub_79385F+2C↑j
                mov     eax, [ebp+var_4]
                shr     eax, 1
                add     eax, [ebp+var_4]
                mov     [ebp+var_10], eax
                mov     eax, [ebp+var_10]
                cmp     eax, [ebp+arg_0]
                jnb     short loc_7938AA
                mov     eax, [ebp+arg_0]
                jmp     short locret_7938AD
; ---------------------------------------------------------------------------

loc_7938AA:                             ; CODE XREF: sub_79385F+44↑j
                mov     eax, [ebp+var_10]

locret_7938AD:                          ; CODE XREF: sub_79385F+31↑j
                                        ; sub_79385F+49↑j
                leave
                retn    4
sub_79385F      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int __thiscall sub_7938B1(void *this, int, int, int)
sub_7938B1      proc near               ; CODE XREF: sub_793363+CB↑p

var_8           = dword ptr -8
var_4           = dword ptr -4
arg_0           = dword ptr  8
arg_4           = dword ptr  0Ch
arg_8           = dword ptr  10h

                push    ebp
                mov     ebp, esp
                push    ecx
                push    ecx
                mov     [ebp+var_8], ecx
                xor     eax, eax
                mov     byte ptr [ebp+var_4], al
                push    [ebp+var_4]
                push    [ebp+arg_8]
                push    [ebp+arg_4]
                push    [ebp+arg_0]
                mov     ecx, [ebp+var_8]
                call    sub_793A0B
                leave
                retn    0Ch
sub_7938B1      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int __thiscall sub_7938D6(void *this)
sub_7938D6      proc near               ; CODE XREF: sub_793363+28↑p
                                        ; sub_79385F+17↑p

var_C           = dword ptr -0Ch
var_8           = dword ptr -8
var_4           = dword ptr -4

                push    ebp
                mov     ebp, esp
                sub     esp, 0Ch
                mov     [ebp+var_4], ecx
                mov     ecx, [ebp+var_4]
                call    sub_792205
                push    eax
                call    sub_793A4E
                pop     ecx
                mov     [ebp+var_8], eax
                call    unknown_libname_1 ; Microsoft VisualC 14/net runtime
                mov     [ebp+var_C], eax
                lea     eax, [ebp+var_8]
                push    eax
                lea     eax, [ebp+var_C]
                push    eax
                call    sub_792B21
                pop     ecx
                pop     ecx
                mov     eax, [eax]
                leave
                retn
sub_7938D6      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _DWORD *__thiscall sub_79390C(_DWORD *this, unsigned int)
sub_79390C      proc near               ; CODE XREF: sub_793285+24↑p
                                        ; sub_7932D3+24↑p ...

var_4           = dword ptr -4
arg_0           = dword ptr  8

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+var_4], ecx
                push    6C078965h
                push    0FFFFFFFFh
                push    [ebp+arg_0]
                mov     ecx, [ebp+var_4]
                call    sub_793A58
                mov     eax, [ebp+var_4]
                leave
                retn    4
sub_79390C      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int *__thiscall sub_79392C(int *this, unsigned int)
sub_79392C      proc near               ; CODE XREF: sub_792F66+93↑p

var_8           = dword ptr -8
var_4           = dword ptr -4
arg_0           = dword ptr  8

                push    ebp
                mov     ebp, esp
                push    ecx
                push    ecx
                mov     [ebp+var_4], ecx
                mov     eax, [ebp+var_4]
                mov     [ebp+var_8], eax
                push    [ebp+arg_0]
                mov     ecx, [ebp+var_8]
                call    sub_7927F8
                push    [ebp+arg_0]
                mov     ecx, [ebp+var_4]
                call    sub_79263A
                mov     eax, [ebp+var_4]
                leave
                retn    4
sub_79392C      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _DWORD *__thiscall sub_793957(_DWORD *this, int, int)
sub_793957      proc near               ; CODE XREF: sub_79368D+10↑p

var_8           = dword ptr -8
var_4           = dword ptr -4
arg_0           = dword ptr  8
arg_4           = dword ptr  0Ch

                push    ebp
                mov     ebp, esp
                push    ecx
                push    ecx
                mov     [ebp+var_4], ecx
                mov     eax, [ebp+var_4]
                mov     [ebp+var_8], eax
                push    [ebp+arg_4]
                push    [ebp+arg_0]
                mov     ecx, [ebp+var_8]
                call    sub_793A80
                mov     eax, [ebp+var_4]
                leave
                retn    8
sub_793957      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _WORD *__thiscall sub_79397A(_WORD *this, __int16, __int16)
sub_79397A      proc near               ; CODE XREF: sub_7936A9+10↑p

var_8           = dword ptr -8
var_4           = dword ptr -4
arg_0           = dword ptr  8
arg_4           = dword ptr  0Ch

                push    ebp
                mov     ebp, esp
                push    ecx
                push    ecx
                mov     [ebp+var_4], ecx
                mov     eax, [ebp+var_4]
                mov     [ebp+var_8], eax
                push    [ebp+arg_4]
                push    [ebp+arg_0]
                mov     ecx, [ebp+var_8]
                call    sub_793A9C
                mov     eax, [ebp+var_4]
                leave
                retn    8
sub_79397A      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _DWORD *__thiscall sub_79399D(_DWORD *this, int, int, int, int)
sub_79399D      proc near               ; CODE XREF: sub_7936C5+16↑p

var_8           = dword ptr -8
var_4           = dword ptr -4
arg_0           = dword ptr  8
arg_4           = dword ptr  0Ch
arg_8           = dword ptr  10h
arg_C           = dword ptr  14h

                push    ebp
                mov     ebp, esp
                push    ecx
                push    ecx
                mov     [ebp+var_4], ecx
                mov     eax, [ebp+var_4]
                mov     [ebp+var_8], eax
                push    [ebp+arg_C]
                push    [ebp+arg_8]
                push    [ebp+arg_4]
                push    [ebp+arg_0]
                mov     ecx, [ebp+var_8]
                call    sub_793AB8
                mov     eax, [ebp+var_4]
                leave
                retn    10h
sub_79399D      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int __thiscall sub_7939C6(_DWORD *this, int)
sub_7939C6      proc near               ; CODE XREF: sub_7936F6+23↑p

var_C           = dword ptr -0Ch
var_8           = dword ptr -8
var_4           = dword ptr -4
arg_0           = dword ptr  8

                push    ebp
                mov     ebp, esp
                sub     esp, 0Ch
                mov     [ebp+var_8], ecx
                mov     eax, [ebp+var_8]
                mov     ecx, [ebp+arg_0]
                mov     [eax], ecx
                mov     eax, [ebp+var_8]
                mov     eax, [eax]
                mov     [ebp+var_C], eax
                mov     eax, [ebp+var_C]
                mov     eax, [eax]
                mov     ecx, [ebp+var_C]
                add     ecx, [eax+4]
                call    ds:?rdbuf@?$basic_ios@DU?$char_traits@D@std@@@std@@QBEPAV?$basic_streambuf@DU?$char_traits@D@std@@@2@XZ ; std::ios::rdbuf(void)
                mov     [ebp+var_4], eax
                cmp     [ebp+var_4], 0
                jz      short loc_793A04
                mov     eax, [ebp+var_4]
                mov     eax, [eax]
                mov     ecx, [ebp+var_4]
                call    dword ptr [eax+4]

loc_793A04:                             ; CODE XREF: sub_7939C6+31↑j
                mov     eax, [ebp+var_8]
                leave
                retn    4
sub_7939C6      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int __thiscall sub_793A0B(void *this, int, int, int, int)
sub_793A0B      proc near               ; CODE XREF: sub_7938B1+1C↑p

var_4           = dword ptr -4
arg_0           = dword ptr  8
arg_4           = dword ptr  0Ch
arg_8           = dword ptr  10h

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+var_4], ecx
                mov     ecx, [ebp+var_4]
                call    sub_792205
                push    eax
                push    [ebp+arg_8]
                push    [ebp+arg_4]
                push    [ebp+arg_0]
                call    sub_79349C
                add     esp, 10h
                leave
                retn    10h
sub_793A0B      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int __thiscall sub_793A30(_DWORD *this)
sub_793A30      proc near               ; CODE XREF: sub_79385F+C↑p

var_8           = dword ptr -8
var_4           = dword ptr -4

                push    ebp
                mov     ebp, esp
                push    ecx
                push    ecx
                mov     [ebp+var_8], ecx
                mov     eax, [ebp+var_8]
                mov     [ebp+var_4], eax
                mov     eax, [ebp+var_4]
                mov     ecx, [ebp+var_4]
                mov     eax, [eax+8]
                sub     eax, [ecx]
                sar     eax, 3
                leave
                retn
sub_793A30      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int sub_793A4E()
sub_793A4E      proc near               ; CODE XREF: sub_7938D6+12↑p
                push    ebp
                mov     ebp, esp
                mov     eax, 1FFFFFFFh
                pop     ebp
                retn
sub_793A4E      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _DWORD *__thiscall sub_793A58(_DWORD *this, unsigned int, int, int)
sub_793A58      proc near               ; CODE XREF: sub_79390C+14↑p

var_4           = dword ptr -4
arg_0           = dword ptr  8
arg_4           = dword ptr  0Ch
arg_8           = dword ptr  10h

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+var_4], ecx
                mov     eax, [ebp+var_4]
                mov     ecx, [ebp+arg_4]
                mov     [eax+1384h], ecx
                push    [ebp+arg_8]
                push    [ebp+arg_0]
                mov     ecx, [ebp+var_4]
                call    sub_793ADA
                mov     eax, [ebp+var_4]
                leave
                retn    0Ch
sub_793A58      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _DWORD *__thiscall sub_793A80(_DWORD *this, int, int)
sub_793A80      proc near               ; CODE XREF: sub_793957+17↑p

var_4           = dword ptr -4
arg_0           = dword ptr  8
arg_4           = dword ptr  0Ch

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+var_4], ecx
                push    [ebp+arg_4]
                push    [ebp+arg_0]
                mov     ecx, [ebp+var_4]
                call    sub_793B49
                mov     eax, [ebp+var_4]
                leave
                retn    8
sub_793A80      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _WORD *__thiscall sub_793A9C(_WORD *this, __int16, __int16)
sub_793A9C      proc near               ; CODE XREF: sub_79397A+17↑p

var_4           = dword ptr -4
arg_0           = dword ptr  8
arg_4           = dword ptr  0Ch

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+var_4], ecx
                push    [ebp+arg_4]
                push    [ebp+arg_0]
                mov     ecx, [ebp+var_4]
                call    sub_793B65
                mov     eax, [ebp+var_4]
                leave
                retn    8
sub_793A9C      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _DWORD *__thiscall sub_793AB8(_DWORD *this, int, int, int, int)
sub_793AB8      proc near               ; CODE XREF: sub_79399D+1D↑p

var_4           = dword ptr -4
arg_0           = dword ptr  8
arg_4           = dword ptr  0Ch
arg_8           = dword ptr  10h
arg_C           = dword ptr  14h

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+var_4], ecx
                push    [ebp+arg_C]
                push    [ebp+arg_8]
                push    [ebp+arg_4]
                push    [ebp+arg_0]
                mov     ecx, [ebp+var_4]
                call    sub_793B85
                mov     eax, [ebp+var_4]
                leave
                retn    10h
sub_793AB8      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _DWORD *__thiscall sub_793ADA(_DWORD *this, unsigned int, int)
sub_793ADA      proc near               ; CODE XREF: sub_793A58+1C↑p

var_10          = dword ptr -10h
var_C           = dword ptr -0Ch
var_8           = dword ptr -8
var_4           = dword ptr -4
arg_0           = dword ptr  8
arg_4           = dword ptr  0Ch

                push    ebp
                mov     ebp, esp
                sub     esp, 10h
                mov     [ebp+var_C], ecx
                push    4
                pop     eax
                imul    eax, 0
                mov     ecx, [ebp+var_C]
                mov     edx, [ebp+arg_0]
                mov     [ecx+eax+4], edx
                mov     eax, [ebp+arg_0]
                mov     [ebp+var_8], eax
                mov     [ebp+var_4], 1
                jmp     short loc_793B09
; ---------------------------------------------------------------------------

loc_793B02:                             ; CODE XREF: sub_793ADA+60↓j
                mov     eax, [ebp+var_4]
                inc     eax
                mov     [ebp+var_4], eax

loc_793B09:                             ; CODE XREF: sub_793ADA+26↑j
                cmp     [ebp+var_4], 270h
                jnb     short loc_793B3C
                mov     eax, [ebp+var_8]
                shr     eax, 1Eh
                xor     eax, [ebp+var_8]
                imul    eax, [ebp+arg_4]
                mov     ecx, [ebp+var_4]
                add     ecx, eax
                mov     [ebp+var_10], ecx
                mov     eax, [ebp+var_4]
                mov     ecx, [ebp+var_C]
                mov     edx, [ebp+var_10]
                mov     [ecx+eax*4+4], edx
                mov     eax, [ebp+var_10]
                mov     [ebp+var_8], eax
                jmp     short loc_793B02
; ---------------------------------------------------------------------------

loc_793B3C:                             ; CODE XREF: sub_793ADA+36↑j
                mov     eax, [ebp+var_C]
                mov     dword ptr [eax], 270h
                leave
                retn    8
sub_793ADA      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _DWORD *__thiscall sub_793B49(_DWORD *this, int, int)
sub_793B49      proc near               ; CODE XREF: sub_793A80+10↑p

var_4           = dword ptr -4
arg_0           = dword ptr  8
arg_4           = dword ptr  0Ch

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+var_4], ecx
                mov     eax, [ebp+var_4]
                mov     ecx, [ebp+arg_0]
                mov     [eax], ecx
                mov     eax, [ebp+var_4]
                mov     ecx, [ebp+arg_4]
                mov     [eax+4], ecx
                leave
                retn    8
sub_793B49      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _WORD *__thiscall sub_793B65(_WORD *this, __int16, __int16)
sub_793B65      proc near               ; CODE XREF: sub_793A9C+10↑p

var_4           = dword ptr -4
arg_0           = word ptr  8
arg_4           = word ptr  0Ch

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+var_4], ecx
                mov     eax, [ebp+var_4]
                mov     cx, [ebp+arg_0]
                mov     [eax], cx
                mov     eax, [ebp+var_4]
                mov     cx, [ebp+arg_4]
                mov     [eax+2], cx
                leave
                retn    8
sub_793B65      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _DWORD *__thiscall sub_793B85(_DWORD *this, int, int, int, int)
sub_793B85      proc near               ; CODE XREF: sub_793AB8+16↑p

var_4           = dword ptr -4
arg_0           = dword ptr  8
arg_4           = dword ptr  0Ch
arg_8           = dword ptr  10h
arg_C           = dword ptr  14h

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+var_4], ecx
                mov     eax, [ebp+var_4]
                mov     ecx, [ebp+arg_0]
                mov     edx, [ebp+arg_4]
                mov     [eax], ecx
                mov     [eax+4], edx
                mov     eax, [ebp+var_4]
                mov     ecx, [ebp+arg_8]
                mov     edx, [ebp+arg_C]
                mov     [eax+8], ecx
                mov     [eax+0Ch], edx
                leave
                retn    10h
sub_793B85      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _DWORD *__thiscall sub_793BAD(_DWORD *this, int, int)
sub_793BAD      proc near               ; CODE XREF: sub_7931DB+19↑p

var_4           = dword ptr -4
arg_4           = dword ptr  0Ch

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+var_4], ecx
                push    [ebp+arg_4]
                call    unknown_libname_3 ; Microsoft VisualC 14/net runtime
                pop     ecx
                mov     ecx, [ebp+var_4]
                mov     eax, [eax]
                mov     [ecx], eax
                mov     eax, [ebp+var_4]
                leave
                retn    8
sub_793BAD      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _DWORD *__cdecl sub_793BCB(_DWORD *, int *, void *)
sub_793BCB      proc near               ; CODE XREF: sub_793200+1A↑p

var_18          = qword ptr -18h
var_10          = qword ptr -10h
var_8           = dword ptr -8
var_4           = dword ptr -4
arg_0           = dword ptr  8
arg_4           = dword ptr  0Ch
arg_8           = dword ptr  10h

                push    ebp
                mov     ebp, esp
                sub     esp, 18h
                push    esi
                push    edi
                mov     eax, [ebp+arg_4]
                mov     ecx, [eax]
                mov     eax, [eax+4]
                mov     [ebp+var_8], ecx
                mov     [ebp+var_4], eax
                lea     ecx, [ebp+var_8]
                call    sub_791882
                mov     esi, eax
                mov     edi, edx
                push    [ebp+arg_8]
                lea     ecx, [ebp+var_18]
                call    sub_793F7F
                mov     ecx, eax
                call    sub_791882
                add     esi, eax
                adc     edi, edx
                mov     dword ptr [ebp+var_10], esi
                mov     dword ptr [ebp+var_10+4], edi
                lea     eax, [ebp+var_10]
                push    eax
                mov     ecx, [ebp+arg_0]
                call    sub_791864
                mov     eax, [ebp+arg_0]
                pop     edi
                pop     esi
                leave
                retn
sub_793BCB      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; bool __cdecl sub_793C1C(_DWORD *, _DWORD *)
sub_793C1C      proc near               ; CODE XREF: sub_793230+17↑p

var_4           = dword ptr -4
arg_0           = dword ptr  8
arg_4           = dword ptr  0Ch

                push    ebp
                mov     ebp, esp
                push    ecx
                push    [ebp+arg_0]
                push    [ebp+arg_4]
                call    sub_793FAC
                pop     ecx
                pop     ecx
                movzx   eax, al
                test    eax, eax
                jnz     short loc_793C3D
                mov     [ebp+var_4], 1
                jmp     short loc_793C41
; ---------------------------------------------------------------------------

loc_793C3D:                             ; CODE XREF: sub_793C1C+16↑j
                and     [ebp+var_4], 0

loc_793C41:                             ; CODE XREF: sub_793C1C+1F↑j
                mov     al, byte ptr [ebp+var_4]
                leave
                retn
sub_793C1C      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _DWORD *__cdecl sub_793C46(_DWORD *, _DWORD *, _DWORD *)
sub_793C46      proc near               ; CODE XREF: sub_793230+32↑p

var_18          = dword ptr -18h
var_10          = dword ptr -10h
var_8           = dword ptr -8
var_4           = dword ptr -4
arg_0           = dword ptr  8
arg_4           = dword ptr  0Ch
arg_8           = dword ptr  10h

                push    ebp
                mov     ebp, esp
                sub     esp, 18h
                lea     eax, [ebp+var_10]
                push    eax
                mov     ecx, [ebp+arg_8]
                call    sub_791FA1
                mov     [ebp+var_4], eax
                lea     eax, [ebp+var_18]
                push    eax
                mov     ecx, [ebp+arg_4]
                call    sub_791FA1
                mov     [ebp+var_8], eax
                push    [ebp+var_4]
                push    [ebp+var_8]
                push    [ebp+arg_0]
                call    sub_793FDF
                add     esp, 0Ch
                mov     eax, [ebp+arg_0]
                leave
                retn
sub_793C46      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; bool __cdecl sub_793C80(int, void *)
sub_793C80      proc near               ; CODE XREF: sub_793230+3F↑p

var_48          = dword ptr -48h
var_40          = dword ptr -40h
var_38          = dword ptr -38h
var_30          = qword ptr -30h
var_28          = qword ptr -28h
var_20          = dword ptr -20h
var_18          = dword ptr -18h
var_14          = dword ptr -14h
var_10          = qword ptr -10h
var_8           = dword ptr -8
var_1           = byte ptr -1
arg_0           = dword ptr  8
arg_4           = dword ptr  0Ch

                push    ebp
                mov     ebp, esp
                sub     esp, 48h
                mov     eax, 311CDh
                mov     [ebp+var_18], 0AD160000h
                mov     [ebp+var_14], eax
                movsd   xmm0, ds:qword_7973E8
                movsd   [ebp+var_28], xmm0
                lea     eax, [ebp+var_38]
                push    eax
                call    sub_791797
                pop     ecx
                mov     [ebp+var_8], eax
                lea     eax, [ebp+var_40]
                push    eax
                mov     ecx, [ebp+var_8]
                call    sub_791FA1
                push    eax
                lea     ecx, [ebp+var_10]
                call    sub_794034
                push    [ebp+arg_4]
                lea     eax, [ebp+var_28]
                push    eax
                call    sub_794061
                pop     ecx
                pop     ecx
                mov     [ebp+var_1], al
                movzx   eax, [ebp+var_1]
                test    eax, eax
                jz      short loc_793CEB
                lea     eax, [ebp+var_18]
                push    eax
                lea     ecx, [ebp+var_10]
                call    sub_793E6F
                jmp     short loc_793D02
; ---------------------------------------------------------------------------

loc_793CEB:                             ; CODE XREF: sub_793C80+5B↑j
                push    [ebp+arg_4]
                lea     eax, [ebp+var_48]
                push    eax
                call    sub_7940BD
                pop     ecx
                pop     ecx
                push    eax
                lea     ecx, [ebp+var_10]
                call    sub_793E6F

loc_793D02:                             ; CODE XREF: sub_793C80+69↑j
                lea     eax, [ebp+var_10]
                push    eax
                lea     eax, [ebp+var_20]
                push    eax
                call    sub_793E95
                pop     ecx
                pop     ecx
                lea     ecx, [ebp+var_20]
                call    sub_791882
                mov     ecx, [ebp+arg_0]
                mov     [ecx], eax
                mov     [ecx+4], edx
                lea     eax, [ebp+var_20]
                push    eax
                lea     ecx, [ebp+var_30]
                call    sub_793F52
                lea     eax, [ebp+var_30]
                push    eax
                lea     ecx, [ebp+var_10]
                call    sub_793E49
                lea     ecx, [ebp+var_10]
                call    sub_791882
                mov     ecx, [ebp+arg_0]
                mov     [ecx+8], eax
                mov     al, [ebp+var_1]
                leave
                retn
sub_793C80      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int __thiscall sub_793D4C(int *this, int)
sub_793D4C      proc near               ; CODE XREF: sub_793285+47↑p

var_4           = dword ptr -4
arg_0           = dword ptr  8

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+var_4], ecx
                mov     eax, [ebp+var_4]
                push    dword ptr [eax+0Ch]
                push    dword ptr [eax+8]
                mov     eax, [ebp+var_4]
                push    dword ptr [eax+4]
                push    dword ptr [eax]
                push    [ebp+arg_0]
                mov     ecx, [ebp+var_4]
                call    sub_79415C
                leave
                retn    4
sub_793D4C      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; __int16 __thiscall sub_793D73(__int16 *this, int)
sub_793D73      proc near               ; CODE XREF: sub_7932D3+41↑p

var_4           = dword ptr -4
arg_0           = dword ptr  8

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+var_4], ecx
                mov     eax, [ebp+var_4]
                movzx   eax, word ptr [eax+2]
                push    eax
                mov     eax, [ebp+var_4]
                movzx   eax, word ptr [eax]
                push    eax
                push    [ebp+arg_0]
                mov     ecx, [ebp+var_4]
                call    sub_7941FE
                leave
                retn    4
sub_793D73      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int __thiscall sub_793D98(int *this, int)
sub_793D98      proc near               ; CODE XREF: sub_79331B+41↑p

var_4           = dword ptr -4
arg_0           = dword ptr  8

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+var_4], ecx
                mov     eax, [ebp+var_4]
                push    dword ptr [eax+4]
                mov     eax, [ebp+var_4]
                push    dword ptr [eax]
                push    [ebp+arg_0]
                mov     ecx, [ebp+var_4]
                call    sub_794278
                leave
                retn    4
sub_793D98      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int __thiscall sub_793DB9(_DWORD *this, int)
sub_793DB9      proc near               ; CODE XREF: sub_79349C+60↑p

var_10          = dword ptr -10h
var_C           = dword ptr -0Ch
var_8           = dword ptr -8
var_4           = dword ptr -4
arg_0           = dword ptr  8

                push    ebp
                mov     ebp, esp
                sub     esp, 10h
                mov     [ebp+var_4], ecx
                push    [ebp+arg_0]
                call    unknown_libname_3 ; Microsoft VisualC 14/net runtime
                pop     ecx
                mov     [ebp+var_8], eax
                mov     eax, [ebp+var_4]
                push    dword ptr [eax+4]
                call    unknown_libname_3 ; Microsoft VisualC 14/net runtime
                pop     ecx
                mov     [ebp+var_C], eax
                mov     eax, [ebp+var_4]
                mov     eax, [eax+8]
                mov     [ebp+var_10], eax
                push    [ebp+var_8]     ; int
                push    [ebp+var_C]     ; void *
                push    [ebp+var_10]    ; int
                call    sub_7942E0
                add     esp, 0Ch
                mov     eax, [ebp+var_4]
                mov     eax, [eax+4]
                add     eax, 8
                mov     ecx, [ebp+var_4]
                mov     [ecx+4], eax
                leave
                retn    4
sub_793DB9      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int __thiscall sub_793E0A(_DWORD *this)
sub_793E0A      proc near               ; CODE XREF: sub_7935AC+3F↑p

var_C           = dword ptr -0Ch
var_8           = dword ptr -8
var_4           = dword ptr -4

                push    ebp
                mov     ebp, esp
                sub     esp, 0Ch
                mov     [ebp+var_4], ecx
                mov     eax, [ebp+var_4]
                push    dword ptr [eax+4]
                call    unknown_libname_3 ; Microsoft VisualC 14/net runtime
                pop     ecx
                mov     [ebp+var_8], eax
                mov     eax, [ebp+var_4]
                mov     eax, [eax+8]
                mov     [ebp+var_C], eax
                push    [ebp+var_8]     ; void *
                push    [ebp+var_C]     ; int
                call    sub_79430D
                pop     ecx
                pop     ecx
                mov     eax, [ebp+var_4]
                mov     eax, [eax+4]
                add     eax, 8
                mov     ecx, [ebp+var_4]
                mov     [ecx+4], eax
                leave
                retn
sub_793E0A      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _QWORD *__thiscall sub_793E49(_QWORD *this, _QWORD *)
sub_793E49      proc near               ; CODE XREF: sub_793C80+B4↑p

var_4           = dword ptr -4
arg_0           = dword ptr  8

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+var_4], ecx
                mov     eax, [ebp+var_4]
                mov     ecx, [ebp+arg_0]
                mov     edx, [eax]
                sub     edx, [ecx]
                mov     eax, [eax+4]
                sbb     eax, [ecx+4]
                mov     ecx, [ebp+var_4]
                mov     [ecx], edx
                mov     [ecx+4], eax
                mov     eax, [ebp+var_4]
                leave
                retn    4
sub_793E49      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _QWORD *__thiscall sub_793E6F(_QWORD *this, _QWORD *)
sub_793E6F      proc near               ; CODE XREF: sub_793C80+64↑p
                                        ; sub_793C80+7D↑p

var_4           = dword ptr -4
arg_0           = dword ptr  8

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+var_4], ecx
                mov     eax, [ebp+var_4]
                mov     ecx, [ebp+arg_0]
                mov     edx, [eax]
                add     edx, [ecx]
                mov     eax, [eax+4]
                adc     eax, [ecx+4]
                mov     ecx, [ebp+var_4]
                mov     [ecx], edx
                mov     [ecx+4], eax
                mov     eax, [ebp+var_4]
                leave
                retn    4
sub_793E6F      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _DWORD *__cdecl sub_793E95(_DWORD *, void *)
sub_793E95      proc near               ; CODE XREF: sub_793C80+8A↑p

var_24          = dword ptr -24h
var_20          = dword ptr -20h
var_1C          = qword ptr -1Ch
var_14          = dword ptr -14h
var_10          = dword ptr -10h
var_C           = dword ptr -0Ch
var_8           = dword ptr -8
var_2           = byte ptr -2
var_1           = byte ptr -1
arg_0           = dword ptr  8
arg_4           = dword ptr  0Ch

                push    ebp
                mov     ebp, esp
                sub     esp, 24h
                mov     [ebp+var_1], 1
                mov     [ebp+var_2], 0
                xor     eax, eax
                jz      short loc_793EF1
                xor     eax, eax
                inc     eax
                jz      short loc_793ED0
                mov     ecx, [ebp+arg_4]
                call    sub_791882
                mov     [ebp+var_C], eax
                mov     [ebp+var_8], edx
                lea     eax, [ebp+var_C]
                push    eax
                mov     ecx, [ebp+arg_0]
                call    sub_791864
                mov     eax, [ebp+arg_0]
                jmp     locret_793F50
; ---------------------------------------------------------------------------
                jmp     short loc_793EEF
; ---------------------------------------------------------------------------

loc_793ED0:                             ; CODE XREF: sub_793E95+15↑j
                mov     ecx, [ebp+arg_4]
                call    sub_791882
                mov     [ebp+var_14], eax
                mov     [ebp+var_10], edx
                lea     eax, [ebp+var_14]
                push    eax
                mov     ecx, [ebp+arg_0]
                call    sub_791864
                mov     eax, [ebp+arg_0]
                jmp     short locret_793F50
; ---------------------------------------------------------------------------

loc_793EEF:                             ; CODE XREF: sub_793E95+39↑j
                jmp     short locret_793F50
; ---------------------------------------------------------------------------

loc_793EF1:                             ; CODE XREF: sub_793E95+10↑j
                xor     eax, eax
                inc     eax
                jz      short loc_793F25
                mov     ecx, [ebp+arg_4]
                call    sub_791882
                push    0
                push    3B9ACA00h
                push    edx
                push    eax
                call    __alldiv
                mov     dword ptr [ebp+var_1C], eax
                mov     dword ptr [ebp+var_1C+4], edx
                lea     eax, [ebp+var_1C]
                push    eax
                mov     ecx, [ebp+arg_0]
                call    sub_791864
                mov     eax, [ebp+arg_0]
                jmp     short locret_793F50
; ---------------------------------------------------------------------------
                jmp     short locret_793F50
; ---------------------------------------------------------------------------

loc_793F25:                             ; CODE XREF: sub_793E95+5F↑j
                mov     ecx, [ebp+arg_4]
                call    sub_791882
                push    0
                push    3B9ACA00h
                push    edx
                push    eax
                call    __alldiv
                mov     [ebp+var_24], eax
                mov     [ebp+var_20], edx
                lea     eax, [ebp+var_24]
                push    eax
                mov     ecx, [ebp+arg_0]
                call    sub_791864
                mov     eax, [ebp+arg_0]

locret_793F50:                          ; CODE XREF: sub_793E95+34↑j
                                        ; sub_793E95+58↑j ...
                leave
                retn
sub_793E95      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; __int64 *__thiscall sub_793F52(__int64 *this, void *)
sub_793F52      proc near               ; CODE XREF: sub_793C80+A8↑p

var_C           = dword ptr -0Ch
var_4           = dword ptr -4
arg_0           = dword ptr  8

                push    ebp
                mov     ebp, esp
                sub     esp, 0Ch
                mov     [ebp+var_4], ecx
                push    [ebp+arg_0]
                lea     eax, [ebp+var_C]
                push    eax
                call    sub_794B5C
                pop     ecx
                pop     ecx
                mov     ecx, eax
                call    sub_791882
                mov     ecx, [ebp+var_4]
                mov     [ecx], eax
                mov     [ecx+4], edx
                mov     eax, [ebp+var_4]
                leave
                retn    4
sub_793F52      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; __int64 *__thiscall sub_793F7F(__int64 *this, void *)
sub_793F7F      proc near               ; CODE XREF: sub_793BCB+28↑p

var_C           = dword ptr -0Ch
var_4           = dword ptr -4
arg_0           = dword ptr  8

                push    ebp
                mov     ebp, esp
                sub     esp, 0Ch
                mov     [ebp+var_4], ecx
                push    [ebp+arg_0]
                lea     eax, [ebp+var_C]
                push    eax
                call    sub_794C18
                pop     ecx
                pop     ecx
                mov     ecx, eax
                call    sub_791882
                mov     ecx, [ebp+var_4]
                mov     [ecx], eax
                mov     [ecx+4], edx
                mov     eax, [ebp+var_4]
                leave
                retn    4
sub_793F7F      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; bool __cdecl sub_793FAC(_DWORD *, _DWORD *)
sub_793FAC      proc near               ; CODE XREF: sub_793C1C+A↑p

var_18          = dword ptr -18h
var_10          = dword ptr -10h
var_8           = dword ptr -8
var_4           = dword ptr -4
arg_0           = dword ptr  8
arg_4           = dword ptr  0Ch

                push    ebp
                mov     ebp, esp
                sub     esp, 18h
                lea     eax, [ebp+var_10]
                push    eax
                mov     ecx, [ebp+arg_4]
                call    sub_791FA1
                mov     [ebp+var_4], eax
                lea     eax, [ebp+var_18]
                push    eax
                mov     ecx, [ebp+arg_0]
                call    sub_791FA1
                mov     [ebp+var_8], eax
                push    [ebp+var_4]
                push    [ebp+var_8]
                call    sub_794CD4
                pop     ecx
                pop     ecx
                leave
                retn
sub_793FAC      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _DWORD *__cdecl sub_793FDF(_DWORD *, int *, int *)
sub_793FDF      proc near               ; CODE XREF: sub_793C46+2D↑p

var_18          = qword ptr -18h
var_10          = dword ptr -10h
var_C           = dword ptr -0Ch
var_8           = dword ptr -8
var_4           = dword ptr -4
arg_0           = dword ptr  8
arg_4           = dword ptr  0Ch
arg_8           = dword ptr  10h

                push    ebp
                mov     ebp, esp
                sub     esp, 18h
                push    esi
                push    edi
                mov     eax, [ebp+arg_4]
                mov     ecx, [eax]
                mov     eax, [eax+4]
                mov     [ebp+var_8], ecx
                mov     [ebp+var_4], eax
                mov     eax, [ebp+arg_8]
                mov     ecx, [eax]
                mov     eax, [eax+4]
                mov     [ebp+var_10], ecx
                mov     [ebp+var_C], eax
                lea     ecx, [ebp+var_8]
                call    sub_791882
                mov     esi, eax
                mov     edi, edx
                lea     ecx, [ebp+var_10]
                call    sub_791882
                sub     esi, eax
                sbb     edi, edx
                mov     dword ptr [ebp+var_18], esi
                mov     dword ptr [ebp+var_18+4], edi
                lea     eax, [ebp+var_18]
                push    eax
                mov     ecx, [ebp+arg_0]
                call    sub_791864
                mov     eax, [ebp+arg_0]
                pop     edi
                pop     esi
                leave
                retn
sub_793FDF      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; __int64 *__thiscall sub_794034(__int64 *this, void *)
sub_794034      proc near               ; CODE XREF: sub_793C80+3F↑p

var_C           = dword ptr -0Ch
var_4           = dword ptr -4
arg_0           = dword ptr  8

                push    ebp
                mov     ebp, esp
                sub     esp, 0Ch
                mov     [ebp+var_4], ecx
                push    [ebp+arg_0]
                lea     eax, [ebp+var_C]
                push    eax
                call    sub_794D3E
                pop     ecx
                pop     ecx
                mov     ecx, eax
                call    sub_791882
                mov     ecx, [ebp+var_4]
                mov     [ecx], eax
                mov     [ecx+4], edx
                mov     eax, [ebp+var_4]
                leave
                retn    4
sub_794034      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; bool __cdecl sub_794061(void *, void *)
sub_794061      proc near               ; CODE XREF: sub_793C80+4B↑p

var_2C          = qword ptr -2Ch
var_24          = qword ptr -24h
var_1C          = qword ptr -1Ch
var_14          = qword ptr -14h
var_C           = qword ptr -0Ch
var_4           = dword ptr -4
arg_0           = dword ptr  8
arg_4           = dword ptr  0Ch

                push    ebp
                mov     ebp, esp
                sub     esp, 2Ch
                push    [ebp+arg_0]
                lea     ecx, [ebp+var_24]
                call    sub_794DF1
                mov     ecx, eax
                call    sub_791893
                fstp    [ebp+var_C]
                movsd   xmm0, [ebp+var_C]
                push    [ebp+arg_4]
                lea     ecx, [ebp+var_2C]
                movsd   [ebp+var_1C], xmm0
                call    sub_794E1B
                mov     ecx, eax
                call    sub_791893
                fstp    [ebp+var_14]
                movsd   xmm0, [ebp+var_14]
                movsd   xmm1, [ebp+var_1C]
                comisd  xmm0, xmm1
                jbe     short loc_7940B4
                mov     [ebp+var_4], 1
                jmp     short loc_7940B8
; ---------------------------------------------------------------------------

loc_7940B4:                             ; CODE XREF: sub_794061+48↑j
                and     [ebp+var_4], 0

loc_7940B8:                             ; CODE XREF: sub_794061+51↑j
                mov     al, byte ptr [ebp+var_4]
                leave
                retn
sub_794061      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _DWORD *__cdecl sub_7940BD(_DWORD *, void *)
sub_7940BD      proc near               ; CODE XREF: sub_793C80+72↑p

var_24          = dword ptr -24h
var_20          = dword ptr -20h
var_1C          = dword ptr -1Ch
var_18          = dword ptr -18h
var_14          = dword ptr -14h
var_10          = dword ptr -10h
var_C           = qword ptr -0Ch
var_2           = byte ptr -2
var_1           = byte ptr -1
arg_0           = dword ptr  8
arg_4           = dword ptr  0Ch

                push    ebp
                mov     ebp, esp
                sub     esp, 24h
                mov     [ebp+var_1], 1
                mov     [ebp+var_2], 1
                xor     eax, eax
                inc     eax
                jz      short loc_794117
                xor     eax, eax
                inc     eax
                jz      short loc_7940F6
                mov     ecx, [ebp+arg_4]
                call    sub_791882
                mov     dword ptr [ebp+var_C], eax
                mov     dword ptr [ebp+var_C+4], edx
                lea     eax, [ebp+var_C]
                push    eax
                mov     ecx, [ebp+arg_0]
                call    sub_791864
                mov     eax, [ebp+arg_0]
                jmp     short locret_79415A
; ---------------------------------------------------------------------------
                jmp     short loc_794115
; ---------------------------------------------------------------------------

loc_7940F6:                             ; CODE XREF: sub_7940BD+16↑j
                mov     ecx, [ebp+arg_4]
                call    sub_791882
                mov     [ebp+var_14], eax
                mov     [ebp+var_10], edx
                lea     eax, [ebp+var_14]
                push    eax
                mov     ecx, [ebp+arg_0]
                call    sub_791864
                mov     eax, [ebp+arg_0]
                jmp     short locret_79415A
; ---------------------------------------------------------------------------

loc_794115:                             ; CODE XREF: sub_7940BD+37↑j
                jmp     short locret_79415A
; ---------------------------------------------------------------------------

loc_794117:                             ; CODE XREF: sub_7940BD+11↑j
                xor     eax, eax
                inc     eax
                jz      short loc_79413D
                mov     ecx, [ebp+arg_4]
                call    sub_791882
                mov     [ebp+var_1C], eax
                mov     [ebp+var_18], edx
                lea     eax, [ebp+var_1C]
                push    eax
                mov     ecx, [ebp+arg_0]
                call    sub_791864
                mov     eax, [ebp+arg_0]
                jmp     short locret_79415A
; ---------------------------------------------------------------------------
                jmp     short locret_79415A
; ---------------------------------------------------------------------------

loc_79413D:                             ; CODE XREF: sub_7940BD+5D↑j
                mov     ecx, [ebp+arg_4]
                call    sub_791882
                mov     [ebp+var_24], eax
                mov     [ebp+var_20], edx
                lea     eax, [ebp+var_24]
                push    eax
                mov     ecx, [ebp+arg_0]
                call    sub_791864
                mov     eax, [ebp+arg_0]

locret_79415A:                          ; CODE XREF: sub_7940BD+35↑j
                                        ; sub_7940BD+56↑j ...
                leave
                retn
sub_7940BD      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int __thiscall sub_79415C(void *this, int, int, int, int, int)
sub_79415C      proc near               ; CODE XREF: sub_793D4C+1E↑p

var_34          = dword ptr -34h
var_24          = dword ptr -24h
var_20          = dword ptr -20h
var_1C          = qword ptr -1Ch
var_14          = qword ptr -14h
var_C           = qword ptr -0Ch
var_4           = dword ptr -4
arg_0           = dword ptr  8
arg_4           = dword ptr  0Ch
arg_8           = dword ptr  10h
arg_C           = dword ptr  14h
arg_10          = dword ptr  18h

                push    ebp
                mov     ebp, esp
                sub     esp, 34h
                mov     [ebp+var_4], ecx
                push    [ebp+arg_0]
                lea     ecx, [ebp+var_34]
                call    sub_794700
                push    [ebp+arg_8]
                push    [ebp+arg_4]
                call    sub_7947C1
                pop     ecx
                pop     ecx
                mov     dword ptr [ebp+var_C], eax
                mov     dword ptr [ebp+var_C+4], edx
                push    [ebp+arg_10]
                push    [ebp+arg_C]
                call    sub_7947C1
                pop     ecx
                pop     ecx
                mov     dword ptr [ebp+var_14], eax
                mov     dword ptr [ebp+var_14+4], edx
                mov     eax, dword ptr [ebp+var_14]
                sub     eax, dword ptr [ebp+var_C]
                mov     ecx, dword ptr [ebp+var_14+4]
                sbb     ecx, dword ptr [ebp+var_C+4]
                mov     [ebp+var_24], eax
                mov     [ebp+var_20], ecx
                mov     eax, [ebp+var_24]
                and     eax, [ebp+var_20]
                cmp     eax, 0FFFFFFFFh
                jnz     short loc_7941C3
                lea     ecx, [ebp+var_34]
                call    sub_794528
                mov     dword ptr [ebp+var_1C], eax
                mov     dword ptr [ebp+var_1C+4], edx
                jmp     short loc_7941E5
; ---------------------------------------------------------------------------

loc_7941C3:                             ; CODE XREF: sub_79415C+55↑j
                mov     eax, dword ptr [ebp+var_14]
                sub     eax, dword ptr [ebp+var_C]
                mov     ecx, dword ptr [ebp+var_14+4]
                sbb     ecx, dword ptr [ebp+var_C+4]
                add     eax, 1
                adc     ecx, 0
                push    ecx
                push    eax
                lea     ecx, [ebp+var_34]
                call    sub_79459A
                mov     dword ptr [ebp+var_1C], eax
                mov     dword ptr [ebp+var_1C+4], edx

loc_7941E5:                             ; CODE XREF: sub_79415C+65↑j
                mov     eax, dword ptr [ebp+var_1C]
                add     eax, dword ptr [ebp+var_C]
                mov     ecx, dword ptr [ebp+var_1C+4]
                adc     ecx, dword ptr [ebp+var_C+4]
                push    ecx
                push    eax
                call    sub_7947C1
                pop     ecx
                pop     ecx
                leave
                retn    14h
sub_79415C      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; __int16 __thiscall sub_7941FE(void *this, int, __int16, __int16)
sub_7941FE      proc near               ; CODE XREF: sub_793D73+1C↑p

var_1C          = byte ptr -1Ch
var_10          = dword ptr -10h
var_C           = word ptr -0Ch
var_8           = word ptr -8
var_4           = word ptr -4
arg_0           = dword ptr  8
arg_4           = dword ptr  0Ch
arg_8           = dword ptr  10h

                push    ebp
                mov     ebp, esp
                sub     esp, 1Ch
                mov     [ebp+var_10], ecx
                push    [ebp+arg_0]
                lea     ecx, [ebp+var_1C]
                call    sub_79441A
                push    [ebp+arg_4]
                call    sub_7947A8
                pop     ecx
                mov     [ebp+var_4], ax
                push    [ebp+arg_8]
                call    sub_7947A8
                pop     ecx
                mov     [ebp+var_8], ax
                movzx   eax, [ebp+var_8]
                movzx   ecx, [ebp+var_4]
                sub     eax, ecx
                cmp     eax, 0FFFFh
                jnz     short loc_79424B
                lea     ecx, [ebp+var_1C]
                call    sub_79432A
                mov     [ebp+var_C], ax
                jmp     short loc_794263
; ---------------------------------------------------------------------------

loc_79424B:                             ; CODE XREF: sub_7941FE+3D↑j
                movzx   eax, [ebp+var_8]
                movzx   ecx, [ebp+var_4]
                sub     eax, ecx
                inc     eax
                push    eax
                lea     ecx, [ebp+var_1C]
                call    sub_794478
                mov     [ebp+var_C], ax

loc_794263:                             ; CODE XREF: sub_7941FE+4B↑j
                movzx   eax, [ebp+var_C]
                movzx   ecx, [ebp+var_4]
                add     eax, ecx
                push    eax
                call    sub_7947A8
                pop     ecx
                leave
                retn    0Ch
sub_7941FE      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int __thiscall sub_794278(void *this, int, int, int)
sub_794278      proc near               ; CODE XREF: sub_793D98+18↑p

var_1C          = byte ptr -1Ch
var_10          = dword ptr -10h
var_C           = dword ptr -0Ch
var_8           = dword ptr -8
var_4           = dword ptr -4
arg_0           = dword ptr  8
arg_4           = dword ptr  0Ch
arg_8           = dword ptr  10h

                push    ebp
                mov     ebp, esp
                sub     esp, 1Ch
                mov     [ebp+var_10], ecx
                push    [ebp+arg_0]
                lea     ecx, [ebp+var_1C]
                call    sub_79441A
                push    [ebp+arg_4]
                call    sub_79478F
                pop     ecx
                mov     [ebp+var_4], eax
                push    [ebp+arg_8]
                call    sub_79478F
                pop     ecx
                mov     [ebp+var_8], eax
                mov     eax, [ebp+var_8]
                sub     eax, [ebp+var_4]
                cmp     eax, 0FFFFFFFFh
                jnz     short loc_7942BC
                lea     ecx, [ebp+var_1C]
                call    sub_79432A
                mov     [ebp+var_C], eax
                jmp     short loc_7942CF
; ---------------------------------------------------------------------------

loc_7942BC:                             ; CODE XREF: sub_794278+35↑j
                mov     eax, [ebp+var_8]
                sub     eax, [ebp+var_4]
                inc     eax
                push    eax
                lea     ecx, [ebp+var_1C]
                call    sub_79437B
                mov     [ebp+var_C], eax

loc_7942CF:                             ; CODE XREF: sub_794278+42↑j
                mov     eax, [ebp+var_C]
                add     eax, [ebp+var_4]
                push    eax
                call    sub_79478F
                pop     ecx
                leave
                retn    0Ch
sub_794278      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _DWORD *__cdecl sub_7942E0(int, void *, int)
sub_7942E0      proc near               ; CODE XREF: sub_793DB9+36↑p

var_8           = dword ptr -8
var_4           = dword ptr -4
arg_4           = dword ptr  0Ch
arg_8           = dword ptr  10h

                push    ebp
                mov     ebp, esp
                push    ecx
                push    ecx
                push    [ebp+arg_4]     ; void *
                push    8               ; unsigned int
                call    ??2@YAPAXIPAX@Z ; operator new(uint,void *)
                pop     ecx
                pop     ecx
                mov     [ebp+var_8], eax
                push    [ebp+arg_8]
                call    unknown_libname_3 ; Microsoft VisualC 14/net runtime
                pop     ecx
                mov     [ebp+var_4], eax
                push    [ebp+var_4]
                mov     ecx, [ebp+var_8]
                call    sub_7947DE
                leave
                retn
sub_7942E0      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int *__cdecl sub_79430D(int, void *)
sub_79430D      proc near               ; CODE XREF: sub_793E0A+27↑p

var_4           = dword ptr -4
arg_4           = dword ptr  0Ch

                push    ebp
                mov     ebp, esp
                push    ecx
                push    [ebp+arg_4]     ; void *
                push    8               ; unsigned int
                call    ??2@YAPAXIPAX@Z ; operator new(uint,void *)
                pop     ecx
                pop     ecx
                mov     [ebp+var_4], eax
                mov     ecx, [ebp+var_4]
                call    sub_794802
                leave
                retn
sub_79430D      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; unsigned int __thiscall sub_79432A(_DWORD *this)
sub_79432A      proc near               ; CODE XREF: sub_7941FE+42↑p
                                        ; sub_794278+3A↑p

var_C           = dword ptr -0Ch
var_8           = dword ptr -8
var_4           = dword ptr -4

                push    ebp
                mov     ebp, esp
                sub     esp, 0Ch
                mov     [ebp+var_C], ecx
                and     [ebp+var_4], 0
                and     [ebp+var_8], 0
                jmp     short loc_794349
; ---------------------------------------------------------------------------

loc_79433D:                             ; CODE XREF: sub_79432A+4A↓j
                mov     eax, [ebp+var_C]
                mov     ecx, [ebp+var_8]
                add     ecx, [eax+4]
                mov     [ebp+var_8], ecx

loc_794349:                             ; CODE XREF: sub_79432A+11↑j
                cmp     [ebp+var_8], 20h ; ' '
                jnb     short loc_794376
                mov     eax, [ebp+var_C]
                mov     ecx, [eax+4]
                dec     ecx
                mov     eax, [ebp+var_4]
                shl     eax, cl
                mov     [ebp+var_4], eax
                mov     eax, [ebp+var_4]
                shl     eax, 1
                mov     [ebp+var_4], eax
                mov     ecx, [ebp+var_C]
                call    sub_794823
                or      eax, [ebp+var_4]
                mov     [ebp+var_4], eax
                jmp     short loc_79433D
; ---------------------------------------------------------------------------

loc_794376:                             ; CODE XREF: sub_79432A+23↑j
                mov     eax, [ebp+var_4]
                leave
                retn
sub_79432A      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; unsigned int __thiscall sub_79437B(_DWORD *this, unsigned int)
sub_79437B      proc near               ; CODE XREF: sub_794278+4F↑p

var_C           = dword ptr -0Ch
var_8           = dword ptr -8
var_4           = dword ptr -4
arg_0           = dword ptr  8

                push    ebp
                mov     ebp, esp
                sub     esp, 0Ch
                mov     [ebp+var_C], ecx

loc_794384:                             ; CODE XREF: sub_79437B:loc_794411↓j
                and     [ebp+var_8], 0
                and     [ebp+var_4], 0

loc_79438C:                             ; CODE XREF: sub_79437B+62↓j
                mov     eax, [ebp+arg_0]
                dec     eax
                cmp     [ebp+var_4], eax
                jnb     short loc_7943DF
                mov     eax, [ebp+var_C]
                mov     ecx, [eax+4]
                dec     ecx
                mov     eax, [ebp+var_8]
                shl     eax, cl
                mov     [ebp+var_8], eax
                mov     eax, [ebp+var_8]
                shl     eax, 1
                mov     [ebp+var_8], eax
                mov     ecx, [ebp+var_C]
                call    sub_794823
                or      eax, [ebp+var_8]
                mov     [ebp+var_8], eax
                mov     eax, [ebp+var_C]
                mov     ecx, [eax+4]
                dec     ecx
                mov     eax, [ebp+var_4]
                shl     eax, cl
                mov     [ebp+var_4], eax
                mov     eax, [ebp+var_4]
                shl     eax, 1
                mov     [ebp+var_4], eax
                mov     eax, [ebp+var_C]
                mov     ecx, [ebp+var_4]
                or      ecx, [eax+8]
                mov     [ebp+var_4], ecx
                jmp     short loc_79438C
; ---------------------------------------------------------------------------

loc_7943DF:                             ; CODE XREF: sub_79437B+18↑j
                mov     eax, [ebp+var_8]
                xor     edx, edx
                div     [ebp+arg_0]
                mov     ecx, eax
                mov     eax, [ebp+var_4]
                xor     edx, edx
                div     [ebp+arg_0]
                cmp     ecx, eax
                jb      short loc_794405
                mov     eax, [ebp+var_4]
                xor     edx, edx
                div     [ebp+arg_0]
                mov     eax, [ebp+arg_0]
                dec     eax
                cmp     edx, eax
                jnz     short loc_794411

loc_794405:                             ; CODE XREF: sub_79437B+78↑j
                mov     eax, [ebp+var_8]
                xor     edx, edx
                div     [ebp+arg_0]
                mov     eax, edx
                jmp     short locret_794416
; ---------------------------------------------------------------------------

loc_794411:                             ; CODE XREF: sub_79437B+88↑j
                jmp     loc_794384
; ---------------------------------------------------------------------------

locret_794416:                          ; CODE XREF: sub_79437B+94↑j
                leave
                retn    4
sub_79437B      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _DWORD *__thiscall sub_79441A(_DWORD *this, int)
sub_79441A      proc near               ; CODE XREF: sub_7941FE+F↑p
                                        ; sub_794278+F↑p

var_4           = dword ptr -4
arg_0           = dword ptr  8

                push    ebp
                mov     ebp, esp
                push    ecx
                push    esi
                mov     [ebp+var_4], ecx
                mov     eax, [ebp+var_4]
                mov     ecx, [ebp+arg_0]
                mov     [eax], ecx
                mov     eax, [ebp+var_4]
                mov     dword ptr [eax+4], 20h ; ' '
                mov     eax, [ebp+var_4]
                or      dword ptr [eax+8], 0FFFFFFFFh
                jmp     short loc_79444B
; ---------------------------------------------------------------------------

loc_79443D:                             ; CODE XREF: sub_79441A+54↓j
                mov     eax, [ebp+var_4]
                mov     eax, [eax+8]
                shr     eax, 1
                mov     ecx, [ebp+var_4]
                mov     [ecx+8], eax

loc_79444B:                             ; CODE XREF: sub_79441A+21↑j
                call    ?max@?$numeric_limits@I@std@@SAIXZ ; std::numeric_limits<uint>::max(void)
                mov     esi, eax
                call    ___scrt_stub_for_initialize_mta
                sub     esi, eax
                mov     eax, [ebp+var_4]
                cmp     esi, [eax+8]
                jnb     short loc_794470
                mov     eax, [ebp+var_4]
                mov     eax, [eax+4]
                dec     eax
                mov     ecx, [ebp+var_4]
                mov     [ecx+4], eax
                jmp     short loc_79443D
; ---------------------------------------------------------------------------

loc_794470:                             ; CODE XREF: sub_79441A+45↑j
                mov     eax, [ebp+var_4]
                pop     esi
                leave
                retn    4
sub_79441A      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; __int16 __thiscall sub_794478(_DWORD *this, unsigned __int16)
sub_794478      proc near               ; CODE XREF: sub_7941FE+5C↑p

var_C           = dword ptr -0Ch
var_8           = dword ptr -8
var_4           = dword ptr -4
arg_0           = word ptr  8

                push    ebp
                mov     ebp, esp
                sub     esp, 0Ch
                push    esi
                mov     [ebp+var_C], ecx

loc_794482:                             ; CODE XREF: sub_794478:loc_79451E↓j
                and     [ebp+var_8], 0
                and     [ebp+var_4], 0

loc_79448A:                             ; CODE XREF: sub_794478+64↓j
                movzx   eax, [ebp+arg_0]
                dec     eax
                cmp     [ebp+var_4], eax
                jnb     short loc_7944DE
                mov     eax, [ebp+var_C]
                mov     ecx, [eax+4]
                dec     ecx
                mov     eax, [ebp+var_8]
                shl     eax, cl
                mov     [ebp+var_8], eax
                mov     eax, [ebp+var_8]
                shl     eax, 1
                mov     [ebp+var_8], eax
                mov     ecx, [ebp+var_C]
                call    sub_794823
                or      eax, [ebp+var_8]
                mov     [ebp+var_8], eax
                mov     eax, [ebp+var_C]
                mov     ecx, [eax+4]
                dec     ecx
                mov     eax, [ebp+var_4]
                shl     eax, cl
                mov     [ebp+var_4], eax
                mov     eax, [ebp+var_4]
                shl     eax, 1
                mov     [ebp+var_4], eax
                mov     eax, [ebp+var_C]
                mov     ecx, [ebp+var_4]
                or      ecx, [eax+8]
                mov     [ebp+var_4], ecx
                jmp     short loc_79448A
; ---------------------------------------------------------------------------

loc_7944DE:                             ; CODE XREF: sub_794478+1A↑j
                movzx   ecx, [ebp+arg_0]
                mov     eax, [ebp+var_8]
                xor     edx, edx
                div     ecx
                mov     ecx, eax
                movzx   esi, [ebp+arg_0]
                mov     eax, [ebp+var_4]
                xor     edx, edx
                div     esi
                cmp     ecx, eax
                jb      short loc_79450E
                movzx   ecx, [ebp+arg_0]
                mov     eax, [ebp+var_4]
                xor     edx, edx
                div     ecx
                movzx   eax, [ebp+arg_0]
                dec     eax
                cmp     edx, eax
                jnz     short loc_79451E

loc_79450E:                             ; CODE XREF: sub_794478+80↑j
                movzx   ecx, [ebp+arg_0]
                mov     eax, [ebp+var_8]
                xor     edx, edx
                div     ecx
                mov     ax, dx
                jmp     short loc_794523
; ---------------------------------------------------------------------------

loc_79451E:                             ; CODE XREF: sub_794478+94↑j
                jmp     loc_794482
; ---------------------------------------------------------------------------

loc_794523:                             ; CODE XREF: sub_794478+A4↑j
                pop     esi
                leave
                retn    4
sub_794478      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; __int64 __thiscall sub_794528(int this)
sub_794528      proc near               ; CODE XREF: sub_79415C+5A↑p

var_10          = qword ptr -10h
var_8           = dword ptr -8
var_4           = dword ptr -4

                push    ebp
                mov     ebp, esp
                sub     esp, 10h
                mov     [ebp+var_8], ecx
                xorps   xmm0, xmm0
                movlpd  [ebp+var_10], xmm0
                and     [ebp+var_4], 0
                jmp     short loc_79454B
; ---------------------------------------------------------------------------

loc_79453F:                             ; CODE XREF: sub_794528+68↓j
                mov     eax, [ebp+var_8]
                mov     ecx, [ebp+var_4]
                add     ecx, [eax+4]
                mov     [ebp+var_4], ecx

loc_79454B:                             ; CODE XREF: sub_794528+15↑j
                cmp     [ebp+var_4], 40h ; '@'
                jnb     short loc_794592
                mov     eax, [ebp+var_8]
                mov     ecx, [eax+4]
                dec     ecx
                mov     eax, dword ptr [ebp+var_10]
                mov     edx, dword ptr [ebp+var_10+4]
                call    __allshl
                mov     dword ptr [ebp+var_10], eax
                mov     dword ptr [ebp+var_10+4], edx
                mov     eax, dword ptr [ebp+var_10]
                mov     edx, dword ptr [ebp+var_10+4]
                mov     cl, 1
                call    __allshl
                mov     dword ptr [ebp+var_10], eax
                mov     dword ptr [ebp+var_10+4], edx
                mov     ecx, [ebp+var_8]
                call    sub_794857
                or      eax, dword ptr [ebp+var_10]
                or      edx, dword ptr [ebp+var_10+4]
                mov     dword ptr [ebp+var_10], eax
                mov     dword ptr [ebp+var_10+4], edx
                jmp     short loc_79453F
; ---------------------------------------------------------------------------

loc_794592:                             ; CODE XREF: sub_794528+27↑j
                mov     eax, dword ptr [ebp+var_10]
                mov     edx, dword ptr [ebp+var_10+4]
                leave
                retn
sub_794528      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; unsigned __int64 __thiscall sub_79459A(int this, unsigned __int64)
sub_79459A      proc near               ; CODE XREF: sub_79415C+7E↑p

var_3C          = qword ptr -3Ch
var_34          = dword ptr -34h
var_30          = dword ptr -30h
var_2C          = dword ptr -2Ch
var_28          = dword ptr -28h
var_24          = dword ptr -24h
var_20          = dword ptr -20h
var_1C          = qword ptr -1Ch
var_14          = qword ptr -14h
var_C           = qword ptr -0Ch
var_4           = dword ptr -4
arg_0           = qword ptr  8

                push    ebp
                mov     ebp, esp
                sub     esp, 3Ch
                push    esi
                push    edi
                mov     [ebp+var_4], ecx

loc_7945A5:                             ; CODE XREF: sub_79459A:loc_7946F5↓j
                xorps   xmm0, xmm0
                movlpd  [ebp+var_14], xmm0
                xorps   xmm0, xmm0
                movlpd  [ebp+var_C], xmm0

loc_7945B5:                             ; CODE XREF: sub_79459A+C6↓j
                mov     eax, dword ptr [ebp+arg_0]
                sub     eax, 1
                mov     ecx, dword ptr [ebp+arg_0+4]
                sbb     ecx, 0
                mov     dword ptr [ebp+var_1C], eax
                mov     dword ptr [ebp+var_1C+4], ecx
                mov     eax, dword ptr [ebp+var_C+4]
                cmp     eax, dword ptr [ebp+var_1C+4]
                ja      loc_794665
                jb      short loc_7945E1
                mov     eax, dword ptr [ebp+var_C]
                cmp     eax, dword ptr [ebp+var_1C]
                jnb     loc_794665

loc_7945E1:                             ; CODE XREF: sub_79459A+39↑j
                mov     eax, [ebp+var_4]
                mov     ecx, [eax+4]
                dec     ecx
                mov     eax, dword ptr [ebp+var_14]
                mov     edx, dword ptr [ebp+var_14+4]
                call    __allshl
                mov     dword ptr [ebp+var_14], eax
                mov     dword ptr [ebp+var_14+4], edx
                mov     eax, dword ptr [ebp+var_14]
                mov     edx, dword ptr [ebp+var_14+4]
                mov     cl, 1
                call    __allshl
                mov     dword ptr [ebp+var_14], eax
                mov     dword ptr [ebp+var_14+4], edx
                mov     ecx, [ebp+var_4]
                call    sub_794857
                or      eax, dword ptr [ebp+var_14]
                or      edx, dword ptr [ebp+var_14+4]
                mov     dword ptr [ebp+var_14], eax
                mov     dword ptr [ebp+var_14+4], edx
                mov     eax, [ebp+var_4]
                mov     ecx, [eax+4]
                dec     ecx
                mov     eax, dword ptr [ebp+var_C]
                mov     edx, dword ptr [ebp+var_C+4]
                call    __allshl
                mov     dword ptr [ebp+var_C], eax
                mov     dword ptr [ebp+var_C+4], edx
                mov     eax, dword ptr [ebp+var_C]
                mov     edx, dword ptr [ebp+var_C+4]
                mov     cl, 1
                call    __allshl
                mov     dword ptr [ebp+var_C], eax
                mov     dword ptr [ebp+var_C+4], edx
                mov     eax, [ebp+var_4]
                mov     ecx, dword ptr [ebp+var_C]
                or      ecx, [eax+8]
                mov     edx, dword ptr [ebp+var_C+4]
                or      edx, [eax+0Ch]
                mov     dword ptr [ebp+var_C], ecx
                mov     dword ptr [ebp+var_C+4], edx
                jmp     loc_7945B5
; ---------------------------------------------------------------------------

loc_794665:                             ; CODE XREF: sub_79459A+33↑j
                                        ; sub_79459A+41↑j
                push    dword ptr [ebp+arg_0+4]
                push    dword ptr [ebp+arg_0]
                push    dword ptr [ebp+var_14+4]
                push    dword ptr [ebp+var_14]
                call    __aulldiv
                mov     esi, eax
                mov     edi, edx
                push    dword ptr [ebp+arg_0+4]
                push    dword ptr [ebp+arg_0]
                push    dword ptr [ebp+var_C+4]
                push    dword ptr [ebp+var_C]
                call    __aulldiv
                mov     [ebp+var_24], esi
                mov     [ebp+var_20], edi
                mov     [ebp+var_2C], eax
                mov     [ebp+var_28], edx
                mov     eax, [ebp+var_20]
                cmp     eax, [ebp+var_28]
                jb      short loc_7946E2
                ja      short loc_7946A9
                mov     eax, [ebp+var_24]
                cmp     eax, [ebp+var_2C]
                jb      short loc_7946E2

loc_7946A9:                             ; CODE XREF: sub_79459A+105↑j
                push    dword ptr [ebp+arg_0+4]
                push    dword ptr [ebp+arg_0]
                push    dword ptr [ebp+var_C+4]
                push    dword ptr [ebp+var_C]
                call    __aullrem
                mov     ecx, dword ptr [ebp+arg_0]
                sub     ecx, 1
                mov     esi, dword ptr [ebp+arg_0+4]
                sbb     esi, 0
                mov     [ebp+var_34], eax
                mov     [ebp+var_30], edx
                mov     dword ptr [ebp+var_3C], ecx
                mov     dword ptr [ebp+var_3C+4], esi
                mov     eax, [ebp+var_34]
                cmp     eax, dword ptr [ebp+var_3C]
                jnz     short loc_7946F5
                mov     eax, [ebp+var_30]
                cmp     eax, dword ptr [ebp+var_3C+4]
                jnz     short loc_7946F5

loc_7946E2:                             ; CODE XREF: sub_79459A+103↑j
                                        ; sub_79459A+10D↑j
                push    dword ptr [ebp+arg_0+4]
                push    dword ptr [ebp+arg_0]
                push    dword ptr [ebp+var_14+4]
                push    dword ptr [ebp+var_14]
                call    __aullrem
                jmp     short loc_7946FA
; ---------------------------------------------------------------------------

loc_7946F5:                             ; CODE XREF: sub_79459A+13E↑j
                                        ; sub_79459A+146↑j
                jmp     loc_7945A5
; ---------------------------------------------------------------------------

loc_7946FA:                             ; CODE XREF: sub_79459A+159↑j
                pop     edi
                pop     esi
                leave
                retn    8
sub_79459A      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _DWORD *__thiscall sub_794700(_DWORD *this, int)
sub_794700      proc near               ; CODE XREF: sub_79415C+F↑p

var_10          = dword ptr -10h
var_C           = dword ptr -0Ch
var_8           = dword ptr -8
var_4           = dword ptr -4
arg_0           = dword ptr  8

                push    ebp
                mov     ebp, esp
                sub     esp, 10h
                push    esi
                mov     [ebp+var_4], ecx
                mov     eax, [ebp+var_4]
                mov     ecx, [ebp+arg_0]
                mov     [eax], ecx
                mov     eax, [ebp+var_4]
                mov     dword ptr [eax+4], 40h ; '@'
                mov     eax, [ebp+var_4]
                or      ecx, 0FFFFFFFFh
                or      dword ptr [eax+8], 0FFFFFFFFh
                mov     [eax+0Ch], ecx
                jmp     short loc_794744
; ---------------------------------------------------------------------------

loc_79472B:                             ; CODE XREF: sub_794700+85↓j
                mov     ecx, [ebp+var_4]
                mov     eax, [ecx+8]
                mov     edx, [ecx+0Ch]
                mov     cl, 1
                call    __aullshr
                mov     ecx, [ebp+var_4]
                mov     [ecx+8], eax
                mov     [ecx+0Ch], edx

loc_794744:                             ; CODE XREF: sub_794700+29↑j
                call    ?max@?$numeric_limits@I@std@@SAIXZ ; std::numeric_limits<uint>::max(void)
                mov     esi, eax
                call    ___scrt_stub_for_initialize_mta
                sub     esi, eax
                xor     eax, eax
                mov     ecx, [ebp+var_4]
                mov     [ebp+var_10], esi
                mov     [ebp+var_C], eax
                mov     [ebp+var_8], ecx
                mov     eax, [ebp+var_8]
                mov     ecx, [ebp+var_C]
                cmp     ecx, [eax+0Ch]
                ja      short loc_794787
                jb      short loc_794778
                mov     eax, [ebp+var_8]
                mov     ecx, [ebp+var_10]
                cmp     ecx, [eax+8]
                jnb     short loc_794787

loc_794778:                             ; CODE XREF: sub_794700+6B↑j
                mov     eax, [ebp+var_4]
                mov     eax, [eax+4]
                dec     eax
                mov     ecx, [ebp+var_4]
                mov     [ecx+4], eax
                jmp     short loc_79472B
; ---------------------------------------------------------------------------

loc_794787:                             ; CODE XREF: sub_794700+69↑j
                                        ; sub_794700+76↑j
                mov     eax, [ebp+var_4]
                pop     esi
                leave
                retn    4
sub_794700      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int __cdecl sub_79478F(int)
sub_79478F      proc near               ; CODE XREF: sub_794278+17↑p
                                        ; sub_794278+23↑p ...

var_5           = dword ptr -5
var_1           = byte ptr -1
arg_0           = dword ptr  8

                push    ebp
                mov     ebp, esp
                push    ecx
                push    ecx
                xor     eax, eax
                mov     [ebp+var_1], al
                push    [ebp+var_5]
                push    [ebp+arg_0]
                call    sub_7948A7
                pop     ecx
                pop     ecx
                leave
                retn
sub_79478F      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; __int16 __cdecl sub_7947A8(__int16)
sub_7947A8      proc near               ; CODE XREF: sub_7941FE+17↑p
                                        ; sub_7941FE+24↑p ...

var_5           = dword ptr -5
var_1           = byte ptr -1
arg_0           = dword ptr  8

                push    ebp
                mov     ebp, esp
                push    ecx
                push    ecx
                xor     eax, eax
                mov     [ebp+var_1], al
                push    [ebp+var_5]
                push    [ebp+arg_0]
                call    sub_7948D1
                pop     ecx
                pop     ecx
                leave
                retn
sub_7947A8      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int __cdecl sub_7947C1(int, int)
sub_7947C1      proc near               ; CODE XREF: sub_79415C+1A↑p
                                        ; sub_79415C+2D↑p ...

var_5           = dword ptr -5
var_1           = byte ptr -1
arg_0           = dword ptr  8
arg_4           = dword ptr  0Ch

                push    ebp
                mov     ebp, esp
                push    ecx
                push    ecx
                xor     eax, eax
                mov     [ebp+var_1], al
                push    [ebp+var_5]
                push    [ebp+arg_4]
                push    [ebp+arg_0]
                call    ??__K_l@@YA?AUStringLiteral@@PBDI@Z ; operator"" _l(char const *,uint)
                add     esp, 0Ch
                leave
                retn
sub_7947C1      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _DWORD *__thiscall sub_7947DE(_DWORD *this, _DWORD *)
sub_7947DE      proc near               ; CODE XREF: sub_7942E0+26↑p

var_4           = dword ptr -4
arg_0           = dword ptr  8

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+var_4], ecx
                mov     eax, [ebp+var_4]
                mov     ecx, [ebp+arg_0]
                mov     ecx, [ecx]
                mov     [eax], ecx
                mov     eax, [ebp+var_4]
                mov     ecx, [ebp+arg_0]
                mov     ecx, [ecx+4]
                mov     [eax+4], ecx
                mov     eax, [ebp+var_4]
                leave
                retn    4
sub_7947DE      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int *__thiscall sub_794802(int *this)
sub_794802      proc near               ; CODE XREF: sub_79430D+16↑p

var_4           = dword ptr -4

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+var_4], ecx
                call    sub_7929C4
                mov     ecx, [ebp+var_4]
                mov     [ecx], eax
                mov     eax, [ebp+var_4]
                mov     ecx, [ebp+var_4]
                mov     ecx, [ecx]
                mov     [eax+4], ecx
                mov     eax, [ebp+var_4]
                leave
                retn
sub_794802      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; unsigned int __thiscall sub_794823(_DWORD *this)
sub_794823      proc near               ; CODE XREF: sub_79432A+3F↑p
                                        ; sub_79437B+34↑p ...

var_8           = dword ptr -8
var_4           = dword ptr -4

                push    ebp
                mov     ebp, esp
                push    ecx
                push    ecx
                push    esi
                mov     [ebp+var_4], ecx

loc_79482C:                             ; CODE XREF: sub_794823:loc_794852↓j
                mov     eax, [ebp+var_4]
                mov     ecx, [eax]
                call    sub_7948E5
                mov     esi, eax
                call    ___scrt_stub_for_initialize_mta
                sub     esi, eax
                mov     [ebp+var_8], esi
                mov     eax, [ebp+var_4]
                mov     ecx, [ebp+var_8]
                cmp     ecx, [eax+8]
                ja      short loc_794852
                mov     eax, [ebp+var_8]
                jmp     short loc_794854
; ---------------------------------------------------------------------------

loc_794852:                             ; CODE XREF: sub_794823+28↑j
                jmp     short loc_79482C
; ---------------------------------------------------------------------------

loc_794854:                             ; CODE XREF: sub_794823+2D↑j
                pop     esi
                leave
                retn
sub_794823      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; __int64 __thiscall sub_794857(_QWORD *this)
sub_794857      proc near               ; CODE XREF: sub_794528+57↑p
                                        ; sub_79459A+75↑p

var_10          = dword ptr -10h
var_C           = dword ptr -0Ch
var_8           = dword ptr -8
var_4           = dword ptr -4

                push    ebp
                mov     ebp, esp
                sub     esp, 10h
                push    esi
                mov     [ebp+var_4], ecx

loc_794861:                             ; CODE XREF: sub_794857:loc_7948A2↓j
                mov     eax, [ebp+var_4]
                mov     ecx, [eax]
                call    sub_7948E5
                mov     esi, eax
                call    ___scrt_stub_for_initialize_mta
                sub     esi, eax
                xor     eax, eax
                mov     [ebp+var_10], esi
                mov     [ebp+var_C], eax
                mov     eax, [ebp+var_4]
                mov     [ebp+var_8], eax
                mov     eax, [ebp+var_8]
                mov     ecx, [ebp+var_C]
                cmp     ecx, [eax+0Ch]
                ja      short loc_7948A2
                jb      short loc_79489A
                mov     eax, [ebp+var_8]
                mov     ecx, [ebp+var_10]
                cmp     ecx, [eax+8]
                ja      short loc_7948A2

loc_79489A:                             ; CODE XREF: sub_794857+36↑j
                mov     eax, [ebp+var_10]
                mov     edx, [ebp+var_C]
                jmp     short loc_7948A4
; ---------------------------------------------------------------------------

loc_7948A2:                             ; CODE XREF: sub_794857+34↑j
                                        ; sub_794857+41↑j
                jmp     short loc_794861
; ---------------------------------------------------------------------------

loc_7948A4:                             ; CODE XREF: sub_794857+49↑j
                pop     esi
                leave
                retn
sub_794857      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int __cdecl sub_7948A7(int)
sub_7948A7      proc near               ; CODE XREF: sub_79478F+10↑p

var_4           = dword ptr -4
arg_0           = dword ptr  8

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+var_4], 80000000h
                cmp     [ebp+arg_0], 80000000h
                jnb     short loc_7948C7
                mov     eax, [ebp+arg_0]
                sub     eax, 80000000h
                jmp     short locret_7948CF
; ---------------------------------------------------------------------------
                jmp     short locret_7948CF
; ---------------------------------------------------------------------------

loc_7948C7:                             ; CODE XREF: sub_7948A7+12↑j
                mov     eax, [ebp+arg_0]
                sub     eax, 80000000h

locret_7948CF:                          ; CODE XREF: sub_7948A7+1C↑j
                                        ; sub_7948A7+1E↑j
                leave
                retn
sub_7948A7      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; __int16 __cdecl sub_7948D1(__int16)
sub_7948D1      proc near               ; CODE XREF: sub_7947A8+10↑p

arg_0           = word ptr  8

                push    ebp
                mov     ebp, esp
                mov     ax, [ebp+arg_0]
                pop     ebp
                retn
sub_7948D1      endp

; [0000000B BYTES: COLLAPSED FUNCTION operator"" _l(char const *,uint). PRESS CTRL-NUMPAD+ TO EXPAND]

; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; unsigned int __thiscall sub_7948E5(_DWORD *this)
sub_7948E5      proc near               ; CODE XREF: sub_794823+E↑p
                                        ; sub_794857+F↑p

var_C           = dword ptr -0Ch
var_8           = dword ptr -8
var_4           = dword ptr -4

                push    ebp
                mov     ebp, esp
                sub     esp, 0Ch
                mov     [ebp+var_8], ecx
                mov     eax, [ebp+var_8]
                cmp     dword ptr [eax], 270h
                jnz     short loc_794903
                mov     ecx, [ebp+var_8]
                call    sub_79497E
                jmp     short loc_794916
; ---------------------------------------------------------------------------

loc_794903:                             ; CODE XREF: sub_7948E5+12↑j
                mov     eax, [ebp+var_8]
                cmp     dword ptr [eax], 4E0h
                jb      short loc_794916
                mov     ecx, [ebp+var_8]
                call    sub_794A02

loc_794916:                             ; CODE XREF: sub_7948E5+1C↑j
                                        ; sub_7948E5+27↑j
                mov     eax, [ebp+var_8]
                mov     eax, [eax]
                mov     ecx, [ebp+var_8]
                mov     eax, [ecx+eax*4+4]
                mov     [ebp+var_C], eax
                mov     eax, [ebp+var_8]
                mov     eax, [eax]
                inc     eax
                mov     ecx, [ebp+var_8]
                mov     [ecx], eax
                mov     eax, [ebp+var_C]
                mov     [ebp+var_4], eax
                mov     eax, [ebp+var_4]
                shr     eax, 0Bh
                mov     ecx, [ebp+var_8]
                and     eax, [ecx+1384h]
                xor     eax, [ebp+var_4]
                mov     [ebp+var_4], eax
                mov     eax, [ebp+var_4]
                shl     eax, 7
                and     eax, 9D2C5680h
                xor     eax, [ebp+var_4]
                mov     [ebp+var_4], eax
                mov     eax, [ebp+var_4]
                shl     eax, 0Fh
                and     eax, 0EFC60000h
                xor     eax, [ebp+var_4]
                mov     [ebp+var_4], eax
                mov     eax, [ebp+var_4]
                shr     eax, 12h
                xor     eax, [ebp+var_4]
                mov     [ebp+var_4], eax
                mov     eax, [ebp+var_4]
                leave
                retn
sub_7948E5      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; unsigned int __thiscall sub_79497E(_DWORD *this)
sub_79497E      proc near               ; CODE XREF: sub_7948E5+17↑p

var_10          = dword ptr -10h
var_C           = dword ptr -0Ch
var_8           = dword ptr -8
var_4           = dword ptr -4

                push    ebp
                mov     ebp, esp
                sub     esp, 10h
                mov     [ebp+var_8], ecx
                mov     [ebp+var_4], 270h
                jmp     short loc_794997
; ---------------------------------------------------------------------------

loc_794990:                             ; CODE XREF: sub_79497E+80↓j
                mov     eax, [ebp+var_4]
                inc     eax
                mov     [ebp+var_4], eax

loc_794997:                             ; CODE XREF: sub_79497E+10↑j
                cmp     [ebp+var_4], 4E0h
                jnb     short locret_794A00
                mov     eax, [ebp+var_4]
                mov     ecx, [ebp+var_8]
                mov     eax, [ecx+eax*4-9BCh]
                and     eax, 80000000h
                mov     ecx, [ebp+var_4]
                mov     edx, [ebp+var_8]
                mov     ecx, [edx+ecx*4-9B8h]
                and     ecx, 7FFFFFFFh
                or      eax, ecx
                mov     [ebp+var_C], eax
                mov     eax, [ebp+var_C]
                and     eax, 1
                jz      short loc_7949DB
                mov     [ebp+var_10], 9908B0DFh
                jmp     short loc_7949DF
; ---------------------------------------------------------------------------

loc_7949DB:                             ; CODE XREF: sub_79497E+52↑j
                and     [ebp+var_10], 0

loc_7949DF:                             ; CODE XREF: sub_79497E+5B↑j
                mov     eax, [ebp+var_C]
                shr     eax, 1
                xor     eax, [ebp+var_10]
                mov     ecx, [ebp+var_4]
                mov     edx, [ebp+var_8]
                xor     eax, [edx+ecx*4-388h]
                mov     ecx, [ebp+var_4]
                mov     edx, [ebp+var_8]
                mov     [edx+ecx*4+4], eax
                jmp     short loc_794990
; ---------------------------------------------------------------------------

locret_794A00:                          ; CODE XREF: sub_79497E+20↑j
                leave
                retn
sub_79497E      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _BYTE *__thiscall sub_794A02(_BYTE *this)
sub_794A02      proc near               ; CODE XREF: sub_7948E5+2C↑p

var_20          = dword ptr -20h
var_1C          = dword ptr -1Ch
var_18          = dword ptr -18h
var_14          = dword ptr -14h
var_10          = dword ptr -10h
var_C           = dword ptr -0Ch
var_8           = dword ptr -8
var_4           = dword ptr -4

                push    ebp
                mov     ebp, esp
                sub     esp, 20h
                mov     [ebp+var_8], ecx
                and     [ebp+var_4], 0
                jmp     short loc_794A18
; ---------------------------------------------------------------------------

loc_794A11:                             ; CODE XREF: sub_794A02+7D↓j
                mov     eax, [ebp+var_4]
                inc     eax
                mov     [ebp+var_4], eax

loc_794A18:                             ; CODE XREF: sub_794A02+D↑j
                cmp     [ebp+var_4], 0E3h
                jnb     short loc_794A81
                mov     eax, [ebp+var_4]
                mov     ecx, [ebp+var_8]
                mov     eax, [ecx+eax*4+9C4h]
                and     eax, 80000000h
                mov     ecx, [ebp+var_4]
                mov     edx, [ebp+var_8]
                mov     ecx, [edx+ecx*4+9C8h]
                and     ecx, 7FFFFFFFh
                or      eax, ecx
                mov     [ebp+var_C], eax
                mov     eax, [ebp+var_C]
                and     eax, 1
                jz      short loc_794A5C
                mov     [ebp+var_10], 9908B0DFh
                jmp     short loc_794A60
; ---------------------------------------------------------------------------

loc_794A5C:                             ; CODE XREF: sub_794A02+4F↑j
                and     [ebp+var_10], 0

loc_794A60:                             ; CODE XREF: sub_794A02+58↑j
                mov     eax, [ebp+var_C]
                shr     eax, 1
                xor     eax, [ebp+var_10]
                mov     ecx, [ebp+var_4]
                mov     edx, [ebp+var_8]
                xor     eax, [edx+ecx*4+0FF8h]
                mov     ecx, [ebp+var_4]
                mov     edx, [ebp+var_8]
                mov     [edx+ecx*4+4], eax
                jmp     short loc_794A11
; ---------------------------------------------------------------------------

loc_794A81:                             ; CODE XREF: sub_794A02+1D↑j
                jmp     short loc_794A8A
; ---------------------------------------------------------------------------

loc_794A83:                             ; CODE XREF: sub_794A02+EF↓j
                mov     eax, [ebp+var_4]
                inc     eax
                mov     [ebp+var_4], eax

loc_794A8A:                             ; CODE XREF: sub_794A02:loc_794A81↑j
                cmp     [ebp+var_4], 26Fh
                jnb     short loc_794AF3
                mov     eax, [ebp+var_4]
                mov     ecx, [ebp+var_8]
                mov     eax, [ecx+eax*4+9C4h]
                and     eax, 80000000h
                mov     ecx, [ebp+var_4]
                mov     edx, [ebp+var_8]
                mov     ecx, [edx+ecx*4+9C8h]
                and     ecx, 7FFFFFFFh
                or      eax, ecx
                mov     [ebp+var_14], eax
                mov     eax, [ebp+var_14]
                and     eax, 1
                jz      short loc_794ACE
                mov     [ebp+var_18], 9908B0DFh
                jmp     short loc_794AD2
; ---------------------------------------------------------------------------

loc_794ACE:                             ; CODE XREF: sub_794A02+C1↑j
                and     [ebp+var_18], 0

loc_794AD2:                             ; CODE XREF: sub_794A02+CA↑j
                mov     eax, [ebp+var_14]
                shr     eax, 1
                xor     eax, [ebp+var_18]
                mov     ecx, [ebp+var_4]
                mov     edx, [ebp+var_8]
                xor     eax, [edx+ecx*4-388h]
                mov     ecx, [ebp+var_4]
                mov     edx, [ebp+var_8]
                mov     [edx+ecx*4+4], eax
                jmp     short loc_794A83
; ---------------------------------------------------------------------------

loc_794AF3:                             ; CODE XREF: sub_794A02+8F↑j
                mov     eax, [ebp+var_4]
                mov     ecx, [ebp+var_8]
                mov     eax, [ecx+eax*4+9C4h]
                and     eax, 80000000h
                push    4
                pop     ecx
                imul    ecx, 0
                mov     edx, [ebp+var_8]
                mov     ecx, [edx+ecx+4]
                and     ecx, 7FFFFFFFh
                or      eax, ecx
                mov     [ebp+var_1C], eax
                mov     eax, [ebp+var_1C]
                and     eax, 1
                jz      short loc_794B2E
                mov     [ebp+var_20], 9908B0DFh
                jmp     short loc_794B32
; ---------------------------------------------------------------------------

loc_794B2E:                             ; CODE XREF: sub_794A02+121↑j
                and     [ebp+var_20], 0

loc_794B32:                             ; CODE XREF: sub_794A02+12A↑j
                mov     eax, [ebp+var_1C]
                shr     eax, 1
                xor     eax, [ebp+var_20]
                push    4
                pop     ecx
                imul    ecx, 18Ch
                mov     edx, [ebp+var_8]
                xor     eax, [edx+ecx+4]
                mov     ecx, [ebp+var_4]
                mov     edx, [ebp+var_8]
                mov     [edx+ecx*4+4], eax
                mov     eax, [ebp+var_8]
                and     dword ptr [eax], 0
                leave
                retn
sub_794A02      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _DWORD *__cdecl sub_794B5C(_DWORD *, void *)
sub_794B5C      proc near               ; CODE XREF: sub_793F52+10↑p

var_24          = dword ptr -24h
var_20          = dword ptr -20h
var_1C          = dword ptr -1Ch
var_18          = dword ptr -18h
var_14          = qword ptr -14h
var_C           = dword ptr -0Ch
var_8           = dword ptr -8
var_2           = byte ptr -2
var_1           = byte ptr -1
arg_0           = dword ptr  8
arg_4           = dword ptr  0Ch

                push    ebp
                mov     ebp, esp
                sub     esp, 24h
                mov     [ebp+var_1], 0
                mov     [ebp+var_2], 1
                xor     eax, eax
                inc     eax
                jz      short loc_794BC6
                xor     eax, eax
                jz      short loc_794B97
                mov     ecx, [ebp+arg_4]
                call    sub_791882
                mov     [ebp+var_C], eax
                mov     [ebp+var_8], edx
                lea     eax, [ebp+var_C]
                push    eax
                mov     ecx, [ebp+arg_0]
                call    sub_791864
                mov     eax, [ebp+arg_0]
                jmp     locret_794C16
; ---------------------------------------------------------------------------
                jmp     short loc_794BC4
; ---------------------------------------------------------------------------

loc_794B97:                             ; CODE XREF: sub_794B5C+15↑j
                mov     ecx, [ebp+arg_4]
                call    sub_791882
                push    0
                push    3B9ACA00h
                push    edx
                push    eax
                call    __allmul
                mov     dword ptr [ebp+var_14], eax
                mov     dword ptr [ebp+var_14+4], edx
                lea     eax, [ebp+var_14]
                push    eax
                mov     ecx, [ebp+arg_0]
                call    sub_791864
                mov     eax, [ebp+arg_0]
                jmp     short locret_794C16
; ---------------------------------------------------------------------------

loc_794BC4:                             ; CODE XREF: sub_794B5C+39↑j
                jmp     short locret_794C16
; ---------------------------------------------------------------------------

loc_794BC6:                             ; CODE XREF: sub_794B5C+11↑j
                xor     eax, eax
                jz      short loc_794BEB
                mov     ecx, [ebp+arg_4]
                call    sub_791882
                mov     [ebp+var_1C], eax
                mov     [ebp+var_18], edx
                lea     eax, [ebp+var_1C]
                push    eax
                mov     ecx, [ebp+arg_0]
                call    sub_791864
                mov     eax, [ebp+arg_0]
                jmp     short locret_794C16
; ---------------------------------------------------------------------------
                jmp     short locret_794C16
; ---------------------------------------------------------------------------

loc_794BEB:                             ; CODE XREF: sub_794B5C+6C↑j
                mov     ecx, [ebp+arg_4]
                call    sub_791882
                push    0
                push    3B9ACA00h
                push    edx
                push    eax
                call    __allmul
                mov     [ebp+var_24], eax
                mov     [ebp+var_20], edx
                lea     eax, [ebp+var_24]
                push    eax
                mov     ecx, [ebp+arg_0]
                call    sub_791864
                mov     eax, [ebp+arg_0]

locret_794C16:                          ; CODE XREF: sub_794B5C+34↑j
                                        ; sub_794B5C+66↑j ...
                leave
                retn
sub_794B5C      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _DWORD *__cdecl sub_794C18(_DWORD *, void *)
sub_794C18      proc near               ; CODE XREF: sub_793F7F+10↑p

var_24          = dword ptr -24h
var_20          = dword ptr -20h
var_1C          = dword ptr -1Ch
var_18          = dword ptr -18h
var_14          = qword ptr -14h
var_C           = dword ptr -0Ch
var_8           = dword ptr -8
var_2           = byte ptr -2
var_1           = byte ptr -1
arg_0           = dword ptr  8
arg_4           = dword ptr  0Ch

                push    ebp
                mov     ebp, esp
                sub     esp, 24h
                mov     [ebp+var_1], 0
                mov     [ebp+var_2], 1
                xor     eax, eax
                inc     eax
                jz      short loc_794C82
                xor     eax, eax
                jz      short loc_794C53
                mov     ecx, [ebp+arg_4]
                call    sub_791882
                mov     [ebp+var_C], eax
                mov     [ebp+var_8], edx
                lea     eax, [ebp+var_C]
                push    eax
                mov     ecx, [ebp+arg_0]
                call    sub_791864
                mov     eax, [ebp+arg_0]
                jmp     locret_794CD2
; ---------------------------------------------------------------------------
                jmp     short loc_794C80
; ---------------------------------------------------------------------------

loc_794C53:                             ; CODE XREF: sub_794C18+15↑j
                mov     ecx, [ebp+arg_4]
                call    sub_791882
                push    0
                push    0F4240h
                push    edx
                push    eax
                call    __allmul
                mov     dword ptr [ebp+var_14], eax
                mov     dword ptr [ebp+var_14+4], edx
                lea     eax, [ebp+var_14]
                push    eax
                mov     ecx, [ebp+arg_0]
                call    sub_791864
                mov     eax, [ebp+arg_0]
                jmp     short locret_794CD2
; ---------------------------------------------------------------------------

loc_794C80:                             ; CODE XREF: sub_794C18+39↑j
                jmp     short locret_794CD2
; ---------------------------------------------------------------------------

loc_794C82:                             ; CODE XREF: sub_794C18+11↑j
                xor     eax, eax
                jz      short loc_794CA7
                mov     ecx, [ebp+arg_4]
                call    sub_791882
                mov     [ebp+var_1C], eax
                mov     [ebp+var_18], edx
                lea     eax, [ebp+var_1C]
                push    eax
                mov     ecx, [ebp+arg_0]
                call    sub_791864
                mov     eax, [ebp+arg_0]
                jmp     short locret_794CD2
; ---------------------------------------------------------------------------
                jmp     short locret_794CD2
; ---------------------------------------------------------------------------

loc_794CA7:                             ; CODE XREF: sub_794C18+6C↑j
                mov     ecx, [ebp+arg_4]
                call    sub_791882
                push    0
                push    0F4240h
                push    edx
                push    eax
                call    __allmul
                mov     [ebp+var_24], eax
                mov     [ebp+var_20], edx
                lea     eax, [ebp+var_24]
                push    eax
                mov     ecx, [ebp+arg_0]
                call    sub_791864
                mov     eax, [ebp+arg_0]

locret_794CD2:                          ; CODE XREF: sub_794C18+34↑j
                                        ; sub_794C18+66↑j ...
                leave
                retn
sub_794C18      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; bool __cdecl sub_794CD4(int *, int *)
sub_794CD4      proc near               ; CODE XREF: sub_793FAC+2A↑p

var_24          = dword ptr -24h
var_20          = dword ptr -20h
var_1C          = dword ptr -1Ch
var_18          = dword ptr -18h
var_14          = qword ptr -14h
var_C           = qword ptr -0Ch
var_4           = dword ptr -4
arg_0           = dword ptr  8
arg_4           = dword ptr  0Ch

                push    ebp
                mov     ebp, esp
                sub     esp, 24h
                push    esi
                push    edi
                mov     eax, [ebp+arg_0]
                mov     ecx, [eax]
                mov     eax, [eax+4]
                mov     [ebp+var_1C], ecx
                mov     [ebp+var_18], eax
                mov     eax, [ebp+arg_4]
                mov     ecx, [eax]
                mov     eax, [eax+4]
                mov     [ebp+var_24], ecx
                mov     [ebp+var_20], eax
                lea     ecx, [ebp+var_1C]
                call    sub_791882
                mov     esi, eax
                mov     edi, edx
                lea     ecx, [ebp+var_24]
                call    sub_791882
                mov     dword ptr [ebp+var_C], esi
                mov     dword ptr [ebp+var_C+4], edi
                mov     dword ptr [ebp+var_14], eax
                mov     dword ptr [ebp+var_14+4], edx
                mov     eax, dword ptr [ebp+var_C+4]
                cmp     eax, dword ptr [ebp+var_14+4]
                jg      short loc_794D33
                jl      short loc_794D2A
                mov     eax, dword ptr [ebp+var_C]
                cmp     eax, dword ptr [ebp+var_14]
                jnb     short loc_794D33

loc_794D2A:                             ; CODE XREF: sub_794CD4+4C↑j
                mov     [ebp+var_4], 1
                jmp     short loc_794D37
; ---------------------------------------------------------------------------

loc_794D33:                             ; CODE XREF: sub_794CD4+4A↑j
                                        ; sub_794CD4+54↑j
                and     [ebp+var_4], 0

loc_794D37:                             ; CODE XREF: sub_794CD4+5D↑j
                mov     al, byte ptr [ebp+var_4]
                pop     edi
                pop     esi
                leave
                retn
sub_794CD4      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _DWORD *__cdecl sub_794D3E(_DWORD *, void *)
sub_794D3E      proc near               ; CODE XREF: sub_794034+10↑p

var_24          = dword ptr -24h
var_20          = dword ptr -20h
var_1C          = dword ptr -1Ch
var_18          = dword ptr -18h
var_14          = qword ptr -14h
var_C           = dword ptr -0Ch
var_8           = dword ptr -8
var_2           = byte ptr -2
var_1           = byte ptr -1
arg_0           = dword ptr  8
arg_4           = dword ptr  0Ch

                push    ebp
                mov     ebp, esp
                sub     esp, 24h
                mov     [ebp+var_1], 0
                mov     [ebp+var_2], 1
                xor     eax, eax
                inc     eax
                jz      short loc_794DA2
                xor     eax, eax
                jz      short loc_794D76
                mov     ecx, [ebp+arg_4]
                call    sub_791882
                mov     [ebp+var_C], eax
                mov     [ebp+var_8], edx
                lea     eax, [ebp+var_C]
                push    eax
                mov     ecx, [ebp+arg_0]
                call    sub_791864
                mov     eax, [ebp+arg_0]
                jmp     short locret_794DEF
; ---------------------------------------------------------------------------
                jmp     short loc_794DA0
; ---------------------------------------------------------------------------

loc_794D76:                             ; CODE XREF: sub_794D3E+15↑j
                mov     ecx, [ebp+arg_4]
                call    sub_791882
                push    0
                push    64h ; 'd'
                push    edx
                push    eax
                call    __allmul
                mov     dword ptr [ebp+var_14], eax
                mov     dword ptr [ebp+var_14+4], edx
                lea     eax, [ebp+var_14]
                push    eax
                mov     ecx, [ebp+arg_0]
                call    sub_791864
                mov     eax, [ebp+arg_0]
                jmp     short locret_794DEF
; ---------------------------------------------------------------------------

loc_794DA0:                             ; CODE XREF: sub_794D3E+36↑j
                jmp     short locret_794DEF
; ---------------------------------------------------------------------------

loc_794DA2:                             ; CODE XREF: sub_794D3E+11↑j
                xor     eax, eax
                jz      short loc_794DC7
                mov     ecx, [ebp+arg_4]
                call    sub_791882
                mov     [ebp+var_1C], eax
                mov     [ebp+var_18], edx
                lea     eax, [ebp+var_1C]
                push    eax
                mov     ecx, [ebp+arg_0]
                call    sub_791864
                mov     eax, [ebp+arg_0]
                jmp     short locret_794DEF
; ---------------------------------------------------------------------------
                jmp     short locret_794DEF
; ---------------------------------------------------------------------------

loc_794DC7:                             ; CODE XREF: sub_794D3E+66↑j
                mov     ecx, [ebp+arg_4]
                call    sub_791882
                push    0
                push    64h ; 'd'
                push    edx
                push    eax
                call    __allmul
                mov     [ebp+var_24], eax
                mov     [ebp+var_20], edx
                lea     eax, [ebp+var_24]
                push    eax
                mov     ecx, [ebp+arg_0]
                call    sub_791864
                mov     eax, [ebp+arg_0]

locret_794DEF:                          ; CODE XREF: sub_794D3E+34↑j
                                        ; sub_794D3E+60↑j ...
                leave
                retn
sub_794D3E      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; double *__thiscall sub_794DF1(double *this, void *)
sub_794DF1      proc near               ; CODE XREF: sub_794061+C↑p

var_C           = qword ptr -0Ch
var_4           = dword ptr -4
arg_0           = dword ptr  8

                push    ebp
                mov     ebp, esp
                sub     esp, 0Ch
                mov     [ebp+var_4], ecx
                push    [ebp+arg_0]
                lea     eax, [ebp+var_C]
                push    eax
                call    sub_794E45
                pop     ecx
                pop     ecx
                mov     ecx, eax
                call    sub_791893
                mov     eax, [ebp+var_4]
                fstp    qword ptr [eax]
                mov     eax, [ebp+var_4]
                leave
                retn    4
sub_794DF1      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; double *__thiscall sub_794E1B(double *this, void *)
sub_794E1B      proc near               ; CODE XREF: sub_794061+2B↑p

var_C           = qword ptr -0Ch
var_4           = dword ptr -4
arg_0           = dword ptr  8

                push    ebp
                mov     ebp, esp
                sub     esp, 0Ch
                mov     [ebp+var_4], ecx
                push    [ebp+arg_0]
                lea     eax, [ebp+var_C]
                push    eax
                call    sub_794F17
                pop     ecx
                pop     ecx
                mov     ecx, eax
                call    sub_791893
                mov     eax, [ebp+var_4]
                fstp    qword ptr [eax]
                mov     eax, [ebp+var_4]
                leave
                retn    4
sub_794E1B      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _QWORD *__cdecl sub_794E45(_QWORD *, void *)
sub_794E45      proc near               ; CODE XREF: sub_794DF1+10↑p

var_3C          = qword ptr -3Ch
var_34          = qword ptr -34h
var_2C          = qword ptr -2Ch
var_24          = qword ptr -24h
var_1C          = qword ptr -1Ch
var_14          = qword ptr -14h
var_C           = qword ptr -0Ch
var_2           = byte ptr -2
var_1           = byte ptr -1
arg_0           = dword ptr  8
arg_4           = dword ptr  0Ch

                push    ebp
                mov     ebp, esp
                sub     esp, 3Ch
                mov     [ebp+var_1], 0
                mov     [ebp+var_2], 1
                xor     eax, eax
                inc     eax
                jz      short loc_794EAD
                xor     eax, eax
                jz      short loc_794E7D
                mov     ecx, [ebp+arg_4]
                call    sub_791893
                fstp    [ebp+var_C]
                lea     eax, [ebp+var_C]
                push    eax
                mov     ecx, [ebp+arg_0]
                call    sub_794FF1
                mov     eax, [ebp+arg_0]
                jmp     locret_794F15
; ---------------------------------------------------------------------------
                jmp     short loc_794EAB
; ---------------------------------------------------------------------------

loc_794E7D:                             ; CODE XREF: sub_794E45+15↑j
                mov     ecx, [ebp+arg_4]
                call    sub_791893
                fstp    [ebp+var_14]
                movsd   xmm0, [ebp+var_14]
                mulsd   xmm0, ds:qword_7973F0
                movsd   [ebp+var_1C], xmm0
                lea     eax, [ebp+var_1C]
                push    eax
                mov     ecx, [ebp+arg_0]
                call    sub_794FF1
                mov     eax, [ebp+arg_0]
                jmp     short locret_794F15
; ---------------------------------------------------------------------------

loc_794EAB:                             ; CODE XREF: sub_794E45+36↑j
                jmp     short locret_794F15
; ---------------------------------------------------------------------------

loc_794EAD:                             ; CODE XREF: sub_794E45+11↑j
                xor     eax, eax
                jz      short loc_794EE1
                mov     ecx, [ebp+arg_4]
                call    sub_791893
                fstp    [ebp+var_24]
                movsd   xmm0, [ebp+var_24]
                divsd   xmm0, ds:qword_7973E0
                movsd   [ebp+var_2C], xmm0
                lea     eax, [ebp+var_2C]
                push    eax
                mov     ecx, [ebp+arg_0]
                call    sub_794FF1
                mov     eax, [ebp+arg_0]
                jmp     short locret_794F15
; ---------------------------------------------------------------------------
                jmp     short locret_794F15
; ---------------------------------------------------------------------------

loc_794EE1:                             ; CODE XREF: sub_794E45+6A↑j
                mov     ecx, [ebp+arg_4]
                call    sub_791893
                fstp    [ebp+var_34]
                movsd   xmm0, [ebp+var_34]
                mulsd   xmm0, ds:qword_7973F0
                divsd   xmm0, ds:qword_7973E0
                movsd   [ebp+var_3C], xmm0
                lea     eax, [ebp+var_3C]
                push    eax
                mov     ecx, [ebp+arg_0]
                call    sub_794FF1
                mov     eax, [ebp+arg_0]

locret_794F15:                          ; CODE XREF: sub_794E45+31↑j
                                        ; sub_794E45+64↑j ...
                leave
                retn
sub_794E45      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _QWORD *__cdecl sub_794F17(_QWORD *, void *)
sub_794F17      proc near               ; CODE XREF: sub_794E1B+10↑p

var_24          = qword ptr -24h
var_1C          = qword ptr -1Ch
var_14          = qword ptr -14h
var_C           = qword ptr -0Ch
var_2           = byte ptr -2
var_1           = byte ptr -1
arg_0           = dword ptr  8
arg_4           = dword ptr  0Ch

                push    ebp
                mov     ebp, esp
                sub     esp, 24h
                mov     [ebp+var_1], 1
                mov     [ebp+var_2], 1
                xor     eax, eax
                inc     eax
                jz      short loc_794F88
                xor     eax, eax
                inc     eax
                jz      short loc_794F59
                mov     ecx, [ebp+arg_4]
                call    sub_791882
                mov     ecx, eax
                call    __ltod3
                movsd   [ebp+var_C], xmm0
                lea     eax, [ebp+var_C]
                push    eax
                mov     ecx, [ebp+arg_0]
                call    sub_794FF1
                mov     eax, [ebp+arg_0]
                jmp     locret_794FEF
; ---------------------------------------------------------------------------
                jmp     short loc_794F86
; ---------------------------------------------------------------------------

loc_794F59:                             ; CODE XREF: sub_794F17+16↑j
                mov     ecx, [ebp+arg_4]
                call    sub_791882
                mov     ecx, eax
                call    __ltod3
                mulsd   xmm0, ds:qword_7973E0
                movsd   [ebp+var_14], xmm0
                lea     eax, [ebp+var_14]
                push    eax
                mov     ecx, [ebp+arg_0]
                call    sub_794FF1
                mov     eax, [ebp+arg_0]
                jmp     short locret_794FEF
; ---------------------------------------------------------------------------

loc_794F86:                             ; CODE XREF: sub_794F17+40↑j
                jmp     short locret_794FEF
; ---------------------------------------------------------------------------

loc_794F88:                             ; CODE XREF: sub_794F17+11↑j
                xor     eax, eax
                inc     eax
                jz      short loc_794FBC
                mov     ecx, [ebp+arg_4]
                call    sub_791882
                mov     ecx, eax
                call    __ltod3
                divsd   xmm0, ds:qword_7973E0
                movsd   [ebp+var_1C], xmm0
                lea     eax, [ebp+var_1C]
                push    eax
                mov     ecx, [ebp+arg_0]
                call    sub_794FF1
                mov     eax, [ebp+arg_0]
                jmp     short locret_794FEF
; ---------------------------------------------------------------------------
                jmp     short locret_794FEF
; ---------------------------------------------------------------------------

loc_794FBC:                             ; CODE XREF: sub_794F17+74↑j
                mov     ecx, [ebp+arg_4]
                call    sub_791882
                mov     ecx, eax
                call    __ltod3
                mulsd   xmm0, ds:qword_7973E0
                divsd   xmm0, ds:qword_7973E0
                movsd   [ebp+var_24], xmm0
                lea     eax, [ebp+var_24]
                push    eax
                mov     ecx, [ebp+arg_0]
                call    sub_794FF1
                mov     eax, [ebp+arg_0]

locret_794FEF:                          ; CODE XREF: sub_794F17+3B↑j
                                        ; sub_794F17+6D↑j ...
                leave
                retn
sub_794F17      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _QWORD *__thiscall sub_794FF1(_QWORD *this, _QWORD *)
sub_794FF1      proc near               ; CODE XREF: sub_794E45+29↑p
                                        ; sub_794E45+5C↑p ...

var_4           = dword ptr -4
arg_0           = dword ptr  8

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+var_4], ecx
                mov     eax, [ebp+var_4]
                mov     ecx, [ebp+arg_0]
                movsd   xmm0, qword ptr [ecx]
                movsd   qword ptr [eax], xmm0
                mov     eax, [ebp+var_4]
                leave
                retn    4
sub_794FF1      endp

; [00000031 BYTES: COLLAPSED FUNCTION std::_Fac_node::~_Fac_node(void). PRESS CTRL-NUMPAD+ TO EXPAND]
; [00000027 BYTES: COLLAPSED FUNCTION std::_Fac_tidy_reg_t::~_Fac_tidy_reg_t(void). PRESS CTRL-NUMPAD+ TO EXPAND]
; [0000002C BYTES: COLLAPSED FUNCTION std::_Facet_Register(std::_Facet_base *). PRESS CTRL-NUMPAD+ TO EXPAND]
; [00000030 BYTES: COLLAPSED FUNCTION operator new(uint). PRESS CTRL-NUMPAD+ TO EXPAND]
; [00000044 BYTES: COLLAPSED FUNCTION find_pe_section(uchar * const,uint). PRESS CTRL-NUMPAD+ TO EXPAND]
; [00000032 BYTES: COLLAPSED FUNCTION ___scrt_acquire_startup_lock. PRESS CTRL-NUMPAD+ TO EXPAND]
; [00000039 BYTES: COLLAPSED FUNCTION ___scrt_initialize_crt. PRESS CTRL-NUMPAD+ TO EXPAND]
; [00000087 BYTES: COLLAPSED FUNCTION ___scrt_initialize_onexit_tables. PRESS CTRL-NUMPAD+ TO EXPAND]
; [00000094 BYTES: COLLAPSED FUNCTION ___scrt_is_nonwritable_in_current_image. PRESS CTRL-NUMPAD+ TO EXPAND]
; [0000001D BYTES: COLLAPSED FUNCTION ___scrt_release_startup_lock. PRESS CTRL-NUMPAD+ TO EXPAND]
; [00000028 BYTES: COLLAPSED FUNCTION ___scrt_uninitialize_crt. PRESS CTRL-NUMPAD+ TO EXPAND]
; [0000002D BYTES: COLLAPSED FUNCTION __onexit. PRESS CTRL-NUMPAD+ TO EXPAND]
; [00000015 BYTES: COLLAPSED FUNCTION _atexit. PRESS CTRL-NUMPAD+ TO EXPAND]

; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; void __cdecl sub_795312(void *Block)
sub_795312      proc near               ; CODE XREF: sub_791449+1C↑p
                                        ; sub_791497+1C↑p ...

Block           = dword ptr  8

                push    ebp
                mov     ebp, esp
                push    [ebp+Block]     ; Block
                call    j_free
                pop     ecx
                pop     ebp
                retn
sub_795312      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _DWORD *__thiscall sub_795320(_DWORD *Block, char)
sub_795320      proc near               ; DATA XREF: .rdata:const type_info::`vftable'↓o

arg_0           = byte ptr  8

                push    ebp
                mov     ebp, esp
                test    [ebp+arg_0], 1
                push    esi
                mov     esi, ecx
                mov     dword ptr [esi], offset ??_7type_info@@6B@ ; const type_info::`vftable'
                jz      short loc_79533C
                push    0Ch
                push    esi             ; Block
                call    sub_795312
                pop     ecx
                pop     ecx

loc_79533C:                             ; CODE XREF: sub_795320+10↑j
                mov     eax, esi
                pop     esi
                pop     ebp
                retn    4
sub_795320      endp

; [000000AB BYTES: COLLAPSED FUNCTION pre_c_initialization(void). PRESS CTRL-NUMPAD+ TO EXPAND]

; =============== S U B R O U T I N E =======================================


; int sub_7953EE()
sub_7953EE      proc near               ; DATA XREF: .rdata:00797190↓o
                call    ___scrt_initialize_default_local_stdio_options
                xor     eax, eax
                retn
sub_7953EE      endp


; =============== S U B R O U T I N E =======================================


; int sub_7953F6()
sub_7953F6      proc near               ; DATA XREF: .rdata:00797158↓o
                call    sub_79592E
                call    UserMathErrorFunction
                push    eax             ; NewMode
                call    _set_new_mode
                pop     ecx
                retn
sub_7953F6      endp

; [00000182 BYTES: COLLAPSED FUNCTION __scrt_common_main_seh(void). PRESS CTRL-NUMPAD+ TO EXPAND]
; [0000000A BYTES: COLLAPSED FUNCTION start. PRESS CTRL-NUMPAD+ TO EXPAND]
; [00000003 BYTES: COLLAPSED FUNCTION nullsub_1. PRESS CTRL-NUMPAD+ TO EXPAND]

; =============== S U B R O U T I N E =======================================


; _DWORD *__thiscall sub_795597(_DWORD *this)
sub_795597      proc near               ; CODE XREF: sub_7955AF+9↓p
                and     dword ptr [ecx+4], 0
                mov     eax, ecx
                and     dword ptr [ecx+8], 0
                mov     dword ptr [ecx+4], offset aBadAllocation ; "bad allocation"
                mov     dword ptr [ecx], offset ??_7bad_alloc@std@@6B@ ; const std::bad_alloc::`vftable'
                retn
sub_795597      endp


; =============== S U B R O U T I N E =======================================

; Attributes: noreturn bp-based frame

sub_7955AF      proc near               ; CODE XREF: operator new(uint)+2B↑j

pExceptionObject= dword ptr -0Ch

                push    ebp
                mov     ebp, esp
                sub     esp, 0Ch
                lea     ecx, [ebp+pExceptionObject]
                call    sub_795597
                push    offset __TI2?AVbad_alloc@std@@ ; pThrowInfo
                lea     eax, [ebp+pExceptionObject]
                push    eax             ; pExceptionObject
                call    _CxxThrowException
sub_7955AF      endp

; ---------------------------------------------------------------------------
                align 4

; =============== S U B R O U T I N E =======================================

; Attributes: noreturn bp-based frame

sub_7955CC      proc near               ; CODE XREF: operator new(uint)+25↑j

pExceptionObject= dword ptr -0Ch

                push    ebp
                mov     ebp, esp
                sub     esp, 0Ch
                lea     ecx, [ebp+pExceptionObject]
                call    sub_7914D2
                push    offset __TI3?AVbad_array_new_length@std@@ ; pThrowInfo
                lea     eax, [ebp+pExceptionObject]
                push    eax             ; pExceptionObject
                call    _CxxThrowException
sub_7955CC      endp

; ---------------------------------------------------------------------------
                db 0CCh
; [000001D0 BYTES: COLLAPSED FUNCTION ___isa_available_init. PRESS CTRL-NUMPAD+ TO EXPAND]

; =============== S U B R O U T I N E =======================================


; int sub_7957B9()
sub_7957B9      proc near               ; CODE XREF: pre_c_initialization(void)+41↑p
                xor     eax, eax
                inc     eax
                retn
sub_7957B9      endp

; [0000000C BYTES: COLLAPSED FUNCTION ___scrt_is_ucrt_dll_in_use. PRESS CTRL-NUMPAD+ TO EXPAND]
; [0000011A BYTES: COLLAPSED FUNCTION ___scrt_fastfail. PRESS CTRL-NUMPAD+ TO EXPAND]
; [00000005 BYTES: COLLAPSED FUNCTION j_UserMathErrorFunction. PRESS CTRL-NUMPAD+ TO EXPAND]

; =============== S U B R O U T I N E =======================================


; int __cdecl UserMathErrorFunction()
UserMathErrorFunction proc near         ; CODE XREF: pre_c_initialization(void)+13↑p
                                        ; pre_c_initialization(void)+7A↑p ...
                xor     eax, eax
                retn
UserMathErrorFunction endp

; [00000043 BYTES: COLLAPSED FUNCTION ___scrt_is_managed_app. PRESS CTRL-NUMPAD+ TO EXPAND]

; =============== S U B R O U T I N E =======================================


; LPTOP_LEVEL_EXCEPTION_FILTER sub_79592E()
sub_79592E      proc near               ; CODE XREF: sub_7953F6↑p
                push    offset ___scrt_unhandled_exception_filter@4 ; lpTopLevelExceptionFilter
                call    ds:SetUnhandledExceptionFilter
                retn
sub_79592E      endp

; [00000056 BYTES: COLLAPSED FUNCTION __scrt_unhandled_exception_filter(x). PRESS CTRL-NUMPAD+ TO EXPAND]

; =============== S U B R O U T I N E =======================================


; void sub_795990()
sub_795990      proc near               ; CODE XREF: ___scrt_fastfail+1C↑p
                                        ; ___scrt_fastfail+111↑p
                and     dword_7990F0, 0
                retn
sub_795990      endp

; ---------------------------------------------------------------------------
                align 10h
; [00000044 BYTES: COLLAPSED FUNCTION __SEH_prolog4. PRESS CTRL-NUMPAD+ TO EXPAND]
; ---------------------------------------------------------------------------
                mov     ecx, [ebp-10h]
                mov     fs:0, ecx
                pop     ecx
                pop     edi
                pop     edi
                pop     esi
                pop     ebx
                mov     esp, ebp
                pop     ebp
                push    ecx
                bnd retn
; [0000002F BYTES: COLLAPSED FUNCTION __except_handler4. PRESS CTRL-NUMPAD+ TO EXPAND]
; [00000005 BYTES: COLLAPSED FUNCTION j_free. PRESS CTRL-NUMPAD+ TO EXPAND]
; [0000004D BYTES: COLLAPSED FUNCTION ___get_entropy. PRESS CTRL-NUMPAD+ TO EXPAND]
; [0000004B BYTES: COLLAPSED FUNCTION ___security_init_cookie. PRESS CTRL-NUMPAD+ TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION __get_startup_file_mode. PRESS CTRL-NUMPAD+ TO EXPAND]

; =============== S U B R O U T I N E =======================================


; void sub_795ACA()
sub_795ACA      proc near               ; CODE XREF: pre_c_initialization(void)+52↑p
                push    offset ListHead ; ListHead
                call    ds:InitializeSListHead
                retn
sub_795ACA      endp


; =============== S U B R O U T I N E =======================================


; char sub_795AD6()
sub_795AD6      proc near               ; CODE XREF: ___scrt_initialize_crt+15↑p
                                        ; ___scrt_initialize_crt:loc_795159↑p ...
                mov     al, 1
                retn
sub_795AD6      endp

; [00000021 BYTES: COLLAPSED FUNCTION __initialize_default_precision. PRESS CTRL-NUMPAD+ TO EXPAND]

; =============== S U B R O U T I N E =======================================


; void *sub_795AFA()
sub_795AFA      proc near               ; CODE XREF: ___scrt_initialize_default_local_stdio_options+E↓p
                mov     eax, offset unk_799100
                retn
sub_795AFA      endp

; [0000001D BYTES: COLLAPSED FUNCTION ___scrt_initialize_default_local_stdio_options. PRESS CTRL-NUMPAD+ TO EXPAND]

; =============== S U B R O U T I N E =======================================


; BOOL sub_795B1D()
sub_795B1D      proc near               ; CODE XREF: pre_c_initialization(void)+57↑p
                xor     eax, eax
                cmp     dword_799010, eax
                setz    al
                retn
sub_795B1D      endp


; =============== S U B R O U T I N E =======================================


; void *sub_795B29()
sub_795B29      proc near               ; CODE XREF: __scrt_common_main_seh(void)+98↑p
                mov     eax, offset unk_7994B0
                retn
sub_795B29      endp


; =============== S U B R O U T I N E =======================================


; void *sub_795B2F()
sub_795B2F      proc near               ; CODE XREF: __scrt_common_main_seh(void):loc_7954C8↑p
                mov     eax, offset unk_7994AC
                retn
sub_795B2F      endp


; =============== S U B R O U T I N E =======================================


; void sub_795B35()
sub_795B35      proc near               ; CODE XREF: pre_c_initialization(void)+32↑p
                push    ebx
                push    esi
                mov     esi, offset unk_797A74
                mov     ebx, offset unk_797A74
                cmp     esi, ebx
                jnb     short loc_795B5E
                push    edi

loc_795B46:                             ; CODE XREF: sub_795B35+26↓j
                mov     edi, [esi]
                test    edi, edi
                jz      short loc_795B56
                mov     ecx, edi
                call    ds:___guard_check_icall_fptr
                call    edi

loc_795B56:                             ; CODE XREF: sub_795B35+15↑j
                add     esi, 4
                cmp     esi, ebx
                jb      short loc_795B46
                pop     edi

loc_795B5E:                             ; CODE XREF: sub_795B35+E↑j
                pop     esi
                pop     ebx
                retn
sub_795B35      endp


; =============== S U B R O U T I N E =======================================


; void __cdecl sub_795B61()
sub_795B61      proc near               ; DATA XREF: pre_c_initialization(void)+37↑o
                push    ebx
                push    esi
                mov     esi, offset unk_797A7C
                mov     ebx, offset unk_797A7C
                cmp     esi, ebx
                jnb     short loc_795B8A
                push    edi

loc_795B72:                             ; CODE XREF: sub_795B61+26↓j
                mov     edi, [esi]
                test    edi, edi
                jz      short loc_795B82
                mov     ecx, edi
                call    ds:___guard_check_icall_fptr
                call    edi

loc_795B82:                             ; CODE XREF: sub_795B61+15↑j
                add     esi, 4
                cmp     esi, ebx
                jb      short loc_795B72
                pop     edi

loc_795B8A:                             ; CODE XREF: sub_795B61+E↑j
                pop     esi
                pop     ebx
                retn
sub_795B61      endp

; [00000011 BYTES: COLLAPSED FUNCTION __security_check_cookie(x). PRESS CTRL-NUMPAD+ TO EXPAND]
; [00000028 BYTES: COLLAPSED FUNCTION ___raise_securityfailure. PRESS CTRL-NUMPAD+ TO EXPAND]
; [000000F9 BYTES: COLLAPSED FUNCTION ___report_gsfailure. PRESS CTRL-NUMPAD+ TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION __CxxFrameHandler3. PRESS CTRL-NUMPAD+ TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION _CxxThrowException. PRESS CTRL-NUMPAD+ TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION __current_exception. PRESS CTRL-NUMPAD+ TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION __current_exception_context. PRESS CTRL-NUMPAD+ TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION memset. PRESS CTRL-NUMPAD+ TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION _except_handler4_common. PRESS CTRL-NUMPAD+ TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION _callnewh. PRESS CTRL-NUMPAD+ TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION malloc. PRESS CTRL-NUMPAD+ TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION _configure_narrow_argv. PRESS CTRL-NUMPAD+ TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION _initialize_narrow_environment. PRESS CTRL-NUMPAD+ TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION _initialize_onexit_table. PRESS CTRL-NUMPAD+ TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION _register_onexit_function. PRESS CTRL-NUMPAD+ TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION _crt_atexit. PRESS CTRL-NUMPAD+ TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION _cexit. PRESS CTRL-NUMPAD+ TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION _seh_filter_exe. PRESS CTRL-NUMPAD+ TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION _set_app_type. PRESS CTRL-NUMPAD+ TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION __setusermatherr. PRESS CTRL-NUMPAD+ TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION _get_initial_narrow_environment. PRESS CTRL-NUMPAD+ TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION _initterm. PRESS CTRL-NUMPAD+ TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION _initterm_e. PRESS CTRL-NUMPAD+ TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION exit. PRESS CTRL-NUMPAD+ TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION _exit. PRESS CTRL-NUMPAD+ TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION _set_fmode. PRESS CTRL-NUMPAD+ TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION __p___argc. PRESS CTRL-NUMPAD+ TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION __p___argv. PRESS CTRL-NUMPAD+ TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION _c_exit. PRESS CTRL-NUMPAD+ TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION _register_thread_local_exe_atexit_callback. PRESS CTRL-NUMPAD+ TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION _configthreadlocale. PRESS CTRL-NUMPAD+ TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION _set_new_mode. PRESS CTRL-NUMPAD+ TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION __p__commode. PRESS CTRL-NUMPAD+ TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION terminate. PRESS CTRL-NUMPAD+ TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION free. PRESS CTRL-NUMPAD+ TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION _controlfp_s. PRESS CTRL-NUMPAD+ TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION IsProcessorFeaturePresent. PRESS CTRL-NUMPAD+ TO EXPAND]
; [00000078 BYTES: COLLAPSED FUNCTION __filter_x86_sse2_floating_point_exception_default. PRESS CTRL-NUMPAD+ TO EXPAND]
                align 10h
; [000000AA BYTES: COLLAPSED FUNCTION __alldiv. PRESS CTRL-NUMPAD+ TO EXPAND]
                align 10h
; [00000034 BYTES: COLLAPSED FUNCTION __allmul. PRESS CTRL-NUMPAD+ TO EXPAND]
                align 10h
; [000000B2 BYTES: COLLAPSED FUNCTION __allrem. PRESS CTRL-NUMPAD+ TO EXPAND]
                align 10h
; [0000001F BYTES: COLLAPSED FUNCTION __allshl. PRESS CTRL-NUMPAD+ TO EXPAND]
                align 10h
; [00000068 BYTES: COLLAPSED FUNCTION __aulldiv. PRESS CTRL-NUMPAD+ TO EXPAND]
                align 10h
; [00000075 BYTES: COLLAPSED FUNCTION __aullrem. PRESS CTRL-NUMPAD+ TO EXPAND]
                align 10h
; [0000001F BYTES: COLLAPSED FUNCTION __aullshr. PRESS CTRL-NUMPAD+ TO EXPAND]
                align 10h
; [0000002D BYTES: COLLAPSED FUNCTION __alloca_probe. PRESS CTRL-NUMPAD+ TO EXPAND]
                align 10h

__ftoui3:
                cmp     dword_7990E8, 6
                jl      short loc_796130
                vcvttss2usi eax, xmm0
                retn
; ---------------------------------------------------------------------------

loc_796130:                             ; CODE XREF: .text:00796127↑j
                movd    eax, xmm0
                shl     eax, 1
                jb      short loc_796153
                cmp     eax, 9E000000h
                jnb     short loc_796144

loc_79613F:                             ; CODE XREF: .text:00796158↓j
                cvttss2si eax, xmm0
                retn
; ---------------------------------------------------------------------------

loc_796144:                             ; CODE XREF: .text:0079613D↑j
                cmp     eax, 9F000000h
                jnb     short loc_79615A
                shl     eax, 7
                bts     eax, 1Fh
                retn
; ---------------------------------------------------------------------------

loc_796153:                             ; CODE XREF: .text:00796136↑j
                cmp     eax, 7F000000h
                jb      short loc_79613F

loc_79615A:                             ; CODE XREF: .text:00796149↑j
                cvttss2si ecx, ds:dword_797400
                cmc
                sbb     eax, eax
                retn
; ---------------------------------------------------------------------------

__ftoul3:
                cmp     dword_7990E8, 6
                jl      short loc_796189
                mov     eax, 1
                kmovb   k1, eax
                vcvttps2uqq xmm0{k1}{z}, xmm0
                vmovd   eax, xmm0
                vpextrd edx, xmm0, 1
                retn
; ---------------------------------------------------------------------------

loc_796189:                             ; CODE XREF: .text:0079616D↑j
                movd    eax, xmm0
                shl     eax, 1
                jb      short loc_7961C4
                cmp     eax, 9E000000h
                jnb     short loc_79619F

loc_796198:                             ; CODE XREF: .text:007961C9↓j
                cvttss2si eax, xmm0
                xor     edx, edx
                retn
; ---------------------------------------------------------------------------

loc_79619F:                             ; CODE XREF: .text:00796196↑j
                cmp     eax, 0BF000000h
                jnb     short loc_7961CB
                mov     ecx, eax
                bts     eax, 18h
                shr     ecx, 18h
                shl     eax, 7
                sub     cl, 0BEh
                jns     short loc_7961BF
                xor     edx, edx
                shld    edx, eax, cl
                shl     eax, cl
                retn
; ---------------------------------------------------------------------------

loc_7961BF:                             ; CODE XREF: .text:007961B5↑j
                mov     edx, eax
                xor     eax, eax
                retn
; ---------------------------------------------------------------------------

loc_7961C4:                             ; CODE XREF: .text:0079618F↑j
                cmp     eax, 7F000000h
                jb      short loc_796198

loc_7961CB:                             ; CODE XREF: .text:007961A4↑j
                cvttss2si ecx, ds:dword_797400
                cmc
                sbb     eax, eax
                cdq
                retn
; ---------------------------------------------------------------------------

__ftol3:
                cmp     dword_7990E8, 6
                jl      short loc_7961FB
                mov     eax, 1
                kmovb   k1, eax
                vcvttps2qq xmm0{k1}{z}, xmm0
                vmovd   eax, xmm0
                vpextrd edx, xmm0, 1
                retn
; ---------------------------------------------------------------------------

loc_7961FB:                             ; CODE XREF: .text:007961DF↑j
                movd    eax, xmm0
                cdq
                shl     eax, 1
                cmp     eax, 9E000000h
                jnb     short loc_79620F
                cvttss2si eax, xmm0
                cdq
                retn
; ---------------------------------------------------------------------------

loc_79620F:                             ; CODE XREF: .text:00796207↑j
                cmp     eax, 0BE000000h
                jnb     short loc_79622F
                mov     ecx, eax
                bts     eax, 18h
                shr     ecx, 18h
                shl     eax, 7
                sub     cl, 0BEh
                xor     eax, edx
                sub     eax, edx
                shld    edx, eax, cl
                shl     eax, cl
                retn
; ---------------------------------------------------------------------------

loc_79622F:                             ; CODE XREF: .text:00796214↑j
                jnz     short loc_796235
                test    edx, edx
                js      short loc_79623D

loc_796235:                             ; CODE XREF: .text:loc_79622F↑j
                cvttss2si ecx, ds:dword_797400

loc_79623D:                             ; CODE XREF: .text:00796233↑j
                mov     edx, 80000000h
                xor     eax, eax
                retn
; ---------------------------------------------------------------------------

__dtoui3:
                cmp     dword_7990E8, 6
                jl      short loc_796255
                vcvttsd2usi eax, xmm0
                retn
; ---------------------------------------------------------------------------

loc_796255:                             ; CODE XREF: .text:0079624C↑j
                mov     ecx, esp
                add     esp, 0FFFFFFF8h
                and     esp, 0FFFFFFF8h
                movsd   qword ptr [esp], xmm0
                mov     eax, [esp]
                mov     edx, [esp+4]
                mov     esp, ecx
                btr     edx, 1Fh
                jb      short loc_79629E
                cmp     edx, 41E00000h
                jnb     short loc_79627E
                cvttsd2si eax, xmm0
                retn
; ---------------------------------------------------------------------------

loc_79627E:                             ; CODE XREF: .text:00796277↑j
                cmp     edx, 41F00000h
                jnb     short loc_7962AD
                test    eax, 1FFFFFh
                jz      short loc_796295
                cvttss2si ecx, ds:dword_797404

loc_796295:                             ; CODE XREF: .text:0079628B↑j
                shrd    eax, edx, 15h
                bts     eax, 1Fh
                retn
; ---------------------------------------------------------------------------

loc_79629E:                             ; CODE XREF: .text:0079626F↑j
                cmp     edx, 3FF00000h
                jnb     short loc_7962AD
                cvttsd2si eax, xmm0
                xor     eax, eax
                retn
; ---------------------------------------------------------------------------

loc_7962AD:                             ; CODE XREF: .text:00796284↑j
                                        ; .text:007962A4↑j
                cvttss2si ecx, ds:dword_797400
                xor     eax, eax
                dec     eax
                retn
; ---------------------------------------------------------------------------

__dtoul3:
                cmp     dword_7990E8, 6
                jl      short loc_7962D7
                vmovq   xmm0, xmm0
                vcvttpd2uqq xmm0, xmm0
                vmovd   eax, xmm0
                vpextrd edx, xmm0, 1
                retn
; ---------------------------------------------------------------------------

loc_7962D7:                             ; CODE XREF: .text:007962C0↑j
                mov     ecx, esp
                add     esp, 0FFFFFFF8h
                and     esp, 0FFFFFFF8h
                movsd   qword ptr [esp], xmm0
                mov     eax, [esp]
                mov     edx, [esp+4]
                mov     esp, ecx
                btr     edx, 1Fh
                jb      short loc_79633D
                cmp     edx, 41E00000h
                jnb     short loc_796302
                cvttsd2si eax, xmm0
                xor     edx, edx
                retn
; ---------------------------------------------------------------------------

loc_796302:                             ; CODE XREF: .text:007962F9↑j
                mov     ecx, edx
                bts     edx, 14h
                shr     ecx, 14h
                and     edx, 1FFFFFh
                sub     ecx, 433h
                jge     short loc_796332
                neg     ecx
                push    ebx
                xor     ebx, ebx
                shrd    ebx, eax, cl
                jz      short loc_79632B
                cvttss2si ebx, ds:dword_797404

loc_79632B:                             ; CODE XREF: .text:00796321↑j
                pop     ebx
                shrd    eax, edx, cl
                shr     edx, cl
                retn
; ---------------------------------------------------------------------------

loc_796332:                             ; CODE XREF: .text:00796317↑j
                cmp     ecx, 0Ch
                jnb     short loc_79634E
                shld    edx, eax, cl
                shl     eax, cl
                retn
; ---------------------------------------------------------------------------

loc_79633D:                             ; CODE XREF: .text:007962F1↑j
                cmp     edx, 3FF00000h
                jnb     short loc_79634E
                cvttsd2si eax, xmm0
                xor     eax, eax
                xor     edx, edx
                retn
; ---------------------------------------------------------------------------

loc_79634E:                             ; CODE XREF: .text:00796335↑j
                                        ; .text:00796343↑j
                cvttss2si ecx, ds:dword_797400
                xor     eax, eax
                dec     eax
                cdq
                retn
; ---------------------------------------------------------------------------

__dtol3:
                cmp     dword_7990E8, 6
                jl      short loc_796379
                vmovq   xmm0, xmm0
                vcvttpd2qq xmm0, xmm0
                vmovd   eax, xmm0
                vpextrd edx, xmm0, 1
                retn
; ---------------------------------------------------------------------------

loc_796379:                             ; CODE XREF: .text:00796362↑j
                mov     ecx, esp
                add     esp, 0FFFFFFF8h
                and     esp, 0FFFFFFF8h
                movsd   qword ptr [esp], xmm0
                mov     eax, [esp]
                mov     edx, [esp+4]
                mov     esp, ecx
                btr     edx, 1Fh
                sbb     ecx, ecx
                cmp     edx, 41E00000h
                jnb     short loc_7963D9
                cvttsd2si eax, xmm0
                cdq
                retn

; =============== S U B R O U T I N E =======================================


; unsigned __int64 __usercall sub_7963A3@<edx:eax>(unsigned __int64@<edx:eax>)
sub_7963A3      proc near               ; CODE XREF: .text:007963E3↓j
                                        ; .text:007963E5↓p
                mov     ecx, edx
                bts     edx, 14h
                shr     ecx, 14h
                and     edx, 1FFFFFh
                sub     ecx, 433h
                jge     short loc_7963D3
                neg     ecx
                push    ebx
                xor     ebx, ebx
                shrd    ebx, eax, cl
                jz      short loc_7963CC
                cvttss2si ebx, ds:dword_797404

loc_7963CC:                             ; CODE XREF: sub_7963A3+1F↑j
                pop     ebx
                shrd    eax, edx, cl
                shr     edx, cl
                retn
; ---------------------------------------------------------------------------

loc_7963D3:                             ; CODE XREF: sub_7963A3+15↑j
                shld    edx, eax, cl
                shl     eax, cl
                retn
sub_7963A3      endp

; ---------------------------------------------------------------------------

loc_7963D9:                             ; CODE XREF: .text:0079639B↑j
                cmp     edx, 43E00000h
                jnb     short loc_7963F2
                test    ecx, ecx
                jz      short sub_7963A3
                call    sub_7963A3
                neg     eax
                adc     edx, 0
                neg     edx
                retn
; ---------------------------------------------------------------------------

loc_7963F2:                             ; CODE XREF: .text:007963DF↑j
                jecxz   short loc_7963FA
                ja      short loc_7963FA
                test    eax, eax
                jz      short loc_796402

loc_7963FA:                             ; CODE XREF: .text:loc_7963F2↑j
                                        ; .text:007963F4↑j
                cvttss2si ecx, ds:dword_797400

loc_796402:                             ; CODE XREF: .text:007963F8↑j
                mov     edx, 80000000h
                xor     eax, eax
                retn
; ---------------------------------------------------------------------------
                align 10h

__ultod3:
                cmp     dword_7990E8, 6
                jl      short loc_79642A
                vmovd   xmm0, ecx
                vpinsrd xmm0, xmm0, edx, 1
                vcvtuqq2pd xmm0, xmm0
                retn
; ---------------------------------------------------------------------------

loc_79642A:                             ; CODE XREF: .text:00796417↑j
                xorps   xmm0, xmm0
                cvtsi2sd xmm0, ecx
                shr     ecx, 1Fh
                addsd   xmm0, ds:qword_797408[ecx*8]
                test    edx, edx
                jz      short locret_796460
                xorps   xmm1, xmm1
                cvtsi2sd xmm1, edx
                shr     edx, 1Fh
                addsd   xmm1, ds:qword_797408[edx*8]
                mulsd   xmm1, ds:qword_797410
                addsd   xmm0, xmm1

locret_796460:                          ; CODE XREF: .text:0079643F↑j
                retn
; ---------------------------------------------------------------------------
                align 10h
; [00000041 BYTES: COLLAPSED FUNCTION __ltod3. PRESS CTRL-NUMPAD+ TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION memcpy. PRESS CTRL-NUMPAD+ TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION memmove. PRESS CTRL-NUMPAD+ TO EXPAND]
; ---------------------------------------------------------------------------
; START OF FUNCTION CHUNK FOR sub_7918BC

loc_7964BD:                             ; DATA XREF: .rdata:stru_797AA4↓o
; __unwind { // loc_7964CA
;   cleanup() // owned by 7918F5
                mov     ecx, [ebp-18h]
                jmp     sub_791E5B
; } // starts at 7964BD
; END OF FUNCTION CHUNK FOR sub_7918BC
; ---------------------------------------------------------------------------
                db 5 dup(0CCh)
; ---------------------------------------------------------------------------
; START OF FUNCTION CHUNK FOR sub_7918BC

loc_7964CA:                             ; DATA XREF: sub_7918BC+17↑o
                                        ; .rdata:007976FC↓o
; __unwind { // loc_7964CA
                nop
                nop
                mov     eax, offset stru_797A80
                jmp     __CxxFrameHandler3
; } // starts at 7964CA
; END OF FUNCTION CHUNK FOR sub_7918BC
; ---------------------------------------------------------------------------
; START OF FUNCTION CHUNK FOR BProcessor
;   ADDITIONAL PARENT FUNCTION sub_792216
;   ADDITIONAL PARENT FUNCTION sub_79232A
;   ADDITIONAL PARENT FUNCTION sub_792D9C
;   ADDITIONAL PARENT FUNCTION sub_793751

SEH_403751:                             ; DATA XREF: BProcessor+5↑o
                                        ; sub_792216+5↑o ...
SEH_402D9C:
; __unwind { // SEH_403751
                nop
                nop
                mov     eax, offset stru_797AAC
                jmp     __CxxFrameHandler3
; } // starts at 7964D6
; END OF FUNCTION CHUNK FOR BProcessor
; ---------------------------------------------------------------------------
; START OF FUNCTION CHUNK FOR sub_791000
;   ADDITIONAL PARENT FUNCTION sub_79105D
;   ADDITIONAL PARENT FUNCTION sub_7910BA
;   ADDITIONAL PARENT FUNCTION sub_791117
;   ADDITIONAL PARENT FUNCTION sub_791174
;   ADDITIONAL PARENT FUNCTION sub_7911D1
;   ADDITIONAL PARENT FUNCTION sub_79122E
;   ADDITIONAL PARENT FUNCTION sub_79128B

loc_7964E2:                             ; DATA XREF: .rdata:stru_797AF4↓o
; __unwind { // SEH_401000
;   cleanup() // owned by 791028
;   cleanup() // owned by 791085
;   cleanup() // owned by 7910E2
;   cleanup() // owned by 79113F
;   cleanup() // owned by 79119C
;   cleanup() // owned by 7911F9
;   cleanup() // owned by 791256
;   cleanup() // owned by 7912B3
                lea     ecx, [ebp+var_24]
                jmp     Process_Input
; } // starts at 7964E2
; END OF FUNCTION CHUNK FOR sub_791000
; ---------------------------------------------------------------------------
                db 5 dup(0CCh)
; ---------------------------------------------------------------------------
; START OF FUNCTION CHUNK FOR sub_791000
;   ADDITIONAL PARENT FUNCTION sub_79105D
;   ADDITIONAL PARENT FUNCTION sub_7910BA
;   ADDITIONAL PARENT FUNCTION sub_791117
;   ADDITIONAL PARENT FUNCTION sub_791174
;   ADDITIONAL PARENT FUNCTION sub_7911D1
;   ADDITIONAL PARENT FUNCTION sub_79122E
;   ADDITIONAL PARENT FUNCTION sub_79128B

SEH_401000:                             ; DATA XREF: sub_791000+5↑o
                                        ; sub_79105D+5↑o ...
; __unwind { // SEH_401000
                nop
                nop
                mov     eax, offset stru_797AD0
                jmp     __CxxFrameHandler3
; } // starts at 7964EF
; END OF FUNCTION CHUNK FOR sub_791000
; ---------------------------------------------------------------------------
; START OF FUNCTION CHUNK FOR sub_7919EF

loc_7964FB:                             ; DATA XREF: .rdata:stru_797B20↓o
; __unwind { // SEH_4019EF
;   cleanup() // owned by 791A26
                lea     ecx, [ebp+GETInput_Coordinates]
                jmp     Process_Input
; } // starts at 7964FB
; END OF FUNCTION CHUNK FOR sub_7919EF
; ---------------------------------------------------------------------------
                align 8
; START OF FUNCTION CHUNK FOR sub_7919EF

SEH_4019EF:                             ; DATA XREF: sub_7919EF+5↑o
                                        ; .rdata:00797708↓o
; __unwind { // SEH_4019EF
                nop
                nop
                mov     eax, offset stru_797AFC
                jmp     __CxxFrameHandler3
; } // starts at 796508
; END OF FUNCTION CHUNK FOR sub_7919EF
; ---------------------------------------------------------------------------
; START OF FUNCTION CHUNK FOR Process_Input3

loc_796514:                             ; DATA XREF: .rdata:stru_797B4C↓o
; __unwind { // SEH_401A6B
;   cleanup() // owned by 791B2D
                lea     ecx, [ebp+var_54]
                jmp     sub_791E5B
; } // starts at 796514
; END OF FUNCTION CHUNK FOR Process_Input3
; ---------------------------------------------------------------------------
                db 5 dup(0CCh)
; ---------------------------------------------------------------------------
; START OF FUNCTION CHUNK FOR Process_Input3

SEH_401A6B:                             ; DATA XREF: Process_Input3+5↑o
                                        ; .rdata:0079770C↓o
; __unwind { // SEH_401A6B
                nop
                nop
                mov     eax, offset stru_797B28
                jmp     __CxxFrameHandler3
; } // starts at 796521
; END OF FUNCTION CHUNK FOR Process_Input3
; ---------------------------------------------------------------------------
; START OF FUNCTION CHUNK FOR _main

loc_79652D:                             ; DATA XREF: .rdata:stru_797B78↓o
; __unwind { // _main_SEH
;   cleanup() // owned by 791C17
                lea     ecx, [ebp+Input_Coordinates]
                jmp     sub_7919DE
; } // starts at 79652D
; END OF FUNCTION CHUNK FOR _main
; ---------------------------------------------------------------------------
                db 5 dup(0CCh)
; ---------------------------------------------------------------------------
; START OF FUNCTION CHUNK FOR _main

_main_SEH:                              ; DATA XREF: _main+5↑o
                                        ; .rdata:00797710↓o
; __unwind { // _main_SEH
                nop
                nop
                mov     eax, offset stru_797B54
                jmp     __CxxFrameHandler3
; } // starts at 79653A
; END OF FUNCTION CHUNK FOR _main
; ---------------------------------------------------------------------------
; START OF FUNCTION CHUNK FOR sub_791E6C

loc_796546:                             ; DATA XREF: .rdata:stru_797BA4↓o
; __unwind { // SEH_401E6C
;   cleanup() // owned by 791F0C
                lea     ecx, [ebp+var_28]
                jmp     sub_792153
; } // starts at 796546
; END OF FUNCTION CHUNK FOR sub_791E6C
; ---------------------------------------------------------------------------
                db 5 dup(0CCh)
; ---------------------------------------------------------------------------
; START OF FUNCTION CHUNK FOR sub_791E6C

SEH_401E6C:                             ; DATA XREF: sub_791E6C+5↑o
                                        ; .rdata:00797714↓o
; __unwind { // SEH_401E6C
                nop
                nop
                mov     eax, offset stru_797B80
                jmp     __CxxFrameHandler3
; } // starts at 796553
; END OF FUNCTION CHUNK FOR sub_791E6C
; ---------------------------------------------------------------------------
; START OF FUNCTION CHUNK FOR sub_7920BA

loc_79655F:                             ; DATA XREF: .rdata:stru_797BD0↓o
; __unwind { // SEH_4020BA
;   cleanup() // owned by 7920E9
                mov     ecx, [ebp+var_14]
                jmp     sub_792131
; } // starts at 79655F
; END OF FUNCTION CHUNK FOR sub_7920BA
; ---------------------------------------------------------------------------
                db 5 dup(0CCh)
; ---------------------------------------------------------------------------
; START OF FUNCTION CHUNK FOR sub_7920BA

SEH_4020BA:                             ; DATA XREF: sub_7920BA+5↑o
                                        ; .rdata:00797718↓o
; __unwind { // SEH_4020BA
                nop
                nop
                mov     eax, offset stru_797BAC
                jmp     __CxxFrameHandler3
; } // starts at 79656C
; END OF FUNCTION CHUNK FOR sub_7920BA
; ---------------------------------------------------------------------------
; START OF FUNCTION CHUNK FOR sub_792823

loc_796578:                             ; DATA XREF: .rdata:stru_797BFC↓o
; __unwind { // SEH_402823
;   cleanup() // owned by 792849
;   cleanup() // owned by 7928E0
                lea     ecx, [ebp+var_24]
                jmp     ds:??1_Lockit@std@@QAE@XZ ; std::_Lockit::~_Lockit(void)
; ---------------------------------------------------------------------------

loc_796581:                             ; DATA XREF: .rdata:00797C04↓o
;   cleanup() // owned by 7928B2
                lea     ecx, [ebp+var_1C]
                jmp     sub_792E13
; } // starts at 796578
; END OF FUNCTION CHUNK FOR sub_792823
; ---------------------------------------------------------------------------
                db 5 dup(0CCh)
; ---------------------------------------------------------------------------
; START OF FUNCTION CHUNK FOR sub_792823

SEH_402823:                             ; DATA XREF: sub_792823+5↑o
                                        ; .rdata:0079771C↓o
; __unwind { // SEH_402823
                nop
                nop
                mov     eax, offset stru_797BD8
                jmp     __CxxFrameHandler3
; } // starts at 79658E
; END OF FUNCTION CHUNK FOR sub_792823
; ---------------------------------------------------------------------------
; START OF FUNCTION CHUNK FOR sub_792F66

loc_79659A:                             ; DATA XREF: .rdata:stru_797C30↓o
; __unwind { // SEH_402F66
;   cleanup() // owned by 792F9D
;   cleanup() // owned by 792FE8
;   cleanup() // owned by 793165
;   cleanup() // owned by 79316B
                lea     ecx, [ebp+var_74]
                jmp     sub_793618
; ---------------------------------------------------------------------------

loc_7965A2:                             ; DATA XREF: .rdata:00797C38↓o
;   cleanup() // owned by 792FD8
;   cleanup() // owned by 792FFE
                lea     ecx, [ebp+var_7C]
                jmp     sub_7916D8
; } // starts at 79659A
; END OF FUNCTION CHUNK FOR sub_792F66
; ---------------------------------------------------------------------------
                db 5 dup(0CCh)
; ---------------------------------------------------------------------------
; START OF FUNCTION CHUNK FOR sub_792F66

SEH_402F66:                             ; DATA XREF: sub_792F66+5↑o
                                        ; .rdata:00797720↓o
; __unwind { // SEH_402F66
                nop
                nop
                mov     eax, offset stru_797C0C
                jmp     __CxxFrameHandler3
; } // starts at 7965AF
; END OF FUNCTION CHUNK FOR sub_792F66
; ---------------------------------------------------------------------------
; START OF FUNCTION CHUNK FOR sub_793363

SEH_403363:                             ; DATA XREF: sub_793363+5↑o
                                        ; .rdata:00797724↓o
; __unwind { // SEH_403363
                nop
                nop
                mov     eax, offset stru_797C74
                jmp     __CxxFrameHandler3
; } // starts at 7965BB
; END OF FUNCTION CHUNK FOR sub_793363
; ---------------------------------------------------------------------------
; START OF FUNCTION CHUNK FOR sub_79349C

loc_7965C7:                             ; DATA XREF: .rdata:stru_797CF0↓o
; __unwind { // SEH_40349C
;   cleanup() // owned by 7934DF
                lea     ecx, [ebp+var_20]
                jmp     sub_793643
; } // starts at 7965C7
; END OF FUNCTION CHUNK FOR sub_79349C
; ---------------------------------------------------------------------------
                db 5 dup(0CCh)
; ---------------------------------------------------------------------------
; START OF FUNCTION CHUNK FOR sub_79349C

SEH_40349C:                             ; DATA XREF: sub_79349C+5↑o
                                        ; .rdata:00797728↓o
; __unwind { // SEH_40349C
                nop
                nop
                mov     eax, offset stru_797CCC
                jmp     __CxxFrameHandler3
; } // starts at 7965D4
; END OF FUNCTION CHUNK FOR sub_79349C
; ---------------------------------------------------------------------------
; START OF FUNCTION CHUNK FOR sub_7935AC

loc_7965E0:                             ; DATA XREF: .rdata:stru_797D1C↓o
; __unwind { // SEH_4035AC
;   cleanup() // owned by 7935D5
                lea     ecx, [ebp+var_1C]
                jmp     sub_793643
; } // starts at 7965E0
; END OF FUNCTION CHUNK FOR sub_7935AC
; ---------------------------------------------------------------------------
                db 5 dup(0CCh)
; ---------------------------------------------------------------------------
; START OF FUNCTION CHUNK FOR sub_7935AC

SEH_4035AC:                             ; DATA XREF: sub_7935AC+5↑o
                                        ; .rdata:0079772C↓o
; __unwind { // SEH_4035AC
                nop
                nop
                mov     eax, offset stru_797CF8
                jmp     __CxxFrameHandler3
; } // starts at 7965ED
; END OF FUNCTION CHUNK FOR sub_7935AC
; ---------------------------------------------------------------------------
; START OF FUNCTION CHUNK FOR sub_7936F6

loc_7965F9:                             ; DATA XREF: .rdata:stru_797D48↓o
; __unwind { // SEH_4036F6
;   cleanup() // owned by 79371E
                mov     ecx, [ebp+var_10]
                jmp     sub_793751
; } // starts at 7965F9
; END OF FUNCTION CHUNK FOR sub_7936F6
; ---------------------------------------------------------------------------
                db 5 dup(0CCh)
; ---------------------------------------------------------------------------
; START OF FUNCTION CHUNK FOR sub_7936F6

SEH_4036F6:                             ; DATA XREF: sub_7936F6+5↑o
                                        ; .rdata:00797730↓o
; __unwind { // SEH_4036F6
                nop
                nop
                mov     eax, offset stru_797D24
                jmp     __CxxFrameHandler3
; } // starts at 796606
; END OF FUNCTION CHUNK FOR sub_7936F6

; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; void __cdecl sub_796612()
sub_796612      proc near               ; DATA XREF: sub_791000+46↑o
                push    ebp
                mov     ebp, esp
                mov     ecx, offset dword_79944C
                call    sub_7919DE
                pop     ebp
                retn
sub_796612      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; void __cdecl sub_796621()
sub_796621      proc near               ; DATA XREF: sub_79105D+46↑o
                push    ebp
                mov     ebp, esp
                mov     ecx, offset dword_799458
                call    sub_7919DE
                pop     ebp
                retn
sub_796621      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; void __cdecl sub_796630()
sub_796630      proc near               ; DATA XREF: sub_7910BA+46↑o
                push    ebp
                mov     ebp, esp
                mov     ecx, offset dword_7994A0
                call    sub_7919DE
                pop     ebp
                retn
sub_796630      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; void __cdecl sub_79663F()
sub_79663F      proc near               ; DATA XREF: sub_791117+46↑o
                push    ebp
                mov     ebp, esp
                mov     ecx, offset dword_799440
                call    sub_7919DE
                pop     ebp
                retn
sub_79663F      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; void __cdecl sub_79664E()
sub_79664E      proc near               ; DATA XREF: sub_791174+46↑o
                push    ebp
                mov     ebp, esp
                mov     ecx, offset dword_799464
                call    sub_7919DE
                pop     ebp
                retn
sub_79664E      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; void __cdecl sub_79665D()
sub_79665D      proc near               ; DATA XREF: sub_7911D1+46↑o
                push    ebp
                mov     ebp, esp
                mov     ecx, offset dword_799494
                call    sub_7919DE
                pop     ebp
                retn
sub_79665D      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; void __cdecl sub_79666C()
sub_79666C      proc near               ; DATA XREF: sub_79122E+46↑o
                push    ebp
                mov     ebp, esp
                mov     ecx, offset dword_799434
                call    sub_7919DE
                pop     ebp
                retn
sub_79666C      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; void __cdecl sub_79667B()
sub_79667B      proc near               ; DATA XREF: sub_79128B+46↑o
                push    ebp
                mov     ebp, esp
                mov     ecx, offset dword_799488
                call    sub_7919DE
                pop     ebp
                retn
sub_79667B      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; void __cdecl sub_79668A()
sub_79668A      proc near               ; DATA XREF: sub_7912E8+12↑o
                push    ebp
                mov     ebp, esp
                mov     ecx, offset dword_799470
                call    Process_Input
                pop     ebp
                retn
sub_79668A      endp


; =============== S U B R O U T I N E =======================================


; void __cdecl sub_796699()
sub_796699      proc near               ; DATA XREF: sub_791307↑o
                mov     ecx, offset unk_7990BC ; this
                jmp     ??1_Fac_tidy_reg_t@std@@QAE@XZ ; std::_Fac_tidy_reg_t::~_Fac_tidy_reg_t(void)
sub_796699      endp

; ---------------------------------------------------------------------------
                align 200h
                dd 200h dup(?)
_text           ends

; Section 2. (virtual address 00007000)
; Virtual size                  : 0000190A (   6410.)
; Section size in file          : 00001A00 (   6656.)
; Offset to raw data for section: 00005C00
; Flags 40000040: Data Readable
; Alignment     : default
;
; Imports from KERNEL32.dll
;
; ===========================================================================

; Segment type: Externs
; _idata
; BOOL (__stdcall *TerminateProcess)(HANDLE hProcess, UINT uExitCode)
                extrn TerminateProcess:dword
                                        ; CODE XREF: ___raise_securityfailure+20↑p
                                        ; DATA XREF: ___raise_securityfailure+20↑r ...
; BOOL (__stdcall *IsProcessorFeaturePresent)(DWORD ProcessorFeature)
                extrn __imp_IsProcessorFeaturePresent:dword
                                        ; DATA XREF: IsProcessorFeaturePresent↑r
; BOOL (__stdcall *IsDebuggerPresent)()
                extrn IsDebuggerPresent:dword
                                        ; CODE XREF: ___scrt_fastfail+D7↑p
                                        ; DATA XREF: ___scrt_fastfail+D7↑r
; LONG (__stdcall *UnhandledExceptionFilter)(struct _EXCEPTION_POINTERS *ExceptionInfo)
                extrn UnhandledExceptionFilter:dword
                                        ; CODE XREF: ___scrt_fastfail+101↑p
                                        ; ___raise_securityfailure+E↑p
                                        ; DATA XREF: ...
; HANDLE (__stdcall *GetCurrentProcess)()
                extrn GetCurrentProcess:dword
                                        ; CODE XREF: ___raise_securityfailure+19↑p
                                        ; DATA XREF: ___raise_securityfailure+19↑r
; void (__stdcall *InitializeSListHead)(PSLIST_HEADER ListHead)
                extrn InitializeSListHead:dword
                                        ; CODE XREF: sub_795ACA+5↑p
                                        ; DATA XREF: sub_795ACA+5↑r
; void (__stdcall *GetSystemTimeAsFileTime)(LPFILETIME lpSystemTimeAsFileTime)
                extrn GetSystemTimeAsFileTime:dword
                                        ; CODE XREF: ___get_entropy+12↑p
                                        ; DATA XREF: ___get_entropy+12↑r
; DWORD (__stdcall *GetCurrentThreadId)()
                extrn GetCurrentThreadId:dword
                                        ; CODE XREF: ___get_entropy+21↑p
                                        ; DATA XREF: ___get_entropy+21↑r
; LPTOP_LEVEL_EXCEPTION_FILTER (__stdcall *SetUnhandledExceptionFilter)(LPTOP_LEVEL_EXCEPTION_FILTER lpTopLevelExceptionFilter)
                extrn SetUnhandledExceptionFilter:dword
                                        ; CODE XREF: ___scrt_fastfail+F7↑p
                                        ; sub_79592E+5↑p ...
; DWORD (__stdcall *GetCurrentProcessId)()
                extrn GetCurrentProcessId:dword
                                        ; CODE XREF: ___get_entropy+2A↑p
                                        ; DATA XREF: ___get_entropy+2A↑r
; BOOL (__stdcall *QueryPerformanceCounter)(LARGE_INTEGER *lpPerformanceCount)
                extrn QueryPerformanceCounter:dword
                                        ; CODE XREF: ___get_entropy+37↑p
                                        ; DATA XREF: ___get_entropy+37↑r
; HMODULE (__stdcall *GetModuleHandleW)(LPCWSTR lpModuleName)
                extrn GetModuleHandleW:dword
                                        ; CODE XREF: ___scrt_is_managed_app+2↑p
                                        ; DATA XREF: ___scrt_is_managed_app+2↑r

;
; Imports from MSVCP140.dll
;
; int __thiscall std::ios::setstate(_DWORD, _DWORD, _DWORD, _DWORD, _DWORD, _DWORD, _DWORD, _DWORD, _DWORD, _DWORD, _DWORD, _DWORD, _DWORD, _DWORD, _DWORD, _DWORD, _DWORD, _DWORD, _DWORD, _DWORD, _DWORD, _DWORD, _DWORD, _DWORD, _DWORD, _DWORD, _DWORD, _DWORD, _DWORD, _DWORD, _DWORD, _DWORD, _DWORD, _DWORD, _DWORD, _DWORD, _DWORD)
                extrn ?setstate@?$basic_ios@DU?$char_traits@D@std@@@std@@QAEXH_N@Z:dword
                                        ; CODE XREF: sub_792F66+1F3↑p
                                        ; sub_792F66+24B↑p
                                        ; DATA XREF: ...
; int __thiscall std::ios::rdbuf(_DWORD, _DWORD, _DWORD)
                extrn ?rdbuf@?$basic_ios@DU?$char_traits@D@std@@@std@@QBEPAV?$basic_streambuf@DU?$char_traits@D@std@@@2@XZ:dword
                                        ; CODE XREF: sub_792F66+11A↑p
                                        ; sub_792F66+149↑p ...
; int __thiscall std::streambuf::sgetc(_DWORD)
                extrn ?sgetc@?$basic_streambuf@DU?$char_traits@D@std@@@std@@QAEHXZ:dword
                                        ; CODE XREF: sub_792F66+126↑p
                                        ; DATA XREF: sub_792F66+126↑r
; int __thiscall std::ios_base::getloc(_DWORD, _DWORD)
                extrn ?getloc@ios_base@std@@QBE?AVlocale@2@XZ:dword
                                        ; CODE XREF: sub_792F66+63↑p
                                        ; DATA XREF: sub_792F66+63↑r
; int __thiscall std::streambuf::snextc(_DWORD)
                extrn ?snextc@?$basic_streambuf@DU?$char_traits@D@std@@@std@@QAEHXZ:dword
                                        ; CODE XREF: sub_792F66+155↑p
                                        ; DATA XREF: sub_792F66+155↑r
; public: __int64 __thiscall std::ios_base::width(void)const
                extrn ?width@ios_base@std@@QBE_JXZ:dword
                                        ; CODE XREF: sub_792F66+A7↑p
                                        ; sub_792F66+CC↑p ...
; int __cdecl std::ctype<char>::_Getcat(_DWORD, _DWORD)
                extrn ?_Getcat@?$ctype@D@std@@SAIPAPBVfacet@locale@2@PBV42@@Z:dword
                                        ; CODE XREF: sub_792823+6A↑p
                                        ; DATA XREF: sub_792823+6A↑r
; int __thiscall std::ctype<char>::is(_DWORD, _DWORD, _DWORD)
                extrn ?is@?$ctype@D@std@@QBE_NFD@Z:dword
                                        ; CODE XREF: sub_792F66+1A8↑p
                                        ; DATA XREF: sub_792F66+1A8↑r
; int __thiscall std::locale::id::operator unsigned int(_DWORD)
                extrn ??Bid@locale@std@@QAEIXZ:dword
                                        ; CODE XREF: sub_792823+38↑p
                                        ; DATA XREF: sub_792823+38↑r
; int __thiscall std::istream::_Ipfx(_DWORD, _DWORD)
                extrn ?_Ipfx@?$basic_istream@DU?$char_traits@D@std@@@std@@QAE_N_N@Z:dword
                                        ; CODE XREF: sub_7936F6+3A↑p
                                        ; DATA XREF: sub_7936F6+3A↑r
; __int64 (__cdecl *Xtime_get_ticks)()
                extrn _Xtime_get_ticks:dword ; CODE XREF: sub_791797+6↑p
                                        ; DATA XREF: sub_791797+6↑r
; __int64 (__cdecl *Query_perf_frequency)()
                extrn _Query_perf_frequency:dword
                                        ; CODE XREF: sub_7917C3+6↑p
                                        ; DATA XREF: sub_7917C3+6↑r
; __int64 (__cdecl *Query_perf_counter)()
                extrn _Query_perf_counter:dword
                                        ; CODE XREF: sub_7917C3+12↑p
                                        ; DATA XREF: sub_7917C3+12↑r
; void (__cdecl *Thrd_sleep)(const xtime *)
                extrn _Thrd_sleep:dword ; CODE XREF: sub_793230+4A↑p
                                        ; DATA XREF: sub_793230+4A↑r
; void __cdecl std::_Xlength_error(char const *)
                extrn ?_Xlength_error@std@@YAXPBD@Z:dword
                                        ; CODE XREF: sub_791664+8↑p
                                        ; sub_7937AD+8↑p
                                        ; DATA XREF: ...
; unsigned int __cdecl std::_Random_device(void)
                extrn ?_Random_device@std@@YAIXZ:dword
                                        ; CODE XREF: sub_7918AD+7↑p
                                        ; DATA XREF: sub_7918AD+7↑r
; public: static class std::locale::id std::ctype<char>::id
                extrn ?id@?$ctype@D@std@@2V0locale@2@A:dword
                                        ; DATA XREF: sub_792823+32↑r
; void __cdecl std::_Xout_of_range(char const *)
                extrn ?_Xout_of_range@std@@YAXPBD@Z:dword
                                        ; CODE XREF: sub_792813+8↑p
                                        ; DATA XREF: sub_792813+8↑r
; class std::basic_istream<char, struct std::char_traits<char>> std::cin
                extrn ?cin@std@@3V?$basic_istream@DU?$char_traits@D@std@@@1@A:dword
                                        ; DATA XREF: sub_7919EF+3F↑r
; int std::locale::_Getgloballocale(void)
                extrn ?_Getgloballocale@locale@std@@CAPAV_Locimp@12@XZ:dword
                                        ; CODE XREF: sub_791721:loc_79176F↑p
                                        ; DATA XREF: sub_791721:loc_79176F↑r
; public: __thiscall std::_Lockit::_Lockit(int)
                extrn ??0_Lockit@std@@QAE@H@Z:dword
                                        ; CODE XREF: sub_792823+20↑p
                                        ; DATA XREF: sub_792823+20↑r
; public: __thiscall std::_Lockit::~_Lockit(void)
                extrn ??1_Lockit@std@@QAE@XZ:dword
                                        ; CODE XREF: sub_792823+D6↑p
                                        ; DATA XREF: sub_792823+D6↑r ...
; public: __int64 __thiscall std::ios_base::width(__int64)
                extrn ?width@ios_base@std@@QAE_J_J@Z:dword
                                        ; CODE XREF: sub_792F66+21E↑p
                                        ; DATA XREF: sub_792F66+21E↑r

;
; Imports from VCRUNTIME140.dll
;
; void *(__cdecl *memmove)(void *, const void *Src, size_t Size)
                extrn __imp_memmove:dword ; DATA XREF: memmove↑r
                                        ; .rdata:00797E78↓o
                extrn __imp__except_handler4_common:dword
                                        ; DATA XREF: _except_handler4_common↑r
; void *(__cdecl *memset)(void *, int Val, size_t Size)
                extrn __imp_memset:dword ; DATA XREF: memset↑r
                extrn __imp___current_exception_context:dword
                                        ; DATA XREF: __current_exception_context↑r
                extrn __imp___current_exception:dword
                                        ; DATA XREF: __current_exception↑r
; void (__stdcall __noreturn *_CxxThrowException)(void *pExceptionObject, _ThrowInfo *pThrowInfo)
                extrn __imp__CxxThrowException:dword
                                        ; DATA XREF: _CxxThrowException↑r
; int __cdecl _std_exception_copy(_DWORD, _DWORD)
                extrn __std_exception_copy:dword
                                        ; CODE XREF: sub_7913C7+2B↑p
                                        ; DATA XREF: sub_7913C7+2B↑r
                extrn __imp___CxxFrameHandler3:dword
                                        ; DATA XREF: __CxxFrameHandler3↑r
; void *(__cdecl *memcpy)(void *, const void *Src, size_t Size)
                extrn __imp_memcpy:dword ; DATA XREF: memcpy↑r
; int __cdecl _std_exception_destroy(_DWORD)
                extrn __std_exception_destroy:dword
                                        ; CODE XREF: sub_791401+17↑p
                                        ; DATA XREF: sub_791401+17↑r

;
; Imports from api-ms-win-crt-heap-l1-1-0.dll
;
; int (__cdecl *_set_new_mode)(int NewMode)
                extrn __imp__set_new_mode:dword
                                        ; DATA XREF: _set_new_mode↑r
                                        ; .rdata:00797EB4↓o
; int (__cdecl *_callnewh)(size_t Size)
                extrn __imp__callnewh:dword ; DATA XREF: _callnewh↑r
; void *(__cdecl *malloc)(size_t Size)
                extrn __imp_malloc:dword ; DATA XREF: malloc↑r
; void (__cdecl *free)(void *Block)
                extrn __imp_free:dword  ; DATA XREF: free↑r

;
; Imports from api-ms-win-crt-locale-l1-1-0.dll
;
; int (__cdecl *_configthreadlocale)(int Flag)
                extrn __imp__configthreadlocale:dword
                                        ; DATA XREF: _configthreadlocale↑r
                                        ; .rdata:00797EDC↓o

;
; Imports from api-ms-win-crt-math-l1-1-0.dll
;
; void (__cdecl *__setusermatherr)(_UserMathErrorFunctionPointer UserMathErrorFunction)
                extrn __imp___setusermatherr:dword
                                        ; DATA XREF: __setusermatherr↑r
                                        ; .rdata:00797EC8↓o

;
; Imports from api-ms-win-crt-runtime-l1-1-0.dll
;
; void (__cdecl *_c_exit)()
                extrn __imp__c_exit:dword ; DATA XREF: _c_exit↑r
                                        ; .rdata:00797EA0↓o
; void (__cdecl *_register_thread_local_exe_atexit_callback)(_tls_callback_type Callback)
                extrn __imp__register_thread_local_exe_atexit_callback:dword
                                        ; DATA XREF: _register_thread_local_exe_atexit_callback↑r
; int *(__cdecl *__p___argc)()
                extrn __imp___p___argc:dword ; DATA XREF: __p___argc↑r
; void (__cdecl __noreturn *invalid_parameter_noinfo_noreturn)()
                extrn _invalid_parameter_noinfo_noreturn:dword
                                        ; CODE XREF: sub_7915D8:loc_791622↑p
                                        ; sub_793533:loc_793563↑p
                                        ; DATA XREF: ...
                extrn __imp_terminate:dword ; DATA XREF: terminate↑r
; void (__cdecl __noreturn *_exit)(int Code)
                extrn __imp__exit:dword ; DATA XREF: _exit↑r
; errno_t (__cdecl *_controlfp_s)(unsigned int *CurrentState, unsigned int NewValue, unsigned int Mask)
                extrn __imp__controlfp_s:dword
                                        ; DATA XREF: _controlfp_s↑r
; errno_t (__cdecl *_configure_narrow_argv)(_crt_argv_mode mode)
                extrn __imp__configure_narrow_argv:dword
                                        ; DATA XREF: _configure_narrow_argv↑r
; int (__cdecl *_initialize_narrow_environment)()
                extrn __imp__initialize_narrow_environment:dword
                                        ; DATA XREF: _initialize_narrow_environment↑r
; void (__cdecl __noreturn *exit)(int Code)
                extrn __imp_exit:dword  ; DATA XREF: exit↑r
; char ***(__cdecl *__p___argv)()
                extrn __imp___p___argv:dword ; DATA XREF: __p___argv↑r
; int (__cdecl *_initterm_e)(_PIFV *First, _PIFV *Last)
                extrn __imp__initterm_e:dword ; DATA XREF: _initterm_e↑r
; void (__cdecl *_initterm)(_PVFV *First, _PVFV *Last)
                extrn __imp__initterm:dword ; DATA XREF: _initterm↑r
; char **(__cdecl *_get_initial_narrow_environment)()
                extrn __imp__get_initial_narrow_environment:dword
                                        ; DATA XREF: _get_initial_narrow_environment↑r
; void (__cdecl *_set_app_type)(_crt_app_type Type)
                extrn __imp__set_app_type:dword
                                        ; DATA XREF: _set_app_type↑r
; int (__cdecl *_seh_filter_exe)(unsigned int ExceptionNum, struct _EXCEPTION_POINTERS *ExceptionPtr)
                extrn __imp__seh_filter_exe:dword
                                        ; DATA XREF: _seh_filter_exe↑r
; void (__cdecl *_cexit)()
                extrn __imp__cexit:dword ; DATA XREF: _cexit↑r
; int (__cdecl *_crt_atexit)(_PVFV Function)
                extrn __imp__crt_atexit:dword ; DATA XREF: _crt_atexit↑r
; int (__cdecl *_initialize_onexit_table)(_onexit_table_t *Table)
                extrn __imp__initialize_onexit_table:dword
                                        ; DATA XREF: _initialize_onexit_table↑r
; int (__cdecl *_register_onexit_function)(_onexit_table_t *Table, _onexit_t Function)
                extrn __imp__register_onexit_function:dword
                                        ; DATA XREF: _register_onexit_function↑r

;
; Imports from api-ms-win-crt-stdio-l1-1-0.dll
;
; errno_t (__cdecl *_set_fmode)(int Mode)
                extrn __imp__set_fmode:dword ; DATA XREF: _set_fmode↑r
                                        ; .rdata:00797E8C↓o
; int (__cdecl *getchar)()
                extrn getchar:dword     ; CODE XREF: _main+C2↑p
                                        ; _main+C8↑p
                                        ; DATA XREF: ...
; int (__cdecl *_stdio_common_vfprintf)(unsigned __int64 Options, FILE *Stream, const char *Format, _locale_t Locale, va_list ArgList)
                extrn __stdio_common_vfprintf:dword
                                        ; CODE XREF: sub_791339+19↑p
                                        ; DATA XREF: sub_791339+19↑r
; FILE *(__cdecl *_acrt_iob_func)(unsigned int Ix)
                extrn __acrt_iob_func:dword ; CODE XREF: printf+14↑p
                                        ; DATA XREF: printf+14↑r
; int *(__cdecl *__p__commode)()
                extrn __imp___p__commode:dword
                                        ; DATA XREF: __p__commode↑r


; ===========================================================================

; Segment type: Pure data
; Segment permissions: Read
_rdata          segment para public 'DATA' use32
                assume cs:_rdata
                ;org 797150h
___guard_check_icall_fptr dd offset nullsub_1
                                        ; DATA XREF: std::_Fac_node::~_Fac_node(void)+C↑r
                                        ; std::_Fac_node::~_Fac_node(void)+24↑r ...
; const _PVFV dword_797154
dword_797154    dd 0                    ; DATA XREF: __scrt_common_main_seh(void)+72↑o
                dd offset sub_7953F6
                dd offset sub_791307
                dd offset sub_791000
                dd offset sub_79105D
                dd offset sub_7910BA
                dd offset sub_791117
                dd offset sub_791174
                dd offset sub_7911D1
                dd offset sub_79122E
                dd offset sub_79128B
                dd offset sub_7912E8
; const _PVFV dword_797184
dword_797184    dd 0                    ; DATA XREF: __scrt_common_main_seh(void):loc_795475↑o
; const _PIFV First
First           dd 0                    ; DATA XREF: __scrt_common_main_seh(void)+4C↑o
                dd offset ?pre_c_initialization@@YAHXZ ; pre_c_initialization(void)
                dd offset sub_7953EE
; const _PIFV Last
Last            dd 0                    ; DATA XREF: __scrt_common_main_seh(void)+47↑o
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                dd offset ??_R4type_info@@6B@ ; const type_info::`RTTI Complete Object Locator'
; const type_info::`vftable'
??_7type_info@@6B@ dd offset sub_795320 ; DATA XREF: sub_795320+A↑o
                                        ; .data:type_info `RTTI Type Descriptor'↓o ...
                dd offset ??_R4exception@std@@6B@ ; const std::exception::`RTTI Complete Object Locator'
; const std::exception::`vftable'
??_7exception@std@@6B@ dd offset sub_791449 ; DATA XREF: sub_79139A+A↑o
                                        ; sub_7913C7+A↑o ...
                dd offset sub_791421
                dd offset ??_R4bad_alloc@std@@6B@ ; const std::bad_alloc::`RTTI Complete Object Locator'
; const std::bad_alloc::`vftable'
??_7bad_alloc@std@@6B@ dd offset sub_791497 ; DATA XREF: sub_791473+17↑o
                                        ; sub_79156F+15↑o ...
                dd offset sub_791421
aBadAllocation  db 'bad allocation',0   ; DATA XREF: sub_795597+A↑o
                align 10h
                dd offset ??_R4bad_array_new_length@std@@6B@ ; const std::bad_array_new_length::`RTTI Complete Object Locator'
; const std::bad_array_new_length::`vftable'
??_7bad_array_new_length@std@@6B@ dd offset sub_7914F4
                                        ; DATA XREF: sub_7914D2+17↑o
                                        ; sub_79154D+15↑o
                dd offset sub_791421
; const struct _EXCEPTION_POINTERS ExceptionInfo
ExceptionInfo   _EXCEPTION_POINTERS <offset dword_799108, offset dword_799158>
                                        ; DATA XREF: ___report_gsfailure+ED↑o
aUnknownExcepti db 'Unknown exception',0
                                        ; DATA XREF: sub_791421:loc_79143D↑o
                align 4
aBadArrayNewLen db 'bad array new length',0 ; DATA XREF: sub_7914D2+7↑o
                align 10h
aStringTooLong  db 'string too long',0  ; DATA XREF: sub_791664+3↑o
aBadCast        db 'bad cast',0         ; DATA XREF: sub_791674+9↑o
                align 4
aHttpsDiscordGg db 'https://discord.gg/fmhw85T5zM',0
                                        ; DATA XREF: sub_791000+1B↑o
                align 4
aV1rtu4lall0c   db 'V1rtu4lAll0c',0     ; DATA XREF: sub_79105D+1B↑o
                align 4
aJpofwejfdslfkj db 'jpofwejfdslfkjdslkfghiphap332oiu',0
                                        ; DATA XREF: sub_7910BA+1B↑o
                align 10h
aOhu3mndslwoxfe db 'Ohu3mNdslwoxfedlo34',0 ; DATA XREF: sub_791117+1B↑o
a2Mk43xxy01k    db '2-mk43xxy0.1k',0    ; DATA XREF: sub_791174+1B↑o
                align 4
a324265339152   db ';32;42;65;33;91;52',0 ; DATA XREF: sub_7911D1+1B↑o
                align 4
aSDY9DVk        db 'S`=d`Y9{]D}_vK$#.',0 ; DATA XREF: sub_79122E+1B↑o
                align 4
aXxxxxgot75Huh9 db 'xxxxxGot7.5_HUH?98rjoi2r3oifjdsoigfogdfs',0
                                        ; DATA XREF: sub_79128B+1B↑o
                align 4
aH4ndy51mpl30bf db 'H4ndy51mpL30bFusC4tI0NL1bR4RybYM3mB3R_TH4nKs',0
                                        ; DATA XREF: sub_7912E8+3↑o
                align 4
aCoordinates       db 'Coordinates: ',0       ; DATA XREF: sub_7919EF+1F↑o
                align 4
aV2             db 'v2',0               ; DATA XREF: sub_7919EF+2A↑o
                align 4
aMain           db 'main',0             ; DATA XREF: _main+23↑o
                align 10h
aS              db '%s()',0Ah,0         ; DATA XREF: _main+28↑o
                align 4
aFindCorrectPas db 'Find correct Coordinates',0Ah,0 ; DATA XREF: _main+34↑o
                align 10h
aIncorrectLlu   db 'Incorrect!(%llu)',0Ah,0 ; DATA XREF: _main+82↑o
                align 4
aCorrectPleaseS db 'Correct!',0Ah       ; DATA XREF: _main:loc_791C80↑o
                db 'Please send DM with PW.',0Ah,0
                align 4
aInvalidStringP db 'invalid string position',0
                                        ; DATA XREF: sub_792813+3↑o
aVectorTooLong  db 'vector too long',0  ; DATA XREF: sub_7937AD+3↑o
                dd offset ??_R4bad_cast@std@@6B@ ; const std::bad_cast::`RTTI Complete Object Locator'
; const std::bad_cast::`vftable'
??_7bad_cast@std@@6B@ dd offset sub_791497 ; DATA XREF: sub_791674+19↑o
                                        ; sub_7916B6+15↑o
                dd offset sub_791421
                align 10h
qword_7973E0    dq 3FF0000000000000h    ; DATA XREF: sub_794E45+7C↑r
                                        ; sub_794E45+B4↑r ...
qword_7973E8    dq 412A5E0000000000h    ; DATA XREF: sub_793C80+15↑r
qword_7973F0    dq 41CDCD6500000000h    ; DATA XREF: sub_794E45+48↑r
                                        ; sub_794E45+AC↑r
                align 10h
dword_797400    dd 0FFFFFFFFh           ; DATA XREF: .text:loc_79615A↑r
                                        ; .text:loc_7961CB↑r ...
dword_797404    dd 3FC00000h            ; DATA XREF: .text:0079628D↑r
                                        ; .text:00796323↑r ...
qword_797408    dq 0                    ; DATA XREF: .text:00796434↑r
                                        ; .text:0079644B↑r ...
qword_797410    dq 41F0000000000000h    ; DATA XREF: .text:00796454↑r
                                        ; __ltod3+2B↑r
; Debug Directory entries
                dd 0                    ; Characteristics
                dd 601D544Dh            ; TimeDateStamp: Fri Feb 05 14:21:01 2021
                dw 0                    ; MajorVersion
                dw 0                    ; MinorVersion
                dd 2                    ; Type: IMAGE_DEBUG_TYPE_CODEVIEW
                dd 4Dh                  ; SizeOfData
                dd rva asc_797734       ; AddressOfRawData
                dd 6334h                ; PointerToRawData
                dd 0                    ; Characteristics
                dd 601D544Dh            ; TimeDateStamp: Fri Feb 05 14:21:01 2021
                dw 0                    ; MajorVersion
                dw 0                    ; MinorVersion
                dd 0Ch                  ; Type: IMAGE_DEBUG_TYPE_VC_FEATURE
                dd 14h                  ; SizeOfData
                dd rva unk_797784       ; AddressOfRawData
                dd 6384h                ; PointerToRawData
                dd 0                    ; Characteristics
                dd 601D544Dh            ; TimeDateStamp: Fri Feb 05 14:21:01 2021
                dw 0                    ; MajorVersion
                dw 0                    ; MinorVersion
                dd 0Dh                  ; Type: IMAGE_DEBUG_TYPE_POGO
                dd 2D8h                 ; SizeOfData
                dd rva aGctl            ; AddressOfRawData
                dd 6398h                ; PointerToRawData
                dd 0                    ; Characteristics
                dd 601D544Dh            ; TimeDateStamp: Fri Feb 05 14:21:01 2021
                dw 0                    ; MajorVersion
                dw 0                    ; MinorVersion
                dd 0Eh                  ; Type: IMAGE_DEBUG_TYPE_ILTCG
                dd 0                    ; SizeOfData
                dd 0                    ; AddressOfRawData
                dd 0                    ; PointerToRawData
__load_config_used dd 0BCh              ; Size
                dd 0                    ; Time stamp
                dw 2 dup(0)             ; Version: 0.0
                dd 0                    ; GlobalFlagsClear
                dd 0                    ; GlobalFlagsSet
                dd 0                    ; CriticalSectionDefaultTimeout
                dd 0                    ; DeCommitFreeBlockThreshold
                dd 0                    ; DeCommitTotalFreeThreshold
                dd 0                    ; LockPrefixTable
                dd 0                    ; MaximumAllocationSize
                dd 0                    ; VirtualMemoryThreshold
                dd 0                    ; ProcessAffinityMask
                dd 0                    ; ProcessHeapFlags
                dw 0                    ; CSDVersion
                dw 0                    ; Reserved1
                dd 0                    ; EditList
                dd offset ___security_cookie ; SecurityCookie
                dd offset ___safe_se_handler_table ; SEHandlerTable
                dd 0Fh                  ; SEHandlerCount
                dd offset ___guard_check_icall_fptr ; GuardCFCheckFunctionPointer
                dd 0                    ; GuardCFDispatchFunctionPointer
                dd 0                    ; GuardCFFunctionTable
                dd 0                    ; GuardCFFunctionCount
                dd 100h                 ; GuardFlags
                dw 0                    ; CodeIntegrity.Flags
                dw 0                    ; CodeIntegrity.Catalog
                dd 0                    ; CodeIntegrity.CatalogOffset
                dd 0                    ; CodeIntegrity.Reserved
                dd 0                    ; GuardAddressTakenIatEntryTable
                dd 0                    ; GuardAddressTakenIatEntryCount
                dd 0                    ; GuardLongJumpTargetTable
                dd 0                    ; GuardLongJumpTargetCount
                dd 0                    ; DynamicValueRelocTable
                dd 0                    ; CHPEMetadataPointer
                dd 0                    ; GuardRFFailureRoutine
                dd 0                    ; GuardRFFailureRoutineFunctionPointer
                dd 0                    ; DynamicValueRelocTableOffset
                dw 0                    ; DynamicValueRelocTableSection
                dw 0                    ; Reserved2
                dd 0                    ; GuardRFVerifyStackPointerFunctionPointer
                dd 0                    ; HotPatchTableOffset
                dd 0                    ; Reserved3
                dd 0                    ; EnclaveConfigurationPointer
                dd 0                    ; VolatileMetadataPointer
                dd 0                    ; GuardEHContinuationTable
                dd 0                    ; GuardEHContinuationCount
                dd 0                    ; GuardXFGCheckFunctionPointer
                dd 0                    ; GuardXFGDispatchFunctionPointer
                dd 0                    ; GuardXFGTableDispatchFunctionPointer
                dd offset ___castguard_check_failure_os_handled_fptr ; CastGuardOsDeterminedFailureMode
                align 40h
; const type_info::`RTTI Complete Object Locator'
??_R4type_info@@6B@ dd 0                ; DATA XREF: .rdata:007971B0↑o
                                        ; signature
                dd 0                    ; offset of this vtable in complete class (from top)
                dd 0                    ; offset of constructor displacement
                dd offset ??_R0?AVtype_info@@@8 ; reference to type description
                dd offset ??_R3type_info@@8 ; reference to hierarchy description
; type_info::`RTTI Class Hierarchy Descriptor'
??_R3type_info@@8 dd 0                  ; DATA XREF: .rdata:00797590↑o
                                        ; .rdata:007975C4↓o
                                        ; signature
                dd 0                    ; attributes
                dd 1                    ; # of items in the array of base classes
                dd offset ??_R2type_info@@8 ; reference to the array of base classes
; type_info::`RTTI Base Class Array'
??_R2type_info@@8 dd offset ??_R1A@?0A@EA@type_info@@8
                                        ; DATA XREF: .rdata:007975A0↑o
                                        ; reference to base class decription 1
                db    0
                db    0
                db    0
                db    0
; type_info::`RTTI Base Class Descriptor at (0, -1, 0, 64)'
??_R1A@?0A@EA@type_info@@8 dd offset ??_R0?AVtype_info@@@8
                                        ; DATA XREF: .rdata:type_info::`RTTI Base Class Array'↑o
                                        ; reference to type description
                dd 0                    ; # of sub elements within base class array
                dd 0                    ; member displacement
                dd 4294967295           ; vftable displacement
                dd 0                    ; displacement within vftable
                dd 40h                  ; base class attributes
                dd offset ??_R3type_info@@8 ; reference to class hierarchy descriptor
; const std::exception::`RTTI Complete Object Locator'
??_R4exception@std@@6B@ dd 0            ; DATA XREF: .rdata:007971B8↑o
                                        ; signature
                dd 0                    ; offset of this vtable in complete class (from top)
                dd 0                    ; offset of constructor displacement
                dd offset ??_R0?AVexception@std@@@8 ; reference to type description
                dd offset ??_R3exception@std@@8 ; reference to hierarchy description
; std::bad_array_new_length::`RTTI Base Class Array'
??_R2bad_array_new_length@std@@8 dd offset ??_R1A@?0A@EA@bad_array_new_length@std@@8
                                        ; DATA XREF: .rdata:007976B4↓o
                                        ; reference to base class decription 1
                dd offset ??_R1A@?0A@EA@bad_alloc@std@@8 ; reference to base class decription 2
                dd offset ??_R1A@?0A@EA@exception@std@@8 ; reference to base class decription 3
                db    0
                db    0
                db    0
                db    0
; std::bad_cast::`RTTI Base Class Descriptor at (0, -1, 0, 64)'
??_R1A@?0A@EA@bad_cast@std@@8 dd offset ??_R0?AVbad_cast@std@@@8
                                        ; DATA XREF: .rdata:std::bad_cast::`RTTI Base Class Array'↓o
                                        ; reference to type description
                dd 1                    ; # of sub elements within base class array
                dd 0                    ; member displacement
                dd 4294967295           ; vftable displacement
                dd 0                    ; displacement within vftable
                dd 40h                  ; base class attributes
                dd offset ??_R3bad_cast@std@@8 ; reference to class hierarchy descriptor
; std::bad_alloc::`RTTI Base Class Array'
??_R2bad_alloc@std@@8 dd offset ??_R1A@?0A@EA@bad_alloc@std@@8
                                        ; DATA XREF: .rdata:007976C4↓o
                                        ; reference to base class decription 1
                dd offset ??_R1A@?0A@EA@exception@std@@8 ; reference to base class decription 2
                db    0
                db    0
                db    0
                db    0
; std::exception::`RTTI Base Class Descriptor at (0, -1, 0, 64)'
??_R1A@?0A@EA@exception@std@@8 dd offset ??_R0?AVexception@std@@@8
                                        ; DATA XREF: .rdata:007975E4↑o
                                        ; .rdata:0079760C↑o ...
                                        ; reference to type description
                dd 0                    ; # of sub elements within base class array
                dd 0                    ; member displacement
                dd 4294967295           ; vftable displacement
                dd 0                    ; displacement within vftable
                dd 40h                  ; base class attributes
                dd offset ??_R3exception@std@@8 ; reference to class hierarchy descriptor
; std::bad_alloc::`RTTI Base Class Descriptor at (0, -1, 0, 64)'
??_R1A@?0A@EA@bad_alloc@std@@8 dd offset ??_R0?AVbad_alloc@std@@@8
                                        ; DATA XREF: .rdata:007975E0↑o
                                        ; .rdata:std::bad_alloc::`RTTI Base Class Array'↑o
                                        ; reference to type description
                dd 1                    ; # of sub elements within base class array
                dd 0                    ; member displacement
                dd 4294967295           ; vftable displacement
                dd 0                    ; displacement within vftable
                dd 40h                  ; base class attributes
                dd offset ??_R3bad_alloc@std@@8 ; reference to class hierarchy descriptor
; std::bad_cast::`RTTI Base Class Array'
??_R2bad_cast@std@@8 dd offset ??_R1A@?0A@EA@bad_cast@std@@8
                                        ; DATA XREF: .rdata:0079767C↓o
                                        ; reference to base class decription 1
                dd offset ??_R1A@?0A@EA@exception@std@@8 ; reference to base class decription 2
                align 8
; std::exception::`RTTI Base Class Array'
??_R2exception@std@@8 dd offset ??_R1A@?0A@EA@exception@std@@8
                                        ; DATA XREF: .rdata:0079766C↓o
                                        ; reference to base class decription 1
                align 10h
; std::exception::`RTTI Class Hierarchy Descriptor'
??_R3exception@std@@8 dd 0              ; DATA XREF: .rdata:007975D8↑o
                                        ; .rdata:0079762C↑o
                                        ; signature
                dd 0                    ; attributes
                dd 1                    ; # of items in the array of base classes
                dd offset ??_R2exception@std@@8 ; reference to the array of base classes
; std::bad_cast::`RTTI Class Hierarchy Descriptor'
??_R3bad_cast@std@@8 dd 0               ; DATA XREF: .rdata:00797604↑o
                                        ; .rdata:007976A4↓o
                                        ; signature
                dd 0                    ; attributes
                dd 2                    ; # of items in the array of base classes
                dd offset ??_R2bad_cast@std@@8 ; reference to the array of base classes
; const std::bad_alloc::`RTTI Complete Object Locator'
??_R4bad_alloc@std@@6B@ dd 0            ; DATA XREF: .rdata:007971C4↑o
                                        ; signature
                dd 0                    ; offset of this vtable in complete class (from top)
                dd 0                    ; offset of constructor displacement
                dd offset ??_R0?AVbad_alloc@std@@@8 ; reference to type description
                dd offset ??_R3bad_alloc@std@@8 ; reference to hierarchy description
; const std::bad_cast::`RTTI Complete Object Locator'
??_R4bad_cast@std@@6B@ dd 0             ; DATA XREF: .rdata:007973D0↑o
                                        ; signature
                dd 0                    ; offset of this vtable in complete class (from top)
                dd 0                    ; offset of constructor displacement
                dd offset ??_R0?AVbad_cast@std@@@8 ; reference to type description
                dd offset ??_R3bad_cast@std@@8 ; reference to hierarchy description
; std::bad_array_new_length::`RTTI Class Hierarchy Descriptor'
??_R3bad_array_new_length@std@@8 dd 0   ; DATA XREF: .rdata:007976D8↓o
                                        ; .rdata:007976F4↓o
                                        ; signature
                dd 0                    ; attributes
                dd 3                    ; # of items in the array of base classes
                dd offset ??_R2bad_array_new_length@std@@8 ; reference to the array of base classes
; std::bad_alloc::`RTTI Class Hierarchy Descriptor'
??_R3bad_alloc@std@@8 dd 0              ; DATA XREF: .rdata:00797648↑o
                                        ; .rdata:00797690↑o
                                        ; signature
                dd 0                    ; attributes
                dd 2                    ; # of items in the array of base classes
                dd offset ??_R2bad_alloc@std@@8 ; reference to the array of base classes
; const std::bad_array_new_length::`RTTI Complete Object Locator'
??_R4bad_array_new_length@std@@6B@ dd 0 ; DATA XREF: .rdata:007971E0↑o
                                        ; signature
                dd 0                    ; offset of this vtable in complete class (from top)
                dd 0                    ; offset of constructor displacement
                dd offset ??_R0?AVbad_array_new_length@std@@@8 ; reference to type description
                dd offset ??_R3bad_array_new_length@std@@8 ; reference to hierarchy description
; std::bad_array_new_length::`RTTI Base Class Descriptor at (0, -1, 0, 64)'
??_R1A@?0A@EA@bad_array_new_length@std@@8 dd offset ??_R0?AVbad_array_new_length@std@@@8
                                        ; DATA XREF: .rdata:std::bad_array_new_length::`RTTI Base Class Array'↑o
                                        ; reference to type description
                dd 2                    ; # of sub elements within base class array
                dd 0                    ; member displacement
                dd 4294967295           ; vftable displacement
                dd 0                    ; displacement within vftable
                dd 40h                  ; base class attributes
                dd offset ??_R3bad_array_new_length@std@@8 ; reference to class hierarchy descriptor
___safe_se_handler_table dd rva __except_handler4
                                        ; DATA XREF: .rdata:007974C8↑o
                dd rva loc_7964CA
                dd rva SEH_403751
                dd rva SEH_401000
                dd rva SEH_4019EF
                dd rva SEH_401A6B
                dd rva _main_SEH
                dd rva SEH_401E6C
                dd rva SEH_4020BA
                dd rva SEH_402823
                dd rva SEH_402F66
                dd rva SEH_403363
                dd rva SEH_40349C
                dd rva SEH_4035AC
                dd rva SEH_4036F6
; Debug information (IMAGE_DEBUG_TYPE_CODEVIEW)
asc_797734      db 'RSDS'               ; DATA XREF: .rdata:0079742C↑o
                                        ; CV signature
                dd 33BE94DFh            ; Data1 ; GUID
                dw 7BB3h                ; Data2
                dw 46D7h                ; Data3
                db 0AAh, 20h, 0D1h, 15h, 0F8h, 0FCh, 50h, 0B0h; Data4
                dd 1                    ; Age
                text "UTF-8", 'C:\user\ShinzoAbe\Documents\Secret\fap\hentai\futa.pd' ; PdbFileName
aB              db 'b',0
                align 4
; Debug information (IMAGE_DEBUG_TYPE_VC_FEATURE)
unk_797784      db    0                 ; DATA XREF: .rdata:00797448↑o
                db    0
                db    0
                db    0
                db  29h ; )
                db    0
                db    0
                db    0
                db  26h ; &
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db  26h ; &
                db    0
                db    0
                db    0
; Debug information (IMAGE_DEBUG_TYPE_POGO)
aGctl           db 'GCTL',0             ; DATA XREF: .rdata:00797464↑o
                db  10h
                db    0
                db    0
                db  20h
                db    3
                db    0
                db    0
                db  2Eh ; .
                db  74h ; t
                db  65h ; e
                db  78h ; x
                db  74h ; t
                db  24h ; $
                db  64h ; d
                db  69h ; i
                db    0
                db    0
                db    0
                db    0
                db  20h
                db  13h
                db    0
                db    0
                db  9Dh
                db  51h ; Q
                db    0
                db    0
                db  2Eh ; .
                db  74h ; t
                db  65h ; e
                db  78h ; x
                db  74h ; t
                db  24h ; $
                db  6Dh ; m
                db  6Eh ; n
                db    0
                db    0
                db    0
                db    0
                db 0BDh
                db  64h ; d
                db    0
                db    0
                db  55h ; U
                db    1
                db    0
                db    0
                db  2Eh ; .
                db  74h ; t
                db  65h ; e
                db  78h ; x
                db  74h ; t
                db  24h ; $
                db  78h ; x
                db    0
                db  12h
                db  66h ; f
                db    0
                db    0
                db  91h
                db    0
                db    0
                db    0
                db  2Eh ; .
                db  74h ; t
                db  65h ; e
                db  78h ; x
                db  74h ; t
                db  24h ; $
                db  79h ; y
                db  64h ; d
                db    0
                db    0
                db    0
                db    0
                db    0
                db  70h ; p
                db    0
                db    0
                db  50h ; P
                db    1
                db    0
                db    0
                db  2Eh ; .
                db  69h ; i
                db  64h ; d
                db  61h ; a
                db  74h ; t
                db  61h ; a
                db  24h ; $
                db  35h ; 5
                db    0
                db    0
                db    0
                db    0
                db  50h ; P
                db  71h ; q
                db    0
                db    0
                db    4
                db    0
                db    0
                db    0
                db  2Eh ; .
                db  30h ; 0
                db  30h ; 0
                db  63h ; c
                db  66h ; f
                db  67h ; g
                db    0
                db    0
                db  54h ; T
                db  71h ; q
                db    0
                db    0
                db    4
                db    0
                db    0
                db    0
                db  2Eh ; .
                db  43h ; C
                db  52h ; R
                db  54h ; T
                db  24h ; $
                db  58h ; X
                db  43h ; C
                db  41h ; A
                db    0
                db    0
                db    0
                db    0
                db  58h ; X
                db  71h ; q
                db    0
                db    0
                db    4
                db    0
                db    0
                db    0
                db  2Eh ; .
                db  43h ; C
                db  52h ; R
                db  54h ; T
                db  24h ; $
                db  58h ; X
                db  43h ; C
                db  41h ; A
                db  41h ; A
                db    0
                db    0
                db    0
                db  5Ch ; \
                db  71h ; q
                db    0
                db    0
                db    4
                db    0
                db    0
                db    0
                db  2Eh ; .
                db  43h ; C
                db  52h ; R
                db  54h ; T
                db  24h ; $
                db  58h ; X
                db  43h ; C
                db  4Ch ; L
                db    0
                db    0
                db    0
                db    0
                db  60h ; `
                db  71h ; q
                db    0
                db    0
                db  24h ; $
                db    0
                db    0
                db    0
                db  2Eh ; .
                db  43h ; C
                db  52h ; R
                db  54h ; T
                db  24h ; $
                db  58h ; X
                db  43h ; C
                db  55h ; U
                db    0
                db    0
                db    0
                db    0
                db  84h
                db  71h ; q
                db    0
                db    0
                db    4
                db    0
                db    0
                db    0
                db  2Eh ; .
                db  43h ; C
                db  52h ; R
                db  54h ; T
                db  24h ; $
                db  58h ; X
                db  43h ; C
                db  5Ah ; Z
                db    0
                db    0
                db    0
                db    0
                db  88h
                db  71h ; q
                db    0
                db    0
                db    4
                db    0
                db    0
                db    0
                db  2Eh ; .
                db  43h ; C
                db  52h ; R
                db  54h ; T
                db  24h ; $
                db  58h ; X
                db  49h ; I
                db  41h ; A
                db    0
                db    0
                db    0
                db    0
                db  8Ch
                db  71h ; q
                db    0
                db    0
                db    4
                db    0
                db    0
                db    0
                db  2Eh ; .
                db  43h ; C
                db  52h ; R
                db  54h ; T
                db  24h ; $
                db  58h ; X
                db  49h ; I
                db  41h ; A
                db  41h ; A
                db    0
                db    0
                db    0
                db  90h
                db  71h ; q
                db    0
                db    0
                db    4
                db    0
                db    0
                db    0
                db  2Eh ; .
                db  43h ; C
                db  52h ; R
                db  54h ; T
                db  24h ; $
                db  58h ; X
                db  49h ; I
                db  41h ; A
                db  43h ; C
                db    0
                db    0
                db    0
                db  94h
                db  71h ; q
                db    0
                db    0
                db    4
                db    0
                db    0
                db    0
                db  2Eh ; .
                db  43h ; C
                db  52h ; R
                db  54h ; T
                db  24h ; $
                db  58h ; X
                db  49h ; I
                db  5Ah ; Z
                db    0
                db    0
                db    0
                db    0
                db  98h
                db  71h ; q
                db    0
                db    0
                db    4
                db    0
                db    0
                db    0
                db  2Eh ; .
                db  43h ; C
                db  52h ; R
                db  54h ; T
                db  24h ; $
                db  58h ; X
                db  50h ; P
                db  41h ; A
                db    0
                db    0
                db    0
                db    0
                db  9Ch
                db  71h ; q
                db    0
                db    0
                db    4
                db    0
                db    0
                db    0
                db  2Eh ; .
                db  43h ; C
                db  52h ; R
                db  54h ; T
                db  24h ; $
                db  58h ; X
                db  50h ; P
                db  5Ah ; Z
                db    0
                db    0
                db    0
                db    0
                db 0A0h
                db  71h ; q
                db    0
                db    0
                db    4
                db    0
                db    0
                db    0
                db  2Eh ; .
                db  43h ; C
                db  52h ; R
                db  54h ; T
                db  24h ; $
                db  58h ; X
                db  54h ; T
                db  41h ; A
                db    0
                db    0
                db    0
                db    0
                db 0A4h
                db  71h ; q
                db    0
                db    0
                db  0Ch
                db    0
                db    0
                db    0
                db  2Eh ; .
                db  43h ; C
                db  52h ; R
                db  54h ; T
                db  24h ; $
                db  58h ; X
                db  54h ; T
                db  5Ah ; Z
                db    0
                db    0
                db    0
                db    0
                db 0B0h
                db  71h ; q
                db    0
                db    0
                db 0D0h
                db    3
                db    0
                db    0
                db  2Eh ; .
                db  72h ; r
                db  64h ; d
                db  61h ; a
                db  74h ; t
                db  61h ; a
                db    0
                db    0
                db  80h
                db  75h ; u
                db    0
                db    0
                db  78h ; x
                db    1
                db    0
                db    0
                db  2Eh ; .
                db  72h ; r
                db  64h ; d
                db  61h ; a
                db  74h ; t
                db  61h ; a
                db  24h ; $
                db  72h ; r
                db    0
                db    0
                db    0
                db    0
                db 0F8h
                db  76h ; v
                db    0
                db    0
                db  3Ch ; <
                db    0
                db    0
                db    0
                db  2Eh ; .
                db  72h ; r
                db  64h ; d
                db  61h ; a
                db  74h ; t
                db  61h ; a
                db  24h ; $
                db  73h ; s
                db  78h ; x
                db  64h ; d
                db  61h ; a
                db  74h ; t
                db  61h ; a
                db    0
                db    0
                db    0
                db  34h ; 4
                db  77h ; w
                db    0
                db    0
                db  3Ch ; <
                db    3
                db    0
                db    0
                db  2Eh ; .
                db  72h ; r
                db  64h ; d
                db  61h ; a
                db  74h ; t
                db  61h ; a
                db  24h ; $
                db  7Ah ; z
                db  7Ah ; z
                db  7Ah ; z
                db  64h ; d
                db  62h ; b
                db  67h ; g
                db    0
                db    0
                db    0
                db  70h ; p
                db  7Ah ; z
                db    0
                db    0
                db    4
                db    0
                db    0
                db    0
                db  2Eh ; .
                db  72h ; r
                db  74h ; t
                db  63h ; c
                db  24h ; $
                db  49h ; I
                db  41h ; A
                db  41h ; A
                db    0
                db    0
                db    0
                db    0
                db  74h ; t
                db  7Ah ; z
                db    0
                db    0
                db    4
                db    0
                db    0
                db    0
                db  2Eh ; .
                db  72h ; r
                db  74h ; t
                db  63h ; c
                db  24h ; $
                db  49h ; I
                db  5Ah ; Z
                db  5Ah ; Z
                db    0
                db    0
                db    0
                db    0
                db  78h ; x
                db  7Ah ; z
                db    0
                db    0
                db    4
                db    0
                db    0
                db    0
                db  2Eh ; .
                db  72h ; r
                db  74h ; t
                db  63h ; c
                db  24h ; $
                db  54h ; T
                db  41h ; A
                db  41h ; A
                db    0
                db    0
                db    0
                db    0
                db  7Ch ; |
                db  7Ah ; z
                db    0
                db    0
                db    4
                db    0
                db    0
                db    0
                db  2Eh ; .
                db  72h ; r
                db  74h ; t
                db  63h ; c
                db  24h ; $
                db  54h ; T
                db  5Ah ; Z
                db  5Ah ; Z
                db    0
                db    0
                db    0
                db    0
                db  80h
                db  7Ah ; z
                db    0
                db    0
                db 0D4h
                db    3
                db    0
                db    0
                db  2Eh ; .
                db  78h ; x
                db  64h ; d
                db  61h ; a
                db  74h ; t
                db  61h ; a
                db  24h ; $
                db  78h ; x
                db    0
                db    0
                db    0
                db    0
                db  54h ; T
                db  7Eh ; ~
                db    0
                db    0
                db 0A0h
                db    0
                db    0
                db    0
                db  2Eh ; .
                db  69h ; i
                db  64h ; d
                db  61h ; a
                db  74h ; t
                db  61h ; a
                db  24h ; $
                db  32h ; 2
                db    0
                db    0
                db    0
                db    0
                db 0F4h
                db  7Eh ; ~
                db    0
                db    0
                db  14h
                db    0
                db    0
                db    0
                db  2Eh ; .
                db  69h ; i
                db  64h ; d
                db  61h ; a
                db  74h ; t
                db  61h ; a
                db  24h ; $
                db  33h ; 3
                db    0
                db    0
                db    0
                db    0
                db    8
                db  7Fh ; 
                db    0
                db    0
                db  50h ; P
                db    1
                db    0
                db    0
                db  2Eh ; .
                db  69h ; i
                db  64h ; d
                db  61h ; a
                db  74h ; t
                db  61h ; a
                db  24h ; $
                db  34h ; 4
                db    0
                db    0
                db    0
                db    0
                db  58h ; X
                db  80h
                db    0
                db    0
                db 0B2h
                db    8
                db    0
                db    0
                db  2Eh ; .
                db  69h ; i
                db  64h ; d
                db  61h ; a
                db  74h ; t
                db  61h ; a
                db  24h ; $
                db  36h ; 6
                db    0
                db    0
                db    0
                db    0
                db    0
                db  90h
                db    0
                db    0
                db  24h ; $
                db    0
                db    0
                db    0
                db  2Eh ; .
                db  64h ; d
                db  61h ; a
                db  74h ; t
                db  61h ; a
                db    0
                db    0
                db    0
                db  24h ; $
                db  90h
                db    0
                db    0
                db  94h
                db    0
                db    0
                db    0
                db  2Eh ; .
                db  64h ; d
                db  61h ; a
                db  74h ; t
                db  61h ; a
                db  24h ; $
                db  72h ; r
                db    0
                db 0B8h
                db  90h
                db    0
                db    0
                db 0FCh
                db    3
                db    0
                db    0
                db  2Eh ; .
                db  62h ; b
                db  73h ; s
                db  73h ; s
                db    0
                db    0
                db    0
                db    0
                db    0
                db 0A0h
                db    0
                db    0
                db  60h ; `
                db    0
                db    0
                db    0
                db  2Eh ; .
                db  72h ; r
                db  73h ; s
                db  72h ; r
                db  63h ; c
                db  24h ; $
                db  30h ; 0
                db  31h ; 1
                db    0
                db    0
                db    0
                db    0
                db  60h ; `
                db 0A0h
                db    0
                db    0
                db  80h
                db    1
                db    0
                db    0
                db  2Eh ; .
                db  72h ; r
                db  73h ; s
                db  72h ; r
                db  63h ; c
                db  24h ; $
                db  30h ; 0
                db  32h ; 2
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
unk_797A74      db    0                 ; DATA XREF: sub_795B35+2↑o
                                        ; sub_795B35+7↑o
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
unk_797A7C      db    0                 ; DATA XREF: sub_795B61+2↑o
                                        ; sub_795B61+7↑o
                db    0
                db    0
                db    0
stru_797A80     FuncInfo <19930522h, 1, offset stru_797AA4, 0, 0, 0, 0, 0, 1>
                                        ; DATA XREF: sub_7918BC+4C10↑o
stru_797AA4     UnwindMapEntry <-1, offset loc_7964BD>
                                        ; DATA XREF: .rdata:stru_797A80↑o
stru_797AAC     FuncInfo <19930522h, 0, 0, 0, 0, 0, 0, 0, 5>
                                        ; DATA XREF: BProcessor+4B37↑o
stru_797AD0     FuncInfo <19930522h, 1, offset stru_797AF4, 0, 0, 0, 0, 0, 1>
                                        ; DATA XREF: sub_791000+54F1↑o
stru_797AF4     UnwindMapEntry <-1, offset loc_7964E2>
                                        ; DATA XREF: .rdata:stru_797AD0↑o
stru_797AFC     FuncInfo <19930522h, 1, offset stru_797B20, 0, 0, 0, 0, 0, 1>
                                        ; DATA XREF: sub_7919EF+4B1B↑o
stru_797B20     UnwindMapEntry <-1, offset loc_7964FB>
                                        ; DATA XREF: .rdata:stru_797AFC↑o
stru_797B28     FuncInfo <19930522h, 1, offset stru_797B4C, 0, 0, 0, 0, 0, 1>
                                        ; DATA XREF: Process_Input3+4AB8↑o
stru_797B4C     UnwindMapEntry <-1, offset loc_796514>
                                        ; DATA XREF: .rdata:stru_797B28↑o
stru_797B54     FuncInfo <19930522h, 1, offset stru_797B78, 0, 0, 0, 0, 0, 1>
                                        ; DATA XREF: _main+4973↑o
stru_797B78     UnwindMapEntry <-1, offset loc_79652D>
                                        ; DATA XREF: .rdata:stru_797B54↑o
stru_797B80     FuncInfo <19930522h, 1, offset stru_797BA4, 0, 0, 0, 0, 0, 1>
                                        ; DATA XREF: sub_791E6C+46E9↑o
stru_797BA4     UnwindMapEntry <-1, offset loc_796546>
                                        ; DATA XREF: .rdata:stru_797B80↑o
stru_797BAC     FuncInfo <19930522h, 1, offset stru_797BD0, 0, 0, 0, 0, 0, 1>
                                        ; DATA XREF: sub_7920BA+44B4↑o
stru_797BD0     UnwindMapEntry <-1, offset loc_79655F>
                                        ; DATA XREF: .rdata:stru_797BAC↑o
stru_797BD8     FuncInfo <19930522h, 2, offset stru_797BFC, 0, 0, 0, 0, 0, 1>
                                        ; DATA XREF: sub_792823+3D6D↑o
stru_797BFC     UnwindMapEntry <-1, offset loc_796578>
                                        ; DATA XREF: .rdata:stru_797BD8↑o
                UnwindMapEntry <0, offset loc_796581>
stru_797C0C     FuncInfo <19930522h, 4, offset stru_797C30, 1, offset stru_797C50, 0, \
                                        ; DATA XREF: sub_792F66+364B↑o
                          0, 0, 1>
stru_797C30     UnwindMapEntry <-1, offset loc_79659A>
                                        ; DATA XREF: .rdata:stru_797C0C↑o
                UnwindMapEntry <0, offset loc_7965A2>
                UnwindMapEntry <0>
                UnwindMapEntry <0>
stru_797C50     TryBlockMapEntry <2, 2, 3, 1, offset stru_797C64>
                                        ; DATA XREF: .rdata:stru_797C0C↑o
stru_797C64     HandlerType <40h, 0, 0, offset loc_793144>
                                        ; DATA XREF: .rdata:stru_797C50↑o
stru_797C74     FuncInfo <19930522h, 2, offset stru_797C98, 1, offset stru_797CA8, 0, \
                                        ; DATA XREF: sub_793363+325A↑o
                          0, 0, 1>
stru_797C98     UnwindMapEntry <-1, 0>  ; DATA XREF: .rdata:stru_797C74↑o
                UnwindMapEntry <-1, 0>
stru_797CA8     TryBlockMapEntry <0, 0, 1, 1, offset stru_797CBC>
                                        ; DATA XREF: .rdata:stru_797C74↑o
stru_797CBC     HandlerType <40h, 0, 0, offset loc_793435>
                                        ; DATA XREF: .rdata:stru_797CA8↑o
stru_797CCC     FuncInfo <19930522h, 1, offset stru_797CF0, 0, 0, 0, 0, 0, 1>
                                        ; DATA XREF: sub_79349C+313A↑o
stru_797CF0     UnwindMapEntry <-1, offset loc_7965C7>
                                        ; DATA XREF: .rdata:stru_797CCC↑o
stru_797CF8     FuncInfo <19930522h, 1, offset stru_797D1C, 0, 0, 0, 0, 0, 1>
                                        ; DATA XREF: sub_7935AC+3043↑o
stru_797D1C     UnwindMapEntry <-1, offset loc_7965E0>
                                        ; DATA XREF: .rdata:stru_797CF8↑o
stru_797D24     FuncInfo <19930522h, 1, offset stru_797D48, 0, 0, 0, 0, 0, 1>
                                        ; DATA XREF: sub_7936F6+2F12↑o
stru_797D48     UnwindMapEntry <-1, offset loc_7965F9>
                                        ; DATA XREF: .rdata:stru_797D24↑o
stru_797D50     dd 0FFFFFFFEh           ; GSCookieOffset
                                        ; DATA XREF: ___scrt_is_nonwritable_in_current_image+2↑o
                dd 0                    ; GSCookieXOROffset
                dd 0FFFFFFD8h           ; EHCookieOffset
                dd 0                    ; EHCookieXOROffset
                dd 0FFFFFFFEh           ; ScopeRecord.EnclosingLevel
                dd offset loc_79525C    ; ScopeRecord.FilterFunc
                dd offset loc_79526F    ; ScopeRecord.HandlerFunc
                align 10h
stru_797D70     dd 0FFFFFFFEh           ; GSCookieOffset
                                        ; DATA XREF: __scrt_common_main_seh(void)+2↑o
                dd 0                    ; GSCookieXOROffset
                dd 0FFFFFFCCh           ; EHCookieOffset
                dd 0                    ; EHCookieXOROffset
                dd 0FFFFFFFEh           ; ScopeRecord.EnclosingLevel
                dd offset loc_79552F    ; ScopeRecord.FilterFunc
                dd offset loc_795543    ; ScopeRecord.HandlerFunc
; const _ThrowInfo _TI2_AVbad_alloc_std__
__TI2?AVbad_alloc@std@@ dd 0            ; DATA XREF: sub_7955AF+E↑o
                                        ; attributes
                dd offset sub_7914C1    ; destructor of exception object
                dd 0                    ; forward compatibility frame handler
                dd offset __CTA2?AVbad_alloc@std@@ ; address of catchable types array
__CTA2?AVbad_alloc@std@@ dd 2           ; DATA XREF: .rdata:00797D98↑o
                                        ; count of catchable type addresses following
                dd offset __CT??_R0?AVbad_alloc@std@@@8_40156F ; catchable type 'class std::bad_alloc'
                dd offset __CT??_R0?AVexception@std@@@8_4013C7 ; catchable type 'class std::exception'
__CTA3?AVbad_array_new_length@std@@ dd 3 ; DATA XREF: .rdata:00797E34↓o
                                        ; count of catchable type addresses following
                dd offset __CT??_R0?AVbad_array_new_length@std@@@8_40154D ; catchable type 'class std::bad_array_new_length'
                dd offset __CT??_R0?AVbad_alloc@std@@@8_40156F ; catchable type 'class std::bad_alloc'
                dd offset __CT??_R0?AVexception@std@@@8_4013C7 ; catchable type 'class std::exception'
__CT??_R0?AVbad_alloc@std@@@8_40156F dd CT_IsStdBadAlloc
                                        ; DATA XREF: .rdata:00797DA0↑o
                                        ; .rdata:00797DB0↑o
                                        ; attributes
                dd offset ??_R0?AVbad_alloc@std@@@8 ; std::bad_alloc `RTTI Type Descriptor'
                dd 0                    ; mdisp
                dd 4294967295           ; pdisp
                dd 0                    ; vdisp
                dd 12                   ; size of thrown object
                dd offset sub_79156F    ; reference to optional copy constructor
__CTA2?AVbad_cast@std@@ dd 2            ; DATA XREF: .rdata:00797E08↓o
                                        ; count of catchable type addresses following
                dd offset __CT??_R0?AVbad_cast@std@@@8_4016B6 ; catchable type 'class std::bad_cast'
                dd offset __CT??_R0?AVexception@std@@@8_4013C7 ; catchable type 'class std::exception'
__CT??_R0?AVbad_cast@std@@@8_4016B6 dd 0 ; DATA XREF: .rdata:00797DD8↑o
                                        ; attributes
                dd offset ??_R0?AVbad_cast@std@@@8 ; std::bad_cast `RTTI Type Descriptor'
                dd 0                    ; mdisp
                dd 4294967295           ; pdisp
                dd 0                    ; vdisp
                dd 12                   ; size of thrown object
                dd offset sub_7916B6    ; reference to optional copy constructor
; const _ThrowInfo _TI2_AVbad_cast_std__
__TI2?AVbad_cast@std@@ dd 0             ; DATA XREF: sub_791698+E↑o
                                        ; attributes
                dd offset sub_7914C1    ; destructor of exception object
                dd 0                    ; forward compatibility frame handler
                dd offset __CTA2?AVbad_cast@std@@ ; address of catchable types array
__CT??_R0?AVexception@std@@@8_4013C7 dd 0 ; DATA XREF: .rdata:00797DA4↑o
                                        ; .rdata:00797DB4↑o ...
                                        ; attributes
                dd offset ??_R0?AVexception@std@@@8 ; std::exception `RTTI Type Descriptor'
                dd 0                    ; mdisp
                dd 4294967295           ; pdisp
                dd 0                    ; vdisp
                dd 12                   ; size of thrown object
                dd offset sub_7913C7    ; reference to optional copy constructor
; const _ThrowInfo _TI3_AVbad_array_new_length_std__
__TI3?AVbad_array_new_length@std@@ dd 0 ; DATA XREF: sub_79152F+E↑o
                                        ; sub_7955CC+E↑o
                                        ; attributes
                dd offset sub_79151E    ; destructor of exception object
                dd 0                    ; forward compatibility frame handler
                dd offset __CTA3?AVbad_array_new_length@std@@ ; address of catchable types array
__CT??_R0?AVbad_array_new_length@std@@@8_40154D dd 0
                                        ; DATA XREF: .rdata:00797DAC↑o
                                        ; attributes
                dd offset ??_R0?AVbad_array_new_length@std@@@8 ; std::bad_array_new_length `RTTI Type Descriptor'
                dd 0                    ; mdisp
                dd 4294967295           ; pdisp
                dd 0                    ; vdisp
                dd 12                   ; size of thrown object
                dd offset sub_79154D    ; reference to optional copy constructor
__IMPORT_DESCRIPTOR_MSVCP140 dd rva off_797F3C ; Import Name Table
                dd 0                    ; Time stamp
                dd 0                    ; Forwarder Chain
                dd rva aMsvcp140Dll     ; DLL Name
                dd rva ?setstate@?$basic_ios@DU?$char_traits@D@std@@@std@@QAEXH_N@Z ; Import Address Table
__IMPORT_DESCRIPTOR_VCRUNTIME140 dd rva off_797F9C ; Import Name Table
                dd 0                    ; Time stamp
                dd 0                    ; Forwarder Chain
                dd rva aVcruntime140Dl  ; DLL Name
                dd rva __imp_memmove    ; Import Address Table
                dd rva off_798040       ; Import Name Table
                dd 0                    ; Time stamp
                dd 0                    ; Forwarder Chain
                dd rva aApiMsWinCrtStd  ; DLL Name
                dd rva __imp__set_fmode ; Import Address Table
                dd rva off_797FEC       ; Import Name Table
                dd 0                    ; Time stamp
                dd 0                    ; Forwarder Chain
                dd rva aApiMsWinCrtRun  ; DLL Name
                dd rva __imp__c_exit    ; Import Address Table
                dd rva off_797FC8       ; Import Name Table
                dd 0                    ; Time stamp
                dd 0                    ; Forwarder Chain
                dd rva aApiMsWinCrtHea  ; DLL Name
                dd rva __imp__set_new_mode ; Import Address Table
                dd rva off_797FE4       ; Import Name Table
                dd 0                    ; Time stamp
                dd 0                    ; Forwarder Chain
                dd rva aApiMsWinCrtMat  ; DLL Name
                dd rva __imp___setusermatherr ; Import Address Table
                dd rva off_797FDC       ; Import Name Table
                dd 0                    ; Time stamp
                dd 0                    ; Forwarder Chain
                dd rva aApiMsWinCrtLoc  ; DLL Name
                dd rva __imp__configthreadlocale ; Import Address Table
__IMPORT_DESCRIPTOR_KERNEL32 dd rva off_797F08 ; Import Name Table
                dd 0                    ; Time stamp
                dd 0                    ; Forwarder Chain
                dd rva aKernel32Dll     ; DLL Name
                dd rva TerminateProcess ; Import Address Table
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
;
; Import names for KERNEL32.dll
;
off_797F08      dd rva word_7988D4      ; DATA XREF: .rdata:__IMPORT_DESCRIPTOR_KERNEL32↑o
                dd rva word_7987CC
                dd rva word_7987E8
                dd rva word_7987FC
                dd rva word_7988C0
                dd rva word_7988AA
                dd rva word_798890
                dd rva word_79887A
                dd rva word_798818
                dd rva word_798864
                dd rva word_79884A
                dd rva word_798836
                dd 0
;
; Import names for MSVCP140.dll
;
off_797F3C      dd rva word_79824C      ; DATA XREF: .rdata:__IMPORT_DESCRIPTOR_MSVCP140↑o
                dd rva word_79828C
                dd rva word_7982F4
                dd rva word_798334
                dd rva word_79820C
                dd rva word_798380
                dd rva word_7983A0
                dd rva word_7983DA
                dd rva word_7983FA
                dd rva word_7981CC
                dd rva word_7981B8
                dd rva word_798058
                dd rva word_7981A2
                dd rva word_798194
                dd rva word_798174
                dd rva word_798156
                dd rva word_798132
                dd rva word_798112
                dd rva word_7980D8
                dd rva word_7980A4
                dd rva word_79808A
                dd rva word_798070
                dd rva word_79835E
                dd 0
;
; Import names for VCRUNTIME140.dll
;
off_797F9C      dd rva word_798900      ; DATA XREF: .rdata:__IMPORT_DESCRIPTOR_VCRUNTIME140↑o
                dd rva word_7984C0
                dd rva word_7984B6
                dd rva word_798498
                dd rva word_798482
                dd rva word_79846C
                dd rva word_798454
                dd rva word_798424
                dd rva word_7988F6
                dd rva word_79843A
                dd 0
;
; Import names for api-ms-win-crt-heap-l1-1-0.dll
;
off_797FC8      dd rva word_7986E4      ; DATA XREF: .rdata:00797EA4↑o
                dd rva word_798548
                dd rva word_798554
                dd rva word_798710
                dd 0
;
; Import names for api-ms-win-crt-locale-l1-1-0.dll
;
off_797FDC      dd rva word_7986CE      ; DATA XREF: .rdata:00797ECC↑o
                dd 0
;
; Import names for api-ms-win-crt-math-l1-1-0.dll
;
off_797FE4      dd rva word_79860C      ; DATA XREF: .rdata:00797EB8↑o
                dd 0
;
; Import names for api-ms-win-crt-runtime-l1-1-0.dll
;
off_797FEC      dd rva word_798696      ; DATA XREF: .rdata:00797E90↑o
                dd rva word_7986A0
                dd rva word_79867A
                dd rva word_798522
                dd rva word_798704
                dd rva word_798664
                dd rva word_798718
                dd rva word_79855E
                dd rva word_798578
                dd rva word_79865C
                dd rva word_798688
                dd rva word_79864E
                dd rva word_798642
                dd rva word_798620
                dd rva word_7985FC
                dd rva word_7985EA
                dd rva word_7985E0
                dd rva word_7985D2
                dd rva word_79859A
                dd rva word_7985B6
                dd 0
;
; Import names for api-ms-win-crt-stdio-l1-1-0.dll
;
off_798040      dd rva word_79866C      ; DATA XREF: .rdata:00797E7C↑o
                dd rva word_798518
                dd rva word_7984FE
                dd rva word_7984EC
                dd rva word_7986F4
                dd 0
word_798058     dw 591h                 ; DATA XREF: .rdata:00797F68↑o
                db '_Query_perf_frequency',0
word_798070     dw 0A5h                 ; DATA XREF: .rdata:00797F90↑o
                db '??1_Lockit@std@@QAE@XZ',0
                align 2
word_79808A     dw 6Dh                  ; DATA XREF: .rdata:00797F8C↑o
                db '??0_Lockit@std@@QAE@H@Z',0
word_7980A4     dw 1D5h                 ; DATA XREF: .rdata:00797F88↑o
                db '?_Getgloballocale@locale@std@@CAPAV_Locimp@12@XZ',0
                align 4
word_7980D8     dw 2A3h                 ; DATA XREF: .rdata:00797F84↑o
                db '?cin@std@@3V?$basic_istream@DU?$char_traits@D@std@@@1@A',0
word_798112     dw 28Fh                 ; DATA XREF: .rdata:00797F80↑o
                db '?_Xout_of_range@std@@YAXPBD@Z',0
word_798132     dw 3CFh                 ; DATA XREF: .rdata:00797F7C↑o
                db '?id@?$ctype@D@std@@2V0locale@2@A',0
                align 2
word_798156     dw 25Dh                 ; DATA XREF: .rdata:00797F78↑o
                db '?_Random_device@std@@YAIXZ',0
                align 4
word_798174     dw 28Eh                 ; DATA XREF: .rdata:00797F74↑o
                db '?_Xlength_error@std@@YAXPBD@Z',0
word_798194     dw 5B6h                 ; DATA XREF: .rdata:00797F70↑o
                db '_Thrd_sleep',0
word_7981A2     dw 590h                 ; DATA XREF: .rdata:00797F6C↑o
                db '_Query_perf_counter',0
word_7981B8     dw 5CCh                 ; DATA XREF: .rdata:00797F64↑o
                db '_Xtime_get_ticks',0
                align 4
word_7981CC     dw 219h                 ; DATA XREF: .rdata:00797F60↑o
                db '?_Ipfx@?$basic_istream@DU?$char_traits@D@std@@@std@@QAE_N_N@Z',0
word_79820C     dw 4D8h                 ; DATA XREF: .rdata:00797F4C↑o
                db '?snextc@?$basic_streambuf@DU?$char_traits@D@std@@@std@@QAEHXZ',0
word_79824C     dw 4C5h                 ; DATA XREF: .rdata:off_797F3C↑o
                db '?setstate@?$basic_ios@DU?$char_traits@D@std@@@std@@QAEXH_N@Z',0
                align 4
word_79828C     dw 487h                 ; DATA XREF: .rdata:00797F40↑o
                db '?rdbuf@?$basic_ios@DU?$char_traits@D@std@@@std@@QBEPAV?$basic_str'
                db 'eambuf@DU?$char_traits@D@std@@@2@XZ',0
                align 4
word_7982F4     dw 4CFh                 ; DATA XREF: .rdata:00797F44↑o
                db '?sgetc@?$basic_streambuf@DU?$char_traits@D@std@@@std@@QAEHXZ',0
                align 4
word_798334     dw 3C3h                 ; DATA XREF: .rdata:00797F48↑o
                db '?getloc@ios_base@std@@QBE?AVlocale@2@XZ',0
word_79835E     dw 53Dh                 ; DATA XREF: .rdata:00797F94↑o
                db '?width@ios_base@std@@QAE_J_J@Z',0
                align 10h
word_798380     dw 53Eh                 ; DATA XREF: .rdata:00797F50↑o
                db '?width@ios_base@std@@QBE_JXZ',0
                align 10h
word_7983A0     dw 1B6h                 ; DATA XREF: .rdata:00797F54↑o
                db '?_Getcat@?$ctype@D@std@@SAIPAPBVfacet@locale@2@PBV42@@Z',0
word_7983DA     dw 40Fh                 ; DATA XREF: .rdata:00797F58↑o
                db '?is@?$ctype@D@std@@QBE_NFD@Z',0
                align 2
word_7983FA     dw 131h                 ; DATA XREF: .rdata:00797F5C↑o
                db '??Bid@locale@std@@QAEIXZ',0
                align 2
aMsvcp140Dll    db 'MSVCP140.dll',0     ; DATA XREF: .rdata:00797E60↑o
                align 4
word_798424     dw 10h                  ; DATA XREF: .rdata:00797FB8↑o
                db '__CxxFrameHandler3',0
                align 2
word_79843A     dw 22h                  ; DATA XREF: .rdata:00797FC0↑o
                db '__std_exception_destroy',0
word_798454     dw 21h                  ; DATA XREF: .rdata:00797FB4↑o
                db '__std_exception_copy',0
                align 4
word_79846C     dw 1                    ; DATA XREF: .rdata:00797FB0↑o
                db '_CxxThrowException',0
                align 2
word_798482     dw 1Ch                  ; DATA XREF: .rdata:00797FAC↑o
                db '__current_exception',0
word_798498     dw 1Dh                  ; DATA XREF: .rdata:00797FA8↑o
                db '__current_exception_context',0
word_7984B6     dw 48h                  ; DATA XREF: .rdata:00797FA4↑o
                db 'memset',0
                align 10h
word_7984C0     dw 35h                  ; DATA XREF: .rdata:00797FA0↑o
                db '_except_handler4_common',0
aVcruntime140Dl db 'VCRUNTIME140.dll',0 ; DATA XREF: .rdata:00797E74↑o
                align 4
word_7984EC     dw 0                    ; DATA XREF: .rdata:0079804C↑o
                db '__acrt_iob_func',0
word_7984FE     dw 3                    ; DATA XREF: .rdata:00798048↑o
                db '__stdio_common_vfprintf',0
word_798518     dw 8Ch                  ; DATA XREF: .rdata:00798044↑o
                db 'getchar',0
word_798522     dw 3Bh                  ; DATA XREF: .rdata:00797FF8↑o
                db '_invalid_parameter_noinfo_noreturn',0
                align 4
word_798548     dw 8                    ; DATA XREF: .rdata:00797FCC↑o
                db '_callnewh',0
word_798554     dw 19h                  ; DATA XREF: .rdata:00797FD0↑o
                db 'malloc',0
                align 2
word_79855E     dw 19h                  ; DATA XREF: .rdata:00798008↑o
                db '_configure_narrow_argv',0
                align 4
word_798578     dw 35h                  ; DATA XREF: .rdata:0079800C↑o
                db '_initialize_narrow_environment',0
                align 2
word_79859A     dw 36h                  ; DATA XREF: .rdata:00798034↑o
                db '_initialize_onexit_table',0
                align 2
word_7985B6     dw 3Eh                  ; DATA XREF: .rdata:00798038↑o
                db '_register_onexit_function',0
word_7985D2     dw 1Fh                  ; DATA XREF: .rdata:00798030↑o
                db '_crt_atexit',0
word_7985E0     dw 17h                  ; DATA XREF: .rdata:0079802C↑o
                db '_cexit',0
                align 2
word_7985EA     dw 42h                  ; DATA XREF: .rdata:00798028↑o
                db '_seh_filter_exe',0
word_7985FC     dw 44h                  ; DATA XREF: .rdata:00798024↑o
                db '_set_app_type',0
word_79860C     dw 2Eh                  ; DATA XREF: .rdata:off_797FE4↑o
                db '__setusermatherr',0
                align 10h
word_798620     dw 2Ah                  ; DATA XREF: .rdata:00798020↑o
                db '_get_initial_narrow_environment',0
word_798642     dw 38h                  ; DATA XREF: .rdata:0079801C↑o
                db '_initterm',0
word_79864E     dw 39h                  ; DATA XREF: .rdata:00798018↑o
                db '_initterm_e',0
word_79865C     dw 58h                  ; DATA XREF: .rdata:00798010↑o
                db 'exit',0
                align 4
word_798664     dw 25h                  ; DATA XREF: .rdata:00798000↑o
                db '_exit',0
word_79866C     dw 54h                  ; DATA XREF: .rdata:off_798040↑o
                db '_set_fmode',0
                align 2
word_79867A     dw 5                    ; DATA XREF: .rdata:00797FF4↑o
                db '__p___argc',0
                align 4
word_798688     dw 6                    ; DATA XREF: .rdata:00798014↑o
                db '__p___argv',0
                align 2
word_798696     dw 16h                  ; DATA XREF: .rdata:off_797FEC↑o
                db '_c_exit',0
word_7986A0     dw 3Fh                  ; DATA XREF: .rdata:00797FF0↑o
                db '_register_thread_local_exe_atexit_callback',0
                align 2
word_7986CE     dw 8                    ; DATA XREF: .rdata:off_797FDC↑o
                db '_configthreadlocale',0
word_7986E4     dw 16h                  ; DATA XREF: .rdata:off_797FC8↑o
                db '_set_new_mode',0
word_7986F4     dw 1                    ; DATA XREF: .rdata:00798050↑o
                db '__p__commode',0
                align 4
word_798704     dw 6Ah                  ; DATA XREF: .rdata:00797FFC↑o
                db 'terminate',0
word_798710     dw 18h                  ; DATA XREF: .rdata:00797FD4↑o
                db 'free',0
                align 4
word_798718     dw 1Dh                  ; DATA XREF: .rdata:00798004↑o
                db '_controlfp_s',0
                align 4
aApiMsWinCrtStd db 'api-ms-win-crt-stdio-l1-1-0.dll',0
                                        ; DATA XREF: .rdata:00797E88↑o
aApiMsWinCrtRun db 'api-ms-win-crt-runtime-l1-1-0.dll',0
                                        ; DATA XREF: .rdata:00797E9C↑o
aApiMsWinCrtHea db 'api-ms-win-crt-heap-l1-1-0.dll',0
                                        ; DATA XREF: .rdata:00797EB0↑o
                align 2
aApiMsWinCrtMat db 'api-ms-win-crt-math-l1-1-0.dll',0
                                        ; DATA XREF: .rdata:00797EC4↑o
                align 2
aApiMsWinCrtLoc db 'api-ms-win-crt-locale-l1-1-0.dll',0
                                        ; DATA XREF: .rdata:00797ED8↑o
                align 4
word_7987CC     dw 389h                 ; DATA XREF: .rdata:00797F0C↑o
                db 'IsProcessorFeaturePresent',0
word_7987E8     dw 382h                 ; DATA XREF: .rdata:00797F10↑o
                db 'IsDebuggerPresent',0
word_7987FC     dw 5B1h                 ; DATA XREF: .rdata:00797F14↑o
                db 'UnhandledExceptionFilter',0
                align 4
word_798818     dw 571h                 ; DATA XREF: .rdata:00797F28↑o
                db 'SetUnhandledExceptionFilter',0
word_798836     dw 27Bh                 ; DATA XREF: .rdata:00797F34↑o
                db 'GetModuleHandleW',0
                align 2
word_79884A     dw 44Fh                 ; DATA XREF: .rdata:00797F30↑o
                db 'QueryPerformanceCounter',0
word_798864     dw 21Bh                 ; DATA XREF: .rdata:00797F2C↑o
                db 'GetCurrentProcessId',0
word_79887A     dw 21Fh                 ; DATA XREF: .rdata:00797F24↑o
                db 'GetCurrentThreadId',0
                align 10h
word_798890     dw 2ECh                 ; DATA XREF: .rdata:00797F20↑o
                db 'GetSystemTimeAsFileTime',0
word_7988AA     dw 366h                 ; DATA XREF: .rdata:00797F1C↑o
                db 'InitializeSListHead',0
word_7988C0     dw 21Ah                 ; DATA XREF: .rdata:00797F18↑o
                db 'GetCurrentProcess',0
word_7988D4     dw 590h                 ; DATA XREF: .rdata:off_797F08↑o
                db 'TerminateProcess',0
                align 4
aKernel32Dll    db 'KERNEL32.dll',0     ; DATA XREF: .rdata:00797EEC↑o
                align 2
word_7988F6     dw 46h                  ; DATA XREF: .rdata:00797FBC↑o
                db 'memcpy',0
                align 10h
word_798900     dw 47h                  ; DATA XREF: .rdata:off_797F9C↑o
                db 'memmove',0
                align 800h
_rdata          ends

; Section 3. (virtual address 00009000)
; Virtual size                  : 000004B4 (   1204.)
; Section size in file          : 00000200 (    512.)
; Offset to raw data for section: 00007600
; Flags C0000040: Data Readable Writable
; Alignment     : default
; ===========================================================================

; Segment type: Pure data
; Segment permissions: Read/Write
_data           segment para public 'DATA' use32
                assume cs:_data
                ;org 799000h
                db 0FFh
                db 0FFh
                db 0FFh
                db 0FFh
dword_799004    dd 1                    ; DATA XREF: ___isa_available_init+D↑w
                                        ; ___isa_available_init:loc_7956FC↑r ...
                align 10h
dword_799010    dd 1                    ; DATA XREF: sub_795B1D+2↑r
dword_799014    dd 44BF19B1h            ; DATA XREF: ___security_init_cookie+43↑w
                                        ; ___report_gsfailure+E3↑r
; uintptr_t __security_cookie
___security_cookie dd 0BB40E64Eh        ; DATA XREF: __SEH_prolog4+1C↑r
                                        ; __except_handler4+1F↑o ...
dword_79901C    dd 1                    ; DATA XREF: ___scrt_is_ucrt_dll_in_use+2↑r
                db  75h ; u
                db  98h
                db    0
                db    0
; public class type_info /* mdisp:0 */
; public class type_info /* mdisp:0 */
; class type_info `RTTI Type Descriptor'
??_R0?AVtype_info@@@8 dd offset ??_7type_info@@6B@
                                        ; DATA XREF: .rdata:0079758C↑o
                                        ; .rdata:type_info::`RTTI Base Class Descriptor at (0,-1,0,64)'↑o
                                        ; reference to RTTI's vftable
                dd 0                    ; internal runtime reference
aAvtypeInfo     db '.?AVtype_info@@',0  ; type descriptor name
; public class std::bad_alloc /* mdisp:0 */ :
;   public class std::exception /* mdisp:0 */
; public class std::bad_alloc /* mdisp:0 */ :
;   public class std::exception /* mdisp:0 */
; class std::bad_alloc `RTTI Type Descriptor'
??_R0?AVbad_alloc@std@@@8 dd offset ??_7type_info@@6B@
                                        ; DATA XREF: .rdata:std::bad_alloc::`RTTI Base Class Descriptor at (0,-1,0,64)'↑o
                                        ; .rdata:0079768C↑o ...
                                        ; reference to RTTI's vftable
                dd 0                    ; internal runtime reference
aAvbadAllocStd  db '.?AVbad_alloc@std@@',0 ; type descriptor name
; public class std::bad_cast /* mdisp:0 */ :
;   public class std::exception /* mdisp:0 */
; public class std::bad_cast /* mdisp:0 */ :
;   public class std::exception /* mdisp:0 */
; class std::bad_cast `RTTI Type Descriptor'
??_R0?AVbad_cast@std@@@8 dd offset ??_7type_info@@6B@
                                        ; DATA XREF: .rdata:std::bad_cast::`RTTI Base Class Descriptor at (0,-1,0,64)'↑o
                                        ; .rdata:007976A0↑o ...
                                        ; reference to RTTI's vftable
                dd 0                    ; internal runtime reference
aAvbadCastStd   db '.?AVbad_cast@std@@',0 ; type descriptor name
                align 4
; public class std::exception /* mdisp:0 */
; public class std::exception /* mdisp:0 */
; class std::exception `RTTI Type Descriptor'
??_R0?AVexception@std@@@8 dd offset ??_7type_info@@6B@
                                        ; DATA XREF: .rdata:007975D4↑o
                                        ; .rdata:std::exception::`RTTI Base Class Descriptor at (0,-1,0,64)'↑o ...
                                        ; reference to RTTI's vftable
                dd 0                    ; internal runtime reference
aAvexceptionStd db '.?AVexception@std@@',0 ; type descriptor name
; public class std::bad_array_new_length /* mdisp:0 */ :
;   public class std::bad_alloc /* mdisp:0 */ :
;     public class std::exception /* mdisp:0 */
; public class std::bad_array_new_length /* mdisp:0 */ :
;   public class std::bad_alloc /* mdisp:0 */ :
;     public class std::exception /* mdisp:0 */
; class std::bad_array_new_length `RTTI Type Descriptor'
??_R0?AVbad_array_new_length@std@@@8 dd offset ??_7type_info@@6B@
                                        ; DATA XREF: .rdata:007976D4↑o
                                        ; .rdata:std::bad_array_new_length::`RTTI Base Class Descriptor at (0,-1,0,64)'↑o ...
                                        ; reference to RTTI's vftable
                dd 0                    ; internal runtime reference
aAvbadArrayNewL db '.?AVbad_array_new_length@std@@',0 ; type descriptor name
                align 4
; std::_Fac_node *Block
Block           dd 0                    ; DATA XREF: std::_Fac_tidy_reg_t::~_Fac_tidy_reg_t(void)+7↑w
                                        ; std::_Fac_tidy_reg_t::~_Fac_tidy_reg_t(void):loc_795059↑r ...
; std::_Fac_tidy_reg_t unk_7990BC
unk_7990BC      db    0                 ; DATA XREF: sub_796699↑o
                db    0
                db    0
                db    0
dword_7990C0    dd 0                    ; DATA XREF: __scrt_common_main_seh(void)+2D↑r
                                        ; __scrt_common_main_seh(void)+41↑w ...
unk_7990C4      db    0                 ; DATA XREF: ___scrt_acquire_startup_lock+10↑o
                                        ; ___scrt_release_startup_lock+14↑o
                db    0
                db    0
                db    0
byte_7990C8     db 0                    ; DATA XREF: ___scrt_initialize_crt+9↑w
                                        ; ___scrt_uninitialize_crt+3↑r
byte_7990C9     db 0                    ; DATA XREF: ___scrt_initialize_onexit_tables+3↑r
                                        ; ___scrt_initialize_onexit_tables:loc_7951E3↑w
                align 4
; _onexit_table_t Table
Table           _onexit_table_t <0>     ; DATA XREF: ___scrt_initialize_onexit_tables+2A↑o
                                        ; ___scrt_initialize_onexit_tables+4F↑w ...
; _onexit_table_t stru_7990D8
stru_7990D8     _onexit_table_t <0>     ; DATA XREF: ___scrt_initialize_onexit_tables+39↑o
                                        ; ___scrt_initialize_onexit_tables+61↑w ...
___castguard_check_failure_os_handled_fptr db    0
                                        ; DATA XREF: .rdata:00797540↑o
                db    0
                db    0
                db    0
dword_7990E8    dd 0                    ; DATA XREF: ___isa_available_init+3↑w
                                        ; ___isa_available_init+11B↑w ...
dword_7990EC    dd 0                    ; DATA XREF: ___isa_available_init:loc_7956A5↑r
                                        ; ___isa_available_init+C5↑w ...
dword_7990F0    dd 0                    ; DATA XREF: sub_795990↑w
                align 8
; union _SLIST_HEADER ListHead
ListHead        _SLIST_HEADER <0>       ; DATA XREF: sub_795ACA↑o
unk_799100      db    0                 ; DATA XREF: sub_795AFA↑o
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
dword_799108    dd 0                    ; DATA XREF: ___report_gsfailure+9F↑w
                                        ; .rdata:ExceptionInfo↑o
dword_79910C    dd 0                    ; DATA XREF: ___report_gsfailure+A9↑w
                db    0
                db    0
                db    0
                db    0
dword_799114    dd 0                    ; DATA XREF: ___report_gsfailure+9A↑w
dword_799118    dd 0                    ; DATA XREF: ___report_gsfailure+B3↑w
dword_79911C    dd 0                    ; DATA XREF: ___report_gsfailure+C3↑w
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
dword_799158    dd 0                    ; DATA XREF: ___report_gsfailure+8B↑w
                                        ; .rdata:ExceptionInfo↑o
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
word_7991E4     dw 0                    ; DATA XREF: ___report_gsfailure+5F↑w
                align 4
word_7991E8     dw 0                    ; DATA XREF: ___report_gsfailure+58↑w
                align 4
word_7991EC     dw 0                    ; DATA XREF: ___report_gsfailure+51↑w
                align 10h
word_7991F0     dw 0                    ; DATA XREF: ___report_gsfailure+4A↑w
                align 4
dword_7991F4    dd 0                    ; DATA XREF: ___report_gsfailure+36↑w
dword_7991F8    dd 0                    ; DATA XREF: ___report_gsfailure+30↑w
dword_7991FC    dd 0                    ; DATA XREF: ___report_gsfailure+2A↑w
dword_799200    dd ?                    ; DATA XREF: ___report_gsfailure+24↑w
dword_799204    dd ?                    ; DATA XREF: ___report_gsfailure+1E↑w
dword_799208    dd ?                    ; DATA XREF: ___report_gsfailure:loc_795BDF↑w
dword_79920C    dd ?                    ; DATA XREF: ___report_gsfailure+70↑w
dword_799210    dd ?                    ; DATA XREF: ___report_gsfailure+78↑w
                                        ; ___report_gsfailure+95↑r
word_799214     dw ?                    ; DATA XREF: ___report_gsfailure+43↑w
                align 4
dword_799218    dd ?                    ; DATA XREF: ___report_gsfailure+67↑w
dword_79921C    dd ?                    ; DATA XREF: ___report_gsfailure+80↑w
word_799220     dw ?                    ; DATA XREF: ___report_gsfailure+3C↑w
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
unk_799428      db    ? ;               ; DATA XREF: sub_79132F+3↑o
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
dword_799430    dd ?                    ; DATA XREF: sub_792823+2A↑r
                                        ; sub_792823+AA↑w
; int dword_799434[3]
dword_799434    dd 3 dup(?)             ; DATA XREF: sub_79122E+30↑o
                                        ; Process_Input3+30↑o ...
; int dword_799440[3]
dword_799440    dd 3 dup(?)             ; DATA XREF: sub_791117+30↑o
                                        ; sub_79663F+3↑o
; int dword_79944C[3]
dword_79944C    dd 3 dup(?)             ; DATA XREF: sub_791000+30↑o
                                        ; sub_796612+3↑o
; int dword_799458[3]
dword_799458    dd 3 dup(?)             ; DATA XREF: sub_79105D+30↑o
                                        ; sub_796621+3↑o
; int dword_799464[3]
dword_799464    dd 3 dup(?)             ; DATA XREF: sub_791174+30↑o
                                        ; sub_79664E+3↑o
; unsigned int dword_799470[6]
dword_799470    dd 6 dup(?)             ; DATA XREF: sub_7912E8+8↑o
                                        ; sub_79668A+3↑o
; int dword_799488[3]
dword_799488    dd 3 dup(?)             ; DATA XREF: sub_79128B+30↑o
                                        ; sub_79667B+3↑o
; int dword_799494[3]
dword_799494    dd 3 dup(?)             ; DATA XREF: sub_7911D1+30↑o
                                        ; sub_79665D+3↑o
; int dword_7994A0[3]
dword_7994A0    dd 3 dup(?)             ; DATA XREF: sub_7910BA+30↑o
                                        ; sub_796630+3↑o
unk_7994AC      db    ? ;               ; DATA XREF: sub_795B2F↑o
                db    ? ;
                db    ? ;
                db    ? ;
unk_7994B0      db    ? ;               ; DATA XREF: sub_795B29↑o
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
_data           ends


                end start
