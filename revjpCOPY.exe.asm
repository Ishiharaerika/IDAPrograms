; ---------------------------------------------------------------------------

GUID            struc ; (sizeof=0x10, align=0x4, copyof_2)
                                        ; XREF: .rdata:00E37738/r
Data1           dd ?
Data2           dw ?
Data3           dw ?
Data4           db 8 dup(?)
GUID            ends

; ---------------------------------------------------------------------------

FuncInfo        struc ; (sizeof=0x24, mappedto_5)
                                        ; XREF: .rdata:stru_E37A80/r
                                        ; .rdata:stru_E37AAC/r ...
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
                                        ; XREF: .rdata:stru_E37AA4/r
                                        ; .rdata:stru_E37AF4/r ...
toState         dd ?                    ; base 10
action          dd ?                    ; offset
UnwindMapEntry  ends

; ---------------------------------------------------------------------------

TryBlockMapEntry struc ; (sizeof=0x14, mappedto_7)
                                        ; XREF: .rdata:stru_E37C50/r
                                        ; .rdata:stru_E37CA8/r
tryLow          dd ?                    ; base 10
tryHigh         dd ?                    ; base 10
catchHigh       dd ?                    ; base 10
nCatches        dd ?                    ; base 10
pHandlerArray   dd ?                    ; offset
TryBlockMapEntry ends

; ---------------------------------------------------------------------------

HandlerType     struc ; (sizeof=0x10, mappedto_8)
                                        ; XREF: .rdata:stru_E37C64/r
                                        ; .rdata:stru_E37CBC/r
adjectives      dd ?                    ; base 16
pType           dd ?                    ; offset
dispCatchObj    dd ?                    ; base 10
addressOfHandler dd ?                   ; offset
HandlerType     ends

; ---------------------------------------------------------------------------

_EH4_SCOPETABLE struc ; (sizeof=0x10, align=0x4, copyof_10, variable size)
                                        ; XREF: .rdata:stru_E37D50/r
                                        ; .rdata:stru_E37D70/r
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
old_esp         dd ?                    ; XREF: ___scrt_is_nonwritable_in_current_image:loc_E3526F/r
                                        ; __scrt_common_main_seh(void):loc_E35543/r
exc_ptr         dd ?                    ; XREF: ___scrt_is_nonwritable_in_current_image:loc_E3525C/r
                                        ; __scrt_common_main_seh(void):loc_E3552F/r ; offset
registration    _EH3_EXCEPTION_REGISTRATION ?
                                        ; XREF: ___scrt_is_nonwritable_in_current_image+C/w
                                        ; ___scrt_is_nonwritable_in_current_image+5A/w ...
CPPEH_RECORD    ends

; ---------------------------------------------------------------------------

_EH3_EXCEPTION_REGISTRATION struc ; (sizeof=0x10, align=0x4, copyof_12)
                                        ; XREF: CPPEH_RECORD/r
Next            dd ?                    ; XREF: ___scrt_is_nonwritable_in_current_image:loc_E3527B/r
                                        ; __scrt_common_main_seh(void):loc_E35564/r ; offset
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
                                        ; XREF: sub_E33230/r
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
                                        ; .data:stru_E390D8/r
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
anonymous_0     _SLIST_HEADER::$04C3B4B3818F1694974352AE64BF5082 ?
_SLIST_HEADER   ends

; ---------------------------------------------------------------------------

_SLIST_HEADER::$04C3B4B3818F1694974352AE64BF5082 struc ; (sizeof=0x8, align=0x4, copyof_51)
                                        ; XREF: _SLIST_HEADER/r
Next            SLIST_ENTRY ?
Depth           dw ?
CpuId           dw ?
_SLIST_HEADER::$04C3B4B3818F1694974352AE64BF5082 ends

; ---------------------------------------------------------------------------

SLIST_ENTRY     struc ; (sizeof=0x4, align=0x4, copyof_52)
                                        ; XREF: _SLIST_HEADER::$04C3B4B3818F1694974352AE64BF5082/r
Next            dd ?                    ; offset
SLIST_ENTRY     ends

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

;
; +-------------------------------------------------------------------------+
; |      This file was generated by The Interactive Disassembler (IDA)      |
; |           Copyright (c) 2022 Hex-Rays, <support@hex-rays.com>           |
; |                      License info: 48-591F-7CB6-D6                      |
; |                       Think-Cell Operations GmbH                        |
; +-------------------------------------------------------------------------+
;
; Input SHA256 : 70709F6D6A0F4C3A83CFC42731742934BE73AF4FCB4439764AAADD72FB94B58E
; Input MD5    : FF654D66E6C31FBB0A6B8A7F0D71EADB
; Input CRC32  : CE4CA992

; File Name   : C:\Users\81807\Downloads\revjpCOPY.exe
; Format      : Portable executable for 80386 (PE)
; Imagebase   : 400000
; Timestamp   : 601D544D (Fri Feb 05 14:21:01 2021)
; Section 1. (virtual address 00001000)
; Virtual size                  : 000056A3 (  22179.)
; Section size in file          : 00005800 (  22528.)
; Offset to raw data for section: 00000400
; Flags 60000020: Text Executable Readable
; Alignment     : default
; PDB File Name : C:\user\ShinzoAbe\Documents\Secret\fap\hentai\futa.pd
; OS type         :  MS Windows
; Application type:  Executable 32bit

                .686p
                .mmx
                .model flat

; ===========================================================================

; Segment type: Pure code
; Segment permissions: Read/Execute
_text           segment para public 'CODE' use32
                assume cs:_text
                ;org 0E31000h
                assume es:nothing, ss:nothing, ds:_data, fs:nothing, gs:nothing

; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int sub_E31000()
sub_E31000      proc near               ; DATA XREF: .rdata:00E37160↓o

var_24          = byte ptr -24h
var_C           = dword ptr -0Ch
var_4           = dword ptr -4

; FUNCTION CHUNK AT 00E364E2 SIZE 00000008 BYTES
; FUNCTION CHUNK AT 00E364EF SIZE 0000000C BYTES

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
                call    sub_E320BA
                and     [ebp+var_4], 0
                lea     eax, [ebp+var_24]
                push    eax
                mov     ecx, offset dword_E3944C
                call    sub_E318BC
                or      [ebp+var_4], 0FFFFFFFFh
                lea     ecx, [ebp+var_24]
                call    gEncode
                push    offset sub_E36612 ; void (__cdecl *)()
                call    _atexit
                pop     ecx
                mov     ecx, [ebp+var_C]
                mov     large fs:0, ecx
                leave
                retn
sub_E31000      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int sub_E3105D()
sub_E3105D      proc near               ; DATA XREF: .rdata:00E37164↓o

var_24          = byte ptr -24h
var_C           = dword ptr -0Ch
var_4           = dword ptr -4

; FUNCTION CHUNK AT 00E364E2 SIZE 00000008 BYTES
; FUNCTION CHUNK AT 00E364EF SIZE 0000000C BYTES

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
                call    sub_E320BA
                and     [ebp+var_4], 0
                lea     eax, [ebp+var_24]
                push    eax
                mov     ecx, offset dword_E39458
                call    sub_E318BC
                or      [ebp+var_4], 0FFFFFFFFh
                lea     ecx, [ebp+var_24]
                call    gEncode
                push    offset sub_E36621 ; void (__cdecl *)()
                call    _atexit
                pop     ecx
                mov     ecx, [ebp+var_C]
                mov     large fs:0, ecx
                leave
                retn
sub_E3105D      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int sub_E310BA()
sub_E310BA      proc near               ; DATA XREF: .rdata:00E37168↓o

var_24          = byte ptr -24h
var_C           = dword ptr -0Ch
var_4           = dword ptr -4

; FUNCTION CHUNK AT 00E364E2 SIZE 00000008 BYTES
; FUNCTION CHUNK AT 00E364EF SIZE 0000000C BYTES

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
                call    sub_E320BA
                and     [ebp+var_4], 0
                lea     eax, [ebp+var_24]
                push    eax
                mov     ecx, offset dword_E394A0
                call    sub_E318BC
                or      [ebp+var_4], 0FFFFFFFFh
                lea     ecx, [ebp+var_24]
                call    gEncode
                push    offset sub_E36630 ; void (__cdecl *)()
                call    _atexit
                pop     ecx
                mov     ecx, [ebp+var_C]
                mov     large fs:0, ecx
                leave
                retn
sub_E310BA      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int sub_E31117()
sub_E31117      proc near               ; DATA XREF: .rdata:00E3716C↓o

var_24          = byte ptr -24h
var_C           = dword ptr -0Ch
var_4           = dword ptr -4

; FUNCTION CHUNK AT 00E364E2 SIZE 00000008 BYTES
; FUNCTION CHUNK AT 00E364EF SIZE 0000000C BYTES

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
                call    sub_E320BA
                and     [ebp+var_4], 0
                lea     eax, [ebp+var_24]
                push    eax
                mov     ecx, offset dword_E39440
                call    sub_E318BC
                or      [ebp+var_4], 0FFFFFFFFh
                lea     ecx, [ebp+var_24]
                call    gEncode
                push    offset sub_E3663F ; void (__cdecl *)()
                call    _atexit
                pop     ecx
                mov     ecx, [ebp+var_C]
                mov     large fs:0, ecx
                leave
                retn
sub_E31117      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int sub_E31174()
sub_E31174      proc near               ; DATA XREF: .rdata:00E37170↓o

var_24          = byte ptr -24h
var_C           = dword ptr -0Ch
var_4           = dword ptr -4

; FUNCTION CHUNK AT 00E364E2 SIZE 00000008 BYTES
; FUNCTION CHUNK AT 00E364EF SIZE 0000000C BYTES

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
                call    sub_E320BA
                and     [ebp+var_4], 0
                lea     eax, [ebp+var_24]
                push    eax
                mov     ecx, offset dword_E39464
                call    sub_E318BC
                or      [ebp+var_4], 0FFFFFFFFh
                lea     ecx, [ebp+var_24]
                call    gEncode
                push    offset sub_E3664E ; void (__cdecl *)()
                call    _atexit
                pop     ecx
                mov     ecx, [ebp+var_C]
                mov     large fs:0, ecx
                leave
                retn
sub_E31174      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int sub_E311D1()
sub_E311D1      proc near               ; DATA XREF: .rdata:00E37174↓o

var_24          = byte ptr -24h
var_C           = dword ptr -0Ch
var_4           = dword ptr -4

; FUNCTION CHUNK AT 00E364E2 SIZE 00000008 BYTES
; FUNCTION CHUNK AT 00E364EF SIZE 0000000C BYTES

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
                call    sub_E320BA
                and     [ebp+var_4], 0
                lea     eax, [ebp+var_24]
                push    eax
                mov     ecx, offset dword_E39494
                call    sub_E318BC
                or      [ebp+var_4], 0FFFFFFFFh
                lea     ecx, [ebp+var_24]
                call    gEncode
                push    offset sub_E3665D ; void (__cdecl *)()
                call    _atexit
                pop     ecx
                mov     ecx, [ebp+var_C]
                mov     large fs:0, ecx
                leave
                retn
sub_E311D1      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int sub_E3122E()
sub_E3122E      proc near               ; DATA XREF: .rdata:00E37178↓o

var_24          = byte ptr -24h
var_C           = dword ptr -0Ch
var_4           = dword ptr -4

; FUNCTION CHUNK AT 00E364E2 SIZE 00000008 BYTES
; FUNCTION CHUNK AT 00E364EF SIZE 0000000C BYTES

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
                call    sub_E320BA
                and     [ebp+var_4], 0
                lea     eax, [ebp+var_24]
                push    eax
                mov     ecx, offset dword_E39434
                call    sub_E318BC
                or      [ebp+var_4], 0FFFFFFFFh
                lea     ecx, [ebp+var_24]
                call    gEncode
                push    offset sub_E3666C ; void (__cdecl *)()
                call    _atexit
                pop     ecx
                mov     ecx, [ebp+var_C]
                mov     large fs:0, ecx
                leave
                retn
sub_E3122E      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int sub_E3128B()
sub_E3128B      proc near               ; DATA XREF: .rdata:00E3717C↓o

var_24          = byte ptr -24h
var_C           = dword ptr -0Ch
var_4           = dword ptr -4

; FUNCTION CHUNK AT 00E364E2 SIZE 00000008 BYTES
; FUNCTION CHUNK AT 00E364EF SIZE 0000000C BYTES

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
                call    sub_E320BA
                and     [ebp+var_4], 0
                lea     eax, [ebp+var_24]
                push    eax
                mov     ecx, offset dword_E39488
                call    sub_E318BC
                or      [ebp+var_4], 0FFFFFFFFh
                lea     ecx, [ebp+var_24]
                call    gEncode
                push    offset sub_E3667B ; void (__cdecl *)()
                call    _atexit
                pop     ecx
                mov     ecx, [ebp+var_C]
                mov     large fs:0, ecx
                leave
                retn
sub_E3128B      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int sub_E312E8()
sub_E312E8      proc near               ; DATA XREF: .rdata:00E37180↓o
                push    ebp
                mov     ebp, esp
                push    offset aH4ndy51mpl30bf ; "H4ndy51mpL30bFusC4tI0NL1bR4RybYM3mB3R_T"...
                mov     ecx, offset dword_E39470
                call    sub_E320BA
                push    offset sub_E3668A ; void (__cdecl *)()
                call    _atexit
                pop     ecx
                pop     ebp
                retn
sub_E312E8      endp


; =============== S U B R O U T I N E =======================================


; int sub_E31307()
sub_E31307      proc near               ; DATA XREF: .rdata:00E3715C↓o
                push    offset sub_E36699 ; void (__cdecl *)()
                call    _atexit
                pop     ecx
                retn
sub_E31307      endp

; ---------------------------------------------------------------------------
                align 10h

; =============== S U B R O U T I N E =======================================

; Attributes: library function bp-based frame

; void *__cdecl xEncode(unsigned int, void *)
                public xEncode
xEncode         proc near               ; CODE XREF: sub_E32D1E+10↓p
                                        ; vEncode+A↓p ...

arg_4           = dword ptr  0Ch

                push    ebp
                mov     ebp, esp
                mov     eax, [ebp+arg_4]
                pop     ebp
                retn
xEncode         endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; char sub_E31328()
sub_E31328      proc near               ; CODE XREF: sub_E32565+4↓p
                                        ; sub_E326F2+7↓p
                push    ebp
                mov     ebp, esp
                xor     al, al
                pop     ebp
                retn
sub_E31328      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; void *sub_E3132F()
sub_E3132F      proc near               ; CODE XREF: sub_E31339+F↓p
                                        ; ___scrt_initialize_default_local_stdio_options↓p
                push    ebp
                mov     ebp, esp
                mov     eax, offset unk_E39428
                pop     ebp
                retn
sub_E3132F      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int __cdecl sub_E31339(FILE *Stream, char *Format, _locale_t Locale, va_list ArgList)
sub_E31339      proc near               ; CODE XREF: printf+29↓p

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
                call    sub_E3132F
                push    dword ptr [eax+4]
                push    dword ptr [eax] ; Options
                call    ds:__stdio_common_vfprintf
                add     esp, 18h
                pop     ebp
                retn
sub_E31339      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int printf(char *, ...)
                public printf
printf          proc near               ; CODE XREF: aGetInput+24↓p
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
                call    sub_E31339
                add     esp, 10h
                mov     [ebp+var_10], eax
                and     [ebp+ArgList], 0
                mov     eax, [ebp+var_10]
                leave
                retn
printf          endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _DWORD *__thiscall sub_E3139A(_DWORD *this, int, int)
sub_E3139A      proc near               ; CODE XREF: sub_E31473+F↓p
                                        ; sub_E31674+11↓p

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
sub_E3139A      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _DWORD *__thiscall sub_E313C7(_DWORD *this, int)
sub_E313C7      proc near               ; CODE XREF: sub_E3156F+D↓p
                                        ; sub_E316B6+D↓p
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
sub_E313C7      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int __thiscall sub_E31401(_DWORD *this)
sub_E31401      proc near               ; CODE XREF: sub_E31449+A↓p
                                        ; sub_E314C1+A↓p

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
sub_E31401      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; const char *__thiscall sub_E31421(_DWORD *this)
sub_E31421      proc near               ; DATA XREF: .rdata:00E371C0↓o
                                        ; .rdata:00E371CC↓o ...

var_8           = dword ptr -8
var_4           = dword ptr -4

                push    ebp
                mov     ebp, esp
                push    ecx
                push    ecx
                mov     [ebp+var_4], ecx
                mov     eax, [ebp+var_4]
                cmp     dword ptr [eax+4], 0
                jz      short loc_E3143D
                mov     eax, [ebp+var_4]
                mov     eax, [eax+4]
                mov     [ebp+var_8], eax
                jmp     short loc_E31444
; ---------------------------------------------------------------------------

loc_E3143D:                             ; CODE XREF: sub_E31421+F↑j
                mov     [ebp+var_8], offset aUnknownExcepti ; "Unknown exception"

loc_E31444:                             ; CODE XREF: sub_E31421+1A↑j
                mov     eax, [ebp+var_8]
                leave
                retn
sub_E31421      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _DWORD *__thiscall sub_E31449(_DWORD *this, char)
sub_E31449      proc near               ; DATA XREF: .rdata:const std::exception::`vftable'↓o

Block           = dword ptr -4
arg_0           = dword ptr  8

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+Block], ecx
                mov     ecx, [ebp+Block]
                call    sub_E31401
                mov     eax, [ebp+arg_0]
                and     eax, 1
                jz      short loc_E3146C
                push    0Ch
                push    [ebp+Block]     ; Block
                call    sub_E35312
                pop     ecx
                pop     ecx

loc_E3146C:                             ; CODE XREF: sub_E31449+15↑j
                mov     eax, [ebp+Block]
                leave
                retn    4
sub_E31449      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _DWORD *__thiscall sub_E31473(_DWORD *this, int)
sub_E31473      proc near               ; CODE XREF: sub_E314D2+F↓p

var_4           = dword ptr -4
arg_0           = dword ptr  8

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+var_4], ecx
                push    1
                push    [ebp+arg_0]
                mov     ecx, [ebp+var_4]
                call    sub_E3139A
                mov     eax, [ebp+var_4]
                mov     dword ptr [eax], offset ??_7bad_alloc@std@@6B@ ; const std::bad_alloc::`vftable'
                mov     eax, [ebp+var_4]
                leave
                retn    4
sub_E31473      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _DWORD *__thiscall sub_E31497(_DWORD *this, char)
sub_E31497      proc near               ; DATA XREF: .rdata:const std::bad_alloc::`vftable'↓o
                                        ; .rdata:const std::bad_cast::`vftable'↓o

Block           = dword ptr -4
arg_0           = dword ptr  8

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+Block], ecx
                mov     ecx, [ebp+Block]
                call    sub_E314C1
                mov     eax, [ebp+arg_0]
                and     eax, 1
                jz      short loc_E314BA
                push    0Ch
                push    [ebp+Block]     ; Block
                call    sub_E35312
                pop     ecx
                pop     ecx

loc_E314BA:                             ; CODE XREF: sub_E31497+15↑j
                mov     eax, [ebp+Block]
                leave
                retn    4
sub_E31497      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int __thiscall sub_E314C1(_DWORD *this)
sub_E314C1      proc near               ; CODE XREF: sub_E31497+A↑p
                                        ; sub_E3151E+A↓p
                                        ; DATA XREF: ...

var_4           = dword ptr -4

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+var_4], ecx
                mov     ecx, [ebp+var_4]
                call    sub_E31401
                leave
                retn
sub_E314C1      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _DWORD *__thiscall sub_E314D2(_DWORD *this)
sub_E314D2      proc near               ; CODE XREF: sub_E3152F+9↓p
                                        ; sub_E355CC+9↓p

var_4           = dword ptr -4

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+var_4], ecx
                push    offset aBadArrayNewLen ; "bad array new length"
                mov     ecx, [ebp+var_4]
                call    sub_E31473
                mov     eax, [ebp+var_4]
                mov     dword ptr [eax], offset ??_7bad_array_new_length@std@@6B@ ; const std::bad_array_new_length::`vftable'
                mov     eax, [ebp+var_4]
                leave
                retn
sub_E314D2      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _DWORD *__thiscall sub_E314F4(_DWORD *this, char)
sub_E314F4      proc near               ; DATA XREF: .rdata:const std::bad_array_new_length::`vftable'↓o

Block           = dword ptr -4
arg_0           = dword ptr  8

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+Block], ecx
                mov     ecx, [ebp+Block]
                call    sub_E3151E
                mov     eax, [ebp+arg_0]
                and     eax, 1
                jz      short loc_E31517
                push    0Ch
                push    [ebp+Block]     ; Block
                call    sub_E35312
                pop     ecx
                pop     ecx

loc_E31517:                             ; CODE XREF: sub_E314F4+15↑j
                mov     eax, [ebp+Block]
                leave
                retn    4
sub_E314F4      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int __thiscall sub_E3151E(_DWORD *this)
sub_E3151E      proc near               ; CODE XREF: sub_E314F4+A↑p
                                        ; DATA XREF: .rdata:00E37E2C↓o

var_4           = dword ptr -4

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+var_4], ecx
                mov     ecx, [ebp+var_4]
                call    sub_E314C1
                leave
                retn
sub_E3151E      endp


; =============== S U B R O U T I N E =======================================

; Attributes: noreturn bp-based frame

; void __cdecl __noreturn sub_E3152F()
sub_E3152F      proc near               ; CODE XREF: sub_E32D4A+19↓p
                                        ; sub_E33533+17↓p

pExceptionObject= dword ptr -0Ch

                push    ebp
                mov     ebp, esp
                sub     esp, 0Ch
                lea     ecx, [ebp+pExceptionObject]
                call    sub_E314D2
                push    offset __TI3?AVbad_array_new_length@std@@ ; pThrowInfo
                lea     eax, [ebp+pExceptionObject]
                push    eax             ; pExceptionObject
                call    _CxxThrowException
sub_E3152F      endp

; ---------------------------------------------------------------------------
                leave
                retn

; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _DWORD *__thiscall sub_E3154D(_DWORD *this, int)
sub_E3154D      proc near               ; DATA XREF: .rdata:00E37E50↓o

var_4           = dword ptr -4
arg_0           = dword ptr  8

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+var_4], ecx
                push    [ebp+arg_0]
                mov     ecx, [ebp+var_4]
                call    sub_E3156F
                mov     eax, [ebp+var_4]
                mov     dword ptr [eax], offset ??_7bad_array_new_length@std@@6B@ ; const std::bad_array_new_length::`vftable'
                mov     eax, [ebp+var_4]
                leave
                retn    4
sub_E3154D      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _DWORD *__thiscall sub_E3156F(_DWORD *this, int)
sub_E3156F      proc near               ; CODE XREF: sub_E3154D+D↑p
                                        ; DATA XREF: .rdata:00E37DD0↓o

var_4           = dword ptr -4
arg_0           = dword ptr  8

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+var_4], ecx
                push    [ebp+arg_0]
                mov     ecx, [ebp+var_4]
                call    sub_E313C7
                mov     eax, [ebp+var_4]
                mov     dword ptr [eax], offset ??_7bad_alloc@std@@6B@ ; const std::bad_alloc::`vftable'
                mov     eax, [ebp+var_4]
                leave
                retn    4
sub_E3156F      endp

; [0000000A BYTES: COLLAPSED FUNCTION std::numeric_limits<int>::min(void). PRESS CTRL-NUMPAD+ TO EXPAND]
; [0000000A BYTES: COLLAPSED FUNCTION unknown_libname_1. PRESS CTRL-NUMPAD+ TO EXPAND]
; [00000007 BYTES: COLLAPSED FUNCTION gCrucialEncode. PRESS CTRL-NUMPAD+ TO EXPAND]
; [0000000A BYTES: COLLAPSED FUNCTION MicrosoftVisualC14netruntime2. PRESS CTRL-NUMPAD+ TO EXPAND]

; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; __int64 sub_E315B6()
sub_E315B6      proc near               ; CODE XREF: sub_E3296C+11↓p
                push    ebp
                mov     ebp, esp
                xor     eax, eax
                xor     edx, edx
                pop     ebp
                retn
sub_E315B6      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; __int64 sub_E315BF()
sub_E315BF      proc near               ; CODE XREF: sub_E3296C+6↓p
                push    ebp
                mov     ebp, esp
                or      eax, 0FFFFFFFFh
                or      edx, 0FFFFFFFFh
                pop     ebp
                retn
sub_E315BF      endp

; [0000000E BYTES: COLLAPSED FUNCTION operator new(uint,int,char const *,int). PRESS CTRL-NUMPAD+ TO EXPAND]

; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _DWORD *__cdecl sub_E315D8(_DWORD *, _DWORD *)
sub_E315D8      proc near               ; CODE XREF: sub_E32D9C+29↓p

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

loc_E31614:                             ; CODE XREF: sub_E315D8+56↓j
                cmp     [ebp+var_4], 4
                jb      short loc_E31622
                cmp     [ebp+var_4], 23h ; '#'
                ja      short loc_E31622
                jmp     short loc_E3162C
; ---------------------------------------------------------------------------

loc_E31622:                             ; CODE XREF: sub_E315D8+40↑j
                                        ; sub_E315D8+46↑j ...
                call    ds:_invalid_parameter_noinfo_noreturn
; ---------------------------------------------------------------------------
                xor     eax, eax
                jnz     short loc_E31622

loc_E3162C:                             ; CODE XREF: sub_E315D8+48↑j
                xor     eax, eax
                jnz     short loc_E31614
                mov     eax, [ebp+arg_0]
                mov     ecx, [ebp+var_8]
                mov     [eax], ecx
                leave
                retn
sub_E315D8      endp

; [00000008 BYTES: COLLAPSED FUNCTION MicrosoftVisualC14netruntime. PRESS CTRL-NUMPAD+ TO EXPAND]

; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; void aEncode()
                public aEncode
aEncode         proc near               ; CODE XREF: dEncode+D0↓p
                                        ; sub_E320BA+5D↓p ...

var_4           = dword ptr -4

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+var_4], ecx
                leave
                retn
aEncode         endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; void __stdcall sub_E3164B(int)
sub_E3164B      proc near               ; CODE XREF: sub_E31F52+27↓p

var_4           = dword ptr -4

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+var_4], ecx
                leave
                retn    4
sub_E3164B      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; void *__thiscall bEncode(void *this, int, int)
                public bEncode
bEncode         proc near               ; CODE XREF: dEncode+7B↓p
                                        ; sub_E320BA+42↓p

var_4           = dword ptr -4

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+var_4], ecx
                mov     eax, [ebp+var_4]
                leave
                retn    8
bEncode         endp


; =============== S U B R O U T I N E =======================================

; Attributes: noreturn bp-based frame

; void __noreturn sub_E31664()
sub_E31664      proc near               ; CODE XREF: sub_E32B4B+28↓p
                                        ; sub_E32C68+16↓p
                push    ebp
                mov     ebp, esp
                push    offset aStringTooLong ; "string too long"
                call    ds:?_Xlength_error@std@@YAXPBD@Z ; std::_Xlength_error(char const *)
sub_E31664      endp

; ---------------------------------------------------------------------------
                pop     ebp
                retn

; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _DWORD *__thiscall sub_E31674(_DWORD *this)
sub_E31674      proc near               ; CODE XREF: sub_E31698+9↓p

var_4           = dword ptr -4

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+var_4], ecx
                push    1
                push    offset aBadCast ; "bad cast"
                mov     ecx, [ebp+var_4]
                call    sub_E3139A
                mov     eax, [ebp+var_4]
                mov     dword ptr [eax], offset ??_7bad_cast@std@@6B@ ; const std::bad_cast::`vftable'
                mov     eax, [ebp+var_4]
                leave
                retn
sub_E31674      endp


; =============== S U B R O U T I N E =======================================

; Attributes: noreturn bp-based frame

; void __noreturn sub_E31698()
sub_E31698      proc near               ; CODE XREF: sub_E32823+77↓p

pExceptionObject= dword ptr -0Ch

                push    ebp
                mov     ebp, esp
                sub     esp, 0Ch
                lea     ecx, [ebp+pExceptionObject]
                call    sub_E31674
                push    offset __TI2?AVbad_cast@std@@ ; pThrowInfo
                lea     eax, [ebp+pExceptionObject]
                push    eax             ; pExceptionObject
                call    _CxxThrowException
sub_E31698      endp

; ---------------------------------------------------------------------------
                leave
                retn

; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _DWORD *__thiscall sub_E316B6(_DWORD *this, int)
sub_E316B6      proc near               ; DATA XREF: .rdata:00E37DF8↓o

var_4           = dword ptr -4
arg_0           = dword ptr  8

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+var_4], ecx
                push    [ebp+arg_0]
                mov     ecx, [ebp+var_4]
                call    sub_E313C7
                mov     eax, [ebp+var_4]
                mov     dword ptr [eax], offset ??_7bad_cast@std@@6B@ ; const std::bad_cast::`vftable'
                mov     eax, [ebp+var_4]
                leave
                retn    4
sub_E316B6      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int (__thiscall ***__thiscall sub_E316D8(_DWORD **this))(_DWORD, int)
sub_E316D8      proc near               ; CODE XREF: sub_E32F66+89↓p
                                        ; sub_E32F66+363F↓j

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
                jz      short locret_E3171F
                mov     eax, [ebp+var_4]
                mov     eax, [eax+4]
                mov     ecx, [ebp+var_4]
                mov     eax, [eax]
                mov     ecx, [ecx+4]
                call    dword ptr [eax+8]
                mov     [ebp+var_8], eax
                cmp     [ebp+var_8], 0
                jz      short loc_E3171B
                mov     eax, [ebp+var_8]
                mov     eax, [eax]
                mov     eax, [eax]
                mov     [ebp+var_C], eax
                push    1
                mov     ecx, [ebp+var_8]
                call    [ebp+var_C]
                mov     [ebp+var_10], eax
                jmp     short locret_E3171F
; ---------------------------------------------------------------------------

loc_E3171B:                             ; CODE XREF: sub_E316D8+2A↑j
                and     [ebp+var_10], 0

locret_E3171F:                          ; CODE XREF: sub_E316D8+10↑j
                                        ; sub_E316D8+41↑j
                leave
                retn
sub_E316D8      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int __thiscall sub_E31721(_DWORD *this, unsigned int)
sub_E31721      proc near               ; CODE XREF: sub_E32823+47↓p

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
                jnb     short loc_E3174C
                mov     eax, [ebp+var_4]
                mov     eax, [eax+4]
                mov     eax, [eax+8]
                mov     ecx, [ebp+arg_0]
                mov     eax, [eax+ecx*4]
                mov     [ebp+var_8], eax
                jmp     short loc_E31750
; ---------------------------------------------------------------------------

loc_E3174C:                             ; CODE XREF: sub_E31721+15↑j
                and     [ebp+var_8], 0

loc_E31750:                             ; CODE XREF: sub_E31721+29↑j
                mov     eax, [ebp+var_8]
                mov     [ebp+var_C], eax
                cmp     [ebp+var_C], 0
                jnz     short loc_E3176A
                mov     eax, [ebp+var_4]
                mov     eax, [eax+4]
                movzx   eax, byte ptr [eax+14h]
                test    eax, eax
                jnz     short loc_E3176F

loc_E3176A:                             ; CODE XREF: sub_E31721+39↑j
                mov     eax, [ebp+var_C]
                jmp     short locret_E31793
; ---------------------------------------------------------------------------

loc_E3176F:                             ; CODE XREF: sub_E31721+47↑j
                call    ds:?_Getgloballocale@locale@std@@CAPAV_Locimp@12@XZ ; std::locale::_Getgloballocale(void)
                mov     [ebp+var_10], eax
                mov     eax, [ebp+var_10]
                mov     ecx, [ebp+arg_0]
                cmp     ecx, [eax+0Ch]
                jnb     short loc_E31791
                mov     eax, [ebp+var_10]
                mov     eax, [eax+8]
                mov     ecx, [ebp+arg_0]
                mov     eax, [eax+ecx*4]
                jmp     short locret_E31793
; ---------------------------------------------------------------------------

loc_E31791:                             ; CODE XREF: sub_E31721+60↑j
                xor     eax, eax

locret_E31793:                          ; CODE XREF: sub_E31721+4C↑j
                                        ; sub_E31721+6E↑j
                leave
                retn    4
sub_E31721      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _DWORD *__cdecl sub_E31797(_DWORD *)
sub_E31797      proc near               ; CODE XREF: sub_E33C80+26↓p

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
                call    sub_E31864
                push    eax
                mov     ecx, [ebp+arg_0]
                call    sub_E31F83
                mov     eax, [ebp+arg_0]
                leave
                retn
sub_E31797      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _DWORD *__cdecl sub_E317C3(_DWORD *)
sub_E317C3      proc near               ; CODE XREF: sub_E32943+D↓p
                                        ; sub_E33230+A↓p

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
                call    sub_E31864
                push    eax
                mov     ecx, [ebp+arg_0]
                call    sub_E31F83
                mov     eax, [ebp+arg_0]
                leave
                retn
sub_E317C3      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _DWORD *__thiscall sub_E31864(_DWORD *this, _DWORD *)
sub_E31864      proc near               ; CODE XREF: sub_E31797+19↑p
                                        ; sub_E317C3+8E↑p ...

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
sub_E31864      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; __int64 __thiscall sub_E31882(void *this)
sub_E31882      proc near               ; CODE XREF: sub_E33BCB+19↓p
                                        ; sub_E33BCB+2F↓p ...

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
sub_E31882      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; double __thiscall sub_E31893(void *this)
sub_E31893      proc near               ; CODE XREF: sub_E34061+13↓p
                                        ; sub_E34061+32↓p ...

var_4           = dword ptr -4

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+var_4], ecx
                mov     eax, [ebp+var_4]
                fld     qword ptr [eax]
                leave
                retn
sub_E31893      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; void *__thiscall jCrucialEncode(void *this)
                public jCrucialEncode
jCrucialEncode  proc near               ; CODE XREF: kEncode+A↓p
                                        ; sub_E32B03+A↓p ...

var_4           = dword ptr -4

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+var_4], ecx
                mov     eax, [ebp+var_4]
                leave
                retn
jCrucialEncode  endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; unsigned int kCrucialEncode()
                public kCrucialEncode
kCrucialEncode  proc near               ; CODE XREF: sub_E33285+18↓p
                                        ; hCrucialEncode+18↓p ...

var_4           = dword ptr -4

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+var_4], ecx
                call    ds:?_Random_device@std@@YAIXZ ; std::_Random_device(void)
                leave
                retn
kCrucialEncode  endp


; =============== S U B R O U T I N E =======================================

; Attributes: fuzzy-sp

; int *__userpurge sub_E318BC@<eax>(int *@<ecx>, int@<ebp>, _DWORD *)
sub_E318BC      proc near               ; CODE XREF: sub_E31000+35↑p
                                        ; sub_E3105D+35↑p ...

anonymous_0     = dword ptr -0Ch
var_8           = dword ptr -8

; FUNCTION CHUNK AT 00E364BD SIZE 00000008 BYTES
; FUNCTION CHUNK AT 00E364CA SIZE 0000000C BYTES

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
                push    offset loc_E364CA
                mov     eax, large fs:0
                push    eax
                mov     large fs:0, esp
                push    ebx
                sub     esp, 20h
                mov     [ebp-18h], ecx
                mov     ecx, [ebp-18h]
                call    sub_E31F52
                and     dword ptr [ebp-4], 0
                mov     eax, [ebp-18h]
                mov     [ebp-1Ch], eax
                mov     ecx, [ebx+8]
                call    sub_E31FBF
                push    eax
                mov     ecx, [ebp-1Ch]
                call    sub_E31E40
                and     dword ptr [ebp-14h], 0
                jmp     short loc_E3191D
; ---------------------------------------------------------------------------

loc_E31916:                             ; CODE XREF: sub_E318BC+AC↓j
                mov     eax, [ebp-14h]
                inc     eax
                mov     [ebp-14h], eax

loc_E3191D:                             ; CODE XREF: sub_E318BC+58↑j
                mov     ecx, [ebx+8]
                call    sub_E31FBF
                cmp     [ebp-14h], eax
                jnb     short loc_E3196A
                push    dword ptr [ebp-14h]
                mov     ecx, [ebx+8]
                call    sub_E3208B
                movsx   eax, byte ptr [eax]
                push    eax
                lea     ecx, [ebp-30h]
                call    sub_E31DDF
                mov     ecx, [eax]
                mov     eax, [eax+4]
                mov     [ebp-28h], ecx
                mov     [ebp-24h], eax
                mov     eax, [ebp-18h]
                mov     [ebp-20h], eax
                push    dword ptr [ebp-14h]
                mov     ecx, [ebp-20h]
                call    sub_E31E05
                mov     ecx, [ebp-28h]
                mov     edx, [ebp-24h]
                mov     [eax], ecx
                mov     [eax+4], edx
                jmp     short loc_E31916
; ---------------------------------------------------------------------------

loc_E3196A:                             ; CODE XREF: sub_E318BC+6C↑j
                or      dword ptr [ebp-4], 0FFFFFFFFh
                mov     eax, [ebp-18h]
                mov     ecx, [ebp-0Ch]
                mov     large fs:0, ecx
                mov     esp, ebp
                pop     ebp
                mov     esp, ebx
                pop     ebx
                retn    4
sub_E318BC      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int __thiscall sub_E31984(_DWORD *this, int)
sub_E31984      proc near               ; CODE XREF: eEncode+109↓p
                                        ; eEncode+133↓p

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
                call    sub_E31E05
                leave
                retn    4
sub_E31984      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int *__thiscall cEncode::bCrucialEncode(int *this, int *)
                public cEncode__bCrucialEncode
cEncode__bCrucialEncode proc near       ; CODE XREF: eEncode+24↓p
                                        ; eEncode+35↓p ...

var_10          = dword ptr -10h
var_C           = dword ptr -0Ch
arg_0           = dword ptr  8

; FUNCTION CHUNK AT 00E364D6 SIZE 0000000C BYTES

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
                call    dEncode
                mov     eax, [ebp+arg_0]
                mov     ecx, [ebp+var_C]
                mov     large fs:0, ecx
                leave
                retn    4
cEncode__bCrucialEncode endp

; ---------------------------------------------------------------------------
                db 5 dup(0CCh)

; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int *__thiscall sub_E319DE(int *this)
sub_E319DE      proc near               ; CODE XREF: _main+6A↓p
                                        ; _main+B0↓p ...

var_4           = dword ptr -4

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+var_4], ecx
                mov     ecx, [ebp+var_4]
                call    sub_E31E5B
                leave
                retn
sub_E319DE      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int *__cdecl aGetInput(int *)
                public aGetInput
aGetInput       proc near               ; CODE XREF: _main+48↓p

UserInput       = byte ptr -28h
var_10          = dword ptr -10h
var_C           = dword ptr -0Ch
var_4           = dword ptr -4
arg_0           = dword ptr  8

; FUNCTION CHUNK AT 00E364FB SIZE 00000008 BYTES
; FUNCTION CHUNK AT 00E36508 SIZE 0000000C BYTES

                push    ebp
                mov     ebp, esp
                push    0FFFFFFFFh
                push    offset SEH_4019EF
                mov     eax, large fs:0
                push    eax
                mov     large fs:0, esp
                sub     esp, 1Ch
                and     [ebp+var_10], 0
                push    offset aPassword ; "Password: "
                call    printf
                pop     ecx
                push    offset aV2      ; "v2"
                lea     ecx, [ebp+UserInput]
                call    sub_E320BA
                and     [ebp+var_4], 0
                lea     eax, [ebp+UserInput]
                push    eax
                push    ds:?cin@std@@3V?$basic_istream@DU?$char_traits@D@std@@@1@A ; std::istream std::cin
                call    bGetInput
                pop     ecx
                pop     ecx
                lea     eax, [ebp+UserInput]
                push    eax
                mov     ecx, [ebp+arg_0]
                call    sub_E318BC
                mov     eax, [ebp+var_10]
                or      eax, 1
                mov     [ebp+var_10], eax
                or      [ebp+var_4], 0FFFFFFFFh
                lea     ecx, [ebp+UserInput]
                call    gEncode
                mov     eax, [ebp+arg_0]
                mov     ecx, [ebp+var_C]
                mov     large fs:0, ecx
                leave
                retn
aGetInput       endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; char __cdecl eEncode(int *)
                public eEncode
eEncode         proc near               ; CODE XREF: _main+56↓p

var_54          = dword ptr -54h
var_48          = dword ptr -48h
var_3C          = dword ptr -3Ch
var_30          = word ptr -30h
var_2C          = dword ptr -2Ch
var_28          = dword ptr -28h
var_24          = dword ptr -24h
var_20          = dword ptr -20h
var_1C          = word ptr -1Ch
var_18          = dword ptr -18h
var_14          = word ptr -14h
var_E           = byte ptr -0Eh
var_D           = byte ptr -0Dh
var_C           = dword ptr -0Ch
var_4           = dword ptr -4
arg_0           = dword ptr  8

; FUNCTION CHUNK AT 00E36514 SIZE 00000008 BYTES
; FUNCTION CHUNK AT 00E36521 SIZE 0000000C BYTES

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
                lea     eax, [ebp-72]
                push    eax
                mov     ecx, [ebp+8]
                call    cEncode__bCrucialEncode
                mov     [ebp+var_24], eax
                lea     eax, [ebp+var_3C]
                push    eax
                mov     ecx, offset dword_E39434
                call    cEncode__bCrucialEncode
                mov     [ebp+var_20], eax
                mov     ecx, [ebp+var_20]
                call    fEncode__cCrucialEncode
                mov     esi, eax
                mov     ecx, [ebp+var_24]
                call    fEncode__cCrucialEncode
                cmp     eax, esi
                jz      short loc_E31AC7
                mov     [ebp+var_18], 1
                jmp     short loc_E31ACB
; ---------------------------------------------------------------------------

loc_E31AC7:                             ; CODE XREF: eEncode+51↑j
                and     [ebp+var_18], 0

loc_E31ACB:                             ; CODE XREF: eEncode+5A↑j
                mov     al, byte ptr [ebp+var_18]
                mov     [ebp+var_D], al
                lea     ecx, [ebp+var_3C]
                call    sub_E31E5B
                lea     ecx, [ebp+var_48]
                call    sub_E31E5B
                movzx   eax, [ebp+var_D]
                test    eax, eax
                jz      short loc_E31AF0
                xor     al, al
                jmp     loc_E31BBB
; ---------------------------------------------------------------------------

loc_E31AF0:                             ; CODE XREF: eEncode+7C↑j
                push    0
                lea     ecx, [ebp-14h]
                call    aCrucialEncode
                push    7
                lea     ecx, [ebp+var_1C]
                call    aCrucialEncode
                jmp     short loc_E31B16
; ---------------------------------------------------------------------------

loc_E31B06:                             ; CODE XREF: eEncode:loc_E31BB4↓j
                lea     ecx, [ebp+var_14]
                call    sub_E31D73
                lea     ecx, [ebp+var_1C]
                call    sub_E31D73

loc_E31B16:                             ; CODE XREF: eEncode+99↑j
                lea     eax, [ebp-54h]
                push    eax
                mov     ecx, offset dword_E39434
                call    cEncode__bCrucialEncode
                mov     [ebp+var_28], eax
                mov     eax, [ebp+var_28]
                mov     [ebp+var_2C], eax
                and     [ebp+var_4], 0
                mov     ecx, [ebp+var_2C]
                call    fEncode__cCrucialEncode
                push    eax
                lea     ecx, [ebp-30h]
                call    aCrucialEncode
                lea     eax, [ebp+var_30]
                push    eax
                lea     ecx, [ebp-14h]
                call    dCrucialEncode
                mov     [ebp-0Eh], al
                or      [ebp+var_4], 0FFFFFFFFh
                lea     ecx, [ebp+var_54]
                call    sub_E31E5B
                movzx   eax, [ebp+var_E]
                test    eax, eax
                jz      short loc_E31BB9
                lea     ecx, [ebp+var_14]
                call    eCrucialEncode
                movzx   eax, ax
                push    eax
                mov     ecx, [ebp+arg_0]
                call    sub_E31984
                mov     ecx, eax
                call    sub_E31DCB
                mov     esi, eax
                lea     ecx, [ebp+var_1C]
                call    eCrucialEncode
                movzx   edi, ax
                lea     ecx, [ebp+var_14]
                call    eCrucialEncode
                movzx   eax, ax
                push    eax
                mov     ecx, offset dword_E39434
                call    sub_E31984
                mov     ecx, eax
                call    sub_E31DCB
                xor     edi, eax
                cmp     esi, edi
                jz      short loc_E31BB4
                xor     al, al
                jmp     short loc_E31BBB
; ---------------------------------------------------------------------------

loc_E31BB4:                             ; CODE XREF: eEncode+143↑j
                jmp     loc_E31B06
; ---------------------------------------------------------------------------

loc_E31BB9:                             ; CODE XREF: eEncode+F8↑j
                mov     al, 1

loc_E31BBB:                             ; CODE XREF: eEncode+80↑j
                                        ; eEncode+147↑j
                mov     ecx, [ebp+var_C]
                mov     large fs:0, ecx
                pop     edi
                pop     esi
                leave
                retn
eEncode         endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int __cdecl main(int argc, const char **argv, const char **envp)
_main           proc near               ; CODE XREF: __scrt_common_main_seh(void)+F5↓p

var_34          = dword ptr -34h
var_24          = dword ptr -24h
var_18          = qword ptr -18h
var_10          = dword ptr -10h
var_C           = dword ptr -0Ch
var_4           = dword ptr -4
argc            = dword ptr  8
argv            = dword ptr  0Ch
envp            = dword ptr  10h

; FUNCTION CHUNK AT 00E3652D SIZE 00000008 BYTES
; FUNCTION CHUNK AT 00E3653A SIZE 0000000C BYTES

                push    ebp
                mov     ebp, esp
                push    0FFFFFFFFh
                push    offset _main_SEH
                mov     eax, large fs:0
                push    eax
                mov     large fs:0, esp
                sub     esp, 28h
                lea     ecx, [ebp+var_34]
                call    sub_E31CF9
                push    offset aMain    ; "main"
                push    offset aS       ; "%s()\n"
                call    printf
                pop     ecx
                pop     ecx
                push    offset aFindCorrectPas ; "Find correct password\n"
                call    printf
                pop     ecx

loc_E31C08:                             ; CODE XREF: _main+B5↓j
                xor     eax, eax
                inc     eax
                jz      short loc_E31C80
                lea     eax, [ebp+var_24]
                push    eax
                call    aGetInput
                pop     ecx
                and     [ebp+var_4], 0
                lea     eax, [ebp+var_24]
                push    eax
                call    eEncode
                pop     ecx
                movzx   eax, al
                test    eax, eax
                jz      short loc_E31C3A
                or      [ebp+var_4], 0FFFFFFFFh
                lea     ecx, [ebp+var_24]
                call    sub_E319DE
                jmp     short loc_E31C80
; ---------------------------------------------------------------------------

loc_E31C3A:                             ; CODE XREF: _main+61↑j
                lea     ecx, [ebp+var_34]
                call    sub_E31CC5
                mov     ecx, eax
                call    sub_E31CA5
                push    edx
                push    eax
                push    offset aIncorrectLlu ; "Incorrect!(%llu)\n"
                call    printf
                add     esp, 0Ch
                mov     [ebp+var_10], 0C8h
                lea     eax, [ebp+var_10]
                push    eax
                lea     ecx, [ebp+var_18]
                call    sub_E32927
                push    eax
                call    sub_E32943
                pop     ecx
                or      [ebp+var_4], 0FFFFFFFFh
                lea     ecx, [ebp+var_24]
                call    sub_E319DE
                jmp     short loc_E31C08
; ---------------------------------------------------------------------------

loc_E31C80:                             ; CODE XREF: _main+42↑j
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
_main           endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; __int64 __thiscall sub_E31CA5(_QWORD *this)
sub_E31CA5      proc near               ; CODE XREF: _main+7B↑p
                                        ; sub_E3216E+C↓p ...

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
sub_E31CA5      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _QWORD *__thiscall sub_E31CC5(_QWORD *this)
sub_E31CC5      proc near               ; CODE XREF: _main+74↑p

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
                call    sub_E321A2
                push    eax
                lea     eax, [ebp+var_24]
                push    eax
                mov     ecx, [ebp+var_4]
                call    sub_E3216E
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
sub_E31CC5      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int *__thiscall sub_E31CF9(int *this)
sub_E31CF9      proc near               ; CODE XREF: _main+1E↑p

var_4           = dword ptr -4

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+var_4], ecx
                call    sub_E3296C
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
sub_E31CF9      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int __thiscall eCrucialEncode(unsigned __int16 *this)
                public eCrucialEncode
eCrucialEncode  proc near               ; CODE XREF: eEncode+FD↑p
                                        ; eEncode+11A↑p ...

var_4           = dword ptr -4

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+var_4], ecx
                mov     eax, [ebp+var_4]
                movzx   eax, word ptr [eax+2]
                mov     ecx, [ebp+var_4]
                movzx   ecx, word ptr [ecx]
                xor     eax, ecx
                leave
                retn
eCrucialEncode  endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; bool __thiscall dCrucialEncode(unsigned __int16 *this, unsigned __int16 *)
                public dCrucialEncode
dCrucialEncode  proc near               ; CODE XREF: eEncode+DE↑p

var_8           = dword ptr -8
var_4           = dword ptr -4
arg_0           = dword ptr  8

                push    ebp
                mov     ebp, esp
                push    ecx
                push    ecx
                push    esi
                mov     [ebp+var_8], ecx
                mov     ecx, [ebp+var_8]
                call    eCrucialEncode
                movzx   esi, ax
                mov     ecx, [ebp+arg_0]
                call    eCrucialEncode
                movzx   eax, ax
                cmp     esi, eax
                jge     short loc_E31D67
                mov     [ebp+var_4], 1
                jmp     short loc_E31D6B
; ---------------------------------------------------------------------------

loc_E31D67:                             ; CODE XREF: dCrucialEncode+21↑j
                and     [ebp+var_4], 0

loc_E31D6B:                             ; CODE XREF: dCrucialEncode+2A↑j
                mov     al, byte ptr [ebp+var_4]
                pop     esi
                leave
                retn    4
dCrucialEncode  endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; unsigned __int16 *__thiscall sub_E31D73(unsigned __int16 *this)
sub_E31D73      proc near               ; CODE XREF: eEncode+9E↑p
                                        ; eEncode+A6↑p

var_C           = word ptr -0Ch
var_8           = word ptr -8
var_4           = dword ptr -4

                push    ebp
                mov     ebp, esp
                sub     esp, 0Ch
                mov     [ebp+var_4], ecx
                push    1
                lea     ecx, [ebp+var_8]
                call    aCrucialEncode
                push    eax
                lea     eax, [ebp+var_C]
                push    eax
                mov     ecx, [ebp+var_4]
                call    sub_E321D4
                mov     eax, [eax]
                mov     ecx, [ebp+var_4]
                mov     [ecx], eax
                mov     eax, [ebp+var_4]
                leave
                retn
sub_E31D73      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; __int16 *__thiscall aCrucialEncode(__int16 *this, __int16)
                public aCrucialEncode
aCrucialEncode  proc near               ; CODE XREF: eEncode+8A↑p
                                        ; eEncode+94↑p ...

var_4           = dword ptr -4
arg_0           = word ptr  8

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+var_4], ecx
                call    fCrucialEncode
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
aCrucialEncode  endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int __thiscall sub_E31DCB(_DWORD *this)
sub_E31DCB      proc near               ; CODE XREF: eEncode+110↑p
                                        ; eEncode+13A↑p

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
sub_E31DCB      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int *__thiscall sub_E31DDF(int *this, int)
sub_E31DDF      proc near               ; CODE XREF: sub_E318BC+80↑p

var_4           = dword ptr -4
arg_0           = dword ptr  8

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+var_4], ecx
                call    sub_E329C4
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
sub_E31DDF      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int __thiscall sub_E31E05(_DWORD *this, int)
sub_E31E05      proc near               ; CODE XREF: sub_E318BC+9C↑p
                                        ; sub_E31984+14↑p

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
sub_E31E05      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int __thiscall fEncode::cCrucialEncode(_DWORD *this)
                public fEncode__cCrucialEncode
fEncode__cCrucialEncode proc near       ; CODE XREF: eEncode+40↑p
                                        ; eEncode+4A↑p ...

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
fEncode__cCrucialEncode endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; void __thiscall sub_E31E40(int *this, unsigned int)
sub_E31E40      proc near               ; CODE XREF: sub_E318BC+4F↑p

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
                call    sub_E329E8
                leave
                retn    4
sub_E31E40      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int *__thiscall sub_E31E5B(int *this)
sub_E31E5B      proc near               ; CODE XREF: sub_E319DE+A↑p
                                        ; eEncode+69↑p ...

var_4           = dword ptr -4

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+var_4], ecx
                mov     ecx, [ebp+var_4]
                call    sub_E32216
                leave
                retn
sub_E31E5B      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int *__thiscall dEncode(int *this, int *)
                public dEncode
dEncode         proc near               ; CODE XREF: cEncode__bCrucialEncode+22↑p

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

; FUNCTION CHUNK AT 00E36546 SIZE 00000008 BYTES
; FUNCTION CHUNK AT 00E36553 SIZE 0000000C BYTES

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
                call    kEncode
                push    eax
                lea     eax, [ebp+var_E]
                push    eax
                call    MicrosoftVisualC14netruntime ; Microsoft VisualC 14/net runtime
                pop     ecx
                pop     ecx
                mov     [ebp+var_2C], eax
                mov     al, [ebp+var_F]
                mov     byte ptr [ebp+var_30], al
                push    [ebp+var_2C]
                push    [ebp+var_30]
                mov     ecx, [ebp+var_34]
                call    qEncode
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
                call    bEncode
                mov     eax, [ebp+var_1C]
                cmp     eax, [ebp+var_18]
                jz      short loc_E31F39
                mov     eax, [ebp+var_18]
                sub     eax, [ebp+var_1C]
                sar     eax, 3
                push    eax
                mov     ecx, [ebp+var_14]
                call    lEncode
                mov     eax, [ebp+var_14]
                mov     [ebp+var_28], eax
                and     [ebp+var_4], 0
                mov     eax, [ebp+var_20]
                push    dword ptr [eax]
                push    [ebp+var_18]
                push    [ebp+var_1C]
                mov     ecx, [ebp+var_14]
                call    rEncode
                mov     ecx, [ebp+var_20]
                mov     [ecx+4], eax
                and     [ebp+var_28], 0
                or      [ebp+var_4], 0FFFFFFFFh
                lea     ecx, [ebp+var_28]
                call    jEncode

loc_E31F39:                             ; CODE XREF: dEncode+86↑j
                lea     ecx, [ebp+var_D]
                call    aEncode
                mov     eax, [ebp+var_14]
                mov     ecx, [ebp+var_C]
                mov     large fs:0, ecx
                leave
                retn    4
dEncode         endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _DWORD *__thiscall sub_E31F52(_DWORD *this)
sub_E31F52      proc near               ; CODE XREF: sub_E318BC+34↑p

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
                call    sub_E32B03
                mov     eax, [ebp+var_8]
                mov     [ebp+var_10], eax
                lea     eax, [ebp+var_1]
                push    eax
                mov     ecx, [ebp+var_10]
                call    sub_E3164B
                mov     eax, [ebp+var_8]
                leave
                retn
sub_E31F52      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _DWORD *__thiscall sub_E31F83(_DWORD *this, _DWORD *)
sub_E31F83      proc near               ; CODE XREF: sub_E31797+22↑p
                                        ; sub_E317C3+97↑p ...

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
sub_E31F83      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _DWORD *__thiscall sub_E31FA1(_DWORD *this, _DWORD *)
sub_E31FA1      proc near               ; CODE XREF: sub_E33200+10↓p
                                        ; sub_E33C46+D↓p ...

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
sub_E31FA1      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int __thiscall sub_E31FBF(_DWORD *this)
sub_E31FBF      proc near               ; CODE XREF: sub_E318BC+46↑p
                                        ; sub_E318BC+64↑p

var_4           = dword ptr -4

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+var_4], ecx
                mov     eax, [ebp+var_4]
                mov     eax, [eax+10h]
                leave
                retn
sub_E31FBF      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; unsigned int *__thiscall sub_E31FCE(size_t *this, char)
sub_E31FCE      proc near               ; CODE XREF: sub_E32F66+1CE↓p

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
                jnb     short loc_E3202E
                mov     eax, [ebp+var_C]
                inc     eax
                mov     ecx, [ebp+var_8]
                mov     [ecx+10h], eax
                mov     ecx, [ebp+var_8]
                call    sub_E324C0
                mov     [ebp+var_10], eax
                lea     eax, [ebp+arg_0]
                push    eax
                mov     eax, [ebp+var_10]
                add     eax, [ebp+var_C]
                push    eax
                call    nEncode
                pop     ecx
                pop     ecx
                mov     [ebp+var_1], 0
                lea     eax, [ebp+var_1]
                push    eax
                mov     eax, [ebp+var_C]
                mov     ecx, [ebp+var_10]
                lea     eax, [ecx+eax+1]
                push    eax
                call    nEncode
                pop     ecx
                pop     ecx
                jmp     short locret_E3203E
; ---------------------------------------------------------------------------

loc_E3202E:                             ; CODE XREF: sub_E31FCE+1B↑j
                push    [ebp+arg_0]
                push    [ebp+var_14]
                push    1
                mov     ecx, [ebp+var_8]
                call    sub_E32B4B

locret_E3203E:                          ; CODE XREF: sub_E31FCE+5E↑j
                leave
                retn    4
sub_E31FCE      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _BYTE *__stdcall sub_E32042(_BYTE *, _BYTE *Src, size_t Size, char)
sub_E32042      proc near               ; CODE XREF: sub_E32B4B+B2↓p
                                        ; sub_E32B4B+E0↓p

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
                call    sub_E32565
                add     esp, 0Ch
                lea     eax, [ebp+arg_C]
                push    eax
                mov     eax, [ebp+arg_0]
                add     eax, [ebp+Size]
                push    eax
                call    nEncode
                pop     ecx
                pop     ecx
                mov     [ebp+var_1], 0
                lea     eax, [ebp+var_1]
                push    eax
                mov     eax, [ebp+Size]
                mov     ecx, [ebp+arg_0]
                lea     eax, [ecx+eax+1]
                push    eax
                call    nEncode
                pop     ecx
                pop     ecx
                leave
                retn    10h
sub_E32042      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; char *__thiscall sub_E3208B(_DWORD *this, int)
sub_E3208B      proc near               ; CODE XREF: sub_E318BC+74↑p

var_4           = dword ptr -4
arg_0           = dword ptr  8

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+var_4], ecx
                mov     ecx, [ebp+var_4]
                call    sub_E324C0
                add     eax, [ebp+arg_0]
                leave
                retn    4
sub_E3208B      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; void __thiscall gEncode(void **this)
                public gEncode
gEncode         proc near               ; CODE XREF: sub_E31000+41↑p
                                        ; sub_E3105D+41↑p ...

var_4           = dword ptr -4

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+var_4], ecx
                mov     ecx, [ebp+var_4]
                call    mEncode
                mov     ecx, [ebp+var_4]
                call    hEncode
                leave
                retn
gEncode         endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; unsigned int *__thiscall sub_E320BA(unsigned int *this, char *Src)
sub_E320BA      proc near               ; CODE XREF: sub_E31000+23↑p
                                        ; sub_E3105D+23↑p ...

var_20          = dword ptr -20h
var_1C          = dword ptr -1Ch
var_18          = dword ptr -18h
var_14          = dword ptr -14h
var_E           = byte ptr -0Eh
var_D           = byte ptr -0Dh
var_C           = dword ptr -0Ch
var_4           = dword ptr -4
Src             = dword ptr  8

; FUNCTION CHUNK AT 00E3655F SIZE 00000008 BYTES
; FUNCTION CHUNK AT 00E3656C SIZE 0000000C BYTES

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
                call    sub_E32C45
                and     [ebp+var_4], 0
                lea     eax, [ebp+var_E]
                mov     [ebp+var_1C], eax
                push    [ebp+var_14]
                push    [ebp+var_1C]
                lea     ecx, [ebp+var_D]
                call    bEncode
                mov     ecx, [ebp+var_14]
                call    sub_E323C9
                push    [ebp+Src]       ; Src
                mov     ecx, [ebp+var_14]
                call    sub_E323FD
                lea     ecx, [ebp+var_D]
                call    aEncode
                or      [ebp+var_4], 0FFFFFFFFh
                mov     eax, [ebp+var_14]
                mov     ecx, [ebp+var_C]
                mov     large fs:0, ecx
                leave
                retn    4
sub_E320BA      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; void hEncode()
hEncode         proc near               ; CODE XREF: gEncode+12↑p
                                        ; sub_E320BA+44A8↓j

var_4           = dword ptr -4

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+var_4], ecx
                mov     ecx, [ebp+var_4]
                call    iEncode
                leave
                retn
hEncode         endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; void iEncode()
iEncode         proc near               ; CODE XREF: hEncode+A↑p

var_4           = dword ptr -4

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+var_4], ecx
                mov     ecx, [ebp+var_4]
                call    aEncode
                leave
                retn
iEncode         endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int *__thiscall jEncode(int **this)
                public jEncode
jEncode         proc near               ; CODE XREF: dEncode+C8↑p
                                        ; dEncode+46DD↓j

var_4           = dword ptr -4

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+var_4], ecx
                mov     eax, [ebp+var_4]
                cmp     dword ptr [eax], 0
                jz      short locret_E3216C
                mov     eax, [ebp+var_4]
                mov     ecx, [eax]
                call    sub_E32216

locret_E3216C:                          ; CODE XREF: jEncode+D↑j
                leave
                retn
jEncode         endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int *__thiscall sub_E3216E(_QWORD *this, int *, _QWORD *)
sub_E3216E      proc near               ; CODE XREF: sub_E31CC5+1F↑p

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
                call    sub_E31CA5
                mov     esi, eax
                mov     edi, edx
                mov     ecx, [ebp+arg_4]
                call    sub_E31CA5
                add     esi, eax
                adc     edi, edx
                push    edi
                push    esi
                mov     ecx, [ebp+arg_0]
                call    sub_E321A2
                mov     eax, [ebp+arg_0]
                pop     edi
                pop     esi
                leave
                retn    8
sub_E3216E      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int *__thiscall sub_E321A2(int *this, int, int)
sub_E321A2      proc near               ; CODE XREF: sub_E31CC5+12↑p
                                        ; sub_E3216E+26↑p

var_4           = dword ptr -4
arg_0           = dword ptr  8
arg_4           = dword ptr  0Ch

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+var_4], ecx
                call    sub_E3296C
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
sub_E321A2      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; __int16 *__thiscall sub_E321D4(unsigned __int16 *this, __int16 *, unsigned __int16 *)
sub_E321D4      proc near               ; CODE XREF: sub_E31D73+1B↑p

var_4           = dword ptr -4
arg_0           = dword ptr  8
arg_4           = dword ptr  0Ch

                push    ebp
                mov     ebp, esp
                push    ecx
                push    esi
                mov     [ebp+var_4], ecx
                mov     ecx, [ebp+var_4]
                call    eCrucialEncode
                movzx   esi, ax
                mov     ecx, [ebp+arg_4]
                call    eCrucialEncode
                movzx   eax, ax
                add     esi, eax
                push    esi
                mov     ecx, [ebp+arg_0]
                call    aCrucialEncode
                mov     eax, [ebp+arg_0]
                pop     esi
                leave
                retn    8
sub_E321D4      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; void *__thiscall kEncode(void *this)
                public kEncode
kEncode         proc near               ; CODE XREF: dEncode+27↑p
                                        ; sub_E32216+61↓p ...

var_4           = dword ptr -4

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+var_4], ecx
                mov     ecx, [ebp+var_4]
                call    jCrucialEncode
                leave
                retn
kEncode         endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int *__thiscall sub_E32216(int *this)
sub_E32216      proc near               ; CODE XREF: sub_E31E5B+A↑p
                                        ; jEncode+14↑p

var_2C          = dword ptr -2Ch
Block           = dword ptr -28h
var_24          = dword ptr -24h
var_20          = dword ptr -20h
var_1C          = dword ptr -1Ch
var_18          = dword ptr -18h
var_14          = dword ptr -14h
var_10          = dword ptr -10h
var_C           = dword ptr -0Ch

; FUNCTION CHUNK AT 00E364D6 SIZE 0000000C BYTES

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
                call    aEncode
                mov     eax, [ebp+var_10]
                cmp     dword ptr [eax], 0
                jz      short loc_E322B7
                mov     eax, [ebp+var_1C]
                push    dword ptr [eax]
                mov     eax, [ebp+var_10]
                push    dword ptr [eax]
                mov     ecx, [ebp+var_18]
                call    sub_E325B7
                mov     ecx, [ebp+var_18]
                call    kEncode
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
                call    sub_E3261E
                mov     eax, [ebp+var_10]
                and     dword ptr [eax], 0
                mov     eax, [ebp+var_1C]
                and     dword ptr [eax], 0
                mov     eax, [ebp+var_20]
                and     dword ptr [eax], 0

loc_E322B7:                             ; CODE XREF: sub_E32216+4A↑j
                mov     ecx, [ebp+var_C]
                mov     large fs:0, ecx
                leave
                retn
sub_E32216      endp

; ---------------------------------------------------------------------------
                align 8

; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int __thiscall lEncode(int *this, unsigned int)
                public lEncode
lEncode         proc near               ; CODE XREF: dEncode+95↑p

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
                call    kEncode
                mov     [ebp+var_10], eax
                push    [ebp+arg_0]
                mov     ecx, [ebp+var_10]
                call    oEncode
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
lEncode         endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _BYTE *__thiscall mEncode(void **this)
                public mEncode
mEncode         proc near               ; CODE XREF: gEncode+A↑p

var_1C          = dword ptr -1Ch
Block           = dword ptr -18h
var_14          = dword ptr -14h
var_D           = byte ptr -0Dh
var_C           = dword ptr -0Ch

; FUNCTION CHUNK AT 00E364D6 SIZE 0000000C BYTES

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
                call    aEncode
                mov     ecx, [ebp+var_14]
                call    pEncode
                movzx   eax, al
                test    eax, eax
                jz      short loc_E3238E
                mov     eax, [ebp+var_14]
                mov     eax, [eax]
                mov     [ebp+Block], eax
                mov     ecx, [ebp+var_14]
                call    kEncode
                mov     [ebp+var_1C], eax
                push    [ebp+var_14]
                call    sub_E32C63
                pop     ecx
                mov     eax, [ebp+var_14]
                mov     eax, [eax+14h]
                inc     eax
                push    eax             ; int
                push    [ebp+Block]     ; Block
                mov     ecx, [ebp+var_1C]
                call    sub_E327E0

loc_E3238E:                             ; CODE XREF: mEncode+33↑j
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
                call    nEncode
                pop     ecx
                pop     ecx
                mov     ecx, [ebp+var_C]
                mov     large fs:0, ecx
                leave
                retn
mEncode         endp

; ---------------------------------------------------------------------------
                db 5 dup(0CCh)

; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _BYTE *__thiscall sub_E323C9(int this)
sub_E323C9      proc near               ; CODE XREF: sub_E320BA+4A↑p

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
                call    nEncode
                pop     ecx
                pop     ecx
                leave
                retn
sub_E323C9      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; unsigned int *__thiscall sub_E323FD(unsigned int *this, char *Src)
sub_E323FD      proc near               ; CODE XREF: sub_E320BA+55↑p

var_4           = dword ptr -4
Src             = dword ptr  8

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+var_4], ecx
                push    [ebp+Src]
                call    sub_E32533
                pop     ecx
                push    eax
                call    MicrosoftVisualC14netruntime ; Microsoft VisualC 14/net runtime
                pop     ecx
                push    eax             ; Size
                push    [ebp+Src]       ; Src
                mov     ecx, [ebp+var_4]
                call    sub_E32424
                leave
                retn    4
sub_E323FD      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; unsigned int *__thiscall sub_E32424(unsigned int *this, char *Src, size_t Size)
sub_E32424      proc near               ; CODE XREF: sub_E323FD+1E↑p

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
                ja      short loc_E32478
                mov     ecx, [ebp+var_8]
                call    sub_E324C0
                mov     [ebp+var_C], eax
                mov     eax, [ebp+var_8]
                mov     ecx, [ebp+Size]
                mov     [eax+10h], ecx
                push    [ebp+Size]      ; Size
                push    [ebp+Src]       ; Src
                push    [ebp+var_C]     ; void *
                call    sub_E326F2
                add     esp, 0Ch
                mov     [ebp+var_1], 0
                lea     eax, [ebp+var_1]
                push    eax
                mov     eax, [ebp+var_C]
                add     eax, [ebp+Size]
                push    eax
                call    nEncode
                pop     ecx
                pop     ecx
                mov     eax, [ebp+var_8]
                jmp     short locret_E32489
; ---------------------------------------------------------------------------

loc_E32478:                             ; CODE XREF: sub_E32424+12↑j
                push    [ebp+Src]       ; Src
                push    dword ptr [ebp+var_10] ; char
                push    [ebp+Size]      ; Size
                mov     ecx, [ebp+var_8]
                call    sub_E32C68

locret_E32489:                          ; CODE XREF: sub_E32424+52↑j
                leave
                retn    8
sub_E32424      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _BYTE *__stdcall sub_E3248D(_BYTE *, size_t Size, _BYTE *Src)
sub_E3248D      proc near               ; CODE XREF: sub_E32C68+7A↓p

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
                call    sub_E32565
                add     esp, 0Ch
                mov     [ebp+var_1], 0
                lea     eax, [ebp+var_1]
                push    eax
                mov     eax, [ebp+arg_0]
                add     eax, [ebp+Size]
                push    eax
                call    nEncode
                pop     ecx
                pop     ecx
                leave
                retn    0Ch
sub_E3248D      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _DWORD *__thiscall sub_E324C0(_DWORD *this)
sub_E324C0      proc near               ; CODE XREF: sub_E31FCE+2A↑p
                                        ; sub_E3208B+A↑p ...

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
                call    pEncode
                movzx   eax, al
                test    eax, eax
                jz      short loc_E324EB
                mov     eax, [ebp+var_4]
                push    dword ptr [eax]
                call    MicrosoftVisualC14netruntime ; Microsoft VisualC 14/net runtime
                pop     ecx
                mov     [ebp+var_8], eax

loc_E324EB:                             ; CODE XREF: sub_E324C0+1B↑j
                mov     eax, [ebp+var_8]
                leave
                retn
sub_E324C0      endp

; [00000008 BYTES: COLLAPSED FUNCTION std::numeric_limits<uint>::max(void). PRESS CTRL-NUMPAD+ TO EXPAND]

; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; bool __cdecl sub_E324F8(_DWORD *, _DWORD *)
sub_E324F8      proc near               ; CODE XREF: sub_E32F66+17A↓p

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
                jnz     short loc_E32511
                mov     [ebp+var_4], 1
                jmp     short loc_E32515
; ---------------------------------------------------------------------------

loc_E32511:                             ; CODE XREF: sub_E324F8+E↑j
                and     [ebp+var_4], 0

loc_E32515:                             ; CODE XREF: sub_E324F8+17↑j
                mov     al, byte ptr [ebp+var_4]
                leave
                retn
sub_E324F8      endp

; [0000000A BYTES: COLLAPSED FUNCTION std::_Narrow_char_traits<char,int>::to_char_type(int const &). PRESS CTRL-NUMPAD+ TO EXPAND]

; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _BYTE *__cdecl nEncode(_BYTE *, _BYTE *)
nEncode         proc near               ; CODE XREF: sub_E31FCE+3D↑p
                                        ; sub_E31FCE+57↑p ...

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
nEncode         endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; unsigned int __cdecl sub_E32533(const char *)
sub_E32533      proc near               ; CODE XREF: sub_E323FD+A↑p

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

loc_E32546:                             ; CODE XREF: sub_E32533+22↓j
                mov     eax, [ebp+var_8]
                mov     al, [eax]
                mov     [ebp+var_1], al
                inc     [ebp+var_8]
                cmp     [ebp+var_1], 0
                jnz     short loc_E32546
                mov     eax, [ebp+var_8]
                sub     eax, [ebp+var_C]
                mov     [ebp+var_10], eax
                mov     eax, [ebp+var_10]
                leave
                retn
sub_E32533      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _BYTE *__cdecl sub_E32565(_BYTE *, _BYTE *Src, size_t Size)
sub_E32565      proc near               ; CODE XREF: sub_E32042+11↑p
                                        ; sub_E3248D+11↑p

var_4           = dword ptr -4
arg_0           = dword ptr  8
Src             = dword ptr  0Ch
Size            = dword ptr  10h

                push    ebp
                mov     ebp, esp
                push    ecx
                call    sub_E31328
                movzx   eax, al
                test    eax, eax
                jz      short loc_E325A1
                and     [ebp+var_4], 0
                jmp     short loc_E32582
; ---------------------------------------------------------------------------

loc_E3257B:                             ; CODE XREF: sub_E32565+35↓j
                mov     eax, [ebp+var_4]
                inc     eax
                mov     [ebp+var_4], eax

loc_E32582:                             ; CODE XREF: sub_E32565+14↑j
                mov     eax, [ebp+var_4]
                cmp     eax, [ebp+Size]
                jnb     short loc_E3259C
                mov     eax, [ebp+arg_0]
                add     eax, [ebp+var_4]
                mov     ecx, [ebp+Src]
                add     ecx, [ebp+var_4]
                mov     cl, [ecx]
                mov     [eax], cl
                jmp     short loc_E3257B
; ---------------------------------------------------------------------------

loc_E3259C:                             ; CODE XREF: sub_E32565+23↑j
                mov     eax, [ebp+arg_0]
                jmp     short locret_E325B5
; ---------------------------------------------------------------------------

loc_E325A1:                             ; CODE XREF: sub_E32565+E↑j
                push    [ebp+Size]      ; Size
                push    [ebp+Src]       ; Src
                push    [ebp+arg_0]     ; void *
                call    memcpy
                add     esp, 0Ch
                mov     eax, [ebp+arg_0]

locret_E325B5:                          ; CODE XREF: sub_E32565+3A↑j
                leave
                retn
sub_E32565      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; void __thiscall sub_E325B7(void *this, int, int)
sub_E325B7      proc near               ; CODE XREF: sub_E32216+59↑p
                                        ; sub_E329E8+5F↓p ...

var_4           = dword ptr -4
arg_0           = dword ptr  8
arg_4           = dword ptr  0Ch

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+var_4], ecx
                mov     ecx, [ebp+var_4]
                call    kEncode
                push    eax
                push    [ebp+arg_4]
                push    [ebp+arg_0]
                call    sub_E32C63
                add     esp, 0Ch
                leave
                retn    8
sub_E325B7      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int __stdcall oEncode(unsigned int)
                public oEncode
oEncode         proc near               ; CODE XREF: lEncode+38↑p
                                        ; sub_E33363+7B↓p

var_4           = dword ptr -4
arg_0           = dword ptr  8

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+var_4], ecx
                push    [ebp+arg_0]
                call    sub_E32D4A
                pop     ecx
                push    eax
                call    sub_E32D70
                pop     ecx
                leave
                retn    4
oEncode         endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _DWORD *__cdecl sub_E325F4(_DWORD *, _DWORD *)
sub_E325F4      proc near               ; CODE XREF: sub_E32677+2A↓p
                                        ; sub_E32F19+42↓p

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
                jnb     short loc_E3260D
                mov     eax, [ebp+arg_4]
                mov     [ebp+var_4], eax
                jmp     short loc_E32613
; ---------------------------------------------------------------------------

loc_E3260D:                             ; CODE XREF: sub_E325F4+F↑j
                mov     eax, [ebp+arg_0]
                mov     [ebp+var_4], eax

loc_E32613:                             ; CODE XREF: sub_E325F4+17↑j
                mov     eax, [ebp+var_4]
                mov     [ebp+var_8], eax
                mov     eax, [ebp+var_8]
                leave
                retn
sub_E325F4      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; void __stdcall sub_E3261E(void *Block, int)
sub_E3261E      proc near               ; CODE XREF: sub_E32216+8A↑p
                                        ; sub_E33363+F4↓p ...

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
                call    sub_E32D9C
                pop     ecx
                pop     ecx
                leave
                retn    8
sub_E3261E      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _BYTE *__thiscall sub_E3263A(_DWORD *this, int)
sub_E3263A      proc near               ; CODE XREF: sub_E3392C+1F↓p

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
                call    sub_E324C0
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
                call    nEncode
                pop     ecx
                pop     ecx
                leave
                retn    4
sub_E3263A      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int __thiscall sub_E32677(void *this)
sub_E32677      proc near               ; CODE XREF: sub_E32B4B+1B↓p
                                        ; sub_E32C68+C↓p ...

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
                call    kEncode
                push    eax
                call    ?max@?$numeric_limits@I@std@@SAIXZ ; std::numeric_limits<uint>::max(void)
                pop     ecx
                mov     [ebp+var_C], eax
                mov     [ebp+var_8], 10h
                lea     eax, [ebp+var_8]
                push    eax
                lea     eax, [ebp+var_C]
                push    eax
                call    sub_E325F4
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
                call    sub_E32B21
                pop     ecx
                pop     ecx
                mov     eax, [eax]
                leave
                retn
sub_E32677      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; bool __thiscall pEncode(_DWORD *this)
                public pEncode
pEncode         proc near               ; CODE XREF: mEncode+29↑p
                                        ; sub_E324C0+11↑p

var_8           = dword ptr -8
var_4           = dword ptr -4

                push    ebp
                mov     ebp, esp
                push    ecx
                push    ecx
                mov     [ebp+var_8], ecx
                mov     eax, [ebp+var_8]
                cmp     dword ptr [eax+14h], 10h
                jb      short loc_E326E9
                mov     [ebp+var_4], 1
                jmp     short loc_E326ED
; ---------------------------------------------------------------------------

loc_E326E9:                             ; CODE XREF: pEncode+F↑j
                and     [ebp+var_4], 0

loc_E326ED:                             ; CODE XREF: pEncode+18↑j
                mov     al, byte ptr [ebp+var_4]
                leave
                retn
pEncode         endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; char *__cdecl sub_E326F2(char *, char *Src, size_t Size)
sub_E326F2      proc near               ; CODE XREF: sub_E32424+31↑p

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
                call    sub_E31328
                movzx   eax, al
                test    eax, eax
                jz      loc_E327AE
                mov     eax, [ebp+arg_0]
                cmp     eax, [ebp+Src]
                jnz     short loc_E32719
                mov     eax, [ebp+arg_0]
                jmp     loc_E327C2
; ---------------------------------------------------------------------------

loc_E32719:                             ; CODE XREF: sub_E326F2+1D↑j
                mov     [ebp+var_1], 1
                mov     eax, [ebp+Src]
                mov     [ebp+var_10], eax
                jmp     short loc_E3272C
; ---------------------------------------------------------------------------

loc_E32725:                             ; CODE XREF: sub_E326F2:loc_E32745↓j
                mov     eax, [ebp+var_10]
                inc     eax
                mov     [ebp+var_10], eax

loc_E3272C:                             ; CODE XREF: sub_E326F2+31↑j
                mov     eax, [ebp+Src]
                add     eax, [ebp+Size]
                cmp     [ebp+var_10], eax
                jz      short loc_E32747
                mov     eax, [ebp+arg_0]
                cmp     eax, [ebp+var_10]
                jnz     short loc_E32745
                mov     [ebp+var_1], 0
                jmp     short loc_E32747
; ---------------------------------------------------------------------------

loc_E32745:                             ; CODE XREF: sub_E326F2+4B↑j
                jmp     short loc_E32725
; ---------------------------------------------------------------------------

loc_E32747:                             ; CODE XREF: sub_E326F2+43↑j
                                        ; sub_E326F2+51↑j
                movzx   eax, [ebp+var_1]
                test    eax, eax
                jz      short loc_E32778
                and     [ebp+var_8], 0
                jmp     short loc_E3275C
; ---------------------------------------------------------------------------

loc_E32755:                             ; CODE XREF: sub_E326F2+82↓j
                mov     eax, [ebp+var_8]
                inc     eax
                mov     [ebp+var_8], eax

loc_E3275C:                             ; CODE XREF: sub_E326F2+61↑j
                mov     eax, [ebp+var_8]
                cmp     eax, [ebp+Size]
                jnb     short loc_E32776
                mov     eax, [ebp+arg_0]
                add     eax, [ebp+var_8]
                mov     ecx, [ebp+Src]
                add     ecx, [ebp+var_8]
                mov     cl, [ecx]
                mov     [eax], cl
                jmp     short loc_E32755
; ---------------------------------------------------------------------------

loc_E32776:                             ; CODE XREF: sub_E326F2+70↑j
                jmp     short loc_E327A9
; ---------------------------------------------------------------------------

loc_E32778:                             ; CODE XREF: sub_E326F2+5B↑j
                and     [ebp+var_C], 0
                jmp     short loc_E32785
; ---------------------------------------------------------------------------

loc_E3277E:                             ; CODE XREF: sub_E326F2+B5↓j
                mov     eax, [ebp+var_C]
                inc     eax
                mov     [ebp+var_C], eax

loc_E32785:                             ; CODE XREF: sub_E326F2+8A↑j
                mov     eax, [ebp+var_C]
                cmp     eax, [ebp+Size]
                jnb     short loc_E327A9
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
                jmp     short loc_E3277E
; ---------------------------------------------------------------------------

loc_E327A9:                             ; CODE XREF: sub_E326F2:loc_E32776↑j
                                        ; sub_E326F2+99↑j
                mov     eax, [ebp+arg_0]
                jmp     short loc_E327C2
; ---------------------------------------------------------------------------

loc_E327AE:                             ; CODE XREF: sub_E326F2+11↑j
                push    [ebp+Size]      ; Size
                push    [ebp+Src]       ; Src
                push    [ebp+arg_0]     ; void *
                call    memmove
                add     esp, 0Ch
                mov     eax, [ebp+arg_0]

loc_E327C2:                             ; CODE XREF: sub_E326F2+22↑j
                                        ; sub_E326F2+BA↑j
                pop     esi
                leave
                retn
sub_E326F2      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int __stdcall sub_E327C5(int)
sub_E327C5      proc near               ; CODE XREF: sub_E32B4B+60↓p
                                        ; sub_E32C68+45↓p

var_4           = dword ptr -4
arg_0           = dword ptr  8

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+var_4], ecx
                push    [ebp+arg_0]
                call    sub_E32DEA
                pop     ecx
                push    eax
                call    sub_E32D70
                pop     ecx
                leave
                retn    4
sub_E327C5      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; void __stdcall sub_E327E0(void *Block, int)
sub_E327E0      proc near               ; CODE XREF: mEncode+5F↑p
                                        ; sub_E32B4B+C2↓p ...

var_4           = dword ptr -4
Block           = dword ptr  8
arg_4           = dword ptr  0Ch

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+var_4], ecx
                push    [ebp+arg_4]     ; int
                push    [ebp+Block]     ; Block
                call    sub_E32D9C
                pop     ecx
                pop     ecx
                leave
                retn    8
sub_E327E0      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; void __thiscall sub_E327F8(_DWORD *this, unsigned int)
sub_E327F8      proc near               ; CODE XREF: sub_E3392C+14↓p

var_4           = dword ptr -4
arg_0           = dword ptr  8

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+var_4], ecx
                mov     eax, [ebp+var_4]
                mov     eax, [eax+10h]
                cmp     eax, [ebp+arg_0]
                jnb     short locret_E3280F
                call    sub_E32813

locret_E3280F:                          ; CODE XREF: sub_E327F8+10↑j
                leave
                retn    4
sub_E327F8      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; void sub_E32813()
sub_E32813      proc near               ; CODE XREF: sub_E327F8+12↑p
                push    ebp
                mov     ebp, esp
                push    offset aInvalidStringP ; "invalid string position"
                call    ds:?_Xout_of_range@std@@YAXPBD@Z ; std::_Xout_of_range(char const *)
                pop     ebp
                retn
sub_E32813      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; struct std::_Facet_base *__cdecl sub_E32823(_DWORD *)
sub_E32823      proc near               ; CODE XREF: sub_E32F66+79↓p

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

; FUNCTION CHUNK AT 00E36578 SIZE 00000011 BYTES
; FUNCTION CHUNK AT 00E3658E SIZE 0000000C BYTES

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
                and     [ebp+var_4], 0
                mov     eax, dword_E39430
                mov     [ebp+var_10], eax
                mov     ecx, ds:?id@?$ctype@D@std@@2V0locale@2@A ; std::locale::id std::ctype<char>::id
                call    ds:??Bid@locale@std@@QAEIXZ ; std::locale::id::operator uint(void)
                mov     [ebp+var_20], eax
                push    [ebp+var_20]
                mov     ecx, [ebp+arg_0]
                call    sub_E31721
                mov     [ebp+var_18], eax
                cmp     [ebp+var_18], 0
                jnz     short loc_E328EC
                cmp     [ebp+var_10], 0
                jz      short loc_E32886
                mov     eax, [ebp+var_10]
                mov     [ebp+var_18], eax
                jmp     short loc_E328EC
; ---------------------------------------------------------------------------

loc_E32886:                             ; CODE XREF: sub_E32823+59↑j
                push    [ebp+arg_0]
                lea     eax, [ebp+var_10]
                push    eax
                call    ds:?_Getcat@?$ctype@D@std@@SAIPAPBVfacet@locale@2@PBV42@@Z ; std::ctype<char>::_Getcat(std::locale::facet const * *,std::locale const *)
                pop     ecx
                pop     ecx
                cmp     eax, 0FFFFFFFFh
                jnz     short loc_E328A1
                call    sub_E31698
; ---------------------------------------------------------------------------
                jmp     short loc_E328EC
; ---------------------------------------------------------------------------

loc_E328A1:                             ; CODE XREF: sub_E32823+75↑j
                mov     eax, [ebp+var_10]
                mov     [ebp+var_14], eax
                push    [ebp+var_14]
                lea     ecx, [ebp+var_1C]
                call    sub_E331DB
                mov     byte ptr [ebp+var_4], 1
                push    [ebp+var_14]    ; struct std::_Facet_base *
                call    ?_Facet_Register@std@@YAXPAV_Facet_base@1@@Z ; std::_Facet_Register(std::_Facet_base *)
                pop     ecx
                mov     eax, [ebp+var_14]
                mov     eax, [eax]
                mov     ecx, [ebp+var_14]
                call    dword ptr [eax+4]
                mov     eax, [ebp+var_10]
                mov     dword_E39430, eax
                mov     eax, [ebp+var_10]
                mov     [ebp+var_18], eax
                lea     ecx, [ebp+var_1C]
                call    sub_E32DF7
                mov     byte ptr [ebp+var_4], 0
                lea     ecx, [ebp+var_1C]
                call    sub_E32E13

loc_E328EC:                             ; CODE XREF: sub_E32823+53↑j
                                        ; sub_E32823+61↑j ...
                mov     eax, [ebp+var_18]
                mov     [ebp+var_28], eax
                or      [ebp+var_4], 0FFFFFFFFh
                lea     ecx, [ebp+var_24]
                call    ds:??1_Lockit@std@@QAE@XZ ; std::_Lockit::~_Lockit(void)
                mov     eax, [ebp+var_28]
                mov     ecx, [ebp+var_C]
                mov     large fs:0, ecx
                leave
                retn
sub_E32823      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int __cdecl bGetInput(int, _DWORD *)
                public bGetInput
bGetInput       proc near               ; CODE XREF: aGetInput+45↑p

arg_0           = dword ptr  8
arg_4           = dword ptr  0Ch

                push    ebp
                mov     ebp, esp
                push    [ebp+arg_0]
                call    MicrosoftVisualC14netruntime ; Microsoft VisualC 14/net runtime
                pop     ecx
                push    [ebp+arg_4]
                push    eax
                call    sub_E32F66
                pop     ecx
                pop     ecx
                pop     ebp
                retn
bGetInput       endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _QWORD *__thiscall sub_E32927(_QWORD *this, int *)
sub_E32927      proc near               ; CODE XREF: _main+9D↑p

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
sub_E32927      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; BOOL __cdecl sub_E32943(void *)
sub_E32943      proc near               ; CODE XREF: _main+A3↑p

var_10          = dword ptr -10h
var_8           = dword ptr -8
arg_0           = dword ptr  8

                push    ebp
                mov     ebp, esp
                sub     esp, 10h
                push    [ebp+arg_0]
                lea     eax, [ebp+var_8]
                push    eax
                call    sub_E317C3
                pop     ecx
                push    eax
                lea     eax, [ebp+var_10]
                push    eax
                call    sub_E33200
                add     esp, 0Ch
                push    eax
                call    sub_E33230
                pop     ecx
                leave
                retn
sub_E32943      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int sub_E3296C()
sub_E3296C      proc near               ; CODE XREF: sub_E31CF9+7↑p
                                        ; sub_E321A2+7↑p

var_10          = dword ptr -10h
var_C           = dword ptr -0Ch
var_8           = dword ptr -8
var_4           = dword ptr -4

                push    ebp
                mov     ebp, esp
                sub     esp, 10h
                call    sub_E315BF
                mov     [ebp+var_8], eax
                mov     [ebp+var_4], edx
                call    sub_E315B6
                mov     [ebp+var_10], eax
                mov     [ebp+var_C], edx
                push    [ebp+var_4]
                push    [ebp+var_8]
                push    [ebp+var_C]
                push    [ebp+var_10]
                call    sub_E33285
                add     esp, 10h
                leave
                retn
sub_E3296C      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; __int16 fCrucialEncode()
                public fCrucialEncode
fCrucialEncode  proc near               ; CODE XREF: aCrucialEncode+7↑p

var_8           = dword ptr -8
var_4           = dword ptr -4

                push    ebp
                mov     ebp, esp
                push    ecx
                push    ecx
                call    MicrosoftVisualC14netruntime2 ; Microsoft VisualC 14/net runtime
                mov     word ptr [ebp+var_4], ax
                call    gCrucialEncode
                mov     word ptr [ebp+var_8], ax
                push    [ebp+var_4]
                push    [ebp+var_8]
                call    hCrucialEncode
                pop     ecx
                pop     ecx
                leave
                retn
fCrucialEncode  endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int sub_E329C4()
sub_E329C4      proc near               ; CODE XREF: sub_E31DDF+7↑p
                                        ; sub_E34802+7↓p

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
                call    sub_E3331B
                pop     ecx
                pop     ecx
                leave
                retn
sub_E329C4      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; void __thiscall sub_E329E8(int *this, unsigned int, unsigned __int8 *)
sub_E329E8      proc near               ; CODE XREF: sub_E31E40+12↑p

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
                jnb     short loc_E32A56
                mov     eax, [ebp+var_14]
                mov     eax, [eax]
                mov     ecx, [ebp+arg_0]
                lea     eax, [eax+ecx*8]
                mov     [ebp+var_C], eax
                mov     eax, [ebp+var_4]
                push    dword ptr [eax]
                push    [ebp+var_C]
                mov     ecx, [ebp+var_8]
                call    sub_E32E64
                mov     eax, [ebp+var_4]
                push    dword ptr [eax]
                push    [ebp+var_C]
                mov     ecx, [ebp+var_8]
                call    sub_E325B7
                mov     eax, [ebp+var_4]
                mov     ecx, [ebp+var_C]
                mov     [eax], ecx
                jmp     short locret_E32ABB
; ---------------------------------------------------------------------------

loc_E32A56:                             ; CODE XREF: sub_E329E8+34↑j
                mov     eax, [ebp+arg_0]
                cmp     eax, [ebp+var_18]
                jbe     short locret_E32ABB
                mov     eax, [ebp+var_10]
                mov     ecx, [ebp+var_14]
                mov     eax, [eax+8]
                sub     eax, [ecx]
                sar     eax, 3
                mov     [ebp+var_20], eax
                mov     eax, [ebp+arg_0]
                cmp     eax, [ebp+var_20]
                jbe     short loc_E32A87
                push    [ebp+arg_4]
                push    [ebp+arg_0]
                mov     ecx, [ebp+var_8]
                call    sub_E33363
                jmp     short locret_E32ABB
; ---------------------------------------------------------------------------

loc_E32A87:                             ; CODE XREF: sub_E329E8+8D↑j
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
                call    sub_E32E6F
                mov     ecx, [ebp+var_4]
                mov     [ecx], eax
                push    [ebp+var_1C]
                push    [ebp+var_1C]
                mov     ecx, [ebp+var_8]
                call    sub_E32E64

locret_E32ABB:                          ; CODE XREF: sub_E329E8+6C↑j
                                        ; sub_E329E8+74↑j ...
                leave
                retn    8
sub_E329E8      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _DWORD *__thiscall qEncode(_DWORD *this, int, int)
                public qEncode
qEncode         proc near               ; CODE XREF: dEncode+4A↑p

var_4           = dword ptr -4
arg_4           = dword ptr  0Ch

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+var_4], ecx
                push    [ebp+arg_4]
                call    MicrosoftVisualC14netruntime ; Microsoft VisualC 14/net runtime
                pop     ecx
                mov     ecx, [ebp+var_4]
                call    sEncode
                mov     eax, [ebp+var_4]
                leave
                retn    8
qEncode         endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int __thiscall rEncode(void *this, int, int, int)
rEncode         proc near               ; CODE XREF: dEncode+B2↑p

var_4           = dword ptr -4
arg_0           = dword ptr  8
arg_4           = dword ptr  0Ch
arg_8           = dword ptr  10h

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+var_4], ecx
                mov     ecx, [ebp+var_4]
                call    kEncode
                push    eax
                push    [ebp+arg_8]
                push    [ebp+arg_4]
                push    [ebp+arg_0]
                call    tEncode
                add     esp, 10h
                leave
                retn    0Ch
rEncode         endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _DWORD *__thiscall sub_E32B03(_DWORD *this, int)
sub_E32B03      proc near               ; CODE XREF: sub_E31F52+15↑p

var_4           = dword ptr -4

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+var_4], ecx
                mov     ecx, [ebp+var_4]
                call    jCrucialEncode
                mov     ecx, [ebp+var_4]
                call    sEncode
                mov     eax, [ebp+var_4]
                leave
                retn    4
sub_E32B03      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _DWORD *__cdecl sub_E32B21(_DWORD *, _DWORD *)
sub_E32B21      proc near               ; CODE XREF: sub_E32677+4D↑p
                                        ; sub_E338D6+2B↓p

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
                jnb     short loc_E32B3A
                mov     eax, [ebp+arg_4]
                mov     [ebp+var_4], eax
                jmp     short loc_E32B40
; ---------------------------------------------------------------------------

loc_E32B3A:                             ; CODE XREF: sub_E32B21+F↑j
                mov     eax, [ebp+arg_0]
                mov     [ebp+var_4], eax

loc_E32B40:                             ; CODE XREF: sub_E32B21+17↑j
                mov     eax, [ebp+var_4]
                mov     [ebp+var_8], eax
                mov     eax, [ebp+var_8]
                leave
                retn
sub_E32B21      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; unsigned int *__thiscall sub_E32B4B(size_t *this, size_t, char, char)
sub_E32B4B      proc near               ; CODE XREF: sub_E31FCE+6B↑p

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
                call    sub_E32677
                sub     eax, [ebp+Size]
                cmp     eax, [ebp+arg_0]
                jnb     short loc_E32B78
                call    sub_E31664
; ---------------------------------------------------------------------------

loc_E32B78:                             ; CODE XREF: sub_E32B4B+26↑j
                mov     eax, [ebp+Size]
                add     eax, [ebp+arg_0]
                mov     [ebp+var_14], eax
                mov     eax, [ebp+Src]
                mov     eax, [eax+14h]
                mov     [ebp+var_1C], eax
                push    [ebp+var_14]
                mov     ecx, [ebp+var_8]
                call    sub_E32E91
                mov     [ebp+var_18], eax
                mov     ecx, [ebp+var_8]
                call    kEncode
                mov     [ebp+var_24], eax
                mov     eax, [ebp+var_18]
                inc     eax
                push    eax
                mov     ecx, [ebp+var_24]
                call    sub_E327C5
                mov     [ebp+var_10], eax
                mov     ecx, [ebp+Src]
                call    aEncode
                mov     eax, [ebp+Src]
                mov     ecx, [ebp+var_14]
                mov     [eax+10h], ecx
                mov     eax, [ebp+Src]
                mov     ecx, [ebp+var_18]
                mov     [eax+14h], ecx
                push    [ebp+var_10]
                call    MicrosoftVisualC14netruntime ; Microsoft VisualC 14/net runtime
                pop     ecx
                mov     [ebp+var_28], eax
                cmp     [ebp+var_1C], 10h
                jb      short loc_E32C1C
                mov     eax, [ebp+Src]
                mov     eax, [eax]
                mov     [ebp+Block], eax
                push    dword ptr [ebp+arg_8] ; char
                push    [ebp+Size]      ; Size
                push    [ebp+Block]
                call    MicrosoftVisualC14netruntime ; Microsoft VisualC 14/net runtime
                pop     ecx
                push    eax             ; Src
                push    [ebp+var_28]    ; void *
                lea     ecx, [ebp+arg_4]
                call    sub_E32042
                mov     eax, [ebp+var_1C]
                inc     eax
                push    eax             ; int
                push    [ebp+Block]     ; Block
                mov     ecx, [ebp+var_24]
                call    sub_E327E0
                mov     eax, [ebp+Src]
                mov     ecx, [ebp+var_10]
                mov     [eax], ecx
                jmp     short loc_E32C3E
; ---------------------------------------------------------------------------

loc_E32C1C:                             ; CODE XREF: sub_E32B4B+92↑j
                push    dword ptr [ebp+arg_8] ; char
                push    [ebp+Size]      ; Size
                push    [ebp+Src]       ; Src
                push    [ebp+var_28]    ; void *
                lea     ecx, [ebp+arg_4]
                call    sub_E32042
                lea     eax, [ebp+var_10]
                push    eax
                push    [ebp+Src]
                call    sub_E32D1E
                pop     ecx
                pop     ecx

loc_E32C3E:                             ; CODE XREF: sub_E32B4B+CF↑j
                mov     eax, [ebp+var_8]
                leave
                retn    0Ch
sub_E32B4B      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _DWORD *__thiscall sub_E32C45(_DWORD *this, int)
sub_E32C45      proc near               ; CODE XREF: sub_E320BA+2A↑p

var_4           = dword ptr -4

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+var_4], ecx
                mov     ecx, [ebp+var_4]
                call    jCrucialEncode
                mov     ecx, [ebp+var_4]
                call    sub_E32EC3
                mov     eax, [ebp+var_4]
                leave
                retn    4
sub_E32C45      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; void sub_E32C63()
sub_E32C63      proc near               ; CODE XREF: mEncode+4B↑p
                                        ; sub_E325B7+16↑p ...
                push    ebp
                mov     ebp, esp
                pop     ebp
                retn
sub_E32C63      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; unsigned int *__thiscall sub_E32C68(unsigned int *this, size_t Size, char, _BYTE *Src)
sub_E32C68      proc near               ; CODE XREF: sub_E32424+60↑p

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
                call    sub_E32677
                cmp     [ebp+Size], eax
                jbe     short loc_E32C83
                call    sub_E31664
; ---------------------------------------------------------------------------

loc_E32C83:                             ; CODE XREF: sub_E32C68+14↑j
                mov     eax, [ebp+var_4]
                mov     eax, [eax+14h]
                mov     [ebp+var_10], eax
                push    [ebp+Size]
                mov     ecx, [ebp+var_4]
                call    sub_E32E91
                mov     [ebp+var_C], eax
                mov     ecx, [ebp+var_4]
                call    kEncode
                mov     [ebp+var_14], eax
                mov     eax, [ebp+var_C]
                inc     eax
                push    eax
                mov     ecx, [ebp+var_14]
                call    sub_E327C5
                mov     [ebp+var_8], eax
                mov     ecx, [ebp+var_4]
                call    aEncode
                mov     eax, [ebp+var_4]
                mov     ecx, [ebp+Size]
                mov     [eax+10h], ecx
                mov     eax, [ebp+var_4]
                mov     ecx, [ebp+var_C]
                mov     [eax+14h], ecx
                push    [ebp+Src]       ; Src
                push    [ebp+Size]      ; Size
                push    [ebp+var_8]
                call    MicrosoftVisualC14netruntime ; Microsoft VisualC 14/net runtime
                pop     ecx
                push    eax             ; void *
                lea     ecx, [ebp+arg_4]
                call    sub_E3248D
                cmp     [ebp+var_10], 10h
                jb      short loc_E32D09
                mov     eax, [ebp+var_10]
                inc     eax
                push    eax             ; int
                mov     eax, [ebp+var_4]
                push    dword ptr [eax] ; Block
                mov     ecx, [ebp+var_14]
                call    sub_E327E0
                mov     eax, [ebp+var_4]
                mov     ecx, [ebp+var_8]
                mov     [eax], ecx
                jmp     short loc_E32D17
; ---------------------------------------------------------------------------

loc_E32D09:                             ; CODE XREF: sub_E32C68+83↑j
                lea     eax, [ebp+var_8]
                push    eax
                push    [ebp+var_4]
                call    sub_E32D1E
                pop     ecx
                pop     ecx

loc_E32D17:                             ; CODE XREF: sub_E32C68+9F↑j
                mov     eax, [ebp+var_4]
                leave
                retn    0Ch
sub_E32C68      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int __cdecl sub_E32D1E(int, int)
sub_E32D1E      proc near               ; CODE XREF: sub_E32B4B+EC↑p
                                        ; sub_E32C68+A8↑p

var_4           = dword ptr -4
arg_0           = dword ptr  8
arg_4           = dword ptr  0Ch

                push    ebp
                mov     ebp, esp
                push    ecx
                push    [ebp+arg_0]
                call    MicrosoftVisualC14netruntime ; Microsoft VisualC 14/net runtime
                pop     ecx
                push    eax             ; void *
                push    4               ; unsigned int
                call    xEncode
                pop     ecx
                pop     ecx
                mov     [ebp+var_4], eax
                push    [ebp+arg_4]
                call    MicrosoftVisualC14netruntime ; Microsoft VisualC 14/net runtime
                pop     ecx
                mov     ecx, [ebp+var_4]
                mov     eax, [eax]
                mov     [ecx], eax
                leave
                retn
sub_E32D1E      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; unsigned int __cdecl sub_E32D4A(unsigned int)
sub_E32D4A      proc near               ; CODE XREF: oEncode+A↑p

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
                jbe     short loc_E32D68
                call    sub_E3152F
; ---------------------------------------------------------------------------

loc_E32D68:                             ; CODE XREF: sub_E32D4A+17↑j
                mov     eax, [ebp+arg_0]
                shl     eax, 3
                leave
                retn
sub_E32D4A      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int __cdecl sub_E32D70(_DWORD)
sub_E32D70      proc near               ; CODE XREF: oEncode+11↑p
                                        ; sub_E327C5+11↑p

Size            = dword ptr  8

                push    ebp             ; int
                mov     ebp, esp
                cmp     [ebp+Size], 1000h
                jb      short loc_E32D87
                push    [ebp+Size]
                call    sub_E33533
                pop     ecx
                jmp     short loc_E32D9A
; ---------------------------------------------------------------------------

loc_E32D87:                             ; CODE XREF: sub_E32D70+A↑j
                cmp     [ebp+Size], 0
                jz      short loc_E32D98
                push    [ebp+Size]      ; Size
                call    ??2@YAPAXIHPBDH@Z ; operator new(uint,int,char const *,int)
                pop     ecx
                jmp     short loc_E32D9A
; ---------------------------------------------------------------------------

loc_E32D98:                             ; CODE XREF: sub_E32D70+1B↑j
                xor     eax, eax

loc_E32D9A:                             ; CODE XREF: sub_E32D70+15↑j
                                        ; sub_E32D70+26↑j
                pop     ebp
                retn
sub_E32D70      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; void __cdecl sub_E32D9C(void *Block, unsigned int)
sub_E32D9C      proc near               ; CODE XREF: sub_E3261E+11↑p
                                        ; sub_E327E0+D↑p

var_C           = dword ptr -0Ch
Block           = dword ptr  8
arg_4           = dword ptr  0Ch

; FUNCTION CHUNK AT 00E364D6 SIZE 0000000C BYTES

                push    ebp
                mov     ebp, esp
                push    0FFFFFFFFh
                push    offset SEH_402D9C
                mov     eax, large fs:0
                push    eax
                mov     large fs:0, esp
                cmp     [ebp+arg_4], 1000h
                jb      short loc_E32DCC
                lea     eax, [ebp+arg_4]
                push    eax
                lea     eax, [ebp+Block]
                push    eax
                call    sub_E315D8
                pop     ecx
                pop     ecx

loc_E32DCC:                             ; CODE XREF: sub_E32D9C+1F↑j
                push    [ebp+arg_4]
                push    [ebp+Block]     ; Block
                call    sub_E35312
                pop     ecx
                pop     ecx
                mov     ecx, [ebp+var_C]
                mov     large fs:0, ecx
                leave
                retn
sub_E32D9C      endp

; ---------------------------------------------------------------------------
                db 5 dup(0CCh)

; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int __cdecl sub_E32DEA(int)
sub_E32DEA      proc near               ; CODE XREF: sub_E327C5+A↑p

var_1           = byte ptr -1
arg_0           = dword ptr  8

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+var_1], 0
                mov     eax, [ebp+arg_0]
                leave
                retn
sub_E32DEA      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int __thiscall sub_E32DF7(int *this)
sub_E32DF7      proc near               ; CODE XREF: sub_E32823+B8↑p

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
                call    sub_E33591
                pop     ecx
                pop     ecx
                leave
                retn
sub_E32DF7      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int (__thiscall ***__thiscall sub_E32E13(int (__thiscall ****this)(_DWORD, int)))(_DWORD, int)
sub_E32E13      proc near               ; CODE XREF: sub_E32823+C4↑p
                                        ; sub_E32823+3D61↓j

var_C           = dword ptr -0Ch
var_8           = dword ptr -8
var_4           = dword ptr -4

                push    ebp
                mov     ebp, esp
                sub     esp, 0Ch
                mov     [ebp+var_4], ecx
                mov     eax, [ebp+var_4]
                cmp     dword ptr [eax], 0
                jz      short locret_E32E42
                mov     ecx, [ebp+var_4]
                call    jCrucialEncode
                mov     [ebp+var_C], eax
                mov     eax, [ebp+var_4]
                mov     eax, [eax]
                mov     [ebp+var_8], eax
                push    [ebp+var_8]
                mov     ecx, [ebp+var_C]
                call    sub_E32EE5

locret_E32E42:                          ; CODE XREF: sub_E32E13+F↑j
                leave
                retn
sub_E32E13      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _DWORD *__thiscall sEncode(_DWORD *this)
                public sEncode
sEncode         proc near               ; CODE XREF: qEncode+13↑p
                                        ; sub_E32B03+12↑p

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
sEncode         endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; void __stdcall sub_E32E64(int, int)
sub_E32E64      proc near               ; CODE XREF: sub_E329E8+4F↑p
                                        ; sub_E329E8+CE↑p

var_4           = dword ptr -4

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+var_4], ecx
                leave
                retn    8
sub_E32E64      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int __thiscall sub_E32E6F(void *this, int, int, int)
sub_E32E6F      proc near               ; CODE XREF: sub_E329E8+BB↑p
                                        ; sub_E33363+AD↓p

var_4           = dword ptr -4
arg_0           = dword ptr  8
arg_4           = dword ptr  0Ch

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+var_4], ecx
                mov     ecx, [ebp+var_4]
                call    kEncode
                push    eax
                push    [ebp+arg_4]
                push    [ebp+arg_0]
                call    sub_E335AC
                add     esp, 0Ch
                leave
                retn    0Ch
sub_E32E6F      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; unsigned int __thiscall sub_E32E91(unsigned int *this, int)
sub_E32E91      proc near               ; CODE XREF: sub_E32B4B+45↑p
                                        ; sub_E32C68+2A↑p

var_C           = dword ptr -0Ch
var_8           = dword ptr -8
var_4           = dword ptr -4
arg_0           = dword ptr  8

                push    ebp
                mov     ebp, esp
                sub     esp, 0Ch
                mov     [ebp+var_4], ecx
                mov     ecx, [ebp+var_4]
                call    sub_E32677
                mov     [ebp+var_8], eax
                mov     eax, [ebp+var_4]
                mov     eax, [eax+14h]
                mov     [ebp+var_C], eax
                push    [ebp+var_8]
                push    [ebp+var_C]
                push    [ebp+arg_0]
                call    sub_E32F19
                add     esp, 0Ch
                leave
                retn    4
sub_E32E91      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _DWORD *__thiscall sub_E32EC3(_DWORD *this)
sub_E32EC3      proc near               ; CODE XREF: sub_E32C45+12↑p

var_4           = dword ptr -4

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+var_4], ecx
                mov     ecx, [ebp+var_4]
                call    jCrucialEncode
                mov     eax, [ebp+var_4]
                and     dword ptr [eax+10h], 0
                mov     eax, [ebp+var_4]
                and     dword ptr [eax+14h], 0
                mov     eax, [ebp+var_4]
                leave
                retn
sub_E32EC3      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int (__thiscall ***__stdcall sub_E32EE5(int (__thiscall ***)(_DWORD, int)))(_DWORD, int)
sub_E32EE5      proc near               ; CODE XREF: sub_E32E13+2A↑p

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
                jz      short loc_E32F11
                mov     eax, [ebp+var_4]
                mov     eax, [eax]
                mov     eax, [eax]
                mov     [ebp+var_8], eax
                push    1
                mov     ecx, [ebp+var_4]
                call    [ebp+var_8]
                mov     [ebp+var_C], eax
                jmp     short locret_E32F15
; ---------------------------------------------------------------------------

loc_E32F11:                             ; CODE XREF: sub_E32EE5+13↑j
                and     [ebp+var_C], 0

locret_E32F15:                          ; CODE XREF: sub_E32EE5+2A↑j
                leave
                retn    4
sub_E32EE5      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; unsigned int __cdecl sub_E32F19(int, unsigned int, unsigned int)
sub_E32F19      proc near               ; CODE XREF: sub_E32E91+26↑p

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
                jbe     short loc_E32F34
                mov     eax, [ebp+arg_8]
                jmp     short locret_E32F64
; ---------------------------------------------------------------------------

loc_E32F34:                             ; CODE XREF: sub_E32F19+14↑j
                mov     eax, [ebp+arg_4]
                shr     eax, 1
                mov     ecx, [ebp+arg_8]
                sub     ecx, eax
                cmp     [ebp+arg_4], ecx
                jbe     short loc_E32F48
                mov     eax, [ebp+arg_8]
                jmp     short locret_E32F64
; ---------------------------------------------------------------------------

loc_E32F48:                             ; CODE XREF: sub_E32F19+28↑j
                mov     eax, [ebp+arg_4]
                shr     eax, 1
                add     eax, [ebp+arg_4]
                mov     [ebp+var_8], eax
                lea     eax, [ebp+var_8]
                push    eax
                lea     eax, [ebp+var_4]
                push    eax
                call    sub_E325F4
                pop     ecx
                pop     ecx
                mov     eax, [eax]

locret_E32F64:                          ; CODE XREF: sub_E32F19+19↑j
                                        ; sub_E32F19+2D↑j
                leave
                retn
sub_E32F19      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int __cdecl sub_E32F66(int, _DWORD *)
sub_E32F66      proc near               ; CODE XREF: bGetInput+10↑p

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

; FUNCTION CHUNK AT 00E3659A SIZE 00000010 BYTES
; FUNCTION CHUNK AT 00E365AF SIZE 0000000C BYTES

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
                call    sub_E336F6
                and     [ebp+var_4], 0
                lea     ecx, [ebp+var_74]
                call    sub_E336E7
                movzx   eax, al
                test    eax, eax
                jz      loc_E3316F
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
                mov     byte ptr [ebp+var_4], 1
                push    [ebp+var_2C]
                call    sub_E32823
                pop     ecx
                mov     [ebp+var_44], eax
                mov     byte ptr [ebp+var_4], 0
                lea     ecx, [ebp+var_7C]
                call    sub_E316D8
                push    0
                mov     ecx, [ebp+arg_4]
                call    sub_E3392C
                mov     byte ptr [ebp+var_4], 2
                mov     eax, [ebp+arg_0]
                mov     eax, [eax]
                mov     ecx, [ebp+arg_0]
                add     ecx, [eax+4]
                call    ds:?width@ios_base@std@@QBE_JXZ ; std::ios_base::width(void)
                mov     dword ptr [ebp+var_5C], eax
                mov     dword ptr [ebp+var_5C+4], edx
                cmp     dword ptr [ebp+var_5C+4], 0
                jl      short loc_E3306A
                jg      short loc_E33027
                cmp     dword ptr [ebp+var_5C], 0
                jbe     short loc_E3306A

loc_E33027:                             ; CODE XREF: sub_E32F66+B9↑j
                mov     eax, [ebp+arg_0]
                mov     eax, [eax]
                mov     ecx, [ebp+arg_0]
                add     ecx, [eax+4]
                call    ds:?width@ios_base@std@@QBE_JXZ ; std::ios_base::width(void)
                mov     dword ptr [ebp+var_64], eax
                mov     dword ptr [ebp+var_64+4], edx
                mov     ecx, [ebp+arg_4]
                call    sub_E32677
                cmp     dword ptr [ebp+var_64], eax
                jnb     short loc_E3306A
                mov     eax, [ebp+arg_0]
                mov     eax, [eax]
                mov     ecx, [ebp+arg_0]
                add     ecx, [eax+4]
                call    ds:?width@ios_base@std@@QBE_JXZ ; std::ios_base::width(void)
                mov     dword ptr [ebp+var_6C], eax
                mov     dword ptr [ebp+var_6C+4], edx
                mov     eax, dword ptr [ebp+var_6C]
                mov     [ebp+var_1C], eax
                jmp     short loc_E33075
; ---------------------------------------------------------------------------

loc_E3306A:                             ; CODE XREF: sub_E32F66+B7↑j
                                        ; sub_E32F66+BF↑j ...
                mov     ecx, [ebp+arg_4]
                call    sub_E32677
                mov     [ebp+var_1C], eax

loc_E33075:                             ; CODE XREF: sub_E32F66+102↑j
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
                jmp     short loc_E330CA
; ---------------------------------------------------------------------------

loc_E3309D:                             ; CODE XREF: sub_E32F66:loc_E3313D↓j
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

loc_E330CA:                             ; CODE XREF: sub_E32F66+135↑j
                cmp     [ebp+var_1C], 0
                jbe     short loc_E33142
                call    ?max@?$numeric_limits@I@std@@SAIXZ ; std::numeric_limits<uint>::max(void)
                mov     [ebp+var_40], eax
                lea     eax, [ebp+var_20]
                push    eax
                lea     eax, [ebp+var_40]
                push    eax
                call    sub_E324F8
                pop     ecx
                pop     ecx
                movzx   eax, al
                test    eax, eax
                jz      short loc_E330FB
                mov     eax, [ebp+var_18]
                or      eax, 1
                mov     [ebp+var_18], eax
                jmp     short loc_E33142
; ---------------------------------------------------------------------------
                jmp     short loc_E3313D
; ---------------------------------------------------------------------------

loc_E330FB:                             ; CODE XREF: sub_E32F66+186↑j
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
                jz      short loc_E33123
                jmp     short loc_E33142
; ---------------------------------------------------------------------------
                jmp     short loc_E3313D
; ---------------------------------------------------------------------------

loc_E33123:                             ; CODE XREF: sub_E32F66+1B7↑j
                lea     eax, [ebp+var_20]
                push    eax
                call    ?to_char_type@?$_Narrow_char_traits@DH@std@@SADABH@Z ; std::_Narrow_char_traits<char,int>::to_char_type(int const &)
                pop     ecx
                movzx   eax, al
                push    eax
                mov     ecx, [ebp+arg_4]
                call    sub_E31FCE
                mov     [ebp+var_11], 1

loc_E3313D:                             ; CODE XREF: sub_E32F66+193↑j
                                        ; sub_E32F66+1BB↑j
                jmp     loc_E3309D
; ---------------------------------------------------------------------------

loc_E33142:                             ; CODE XREF: sub_E32F66+168↑j
                                        ; sub_E32F66+191↑j ...
                jmp     short loc_E33165
; ---------------------------------------------------------------------------

loc_E33144:                             ; DATA XREF: .rdata:stru_E37C64↓o
                mov     eax, [ebp+arg_0]
                mov     eax, [eax]
                mov     ecx, [ebp+arg_0]
                add     ecx, [eax+4]
                mov     [ebp+var_48], ecx
                push    1
                push    4
                mov     ecx, [ebp+var_48]
                call    ds:?setstate@?$basic_ios@DU?$char_traits@D@std@@@std@@QAEXH_N@Z ; std::ios::setstate(int,bool)
                mov     eax, offset loc_E3316B
                retn
; ---------------------------------------------------------------------------

loc_E33165:                             ; CODE XREF: sub_E32F66:loc_E33142↑j
                and     [ebp+var_4], 0
                jmp     short loc_E3316F
; ---------------------------------------------------------------------------

loc_E3316B:                             ; CODE XREF: sub_E32F66+1FE↑j
                                        ; DATA XREF: sub_E32F66+1F9↑o
                and     [ebp+var_4], 0

loc_E3316F:                             ; CODE XREF: sub_E32F66+48↑j
                                        ; sub_E32F66+203↑j
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
                jnz     short loc_E3319B
                mov     eax, [ebp+var_18]
                or      eax, 2
                mov     [ebp+var_18], eax

loc_E3319B:                             ; CODE XREF: sub_E32F66+22A↑j
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
                or      [ebp+var_4], 0FFFFFFFFh
                lea     ecx, [ebp+var_74]
                call    sub_E33618
                mov     eax, [ebp+var_54]
                mov     ecx, [ebp+var_C]
                mov     large fs:0, ecx
                pop     edi
                pop     esi
                pop     ebx
                leave
                retn
sub_E32F66      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _DWORD *__thiscall sub_E331DB(_DWORD *this, char)
sub_E331DB      proc near               ; CODE XREF: sub_E32823+8A↑p

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
                call    sub_E33BAD
                mov     eax, [ebp+var_4]
                leave
                retn    4
sub_E331DB      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _DWORD *__cdecl sub_E33200(_DWORD *, _DWORD *, void *)
sub_E33200      proc near               ; CODE XREF: sub_E32943+18↑p

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
                call    sub_E31FA1
                push    eax
                lea     eax, [ebp+var_10]
                push    eax
                call    sub_E33BCB
                add     esp, 0Ch
                push    eax
                mov     ecx, [ebp+arg_0]
                call    sub_E31F83
                mov     eax, [ebp+arg_0]
                leave
                retn
sub_E33200      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; BOOL __cdecl sub_E33230(_DWORD *)
sub_E33230      proc near               ; CODE XREF: sub_E32943+21↑p

var_20          = xtime ptr -20h
var_10          = dword ptr -10h
var_8           = dword ptr -8
arg_0           = dword ptr  8

                push    ebp
                mov     ebp, esp
                sub     esp, 20h

loc_E33236:                             ; CODE XREF: sub_E33230+51↓j
                lea     eax, [ebp+var_8]
                push    eax
                call    sub_E317C3
                pop     ecx
                lea     eax, [ebp+var_8]
                push    eax
                push    [ebp+arg_0]
                call    sub_E33C1C
                pop     ecx
                pop     ecx
                movzx   eax, al
                test    eax, eax
                jz      short loc_E33257
                jmp     short locret_E33283
; ---------------------------------------------------------------------------

loc_E33257:                             ; CODE XREF: sub_E33230+23↑j
                lea     eax, [ebp+var_8]
                push    eax
                push    [ebp+arg_0]
                lea     eax, [ebp+var_10]
                push    eax
                call    sub_E33C46
                add     esp, 0Ch
                push    eax
                lea     eax, [ebp+var_20]
                push    eax
                call    sub_E33C80
                pop     ecx
                pop     ecx
                lea     eax, [ebp+var_20]
                push    eax             ; xtime *
                call    ds:_Thrd_sleep
                pop     ecx
                jmp     short loc_E33236
; ---------------------------------------------------------------------------

locret_E33283:                          ; CODE XREF: sub_E33230+25↑j
                leave
                retn
sub_E33230      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int __cdecl sub_E33285(int, int, int, int)
sub_E33285      proc near               ; CODE XREF: sub_E3296C+28↑p

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
                call    iCrucialEncode
                lea     ecx, [ebp+var_1]
                call    jCrucialEncode
                lea     ecx, [ebp+var_1]
                call    kCrucialEncode
                push    eax
                lea     ecx, [ebp+var_139C]
                call    sub_E3390C
                push    [ebp+arg_C]
                push    [ebp+arg_8]
                push    [ebp+arg_4]
                push    [ebp+arg_0]
                lea     ecx, [ebp+var_14]
                call    sub_E336C5
                lea     eax, [ebp+var_139C]
                push    eax
                lea     ecx, [ebp+var_14]
                call    sub_E33D4C
                leave
                retn
sub_E33285      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; __int16 __cdecl hCrucialEncode(__int16, __int16)
                public hCrucialEncode
hCrucialEncode  proc near               ; CODE XREF: fCrucialEncode+1D↑p

var_1390        = dword ptr -1390h
var_8           = word ptr -8
var_1           = byte ptr -1
arg_0           = dword ptr  8
arg_4           = dword ptr  0Ch

                push    ebp
                mov     ebp, esp
                mov     eax, 1390h
                call    iCrucialEncode
                lea     ecx, [ebp+var_1]
                call    jCrucialEncode
                lea     ecx, [ebp+var_1]
                call    kCrucialEncode
                push    eax
                lea     ecx, [ebp+var_1390]
                call    sub_E3390C
                push    [ebp+arg_4]
                push    [ebp+arg_0]
                lea     ecx, [ebp+var_8]
                call    lCrucialEncode
                lea     eax, [ebp+var_1390]
                push    eax
                lea     ecx, [ebp+var_8]
                call    mCrucialEncode
                leave
                retn
hCrucialEncode  endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int __cdecl sub_E3331B(int, int)
sub_E3331B      proc near               ; CODE XREF: sub_E329C4+1B↑p

var_1394        = dword ptr -1394h
var_C           = byte ptr -0Ch
var_1           = byte ptr -1
arg_0           = dword ptr  8
arg_4           = dword ptr  0Ch

                push    ebp
                mov     ebp, esp
                mov     eax, 1394h
                call    iCrucialEncode
                lea     ecx, [ebp+var_1]
                call    jCrucialEncode
                lea     ecx, [ebp+var_1]
                call    kCrucialEncode
                push    eax
                lea     ecx, [ebp+var_1394]
                call    sub_E3390C
                push    [ebp+arg_4]
                push    [ebp+arg_0]
                lea     ecx, [ebp+var_C]
                call    sub_E3368D
                lea     eax, [ebp+var_1394]
                push    eax
                lea     ecx, [ebp+var_C]
                call    sub_E33D98
                leave
                retn
sub_E3331B      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int __thiscall sub_E33363(int *this, unsigned int, unsigned __int8 *)
sub_E33363      proc near               ; CODE XREF: sub_E329E8+98↑p

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

; FUNCTION CHUNK AT 00E365BB SIZE 0000000C BYTES

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
                call    sub_E338D6
                cmp     [ebp+arg_0], eax
                jbe     short loc_E3339A
                call    sub_E337AD
; ---------------------------------------------------------------------------

loc_E3339A:                             ; CODE XREF: sub_E33363+30↑j
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
                call    sub_E3385F
                mov     [ebp+var_20], eax
                mov     ecx, [ebp+var_14]
                call    kEncode
                mov     [ebp+var_38], eax
                push    [ebp+var_20]
                mov     ecx, [ebp+var_38]
                call    oEncode
                mov     [ebp+Block], eax
                mov     eax, [ebp+var_28]
                mov     ecx, [ebp+Block]
                lea     eax, [ecx+eax*8]
                mov     [ebp+var_1C], eax
                mov     eax, [ebp+var_1C]
                mov     [ebp+var_34], eax
                and     [ebp+var_4], 0
                mov     eax, [ebp+arg_4]
                movzx   eax, byte ptr [eax]
                push    eax
                mov     eax, [ebp+arg_0]
                sub     eax, [ebp+var_28]
                push    eax
                push    [ebp+var_1C]
                mov     ecx, [ebp+var_14]
                call    sub_E32E6F
                mov     [ebp+var_3C], eax
                mov     eax, [ebp+var_3C]
                mov     [ebp+var_34], eax
                push    [ebp+Block]
                mov     eax, [ebp+var_2C]
                push    dword ptr [eax]
                mov     eax, [ebp+var_30]
                push    dword ptr [eax]
                mov     ecx, [ebp+var_14]
                call    sub_E338B1
                jmp     short loc_E3346B
; ---------------------------------------------------------------------------

loc_E33435:                             ; DATA XREF: .rdata:stru_E37CBC↓o
                push    [ebp+var_34]
                push    [ebp+var_1C]
                mov     ecx, [ebp+var_14]
                call    sub_E325B7
                mov     ecx, [ebp+var_14]
                call    kEncode
                mov     [ebp+var_40], eax
                push    [ebp+var_20]    ; int
                push    [ebp+Block]     ; Block
                mov     ecx, [ebp+var_40]
                call    sub_E3261E
                push    0               ; pThrowInfo
                push    0               ; pExceptionObject
                call    _CxxThrowException
; ---------------------------------------------------------------------------
                mov     eax, offset loc_E33471
                retn
; ---------------------------------------------------------------------------

loc_E3346B:                             ; CODE XREF: sub_E33363+D0↑j
                or      [ebp+var_4], 0FFFFFFFFh
                jmp     short loc_E33475
; ---------------------------------------------------------------------------

loc_E33471:                             ; DATA XREF: sub_E33363+102↑o
                or      [ebp+var_4], 0FFFFFFFFh

loc_E33475:                             ; CODE XREF: sub_E33363+10C↑j
                push    [ebp+var_20]
                push    [ebp+arg_0]
                push    [ebp+Block]
                mov     ecx, [ebp+var_14]
                call    sub_E337BD
                mov     ecx, [ebp+var_C]
                mov     large fs:0, ecx
                pop     edi
                pop     esi
                pop     ebx
                leave
                retn    8
sub_E33363      endp

; ---------------------------------------------------------------------------
                db 5 dup(0CCh)

; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int __cdecl tEncode(int, int, int, int)
                public tEncode
tEncode         proc near               ; CODE XREF: rEncode+19↑p
                                        ; sub_E33A0B+19↓p

var_20          = dword ptr -20h
var_14          = dword ptr -14h
var_10          = dword ptr -10h
var_C           = dword ptr -0Ch
var_4           = dword ptr -4
arg_0           = byte ptr  8
arg_4           = byte ptr  0Ch
arg_8           = dword ptr  10h
arg_C           = dword ptr  14h

; FUNCTION CHUNK AT 00E365C7 SIZE 00000008 BYTES
; FUNCTION CHUNK AT 00E365D4 SIZE 0000000C BYTES

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
                call    sub_E33665
                and     [ebp+var_4], 0
                jmp     short loc_E334EE
; ---------------------------------------------------------------------------

loc_E334E5:                             ; CODE XREF: tEncode+65↓j
                mov     eax, [ebp+var_10]
                add     eax, 8
                mov     [ebp+var_10], eax

loc_E334EE:                             ; CODE XREF: tEncode+47↑j
                mov     eax, [ebp+var_10]
                cmp     eax, [ebp+var_14]
                jz      short loc_E33503
                push    [ebp+var_10]
                lea     ecx, [ebp+var_20]
                call    uEncode
                jmp     short loc_E334E5
; ---------------------------------------------------------------------------

loc_E33503:                             ; CODE XREF: tEncode+58↑j
                lea     ecx, [ebp+var_20]
                call    sub_E33629
                mov     [ebp+arg_8], eax
                or      [ebp+var_4], 0FFFFFFFFh
                lea     ecx, [ebp+var_20]
                call    sub_E33643
                mov     eax, [ebp+arg_8]
                mov     ecx, [ebp+var_C]
                mov     large fs:0, ecx
                leave
                retn
tEncode         endp

; [0000000A BYTES: COLLAPSED FUNCTION unknown_libname_4. PRESS CTRL-NUMPAD+ TO EXPAND]

; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; unsigned int __cdecl sub_E33533(unsigned int)
sub_E33533      proc near               ; CODE XREF: sub_E32D70+F↑p

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
                ja      short loc_E3354F
                call    sub_E3152F
; ---------------------------------------------------------------------------

loc_E3354F:                             ; CODE XREF: sub_E33533+15↑j
                push    [ebp+Size]      ; Size
                call    ??2@YAPAXIHPBDH@Z ; operator new(uint,int,char const *,int)
                pop     ecx
                mov     [ebp+var_4], eax

loc_E3355B:                             ; CODE XREF: sub_E33533+3C↓j
                cmp     [ebp+var_4], 0
                jz      short loc_E33563
                jmp     short loc_E3356D
; ---------------------------------------------------------------------------

loc_E33563:                             ; CODE XREF: sub_E33533+2C↑j
                                        ; sub_E33533+38↓j
                call    ds:_invalid_parameter_noinfo_noreturn
; ---------------------------------------------------------------------------
                xor     eax, eax
                jnz     short loc_E33563

loc_E3356D:                             ; CODE XREF: sub_E33533+2E↑j
                xor     eax, eax
                jnz     short loc_E3355B
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
sub_E33533      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int __cdecl sub_E33591(int *, int *)
sub_E33591      proc near               ; CODE XREF: sub_E32DF7+13↑p

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
sub_E33591      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int __cdecl sub_E335AC(int, int, int)
sub_E335AC      proc near               ; CODE XREF: sub_E32E6F+16↑p

var_1C          = dword ptr -1Ch
var_10          = dword ptr -10h
var_C           = dword ptr -0Ch
var_4           = dword ptr -4
arg_0           = dword ptr  8
arg_4           = dword ptr  0Ch
arg_8           = dword ptr  10h

; FUNCTION CHUNK AT 00E365E0 SIZE 00000008 BYTES
; FUNCTION CHUNK AT 00E365ED SIZE 0000000C BYTES

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
                call    sub_E33665
                and     [ebp+var_4], 0
                jmp     short loc_E335E2
; ---------------------------------------------------------------------------

loc_E335DB:                             ; CODE XREF: sub_E335AC+44↓j
                mov     eax, [ebp+arg_4]
                dec     eax
                mov     [ebp+arg_4], eax

loc_E335E2:                             ; CODE XREF: sub_E335AC+2D↑j
                cmp     [ebp+arg_4], 0
                jbe     short loc_E335F2
                lea     ecx, [ebp+var_1C]
                call    sub_E33E0A
                jmp     short loc_E335DB
; ---------------------------------------------------------------------------

loc_E335F2:                             ; CODE XREF: sub_E335AC+3A↑j
                lea     ecx, [ebp+var_1C]
                call    sub_E33629
                mov     [ebp+var_10], eax
                or      [ebp+var_4], 0FFFFFFFFh
                lea     ecx, [ebp+var_1C]
                call    sub_E33643
                mov     eax, [ebp+var_10]
                mov     ecx, [ebp+var_C]
                mov     large fs:0, ecx
                leave
                retn
sub_E335AC      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int __thiscall sub_E33618(_DWORD *this)
sub_E33618      proc near               ; CODE XREF: sub_E32F66+25E↑p
                                        ; sub_E32F66+3637↓j

var_4           = dword ptr -4

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+var_4], ecx
                mov     ecx, [ebp+var_4]
                call    sub_E33751
                leave
                retn
sub_E33618      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int __thiscall sub_E33629(_DWORD *this)
sub_E33629      proc near               ; CODE XREF: tEncode+6A↑p
                                        ; sub_E335AC+49↑p

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
sub_E33629      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; void sub_E33643()
sub_E33643      proc near               ; CODE XREF: tEncode+79↑p
                                        ; sub_E335AC+58↑p ...

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
                call    sub_E32C63
                add     esp, 0Ch
                leave
                retn
sub_E33643      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _DWORD *__thiscall sub_E33665(_DWORD *this, int, int)
sub_E33665      proc near               ; CODE XREF: tEncode+3E↑p
                                        ; sub_E335AC+24↑p

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
sub_E33665      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _DWORD *__thiscall sub_E3368D(_DWORD *this, int, int)
sub_E3368D      proc near               ; CODE XREF: sub_E3331B+32↑p

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
                call    sub_E33957
                mov     eax, [ebp+var_4]
                leave
                retn    8
sub_E3368D      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _WORD *__thiscall lCrucialEncode(_WORD *this, __int16, __int16)
                public lCrucialEncode
lCrucialEncode  proc near               ; CODE XREF: hCrucialEncode+32↑p

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
                call    nCrucialEncode
                mov     eax, [ebp+var_4]
                leave
                retn    8
lCrucialEncode  endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _DWORD *__thiscall sub_E336C5(_DWORD *this, int, int, int, int)
sub_E336C5      proc near               ; CODE XREF: sub_E33285+38↑p

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
                call    sub_E3399D
                mov     eax, [ebp+var_4]
                leave
                retn    10h
sub_E336C5      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; char __thiscall sub_E336E7(_BYTE *this)
sub_E336E7      proc near               ; CODE XREF: sub_E32F66+3E↑p

var_4           = dword ptr -4

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+var_4], ecx
                mov     eax, [ebp+var_4]
                mov     al, [eax+4]
                leave
                retn
sub_E336E7      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _DWORD *__thiscall sub_E336F6(_DWORD *this, int, int)
sub_E336F6      proc near               ; CODE XREF: sub_E32F66+32↑p

var_14          = dword ptr -14h
var_10          = dword ptr -10h
var_C           = dword ptr -0Ch
var_4           = dword ptr -4
arg_0           = dword ptr  8
arg_4           = dword ptr  0Ch

; FUNCTION CHUNK AT 00E365F9 SIZE 00000008 BYTES
; FUNCTION CHUNK AT 00E36606 SIZE 0000000C BYTES

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
                call    sub_E339C6
                and     [ebp+var_4], 0
                mov     eax, [ebp+var_10]
                mov     eax, [eax]
                mov     [ebp+var_14], eax
                push    [ebp+arg_4]
                mov     ecx, [ebp+var_14]
                call    ds:?_Ipfx@?$basic_istream@DU?$char_traits@D@std@@@std@@QAE_N_N@Z ; std::istream::_Ipfx(bool)
                mov     ecx, [ebp+var_10]
                mov     [ecx+4], al
                or      [ebp+var_4], 0FFFFFFFFh
                mov     eax, [ebp+var_10]
                mov     ecx, [ebp+var_C]
                mov     large fs:0, ecx
                leave
                retn    8
sub_E336F6      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int __thiscall sub_E33751(_DWORD *this)
sub_E33751      proc near               ; CODE XREF: sub_E33618+A↑p
                                        ; sub_E336F6+2F06↓j

var_18          = dword ptr -18h
var_14          = dword ptr -14h
var_10          = dword ptr -10h
var_C           = dword ptr -0Ch

; FUNCTION CHUNK AT 00E364D6 SIZE 0000000C BYTES

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
                jz      short loc_E3379C
                mov     eax, [ebp+var_10]
                mov     eax, [eax]
                mov     ecx, [ebp+var_10]
                call    dword ptr [eax+8]

loc_E3379C:                             ; CODE XREF: sub_E33751+3E↑j
                mov     ecx, [ebp+var_C]
                mov     large fs:0, ecx
                leave
                retn
sub_E33751      endp

; ---------------------------------------------------------------------------
                db 5 dup(0CCh)

; =============== S U B R O U T I N E =======================================

; Attributes: noreturn bp-based frame

; void __noreturn sub_E337AD()
sub_E337AD      proc near               ; CODE XREF: sub_E33363+32↑p
                push    ebp
                mov     ebp, esp
                push    offset aVectorTooLong ; "vector too long"
                call    ds:?_Xlength_error@std@@YAXPBD@Z ; std::_Xlength_error(char const *)
sub_E337AD      endp

; ---------------------------------------------------------------------------
                pop     ebp
                retn

; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; char *__thiscall sub_E337BD(void **this, char *, int, int)
sub_E337BD      proc near               ; CODE XREF: sub_E33363+11E↑p

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
                call    aEncode
                mov     eax, [ebp+var_4]
                cmp     dword ptr [eax], 0
                jz      short loc_E33837
                mov     eax, [ebp+var_10]
                push    dword ptr [eax]
                mov     eax, [ebp+var_4]
                push    dword ptr [eax]
                mov     ecx, [ebp+var_C]
                call    sub_E325B7
                mov     ecx, [ebp+var_C]
                call    kEncode
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
                call    sub_E3261E

loc_E33837:                             ; CODE XREF: sub_E337BD+35↑j
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
sub_E337BD      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int __thiscall sub_E3385F(_DWORD *this, unsigned int)
sub_E3385F      proc near               ; CODE XREF: sub_E33363+62↑p

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
                call    sub_E33A30
                mov     [ebp+var_4], eax
                mov     ecx, [ebp+var_8]
                call    sub_E338D6
                mov     [ebp+var_C], eax
                mov     eax, [ebp+var_4]
                shr     eax, 1
                mov     ecx, [ebp+var_C]
                sub     ecx, eax
                cmp     [ebp+var_4], ecx
                jbe     short loc_E33892
                mov     eax, [ebp+var_C]
                jmp     short locret_E338AD
; ---------------------------------------------------------------------------

loc_E33892:                             ; CODE XREF: sub_E3385F+2C↑j
                mov     eax, [ebp+var_4]
                shr     eax, 1
                add     eax, [ebp+var_4]
                mov     [ebp+var_10], eax
                mov     eax, [ebp+var_10]
                cmp     eax, [ebp+arg_0]
                jnb     short loc_E338AA
                mov     eax, [ebp+arg_0]
                jmp     short locret_E338AD
; ---------------------------------------------------------------------------

loc_E338AA:                             ; CODE XREF: sub_E3385F+44↑j
                mov     eax, [ebp+var_10]

locret_E338AD:                          ; CODE XREF: sub_E3385F+31↑j
                                        ; sub_E3385F+49↑j
                leave
                retn    4
sub_E3385F      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int __thiscall sub_E338B1(void *this, int, int, int)
sub_E338B1      proc near               ; CODE XREF: sub_E33363+CB↑p

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
                call    sub_E33A0B
                leave
                retn    0Ch
sub_E338B1      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int __thiscall sub_E338D6(void *this)
sub_E338D6      proc near               ; CODE XREF: sub_E33363+28↑p
                                        ; sub_E3385F+17↑p

var_C           = dword ptr -0Ch
var_8           = dword ptr -8
var_4           = dword ptr -4

                push    ebp
                mov     ebp, esp
                sub     esp, 0Ch
                mov     [ebp+var_4], ecx
                mov     ecx, [ebp+var_4]
                call    kEncode
                push    eax
                call    sub_E33A4E
                pop     ecx
                mov     [ebp+var_8], eax
                call    unknown_libname_1 ; Microsoft VisualC 14/net runtime
                mov     [ebp+var_C], eax
                lea     eax, [ebp+var_8]
                push    eax
                lea     eax, [ebp+var_C]
                push    eax
                call    sub_E32B21
                pop     ecx
                pop     ecx
                mov     eax, [eax]
                leave
                retn
sub_E338D6      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _DWORD *__thiscall sub_E3390C(_DWORD *this, unsigned int)
sub_E3390C      proc near               ; CODE XREF: sub_E33285+24↑p
                                        ; hCrucialEncode+24↑p ...

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
                call    sub_E33A58
                mov     eax, [ebp+var_4]
                leave
                retn    4
sub_E3390C      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _DWORD *__thiscall sub_E3392C(_DWORD *this, unsigned int)
sub_E3392C      proc near               ; CODE XREF: sub_E32F66+93↑p

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
                call    sub_E327F8
                push    [ebp+arg_0]
                mov     ecx, [ebp+var_4]
                call    sub_E3263A
                mov     eax, [ebp+var_4]
                leave
                retn    4
sub_E3392C      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _DWORD *__thiscall sub_E33957(_DWORD *this, int, int)
sub_E33957      proc near               ; CODE XREF: sub_E3368D+10↑p

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
                call    sub_E33A80
                mov     eax, [ebp+var_4]
                leave
                retn    8
sub_E33957      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _WORD *__thiscall nCrucialEncode(_WORD *this, __int16, __int16)
                public nCrucialEncode
nCrucialEncode  proc near               ; CODE XREF: lCrucialEncode+10↑p

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
                call    oCrucialEncode
                mov     eax, [ebp+var_4]
                leave
                retn    8
nCrucialEncode  endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _DWORD *__thiscall sub_E3399D(_DWORD *this, int, int, int, int)
sub_E3399D      proc near               ; CODE XREF: sub_E336C5+16↑p

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
                call    sub_E33AB8
                mov     eax, [ebp+var_4]
                leave
                retn    10h
sub_E3399D      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int __thiscall sub_E339C6(_DWORD *this, int)
sub_E339C6      proc near               ; CODE XREF: sub_E336F6+23↑p

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
                jz      short loc_E33A04
                mov     eax, [ebp+var_4]
                mov     eax, [eax]
                mov     ecx, [ebp+var_4]
                call    dword ptr [eax+4]

loc_E33A04:                             ; CODE XREF: sub_E339C6+31↑j
                mov     eax, [ebp+var_8]
                leave
                retn    4
sub_E339C6      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int __thiscall sub_E33A0B(void *this, int, int, int, int)
sub_E33A0B      proc near               ; CODE XREF: sub_E338B1+1C↑p

var_4           = dword ptr -4
arg_0           = dword ptr  8
arg_4           = dword ptr  0Ch
arg_8           = dword ptr  10h

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+var_4], ecx
                mov     ecx, [ebp+var_4]
                call    kEncode
                push    eax
                push    [ebp+arg_8]
                push    [ebp+arg_4]
                push    [ebp+arg_0]
                call    tEncode
                add     esp, 10h
                leave
                retn    10h
sub_E33A0B      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int __thiscall sub_E33A30(_DWORD *this)
sub_E33A30      proc near               ; CODE XREF: sub_E3385F+C↑p

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
sub_E33A30      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int sub_E33A4E()
sub_E33A4E      proc near               ; CODE XREF: sub_E338D6+12↑p
                push    ebp
                mov     ebp, esp
                mov     eax, 1FFFFFFFh
                pop     ebp
                retn
sub_E33A4E      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _DWORD *__thiscall sub_E33A58(_DWORD *this, unsigned int, int, int)
sub_E33A58      proc near               ; CODE XREF: sub_E3390C+14↑p

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
                call    sub_E33ADA
                mov     eax, [ebp+var_4]
                leave
                retn    0Ch
sub_E33A58      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _DWORD *__thiscall sub_E33A80(_DWORD *this, int, int)
sub_E33A80      proc near               ; CODE XREF: sub_E33957+17↑p

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
                call    sub_E33B49
                mov     eax, [ebp+var_4]
                leave
                retn    8
sub_E33A80      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _WORD *__thiscall oCrucialEncode(_WORD *this, __int16, __int16)
oCrucialEncode  proc near               ; CODE XREF: nCrucialEncode+17↑p

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
                call    pCrucialEncode
                mov     eax, [ebp+var_4]
                leave
                retn    8
oCrucialEncode  endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _DWORD *__thiscall sub_E33AB8(_DWORD *this, int, int, int, int)
sub_E33AB8      proc near               ; CODE XREF: sub_E3399D+1D↑p

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
                call    sub_E33B85
                mov     eax, [ebp+var_4]
                leave
                retn    10h
sub_E33AB8      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _DWORD *__thiscall sub_E33ADA(_DWORD *this, unsigned int, int)
sub_E33ADA      proc near               ; CODE XREF: sub_E33A58+1C↑p

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
                jmp     short loc_E33B09
; ---------------------------------------------------------------------------

loc_E33B02:                             ; CODE XREF: sub_E33ADA+60↓j
                mov     eax, [ebp+var_4]
                inc     eax
                mov     [ebp+var_4], eax

loc_E33B09:                             ; CODE XREF: sub_E33ADA+26↑j
                cmp     [ebp+var_4], 270h
                jnb     short loc_E33B3C
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
                jmp     short loc_E33B02
; ---------------------------------------------------------------------------

loc_E33B3C:                             ; CODE XREF: sub_E33ADA+36↑j
                mov     eax, [ebp+var_C]
                mov     dword ptr [eax], 270h
                leave
                retn    8
sub_E33ADA      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _DWORD *__thiscall sub_E33B49(_DWORD *this, int, int)
sub_E33B49      proc near               ; CODE XREF: sub_E33A80+10↑p

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
sub_E33B49      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _WORD *__thiscall pCrucialEncode(_WORD *this, __int16, __int16)
                public pCrucialEncode
pCrucialEncode  proc near               ; CODE XREF: oCrucialEncode+10↑p

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
pCrucialEncode  endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _DWORD *__thiscall sub_E33B85(_DWORD *this, int, int, int, int)
sub_E33B85      proc near               ; CODE XREF: sub_E33AB8+16↑p

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
sub_E33B85      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _DWORD *__thiscall sub_E33BAD(_DWORD *this, int, int)
sub_E33BAD      proc near               ; CODE XREF: sub_E331DB+19↑p

var_4           = dword ptr -4
arg_4           = dword ptr  0Ch

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+var_4], ecx
                push    [ebp+arg_4]
                call    MicrosoftVisualC14netruntime ; Microsoft VisualC 14/net runtime
                pop     ecx
                mov     ecx, [ebp+var_4]
                mov     eax, [eax]
                mov     [ecx], eax
                mov     eax, [ebp+var_4]
                leave
                retn    8
sub_E33BAD      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _DWORD *__cdecl sub_E33BCB(_DWORD *, int *, void *)
sub_E33BCB      proc near               ; CODE XREF: sub_E33200+1A↑p

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
                call    sub_E31882
                mov     esi, eax
                mov     edi, edx
                push    [ebp+arg_8]
                lea     ecx, [ebp+var_18]
                call    sub_E33F7F
                mov     ecx, eax
                call    sub_E31882
                add     esi, eax
                adc     edi, edx
                mov     dword ptr [ebp+var_10], esi
                mov     dword ptr [ebp+var_10+4], edi
                lea     eax, [ebp+var_10]
                push    eax
                mov     ecx, [ebp+arg_0]
                call    sub_E31864
                mov     eax, [ebp+arg_0]
                pop     edi
                pop     esi
                leave
                retn
sub_E33BCB      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; bool __cdecl sub_E33C1C(_DWORD *, _DWORD *)
sub_E33C1C      proc near               ; CODE XREF: sub_E33230+17↑p

var_4           = dword ptr -4
arg_0           = dword ptr  8
arg_4           = dword ptr  0Ch

                push    ebp
                mov     ebp, esp
                push    ecx
                push    [ebp+arg_0]
                push    [ebp+arg_4]
                call    sub_E33FAC
                pop     ecx
                pop     ecx
                movzx   eax, al
                test    eax, eax
                jnz     short loc_E33C3D
                mov     [ebp+var_4], 1
                jmp     short loc_E33C41
; ---------------------------------------------------------------------------

loc_E33C3D:                             ; CODE XREF: sub_E33C1C+16↑j
                and     [ebp+var_4], 0

loc_E33C41:                             ; CODE XREF: sub_E33C1C+1F↑j
                mov     al, byte ptr [ebp+var_4]
                leave
                retn
sub_E33C1C      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _DWORD *__cdecl sub_E33C46(_DWORD *, _DWORD *, _DWORD *)
sub_E33C46      proc near               ; CODE XREF: sub_E33230+32↑p

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
                call    sub_E31FA1
                mov     [ebp+var_4], eax
                lea     eax, [ebp+var_18]
                push    eax
                mov     ecx, [ebp+arg_4]
                call    sub_E31FA1
                mov     [ebp+var_8], eax
                push    [ebp+var_4]
                push    [ebp+var_8]
                push    [ebp+arg_0]
                call    sub_E33FDF
                add     esp, 0Ch
                mov     eax, [ebp+arg_0]
                leave
                retn
sub_E33C46      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; bool __cdecl sub_E33C80(int, void *)
sub_E33C80      proc near               ; CODE XREF: sub_E33230+3F↑p

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
                movsd   xmm0, ds:qword_E373E8
                movsd   [ebp+var_28], xmm0
                lea     eax, [ebp+var_38]
                push    eax
                call    sub_E31797
                pop     ecx
                mov     [ebp+var_8], eax
                lea     eax, [ebp+var_40]
                push    eax
                mov     ecx, [ebp+var_8]
                call    sub_E31FA1
                push    eax
                lea     ecx, [ebp+var_10]
                call    sub_E34034
                push    [ebp+arg_4]
                lea     eax, [ebp+var_28]
                push    eax
                call    sub_E34061
                pop     ecx
                pop     ecx
                mov     [ebp+var_1], al
                movzx   eax, [ebp+var_1]
                test    eax, eax
                jz      short loc_E33CEB
                lea     eax, [ebp+var_18]
                push    eax
                lea     ecx, [ebp+var_10]
                call    sub_E33E6F
                jmp     short loc_E33D02
; ---------------------------------------------------------------------------

loc_E33CEB:                             ; CODE XREF: sub_E33C80+5B↑j
                push    [ebp+arg_4]
                lea     eax, [ebp+var_48]
                push    eax
                call    sub_E340BD
                pop     ecx
                pop     ecx
                push    eax
                lea     ecx, [ebp+var_10]
                call    sub_E33E6F

loc_E33D02:                             ; CODE XREF: sub_E33C80+69↑j
                lea     eax, [ebp+var_10]
                push    eax
                lea     eax, [ebp+var_20]
                push    eax
                call    sub_E33E95
                pop     ecx
                pop     ecx
                lea     ecx, [ebp+var_20]
                call    sub_E31882
                mov     ecx, [ebp+arg_0]
                mov     [ecx], eax
                mov     [ecx+4], edx
                lea     eax, [ebp+var_20]
                push    eax
                lea     ecx, [ebp+var_30]
                call    sub_E33F52
                lea     eax, [ebp+var_30]
                push    eax
                lea     ecx, [ebp+var_10]
                call    sub_E33E49
                lea     ecx, [ebp+var_10]
                call    sub_E31882
                mov     ecx, [ebp+arg_0]
                mov     [ecx+8], eax
                mov     al, [ebp+var_1]
                leave
                retn
sub_E33C80      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int __thiscall sub_E33D4C(int *this, int)
sub_E33D4C      proc near               ; CODE XREF: sub_E33285+47↑p

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
                call    sub_E3415C
                leave
                retn    4
sub_E33D4C      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; __int16 __thiscall mCrucialEncode(__int16 *this, int)
mCrucialEncode  proc near               ; CODE XREF: hCrucialEncode+41↑p

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
                call    qCrucialEncode
                leave
                retn    4
mCrucialEncode  endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int __thiscall sub_E33D98(int *this, int)
sub_E33D98      proc near               ; CODE XREF: sub_E3331B+41↑p

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
                call    sub_E34278
                leave
                retn    4
sub_E33D98      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int __thiscall uEncode(_DWORD *this, int)
                public uEncode
uEncode         proc near               ; CODE XREF: tEncode+60↑p

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
                call    MicrosoftVisualC14netruntime ; Microsoft VisualC 14/net runtime
                pop     ecx
                mov     [ebp+var_8], eax
                mov     eax, [ebp+var_4]
                push    dword ptr [eax+4]
                call    MicrosoftVisualC14netruntime ; Microsoft VisualC 14/net runtime
                pop     ecx
                mov     [ebp+var_C], eax
                mov     eax, [ebp+var_4]
                mov     eax, [eax+8]
                mov     [ebp+var_10], eax
                push    [ebp+var_8]     ; int
                push    [ebp+var_C]     ; void *
                push    [ebp+var_10]    ; int
                call    vEncode
                add     esp, 0Ch
                mov     eax, [ebp+var_4]
                mov     eax, [eax+4]
                add     eax, 8
                mov     ecx, [ebp+var_4]
                mov     [ecx+4], eax
                leave
                retn    4
uEncode         endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int __thiscall sub_E33E0A(_DWORD *this)
sub_E33E0A      proc near               ; CODE XREF: sub_E335AC+3F↑p

var_C           = dword ptr -0Ch
var_8           = dword ptr -8
var_4           = dword ptr -4

                push    ebp
                mov     ebp, esp
                sub     esp, 0Ch
                mov     [ebp+var_4], ecx
                mov     eax, [ebp+var_4]
                push    dword ptr [eax+4]
                call    MicrosoftVisualC14netruntime ; Microsoft VisualC 14/net runtime
                pop     ecx
                mov     [ebp+var_8], eax
                mov     eax, [ebp+var_4]
                mov     eax, [eax+8]
                mov     [ebp+var_C], eax
                push    [ebp+var_8]     ; void *
                push    [ebp+var_C]     ; int
                call    sub_E3430D
                pop     ecx
                pop     ecx
                mov     eax, [ebp+var_4]
                mov     eax, [eax+4]
                add     eax, 8
                mov     ecx, [ebp+var_4]
                mov     [ecx+4], eax
                leave
                retn
sub_E33E0A      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _QWORD *__thiscall sub_E33E49(_QWORD *this, _QWORD *)
sub_E33E49      proc near               ; CODE XREF: sub_E33C80+B4↑p

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
sub_E33E49      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _QWORD *__thiscall sub_E33E6F(_QWORD *this, _QWORD *)
sub_E33E6F      proc near               ; CODE XREF: sub_E33C80+64↑p
                                        ; sub_E33C80+7D↑p

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
sub_E33E6F      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _DWORD *__cdecl sub_E33E95(_DWORD *, void *)
sub_E33E95      proc near               ; CODE XREF: sub_E33C80+8A↑p

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
                jz      short loc_E33EF1
                xor     eax, eax
                inc     eax
                jz      short loc_E33ED0
                mov     ecx, [ebp+arg_4]
                call    sub_E31882
                mov     [ebp+var_C], eax
                mov     [ebp+var_8], edx
                lea     eax, [ebp+var_C]
                push    eax
                mov     ecx, [ebp+arg_0]
                call    sub_E31864
                mov     eax, [ebp+arg_0]
                jmp     locret_E33F50
; ---------------------------------------------------------------------------
                jmp     short loc_E33EEF
; ---------------------------------------------------------------------------

loc_E33ED0:                             ; CODE XREF: sub_E33E95+15↑j
                mov     ecx, [ebp+arg_4]
                call    sub_E31882
                mov     [ebp+var_14], eax
                mov     [ebp+var_10], edx
                lea     eax, [ebp+var_14]
                push    eax
                mov     ecx, [ebp+arg_0]
                call    sub_E31864
                mov     eax, [ebp+arg_0]
                jmp     short locret_E33F50
; ---------------------------------------------------------------------------

loc_E33EEF:                             ; CODE XREF: sub_E33E95+39↑j
                jmp     short locret_E33F50
; ---------------------------------------------------------------------------

loc_E33EF1:                             ; CODE XREF: sub_E33E95+10↑j
                xor     eax, eax
                inc     eax
                jz      short loc_E33F25
                mov     ecx, [ebp+arg_4]
                call    sub_E31882
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
                call    sub_E31864
                mov     eax, [ebp+arg_0]
                jmp     short locret_E33F50
; ---------------------------------------------------------------------------
                jmp     short locret_E33F50
; ---------------------------------------------------------------------------

loc_E33F25:                             ; CODE XREF: sub_E33E95+5F↑j
                mov     ecx, [ebp+arg_4]
                call    sub_E31882
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
                call    sub_E31864
                mov     eax, [ebp+arg_0]

locret_E33F50:                          ; CODE XREF: sub_E33E95+34↑j
                                        ; sub_E33E95+58↑j ...
                leave
                retn
sub_E33E95      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; __int64 *__thiscall sub_E33F52(__int64 *this, void *)
sub_E33F52      proc near               ; CODE XREF: sub_E33C80+A8↑p

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
                call    sub_E34B5C
                pop     ecx
                pop     ecx
                mov     ecx, eax
                call    sub_E31882
                mov     ecx, [ebp+var_4]
                mov     [ecx], eax
                mov     [ecx+4], edx
                mov     eax, [ebp+var_4]
                leave
                retn    4
sub_E33F52      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; __int64 *__thiscall sub_E33F7F(__int64 *this, void *)
sub_E33F7F      proc near               ; CODE XREF: sub_E33BCB+28↑p

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
                call    sub_E34C18
                pop     ecx
                pop     ecx
                mov     ecx, eax
                call    sub_E31882
                mov     ecx, [ebp+var_4]
                mov     [ecx], eax
                mov     [ecx+4], edx
                mov     eax, [ebp+var_4]
                leave
                retn    4
sub_E33F7F      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; bool __cdecl sub_E33FAC(_DWORD *, _DWORD *)
sub_E33FAC      proc near               ; CODE XREF: sub_E33C1C+A↑p

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
                call    sub_E31FA1
                mov     [ebp+var_4], eax
                lea     eax, [ebp+var_18]
                push    eax
                mov     ecx, [ebp+arg_0]
                call    sub_E31FA1
                mov     [ebp+var_8], eax
                push    [ebp+var_4]
                push    [ebp+var_8]
                call    sub_E34CD4
                pop     ecx
                pop     ecx
                leave
                retn
sub_E33FAC      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _DWORD *__cdecl sub_E33FDF(_DWORD *, int *, int *)
sub_E33FDF      proc near               ; CODE XREF: sub_E33C46+2D↑p

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
                call    sub_E31882
                mov     esi, eax
                mov     edi, edx
                lea     ecx, [ebp+var_10]
                call    sub_E31882
                sub     esi, eax
                sbb     edi, edx
                mov     dword ptr [ebp+var_18], esi
                mov     dword ptr [ebp+var_18+4], edi
                lea     eax, [ebp+var_18]
                push    eax
                mov     ecx, [ebp+arg_0]
                call    sub_E31864
                mov     eax, [ebp+arg_0]
                pop     edi
                pop     esi
                leave
                retn
sub_E33FDF      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; __int64 *__thiscall sub_E34034(__int64 *this, void *)
sub_E34034      proc near               ; CODE XREF: sub_E33C80+3F↑p

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
                call    sub_E34D3E
                pop     ecx
                pop     ecx
                mov     ecx, eax
                call    sub_E31882
                mov     ecx, [ebp+var_4]
                mov     [ecx], eax
                mov     [ecx+4], edx
                mov     eax, [ebp+var_4]
                leave
                retn    4
sub_E34034      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; bool __cdecl sub_E34061(void *, void *)
sub_E34061      proc near               ; CODE XREF: sub_E33C80+4B↑p

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
                call    sub_E34DF1
                mov     ecx, eax
                call    sub_E31893
                fstp    [ebp+var_C]
                movsd   xmm0, [ebp+var_C]
                push    [ebp+arg_4]
                lea     ecx, [ebp+var_2C]
                movsd   [ebp+var_1C], xmm0
                call    sub_E34E1B
                mov     ecx, eax
                call    sub_E31893
                fstp    [ebp+var_14]
                movsd   xmm0, [ebp+var_14]
                movsd   xmm1, [ebp+var_1C]
                comisd  xmm0, xmm1
                jbe     short loc_E340B4
                mov     [ebp+var_4], 1
                jmp     short loc_E340B8
; ---------------------------------------------------------------------------

loc_E340B4:                             ; CODE XREF: sub_E34061+48↑j
                and     [ebp+var_4], 0

loc_E340B8:                             ; CODE XREF: sub_E34061+51↑j
                mov     al, byte ptr [ebp+var_4]
                leave
                retn
sub_E34061      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _DWORD *__cdecl sub_E340BD(_DWORD *, void *)
sub_E340BD      proc near               ; CODE XREF: sub_E33C80+72↑p

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
                jz      short loc_E34117
                xor     eax, eax
                inc     eax
                jz      short loc_E340F6
                mov     ecx, [ebp+arg_4]
                call    sub_E31882
                mov     dword ptr [ebp+var_C], eax
                mov     dword ptr [ebp+var_C+4], edx
                lea     eax, [ebp+var_C]
                push    eax
                mov     ecx, [ebp+arg_0]
                call    sub_E31864
                mov     eax, [ebp+arg_0]
                jmp     short locret_E3415A
; ---------------------------------------------------------------------------
                jmp     short loc_E34115
; ---------------------------------------------------------------------------

loc_E340F6:                             ; CODE XREF: sub_E340BD+16↑j
                mov     ecx, [ebp+arg_4]
                call    sub_E31882
                mov     [ebp+var_14], eax
                mov     [ebp+var_10], edx
                lea     eax, [ebp+var_14]
                push    eax
                mov     ecx, [ebp+arg_0]
                call    sub_E31864
                mov     eax, [ebp+arg_0]
                jmp     short locret_E3415A
; ---------------------------------------------------------------------------

loc_E34115:                             ; CODE XREF: sub_E340BD+37↑j
                jmp     short locret_E3415A
; ---------------------------------------------------------------------------

loc_E34117:                             ; CODE XREF: sub_E340BD+11↑j
                xor     eax, eax
                inc     eax
                jz      short loc_E3413D
                mov     ecx, [ebp+arg_4]
                call    sub_E31882
                mov     [ebp+var_1C], eax
                mov     [ebp+var_18], edx
                lea     eax, [ebp+var_1C]
                push    eax
                mov     ecx, [ebp+arg_0]
                call    sub_E31864
                mov     eax, [ebp+arg_0]
                jmp     short locret_E3415A
; ---------------------------------------------------------------------------
                jmp     short locret_E3415A
; ---------------------------------------------------------------------------

loc_E3413D:                             ; CODE XREF: sub_E340BD+5D↑j
                mov     ecx, [ebp+arg_4]
                call    sub_E31882
                mov     [ebp+var_24], eax
                mov     [ebp+var_20], edx
                lea     eax, [ebp+var_24]
                push    eax
                mov     ecx, [ebp+arg_0]
                call    sub_E31864
                mov     eax, [ebp+arg_0]

locret_E3415A:                          ; CODE XREF: sub_E340BD+35↑j
                                        ; sub_E340BD+56↑j ...
                leave
                retn
sub_E340BD      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int __thiscall sub_E3415C(void *this, int, int, int, int, int)
sub_E3415C      proc near               ; CODE XREF: sub_E33D4C+1E↑p

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
                call    sub_E34700
                push    [ebp+arg_8]
                push    [ebp+arg_4]
                call    sub_E347C1
                pop     ecx
                pop     ecx
                mov     dword ptr [ebp+var_C], eax
                mov     dword ptr [ebp+var_C+4], edx
                push    [ebp+arg_10]
                push    [ebp+arg_C]
                call    sub_E347C1
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
                jnz     short loc_E341C3
                lea     ecx, [ebp+var_34]
                call    sub_E34528
                mov     dword ptr [ebp+var_1C], eax
                mov     dword ptr [ebp+var_1C+4], edx
                jmp     short loc_E341E5
; ---------------------------------------------------------------------------

loc_E341C3:                             ; CODE XREF: sub_E3415C+55↑j
                mov     eax, dword ptr [ebp+var_14]
                sub     eax, dword ptr [ebp+var_C]
                mov     ecx, dword ptr [ebp+var_14+4]
                sbb     ecx, dword ptr [ebp+var_C+4]
                add     eax, 1
                adc     ecx, 0
                push    ecx
                push    eax
                lea     ecx, [ebp+var_34]
                call    sub_E3459A
                mov     dword ptr [ebp+var_1C], eax
                mov     dword ptr [ebp+var_1C+4], edx

loc_E341E5:                             ; CODE XREF: sub_E3415C+65↑j
                mov     eax, dword ptr [ebp+var_1C]
                add     eax, dword ptr [ebp+var_C]
                mov     ecx, dword ptr [ebp+var_1C+4]
                adc     ecx, dword ptr [ebp+var_C+4]
                push    ecx
                push    eax
                call    sub_E347C1
                pop     ecx
                pop     ecx
                leave
                retn    14h
sub_E3415C      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; __int16 __thiscall qCrucialEncode(void *this, int, __int16, __int16)
                public qCrucialEncode
qCrucialEncode  proc near               ; CODE XREF: mCrucialEncode+1C↑p

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
                call    rCrucialEncode
                push    [ebp+arg_4]
                call    sCrucialEncode
                pop     ecx
                mov     [ebp+var_4], ax
                push    [ebp+arg_8]
                call    sCrucialEncode
                pop     ecx
                mov     [ebp+var_8], ax
                movzx   eax, [ebp+var_8]
                movzx   ecx, [ebp+var_4]
                sub     eax, ecx
                cmp     eax, 0FFFFh
                jnz     short loc_E3424B
                lea     ecx, [ebp+var_1C]
                call    tCrucialEncode
                mov     [ebp+var_C], ax
                jmp     short loc_E34263
; ---------------------------------------------------------------------------

loc_E3424B:                             ; CODE XREF: qCrucialEncode+3D↑j
                movzx   eax, [ebp+var_8]
                movzx   ecx, [ebp+var_4]
                sub     eax, ecx
                inc     eax
                push    eax
                lea     ecx, [ebp+var_1C]
                call    sub_E34478
                mov     [ebp+var_C], ax

loc_E34263:                             ; CODE XREF: qCrucialEncode+4B↑j
                movzx   eax, [ebp+var_C]
                movzx   ecx, [ebp+var_4]
                add     eax, ecx
                push    eax
                call    sCrucialEncode
                pop     ecx
                leave
                retn    0Ch
qCrucialEncode  endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int __thiscall sub_E34278(void *this, int, int, int)
sub_E34278      proc near               ; CODE XREF: sub_E33D98+18↑p

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
                call    rCrucialEncode
                push    [ebp+arg_4]
                call    sub_E3478F
                pop     ecx
                mov     [ebp+var_4], eax
                push    [ebp+arg_8]
                call    sub_E3478F
                pop     ecx
                mov     [ebp+var_8], eax
                mov     eax, [ebp+var_8]
                sub     eax, [ebp+var_4]
                cmp     eax, 0FFFFFFFFh
                jnz     short loc_E342BC
                lea     ecx, [ebp+var_1C]
                call    tCrucialEncode
                mov     [ebp+var_C], eax
                jmp     short loc_E342CF
; ---------------------------------------------------------------------------

loc_E342BC:                             ; CODE XREF: sub_E34278+35↑j
                mov     eax, [ebp+var_8]
                sub     eax, [ebp+var_4]
                inc     eax
                push    eax
                lea     ecx, [ebp+var_1C]
                call    sub_E3437B
                mov     [ebp+var_C], eax

loc_E342CF:                             ; CODE XREF: sub_E34278+42↑j
                mov     eax, [ebp+var_C]
                add     eax, [ebp+var_4]
                push    eax
                call    sub_E3478F
                pop     ecx
                leave
                retn    0Ch
sub_E34278      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _DWORD *__cdecl vEncode(int, void *, int)
vEncode         proc near               ; CODE XREF: uEncode+36↑p

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
                call    xEncode
                pop     ecx
                pop     ecx
                mov     [ebp+var_8], eax
                push    [ebp+arg_8]
                call    MicrosoftVisualC14netruntime ; Microsoft VisualC 14/net runtime
                pop     ecx
                mov     [ebp+var_4], eax
                push    [ebp+var_4]
                mov     ecx, [ebp+var_8]
                call    wEncode
                leave
                retn
vEncode         endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int *__cdecl sub_E3430D(int, void *)
sub_E3430D      proc near               ; CODE XREF: sub_E33E0A+27↑p

var_4           = dword ptr -4
arg_4           = dword ptr  0Ch

                push    ebp
                mov     ebp, esp
                push    ecx
                push    [ebp+arg_4]     ; void *
                push    8               ; unsigned int
                call    xEncode
                pop     ecx
                pop     ecx
                mov     [ebp+var_4], eax
                mov     ecx, [ebp+var_4]
                call    sub_E34802
                leave
                retn
sub_E3430D      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; unsigned int __thiscall tCrucialEncode(_DWORD *this)
                public tCrucialEncode
tCrucialEncode  proc near               ; CODE XREF: qCrucialEncode+42↑p
                                        ; sub_E34278+3A↑p

var_C           = dword ptr -0Ch
var_8           = dword ptr -8
var_4           = dword ptr -4

                push    ebp
                mov     ebp, esp
                sub     esp, 0Ch
                mov     [ebp+var_C], ecx
                and     [ebp+var_4], 0
                and     [ebp+var_8], 0
                jmp     short loc_E34349
; ---------------------------------------------------------------------------

loc_E3433D:                             ; CODE XREF: tCrucialEncode+4A↓j
                mov     eax, [ebp+var_C]
                mov     ecx, [ebp+var_8]
                add     ecx, [eax+4]
                mov     [ebp+var_8], ecx

loc_E34349:                             ; CODE XREF: tCrucialEncode+11↑j
                cmp     [ebp+var_8], 20h ; ' '
                jnb     short loc_E34376
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
                call    sub_E34823
                or      eax, [ebp+var_4]
                mov     [ebp+var_4], eax
                jmp     short loc_E3433D
; ---------------------------------------------------------------------------

loc_E34376:                             ; CODE XREF: tCrucialEncode+23↑j
                mov     eax, [ebp+var_4]
                leave
                retn
tCrucialEncode  endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; unsigned int __thiscall sub_E3437B(_DWORD *this, unsigned int)
sub_E3437B      proc near               ; CODE XREF: sub_E34278+4F↑p

var_C           = dword ptr -0Ch
var_8           = dword ptr -8
var_4           = dword ptr -4
arg_0           = dword ptr  8

                push    ebp
                mov     ebp, esp
                sub     esp, 0Ch
                mov     [ebp+var_C], ecx

loc_E34384:                             ; CODE XREF: sub_E3437B:loc_E34411↓j
                and     [ebp+var_8], 0
                and     [ebp+var_4], 0

loc_E3438C:                             ; CODE XREF: sub_E3437B+62↓j
                mov     eax, [ebp+arg_0]
                dec     eax
                cmp     [ebp+var_4], eax
                jnb     short loc_E343DF
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
                call    sub_E34823
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
                jmp     short loc_E3438C
; ---------------------------------------------------------------------------

loc_E343DF:                             ; CODE XREF: sub_E3437B+18↑j
                mov     eax, [ebp+var_8]
                xor     edx, edx
                div     [ebp+arg_0]
                mov     ecx, eax
                mov     eax, [ebp+var_4]
                xor     edx, edx
                div     [ebp+arg_0]
                cmp     ecx, eax
                jb      short loc_E34405
                mov     eax, [ebp+var_4]
                xor     edx, edx
                div     [ebp+arg_0]
                mov     eax, [ebp+arg_0]
                dec     eax
                cmp     edx, eax
                jnz     short loc_E34411

loc_E34405:                             ; CODE XREF: sub_E3437B+78↑j
                mov     eax, [ebp+var_8]
                xor     edx, edx
                div     [ebp+arg_0]
                mov     eax, edx
                jmp     short locret_E34416
; ---------------------------------------------------------------------------

loc_E34411:                             ; CODE XREF: sub_E3437B+88↑j
                jmp     loc_E34384
; ---------------------------------------------------------------------------

locret_E34416:                          ; CODE XREF: sub_E3437B+94↑j
                leave
                retn    4
sub_E3437B      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _DWORD *__thiscall rCrucialEncode(_DWORD *this, int)
                public rCrucialEncode
rCrucialEncode  proc near               ; CODE XREF: qCrucialEncode+F↑p
                                        ; sub_E34278+F↑p

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
                jmp     short loc_E3444B
; ---------------------------------------------------------------------------

loc_E3443D:                             ; CODE XREF: rCrucialEncode+54↓j
                mov     eax, [ebp+var_4]
                mov     eax, [eax+8]
                shr     eax, 1
                mov     ecx, [ebp+var_4]
                mov     [ecx+8], eax

loc_E3444B:                             ; CODE XREF: rCrucialEncode+21↑j
                call    ?max@?$numeric_limits@I@std@@SAIXZ ; std::numeric_limits<uint>::max(void)
                mov     esi, eax
                call    gCrucialEncode
                sub     esi, eax
                mov     eax, [ebp+var_4]
                cmp     esi, [eax+8]
                jnb     short loc_E34470
                mov     eax, [ebp+var_4]
                mov     eax, [eax+4]
                dec     eax
                mov     ecx, [ebp+var_4]
                mov     [ecx+4], eax
                jmp     short loc_E3443D
; ---------------------------------------------------------------------------

loc_E34470:                             ; CODE XREF: rCrucialEncode+45↑j
                mov     eax, [ebp+var_4]
                pop     esi
                leave
                retn    4
rCrucialEncode  endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; __int16 __thiscall sub_E34478(_DWORD *this, unsigned __int16)
sub_E34478      proc near               ; CODE XREF: qCrucialEncode+5C↑p

var_C           = dword ptr -0Ch
var_8           = dword ptr -8
var_4           = dword ptr -4
arg_0           = word ptr  8

                push    ebp
                mov     ebp, esp
                sub     esp, 0Ch
                push    esi
                mov     [ebp+var_C], ecx

loc_E34482:                             ; CODE XREF: sub_E34478:loc_E3451E↓j
                and     [ebp+var_8], 0
                and     [ebp+var_4], 0

loc_E3448A:                             ; CODE XREF: sub_E34478+64↓j
                movzx   eax, [ebp+arg_0]
                dec     eax
                cmp     [ebp+var_4], eax
                jnb     short loc_E344DE
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
                call    sub_E34823
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
                jmp     short loc_E3448A
; ---------------------------------------------------------------------------

loc_E344DE:                             ; CODE XREF: sub_E34478+1A↑j
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
                jb      short loc_E3450E
                movzx   ecx, [ebp+arg_0]
                mov     eax, [ebp+var_4]
                xor     edx, edx
                div     ecx
                movzx   eax, [ebp+arg_0]
                dec     eax
                cmp     edx, eax
                jnz     short loc_E3451E

loc_E3450E:                             ; CODE XREF: sub_E34478+80↑j
                movzx   ecx, [ebp+arg_0]
                mov     eax, [ebp+var_8]
                xor     edx, edx
                div     ecx
                mov     ax, dx
                jmp     short loc_E34523
; ---------------------------------------------------------------------------

loc_E3451E:                             ; CODE XREF: sub_E34478+94↑j
                jmp     loc_E34482
; ---------------------------------------------------------------------------

loc_E34523:                             ; CODE XREF: sub_E34478+A4↑j
                pop     esi
                leave
                retn    4
sub_E34478      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; __int64 __thiscall sub_E34528(int this)
sub_E34528      proc near               ; CODE XREF: sub_E3415C+5A↑p

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
                jmp     short loc_E3454B
; ---------------------------------------------------------------------------

loc_E3453F:                             ; CODE XREF: sub_E34528+68↓j
                mov     eax, [ebp+var_8]
                mov     ecx, [ebp+var_4]
                add     ecx, [eax+4]
                mov     [ebp+var_4], ecx

loc_E3454B:                             ; CODE XREF: sub_E34528+15↑j
                cmp     [ebp+var_4], 40h ; '@'
                jnb     short loc_E34592
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
                call    sub_E34857
                or      eax, dword ptr [ebp+var_10]
                or      edx, dword ptr [ebp+var_10+4]
                mov     dword ptr [ebp+var_10], eax
                mov     dword ptr [ebp+var_10+4], edx
                jmp     short loc_E3453F
; ---------------------------------------------------------------------------

loc_E34592:                             ; CODE XREF: sub_E34528+27↑j
                mov     eax, dword ptr [ebp+var_10]
                mov     edx, dword ptr [ebp+var_10+4]
                leave
                retn
sub_E34528      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; unsigned __int64 __thiscall sub_E3459A(int this, unsigned __int64)
sub_E3459A      proc near               ; CODE XREF: sub_E3415C+7E↑p

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

loc_E345A5:                             ; CODE XREF: sub_E3459A:loc_E346F5↓j
                xorps   xmm0, xmm0
                movlpd  [ebp+var_14], xmm0
                xorps   xmm0, xmm0
                movlpd  [ebp+var_C], xmm0

loc_E345B5:                             ; CODE XREF: sub_E3459A+C6↓j
                mov     eax, dword ptr [ebp+arg_0]
                sub     eax, 1
                mov     ecx, dword ptr [ebp+arg_0+4]
                sbb     ecx, 0
                mov     dword ptr [ebp+var_1C], eax
                mov     dword ptr [ebp+var_1C+4], ecx
                mov     eax, dword ptr [ebp+var_C+4]
                cmp     eax, dword ptr [ebp+var_1C+4]
                ja      loc_E34665
                jb      short loc_E345E1
                mov     eax, dword ptr [ebp+var_C]
                cmp     eax, dword ptr [ebp+var_1C]
                jnb     loc_E34665

loc_E345E1:                             ; CODE XREF: sub_E3459A+39↑j
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
                call    sub_E34857
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
                jmp     loc_E345B5
; ---------------------------------------------------------------------------

loc_E34665:                             ; CODE XREF: sub_E3459A+33↑j
                                        ; sub_E3459A+41↑j
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
                jb      short loc_E346E2
                ja      short loc_E346A9
                mov     eax, [ebp+var_24]
                cmp     eax, [ebp+var_2C]
                jb      short loc_E346E2

loc_E346A9:                             ; CODE XREF: sub_E3459A+105↑j
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
                jnz     short loc_E346F5
                mov     eax, [ebp+var_30]
                cmp     eax, dword ptr [ebp+var_3C+4]
                jnz     short loc_E346F5

loc_E346E2:                             ; CODE XREF: sub_E3459A+103↑j
                                        ; sub_E3459A+10D↑j
                push    dword ptr [ebp+arg_0+4]
                push    dword ptr [ebp+arg_0]
                push    dword ptr [ebp+var_14+4]
                push    dword ptr [ebp+var_14]
                call    __aullrem
                jmp     short loc_E346FA
; ---------------------------------------------------------------------------

loc_E346F5:                             ; CODE XREF: sub_E3459A+13E↑j
                                        ; sub_E3459A+146↑j
                jmp     loc_E345A5
; ---------------------------------------------------------------------------

loc_E346FA:                             ; CODE XREF: sub_E3459A+159↑j
                pop     edi
                pop     esi
                leave
                retn    8
sub_E3459A      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _DWORD *__thiscall sub_E34700(_DWORD *this, int)
sub_E34700      proc near               ; CODE XREF: sub_E3415C+F↑p

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
                jmp     short loc_E34744
; ---------------------------------------------------------------------------

loc_E3472B:                             ; CODE XREF: sub_E34700+85↓j
                mov     ecx, [ebp+var_4]
                mov     eax, [ecx+8]
                mov     edx, [ecx+0Ch]
                mov     cl, 1
                call    __aullshr
                mov     ecx, [ebp+var_4]
                mov     [ecx+8], eax
                mov     [ecx+0Ch], edx

loc_E34744:                             ; CODE XREF: sub_E34700+29↑j
                call    ?max@?$numeric_limits@I@std@@SAIXZ ; std::numeric_limits<uint>::max(void)
                mov     esi, eax
                call    gCrucialEncode
                sub     esi, eax
                xor     eax, eax
                mov     ecx, [ebp+var_4]
                mov     [ebp+var_10], esi
                mov     [ebp+var_C], eax
                mov     [ebp+var_8], ecx
                mov     eax, [ebp+var_8]
                mov     ecx, [ebp+var_C]
                cmp     ecx, [eax+0Ch]
                ja      short loc_E34787
                jb      short loc_E34778
                mov     eax, [ebp+var_8]
                mov     ecx, [ebp+var_10]
                cmp     ecx, [eax+8]
                jnb     short loc_E34787

loc_E34778:                             ; CODE XREF: sub_E34700+6B↑j
                mov     eax, [ebp+var_4]
                mov     eax, [eax+4]
                dec     eax
                mov     ecx, [ebp+var_4]
                mov     [ecx+4], eax
                jmp     short loc_E3472B
; ---------------------------------------------------------------------------

loc_E34787:                             ; CODE XREF: sub_E34700+69↑j
                                        ; sub_E34700+76↑j
                mov     eax, [ebp+var_4]
                pop     esi
                leave
                retn    4
sub_E34700      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int __cdecl sub_E3478F(int)
sub_E3478F      proc near               ; CODE XREF: sub_E34278+17↑p
                                        ; sub_E34278+23↑p ...

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
                call    sub_E348A7
                pop     ecx
                pop     ecx
                leave
                retn
sub_E3478F      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; __int16 __cdecl sCrucialEncode(__int16)
                public sCrucialEncode
sCrucialEncode  proc near               ; CODE XREF: qCrucialEncode+17↑p
                                        ; qCrucialEncode+24↑p ...

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
                call    uCrucialEncode
                pop     ecx
                pop     ecx
                leave
                retn
sCrucialEncode  endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int __cdecl sub_E347C1(int, int)
sub_E347C1      proc near               ; CODE XREF: sub_E3415C+1A↑p
                                        ; sub_E3415C+2D↑p ...

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
sub_E347C1      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _DWORD *__thiscall wEncode(_DWORD *this, _DWORD *)
                public wEncode
wEncode         proc near               ; CODE XREF: vEncode+26↑p

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
wEncode         endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int *__thiscall sub_E34802(int *this)
sub_E34802      proc near               ; CODE XREF: sub_E3430D+16↑p

var_4           = dword ptr -4

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+var_4], ecx
                call    sub_E329C4
                mov     ecx, [ebp+var_4]
                mov     [ecx], eax
                mov     eax, [ebp+var_4]
                mov     ecx, [ebp+var_4]
                mov     ecx, [ecx]
                mov     [eax+4], ecx
                mov     eax, [ebp+var_4]
                leave
                retn
sub_E34802      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; unsigned int __thiscall sub_E34823(_DWORD *this)
sub_E34823      proc near               ; CODE XREF: tCrucialEncode+3F↑p
                                        ; sub_E3437B+34↑p ...

var_8           = dword ptr -8
var_4           = dword ptr -4

                push    ebp
                mov     ebp, esp
                push    ecx
                push    ecx
                push    esi
                mov     [ebp+var_4], ecx

loc_E3482C:                             ; CODE XREF: sub_E34823:loc_E34852↓j
                mov     eax, [ebp+var_4]
                mov     ecx, [eax]
                call    sub_E348E5
                mov     esi, eax
                call    gCrucialEncode
                sub     esi, eax
                mov     [ebp+var_8], esi
                mov     eax, [ebp+var_4]
                mov     ecx, [ebp+var_8]
                cmp     ecx, [eax+8]
                ja      short loc_E34852
                mov     eax, [ebp+var_8]
                jmp     short loc_E34854
; ---------------------------------------------------------------------------

loc_E34852:                             ; CODE XREF: sub_E34823+28↑j
                jmp     short loc_E3482C
; ---------------------------------------------------------------------------

loc_E34854:                             ; CODE XREF: sub_E34823+2D↑j
                pop     esi
                leave
                retn
sub_E34823      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; __int64 __thiscall sub_E34857(_QWORD *this)
sub_E34857      proc near               ; CODE XREF: sub_E34528+57↑p
                                        ; sub_E3459A+75↑p

var_10          = dword ptr -10h
var_C           = dword ptr -0Ch
var_8           = dword ptr -8
var_4           = dword ptr -4

                push    ebp
                mov     ebp, esp
                sub     esp, 10h
                push    esi
                mov     [ebp+var_4], ecx

loc_E34861:                             ; CODE XREF: sub_E34857:loc_E348A2↓j
                mov     eax, [ebp+var_4]
                mov     ecx, [eax]
                call    sub_E348E5
                mov     esi, eax
                call    gCrucialEncode
                sub     esi, eax
                xor     eax, eax
                mov     [ebp+var_10], esi
                mov     [ebp+var_C], eax
                mov     eax, [ebp+var_4]
                mov     [ebp+var_8], eax
                mov     eax, [ebp+var_8]
                mov     ecx, [ebp+var_C]
                cmp     ecx, [eax+0Ch]
                ja      short loc_E348A2
                jb      short loc_E3489A
                mov     eax, [ebp+var_8]
                mov     ecx, [ebp+var_10]
                cmp     ecx, [eax+8]
                ja      short loc_E348A2

loc_E3489A:                             ; CODE XREF: sub_E34857+36↑j
                mov     eax, [ebp+var_10]
                mov     edx, [ebp+var_C]
                jmp     short loc_E348A4
; ---------------------------------------------------------------------------

loc_E348A2:                             ; CODE XREF: sub_E34857+34↑j
                                        ; sub_E34857+41↑j
                jmp     short loc_E34861
; ---------------------------------------------------------------------------

loc_E348A4:                             ; CODE XREF: sub_E34857+49↑j
                pop     esi
                leave
                retn
sub_E34857      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int __cdecl sub_E348A7(int)
sub_E348A7      proc near               ; CODE XREF: sub_E3478F+10↑p

var_4           = dword ptr -4
arg_0           = dword ptr  8

                push    ebp
                mov     ebp, esp
                push    ecx
                mov     [ebp+var_4], 80000000h
                cmp     [ebp+arg_0], 80000000h
                jnb     short loc_E348C7
                mov     eax, [ebp+arg_0]
                sub     eax, 80000000h
                jmp     short locret_E348CF
; ---------------------------------------------------------------------------
                jmp     short locret_E348CF
; ---------------------------------------------------------------------------

loc_E348C7:                             ; CODE XREF: sub_E348A7+12↑j
                mov     eax, [ebp+arg_0]
                sub     eax, 80000000h

locret_E348CF:                          ; CODE XREF: sub_E348A7+1C↑j
                                        ; sub_E348A7+1E↑j
                leave
                retn
sub_E348A7      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; __int16 __cdecl uCrucialEncode(__int16)
                public uCrucialEncode
uCrucialEncode  proc near               ; CODE XREF: sCrucialEncode+10↑p

arg_0           = word ptr  8

                push    ebp
                mov     ebp, esp
                mov     ax, [ebp+arg_0]
                pop     ebp
                retn
uCrucialEncode  endp

; [0000000B BYTES: COLLAPSED FUNCTION operator"" _l(char const *,uint). PRESS CTRL-NUMPAD+ TO EXPAND]

; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int __thiscall sub_E348E5(_DWORD *this)
sub_E348E5      proc near               ; CODE XREF: sub_E34823+E↑p
                                        ; sub_E34857+F↑p

var_C           = dword ptr -0Ch
var_8           = dword ptr -8
var_4           = dword ptr -4

                push    ebp
                mov     ebp, esp
                sub     esp, 0Ch
                mov     [ebp+var_8], ecx
                mov     eax, [ebp+var_8]
                cmp     dword ptr [eax], 270h
                jnz     short loc_E34903
                mov     ecx, [ebp+var_8]
                call    sub_E3497E
                jmp     short loc_E34916
; ---------------------------------------------------------------------------

loc_E34903:                             ; CODE XREF: sub_E348E5+12↑j
                mov     eax, [ebp+var_8]
                cmp     dword ptr [eax], 4E0h
                jb      short loc_E34916
                mov     ecx, [ebp+var_8]
                call    sub_E34A02

loc_E34916:                             ; CODE XREF: sub_E348E5+1C↑j
                                        ; sub_E348E5+27↑j
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
sub_E348E5      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; unsigned int __thiscall sub_E3497E(_DWORD *this)
sub_E3497E      proc near               ; CODE XREF: sub_E348E5+17↑p

var_10          = dword ptr -10h
var_C           = dword ptr -0Ch
var_8           = dword ptr -8
var_4           = dword ptr -4

                push    ebp
                mov     ebp, esp
                sub     esp, 10h
                mov     [ebp+var_8], ecx
                mov     [ebp+var_4], 270h
                jmp     short loc_E34997
; ---------------------------------------------------------------------------

loc_E34990:                             ; CODE XREF: sub_E3497E+80↓j
                mov     eax, [ebp+var_4]
                inc     eax
                mov     [ebp+var_4], eax

loc_E34997:                             ; CODE XREF: sub_E3497E+10↑j
                cmp     [ebp+var_4], 4E0h
                jnb     short locret_E34A00
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
                jz      short loc_E349DB
                mov     [ebp+var_10], 9908B0DFh
                jmp     short loc_E349DF
; ---------------------------------------------------------------------------

loc_E349DB:                             ; CODE XREF: sub_E3497E+52↑j
                and     [ebp+var_10], 0

loc_E349DF:                             ; CODE XREF: sub_E3497E+5B↑j
                mov     eax, [ebp+var_C]
                shr     eax, 1
                xor     eax, [ebp+var_10]
                mov     ecx, [ebp+var_4]
                mov     edx, [ebp+var_8]
                xor     eax, [edx+ecx*4-388h]
                mov     ecx, [ebp+var_4]
                mov     edx, [ebp+var_8]
                mov     [edx+ecx*4+4], eax
                jmp     short loc_E34990
; ---------------------------------------------------------------------------

locret_E34A00:                          ; CODE XREF: sub_E3497E+20↑j
                leave
                retn
sub_E3497E      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _BYTE *__thiscall sub_E34A02(_BYTE *this)
sub_E34A02      proc near               ; CODE XREF: sub_E348E5+2C↑p

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
                jmp     short loc_E34A18
; ---------------------------------------------------------------------------

loc_E34A11:                             ; CODE XREF: sub_E34A02+7D↓j
                mov     eax, [ebp+var_4]
                inc     eax
                mov     [ebp+var_4], eax

loc_E34A18:                             ; CODE XREF: sub_E34A02+D↑j
                cmp     [ebp+var_4], 0E3h
                jnb     short loc_E34A81
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
                jz      short loc_E34A5C
                mov     [ebp+var_10], 9908B0DFh
                jmp     short loc_E34A60
; ---------------------------------------------------------------------------

loc_E34A5C:                             ; CODE XREF: sub_E34A02+4F↑j
                and     [ebp+var_10], 0

loc_E34A60:                             ; CODE XREF: sub_E34A02+58↑j
                mov     eax, [ebp+var_C]
                shr     eax, 1
                xor     eax, [ebp+var_10]
                mov     ecx, [ebp+var_4]
                mov     edx, [ebp+var_8]
                xor     eax, [edx+ecx*4+0FF8h]
                mov     ecx, [ebp+var_4]
                mov     edx, [ebp+var_8]
                mov     [edx+ecx*4+4], eax
                jmp     short loc_E34A11
; ---------------------------------------------------------------------------

loc_E34A81:                             ; CODE XREF: sub_E34A02+1D↑j
                jmp     short loc_E34A8A
; ---------------------------------------------------------------------------

loc_E34A83:                             ; CODE XREF: sub_E34A02+EF↓j
                mov     eax, [ebp+var_4]
                inc     eax
                mov     [ebp+var_4], eax

loc_E34A8A:                             ; CODE XREF: sub_E34A02:loc_E34A81↑j
                cmp     [ebp+var_4], 26Fh
                jnb     short loc_E34AF3
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
                jz      short loc_E34ACE
                mov     [ebp+var_18], 9908B0DFh
                jmp     short loc_E34AD2
; ---------------------------------------------------------------------------

loc_E34ACE:                             ; CODE XREF: sub_E34A02+C1↑j
                and     [ebp+var_18], 0

loc_E34AD2:                             ; CODE XREF: sub_E34A02+CA↑j
                mov     eax, [ebp+var_14]
                shr     eax, 1
                xor     eax, [ebp+var_18]
                mov     ecx, [ebp+var_4]
                mov     edx, [ebp+var_8]
                xor     eax, [edx+ecx*4-388h]
                mov     ecx, [ebp+var_4]
                mov     edx, [ebp+var_8]
                mov     [edx+ecx*4+4], eax
                jmp     short loc_E34A83
; ---------------------------------------------------------------------------

loc_E34AF3:                             ; CODE XREF: sub_E34A02+8F↑j
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
                jz      short loc_E34B2E
                mov     [ebp+var_20], 9908B0DFh
                jmp     short loc_E34B32
; ---------------------------------------------------------------------------

loc_E34B2E:                             ; CODE XREF: sub_E34A02+121↑j
                and     [ebp+var_20], 0

loc_E34B32:                             ; CODE XREF: sub_E34A02+12A↑j
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
sub_E34A02      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _DWORD *__cdecl sub_E34B5C(_DWORD *, void *)
sub_E34B5C      proc near               ; CODE XREF: sub_E33F52+10↑p

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
                jz      short loc_E34BC6
                xor     eax, eax
                jz      short loc_E34B97
                mov     ecx, [ebp+arg_4]
                call    sub_E31882
                mov     [ebp+var_C], eax
                mov     [ebp+var_8], edx
                lea     eax, [ebp+var_C]
                push    eax
                mov     ecx, [ebp+arg_0]
                call    sub_E31864
                mov     eax, [ebp+arg_0]
                jmp     locret_E34C16
; ---------------------------------------------------------------------------
                jmp     short loc_E34BC4
; ---------------------------------------------------------------------------

loc_E34B97:                             ; CODE XREF: sub_E34B5C+15↑j
                mov     ecx, [ebp+arg_4]
                call    sub_E31882
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
                call    sub_E31864
                mov     eax, [ebp+arg_0]
                jmp     short locret_E34C16
; ---------------------------------------------------------------------------

loc_E34BC4:                             ; CODE XREF: sub_E34B5C+39↑j
                jmp     short locret_E34C16
; ---------------------------------------------------------------------------

loc_E34BC6:                             ; CODE XREF: sub_E34B5C+11↑j
                xor     eax, eax
                jz      short loc_E34BEB
                mov     ecx, [ebp+arg_4]
                call    sub_E31882
                mov     [ebp+var_1C], eax
                mov     [ebp+var_18], edx
                lea     eax, [ebp+var_1C]
                push    eax
                mov     ecx, [ebp+arg_0]
                call    sub_E31864
                mov     eax, [ebp+arg_0]
                jmp     short locret_E34C16
; ---------------------------------------------------------------------------
                jmp     short locret_E34C16
; ---------------------------------------------------------------------------

loc_E34BEB:                             ; CODE XREF: sub_E34B5C+6C↑j
                mov     ecx, [ebp+arg_4]
                call    sub_E31882
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
                call    sub_E31864
                mov     eax, [ebp+arg_0]

locret_E34C16:                          ; CODE XREF: sub_E34B5C+34↑j
                                        ; sub_E34B5C+66↑j ...
                leave
                retn
sub_E34B5C      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _DWORD *__cdecl sub_E34C18(_DWORD *, void *)
sub_E34C18      proc near               ; CODE XREF: sub_E33F7F+10↑p

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
                jz      short loc_E34C82
                xor     eax, eax
                jz      short loc_E34C53
                mov     ecx, [ebp+arg_4]
                call    sub_E31882
                mov     [ebp+var_C], eax
                mov     [ebp+var_8], edx
                lea     eax, [ebp+var_C]
                push    eax
                mov     ecx, [ebp+arg_0]
                call    sub_E31864
                mov     eax, [ebp+arg_0]
                jmp     locret_E34CD2
; ---------------------------------------------------------------------------
                jmp     short loc_E34C80
; ---------------------------------------------------------------------------

loc_E34C53:                             ; CODE XREF: sub_E34C18+15↑j
                mov     ecx, [ebp+arg_4]
                call    sub_E31882
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
                call    sub_E31864
                mov     eax, [ebp+arg_0]
                jmp     short locret_E34CD2
; ---------------------------------------------------------------------------

loc_E34C80:                             ; CODE XREF: sub_E34C18+39↑j
                jmp     short locret_E34CD2
; ---------------------------------------------------------------------------

loc_E34C82:                             ; CODE XREF: sub_E34C18+11↑j
                xor     eax, eax
                jz      short loc_E34CA7
                mov     ecx, [ebp+arg_4]
                call    sub_E31882
                mov     [ebp+var_1C], eax
                mov     [ebp+var_18], edx
                lea     eax, [ebp+var_1C]
                push    eax
                mov     ecx, [ebp+arg_0]
                call    sub_E31864
                mov     eax, [ebp+arg_0]
                jmp     short locret_E34CD2
; ---------------------------------------------------------------------------
                jmp     short locret_E34CD2
; ---------------------------------------------------------------------------

loc_E34CA7:                             ; CODE XREF: sub_E34C18+6C↑j
                mov     ecx, [ebp+arg_4]
                call    sub_E31882
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
                call    sub_E31864
                mov     eax, [ebp+arg_0]

locret_E34CD2:                          ; CODE XREF: sub_E34C18+34↑j
                                        ; sub_E34C18+66↑j ...
                leave
                retn
sub_E34C18      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; bool __cdecl sub_E34CD4(int *, int *)
sub_E34CD4      proc near               ; CODE XREF: sub_E33FAC+2A↑p

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
                call    sub_E31882
                mov     esi, eax
                mov     edi, edx
                lea     ecx, [ebp+var_24]
                call    sub_E31882
                mov     dword ptr [ebp+var_C], esi
                mov     dword ptr [ebp+var_C+4], edi
                mov     dword ptr [ebp+var_14], eax
                mov     dword ptr [ebp+var_14+4], edx
                mov     eax, dword ptr [ebp+var_C+4]
                cmp     eax, dword ptr [ebp+var_14+4]
                jg      short loc_E34D33
                jl      short loc_E34D2A
                mov     eax, dword ptr [ebp+var_C]
                cmp     eax, dword ptr [ebp+var_14]
                jnb     short loc_E34D33

loc_E34D2A:                             ; CODE XREF: sub_E34CD4+4C↑j
                mov     [ebp+var_4], 1
                jmp     short loc_E34D37
; ---------------------------------------------------------------------------

loc_E34D33:                             ; CODE XREF: sub_E34CD4+4A↑j
                                        ; sub_E34CD4+54↑j
                and     [ebp+var_4], 0

loc_E34D37:                             ; CODE XREF: sub_E34CD4+5D↑j
                mov     al, byte ptr [ebp+var_4]
                pop     edi
                pop     esi
                leave
                retn
sub_E34CD4      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _DWORD *__cdecl sub_E34D3E(_DWORD *, void *)
sub_E34D3E      proc near               ; CODE XREF: sub_E34034+10↑p

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
                jz      short loc_E34DA2
                xor     eax, eax
                jz      short loc_E34D76
                mov     ecx, [ebp+arg_4]
                call    sub_E31882
                mov     [ebp+var_C], eax
                mov     [ebp+var_8], edx
                lea     eax, [ebp+var_C]
                push    eax
                mov     ecx, [ebp+arg_0]
                call    sub_E31864
                mov     eax, [ebp+arg_0]
                jmp     short locret_E34DEF
; ---------------------------------------------------------------------------
                jmp     short loc_E34DA0
; ---------------------------------------------------------------------------

loc_E34D76:                             ; CODE XREF: sub_E34D3E+15↑j
                mov     ecx, [ebp+arg_4]
                call    sub_E31882
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
                call    sub_E31864
                mov     eax, [ebp+arg_0]
                jmp     short locret_E34DEF
; ---------------------------------------------------------------------------

loc_E34DA0:                             ; CODE XREF: sub_E34D3E+36↑j
                jmp     short locret_E34DEF
; ---------------------------------------------------------------------------

loc_E34DA2:                             ; CODE XREF: sub_E34D3E+11↑j
                xor     eax, eax
                jz      short loc_E34DC7
                mov     ecx, [ebp+arg_4]
                call    sub_E31882
                mov     [ebp+var_1C], eax
                mov     [ebp+var_18], edx
                lea     eax, [ebp+var_1C]
                push    eax
                mov     ecx, [ebp+arg_0]
                call    sub_E31864
                mov     eax, [ebp+arg_0]
                jmp     short locret_E34DEF
; ---------------------------------------------------------------------------
                jmp     short locret_E34DEF
; ---------------------------------------------------------------------------

loc_E34DC7:                             ; CODE XREF: sub_E34D3E+66↑j
                mov     ecx, [ebp+arg_4]
                call    sub_E31882
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
                call    sub_E31864
                mov     eax, [ebp+arg_0]

locret_E34DEF:                          ; CODE XREF: sub_E34D3E+34↑j
                                        ; sub_E34D3E+60↑j ...
                leave
                retn
sub_E34D3E      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; double *__thiscall sub_E34DF1(double *this, void *)
sub_E34DF1      proc near               ; CODE XREF: sub_E34061+C↑p

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
                call    sub_E34E45
                pop     ecx
                pop     ecx
                mov     ecx, eax
                call    sub_E31893
                mov     eax, [ebp+var_4]
                fstp    qword ptr [eax]
                mov     eax, [ebp+var_4]
                leave
                retn    4
sub_E34DF1      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; double *__thiscall sub_E34E1B(double *this, void *)
sub_E34E1B      proc near               ; CODE XREF: sub_E34061+2B↑p

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
                call    sub_E34F17
                pop     ecx
                pop     ecx
                mov     ecx, eax
                call    sub_E31893
                mov     eax, [ebp+var_4]
                fstp    qword ptr [eax]
                mov     eax, [ebp+var_4]
                leave
                retn    4
sub_E34E1B      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _QWORD *__cdecl sub_E34E45(_QWORD *, void *)
sub_E34E45      proc near               ; CODE XREF: sub_E34DF1+10↑p

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
                jz      short loc_E34EAD
                xor     eax, eax
                jz      short loc_E34E7D
                mov     ecx, [ebp+arg_4]
                call    sub_E31893
                fstp    [ebp+var_C]
                lea     eax, [ebp+var_C]
                push    eax
                mov     ecx, [ebp+arg_0]
                call    sub_E34FF1
                mov     eax, [ebp+arg_0]
                jmp     locret_E34F15
; ---------------------------------------------------------------------------
                jmp     short loc_E34EAB
; ---------------------------------------------------------------------------

loc_E34E7D:                             ; CODE XREF: sub_E34E45+15↑j
                mov     ecx, [ebp+arg_4]
                call    sub_E31893
                fstp    [ebp+var_14]
                movsd   xmm0, [ebp+var_14]
                mulsd   xmm0, ds:qword_E373F0
                movsd   [ebp+var_1C], xmm0
                lea     eax, [ebp+var_1C]
                push    eax
                mov     ecx, [ebp+arg_0]
                call    sub_E34FF1
                mov     eax, [ebp+arg_0]
                jmp     short locret_E34F15
; ---------------------------------------------------------------------------

loc_E34EAB:                             ; CODE XREF: sub_E34E45+36↑j
                jmp     short locret_E34F15
; ---------------------------------------------------------------------------

loc_E34EAD:                             ; CODE XREF: sub_E34E45+11↑j
                xor     eax, eax
                jz      short loc_E34EE1
                mov     ecx, [ebp+arg_4]
                call    sub_E31893
                fstp    [ebp+var_24]
                movsd   xmm0, [ebp+var_24]
                divsd   xmm0, ds:qword_E373E0
                movsd   [ebp+var_2C], xmm0
                lea     eax, [ebp+var_2C]
                push    eax
                mov     ecx, [ebp+arg_0]
                call    sub_E34FF1
                mov     eax, [ebp+arg_0]
                jmp     short locret_E34F15
; ---------------------------------------------------------------------------
                jmp     short locret_E34F15
; ---------------------------------------------------------------------------

loc_E34EE1:                             ; CODE XREF: sub_E34E45+6A↑j
                mov     ecx, [ebp+arg_4]
                call    sub_E31893
                fstp    [ebp+var_34]
                movsd   xmm0, [ebp+var_34]
                mulsd   xmm0, ds:qword_E373F0
                divsd   xmm0, ds:qword_E373E0
                movsd   [ebp+var_3C], xmm0
                lea     eax, [ebp+var_3C]
                push    eax
                mov     ecx, [ebp+arg_0]
                call    sub_E34FF1
                mov     eax, [ebp+arg_0]

locret_E34F15:                          ; CODE XREF: sub_E34E45+31↑j
                                        ; sub_E34E45+64↑j ...
                leave
                retn
sub_E34E45      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _QWORD *__cdecl sub_E34F17(_QWORD *, void *)
sub_E34F17      proc near               ; CODE XREF: sub_E34E1B+10↑p

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
                jz      short loc_E34F88
                xor     eax, eax
                inc     eax
                jz      short loc_E34F59
                mov     ecx, [ebp+arg_4]
                call    sub_E31882
                mov     ecx, eax
                call    __ltod3
                movsd   [ebp+var_C], xmm0
                lea     eax, [ebp+var_C]
                push    eax
                mov     ecx, [ebp+arg_0]
                call    sub_E34FF1
                mov     eax, [ebp+arg_0]
                jmp     locret_E34FEF
; ---------------------------------------------------------------------------
                jmp     short loc_E34F86
; ---------------------------------------------------------------------------

loc_E34F59:                             ; CODE XREF: sub_E34F17+16↑j
                mov     ecx, [ebp+arg_4]
                call    sub_E31882
                mov     ecx, eax
                call    __ltod3
                mulsd   xmm0, ds:qword_E373E0
                movsd   [ebp+var_14], xmm0
                lea     eax, [ebp+var_14]
                push    eax
                mov     ecx, [ebp+arg_0]
                call    sub_E34FF1
                mov     eax, [ebp+arg_0]
                jmp     short locret_E34FEF
; ---------------------------------------------------------------------------

loc_E34F86:                             ; CODE XREF: sub_E34F17+40↑j
                jmp     short locret_E34FEF
; ---------------------------------------------------------------------------

loc_E34F88:                             ; CODE XREF: sub_E34F17+11↑j
                xor     eax, eax
                inc     eax
                jz      short loc_E34FBC
                mov     ecx, [ebp+arg_4]
                call    sub_E31882
                mov     ecx, eax
                call    __ltod3
                divsd   xmm0, ds:qword_E373E0
                movsd   [ebp+var_1C], xmm0
                lea     eax, [ebp+var_1C]
                push    eax
                mov     ecx, [ebp+arg_0]
                call    sub_E34FF1
                mov     eax, [ebp+arg_0]
                jmp     short locret_E34FEF
; ---------------------------------------------------------------------------
                jmp     short locret_E34FEF
; ---------------------------------------------------------------------------

loc_E34FBC:                             ; CODE XREF: sub_E34F17+74↑j
                mov     ecx, [ebp+arg_4]
                call    sub_E31882
                mov     ecx, eax
                call    __ltod3
                mulsd   xmm0, ds:qword_E373E0
                divsd   xmm0, ds:qword_E373E0
                movsd   [ebp+var_24], xmm0
                lea     eax, [ebp+var_24]
                push    eax
                mov     ecx, [ebp+arg_0]
                call    sub_E34FF1
                mov     eax, [ebp+arg_0]

locret_E34FEF:                          ; CODE XREF: sub_E34F17+3B↑j
                                        ; sub_E34F17+6D↑j ...
                leave
                retn
sub_E34F17      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _QWORD *__thiscall sub_E34FF1(_QWORD *this, _QWORD *)
sub_E34FF1      proc near               ; CODE XREF: sub_E34E45+29↑p
                                        ; sub_E34E45+5C↑p ...

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
sub_E34FF1      endp

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

; void __cdecl sub_E35312(void *Block)
sub_E35312      proc near               ; CODE XREF: sub_E31449+1C↑p
                                        ; sub_E31497+1C↑p ...

Block           = dword ptr  8

                push    ebp
                mov     ebp, esp
                push    [ebp+Block]     ; Block
                call    j_free
                pop     ecx
                pop     ebp
                retn
sub_E35312      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; _DWORD *__thiscall sub_E35320(_DWORD *Block, char)
sub_E35320      proc near               ; DATA XREF: .rdata:const type_info::`vftable'↓o

arg_0           = byte ptr  8

                push    ebp
                mov     ebp, esp
                test    [ebp+arg_0], 1
                push    esi
                mov     esi, ecx
                mov     dword ptr [esi], offset ??_7type_info@@6B@ ; const type_info::`vftable'
                jz      short loc_E3533C
                push    0Ch
                push    esi             ; Block
                call    sub_E35312
                pop     ecx
                pop     ecx

loc_E3533C:                             ; CODE XREF: sub_E35320+10↑j
                mov     eax, esi
                pop     esi
                pop     ebp
                retn    4
sub_E35320      endp

; [000000AB BYTES: COLLAPSED FUNCTION pre_c_initialization(void). PRESS CTRL-NUMPAD+ TO EXPAND]

; =============== S U B R O U T I N E =======================================


; int sub_E353EE()
sub_E353EE      proc near               ; DATA XREF: .rdata:00E37190↓o
                call    ___scrt_initialize_default_local_stdio_options
                xor     eax, eax
                retn
sub_E353EE      endp


; =============== S U B R O U T I N E =======================================


; int sub_E353F6()
sub_E353F6      proc near               ; DATA XREF: .rdata:00E37158↓o
                call    sub_E3592E
                call    UserMathErrorFunction
                push    eax             ; NewMode
                call    _set_new_mode
                pop     ecx
                retn
sub_E353F6      endp

; [00000182 BYTES: COLLAPSED FUNCTION __scrt_common_main_seh(void). PRESS CTRL-NUMPAD+ TO EXPAND]
; [0000000A BYTES: COLLAPSED FUNCTION start. PRESS CTRL-NUMPAD+ TO EXPAND]
; [00000003 BYTES: COLLAPSED FUNCTION nullsub_1. PRESS CTRL-NUMPAD+ TO EXPAND]

; =============== S U B R O U T I N E =======================================


; _DWORD *__thiscall sub_E35597(_DWORD *this)
sub_E35597      proc near               ; CODE XREF: sub_E355AF+9↓p
                and     dword ptr [ecx+4], 0
                mov     eax, ecx
                and     dword ptr [ecx+8], 0
                mov     dword ptr [ecx+4], offset aBadAllocation ; "bad allocation"
                mov     dword ptr [ecx], offset ??_7bad_alloc@std@@6B@ ; const std::bad_alloc::`vftable'
                retn
sub_E35597      endp


; =============== S U B R O U T I N E =======================================

; Attributes: noreturn bp-based frame

sub_E355AF      proc near               ; CODE XREF: operator new(uint)+2B↑j

pExceptionObject= dword ptr -0Ch

                push    ebp
                mov     ebp, esp
                sub     esp, 0Ch
                lea     ecx, [ebp+pExceptionObject]
                call    sub_E35597
                push    offset __TI2?AVbad_alloc@std@@ ; pThrowInfo
                lea     eax, [ebp+pExceptionObject]
                push    eax             ; pExceptionObject
                call    _CxxThrowException
sub_E355AF      endp

; ---------------------------------------------------------------------------
                align 4

; =============== S U B R O U T I N E =======================================

; Attributes: noreturn bp-based frame

sub_E355CC      proc near               ; CODE XREF: operator new(uint)+25↑j

pExceptionObject= dword ptr -0Ch

                push    ebp
                mov     ebp, esp
                sub     esp, 0Ch
                lea     ecx, [ebp+pExceptionObject]
                call    sub_E314D2
                push    offset __TI3?AVbad_array_new_length@std@@ ; pThrowInfo
                lea     eax, [ebp+pExceptionObject]
                push    eax             ; pExceptionObject
                call    _CxxThrowException
sub_E355CC      endp

; ---------------------------------------------------------------------------
                db 0CCh
; [000001D0 BYTES: COLLAPSED FUNCTION ___isa_available_init. PRESS CTRL-NUMPAD+ TO EXPAND]

; =============== S U B R O U T I N E =======================================


; int sub_E357B9()
sub_E357B9      proc near               ; CODE XREF: pre_c_initialization(void)+41↑p
                xor     eax, eax
                inc     eax
                retn
sub_E357B9      endp

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


; LPTOP_LEVEL_EXCEPTION_FILTER sub_E3592E()
sub_E3592E      proc near               ; CODE XREF: sub_E353F6↑p
                push    offset ___scrt_unhandled_exception_filter@4 ; lpTopLevelExceptionFilter
                call    ds:SetUnhandledExceptionFilter
                retn
sub_E3592E      endp

; [00000056 BYTES: COLLAPSED FUNCTION __scrt_unhandled_exception_filter(x). PRESS CTRL-NUMPAD+ TO EXPAND]

; =============== S U B R O U T I N E =======================================


; void sub_E35990()
sub_E35990      proc near               ; CODE XREF: ___scrt_fastfail+1C↑p
                                        ; ___scrt_fastfail+111↑p
                and     dword_E390F0, 0
                retn
sub_E35990      endp

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


; void sub_E35ACA()
sub_E35ACA      proc near               ; CODE XREF: pre_c_initialization(void)+52↑p
                push    offset ListHead ; ListHead
                call    ds:InitializeSListHead
                retn
sub_E35ACA      endp


; =============== S U B R O U T I N E =======================================


; char sub_E35AD6()
sub_E35AD6      proc near               ; CODE XREF: ___scrt_initialize_crt+15↑p
                                        ; ___scrt_initialize_crt:loc_E35159↑p ...
                mov     al, 1
                retn
sub_E35AD6      endp

; [00000021 BYTES: COLLAPSED FUNCTION __initialize_default_precision. PRESS CTRL-NUMPAD+ TO EXPAND]

; =============== S U B R O U T I N E =======================================


; void *sub_E35AFA()
sub_E35AFA      proc near               ; CODE XREF: ___scrt_initialize_default_local_stdio_options+E↓p
                mov     eax, offset unk_E39100
                retn
sub_E35AFA      endp

; [0000001D BYTES: COLLAPSED FUNCTION ___scrt_initialize_default_local_stdio_options. PRESS CTRL-NUMPAD+ TO EXPAND]

; =============== S U B R O U T I N E =======================================


; BOOL sub_E35B1D()
sub_E35B1D      proc near               ; CODE XREF: pre_c_initialization(void)+57↑p
                xor     eax, eax
                cmp     dword_E39010, eax
                setz    al
                retn
sub_E35B1D      endp


; =============== S U B R O U T I N E =======================================


; void *sub_E35B29()
sub_E35B29      proc near               ; CODE XREF: __scrt_common_main_seh(void)+98↑p
                mov     eax, offset unk_E394B0
                retn
sub_E35B29      endp


; =============== S U B R O U T I N E =======================================


; void *sub_E35B2F()
sub_E35B2F      proc near               ; CODE XREF: __scrt_common_main_seh(void):loc_E354C8↑p
                mov     eax, offset unk_E394AC
                retn
sub_E35B2F      endp


; =============== S U B R O U T I N E =======================================


; void sub_E35B35()
sub_E35B35      proc near               ; CODE XREF: pre_c_initialization(void)+32↑p
                push    ebx
                push    esi
                mov     esi, offset unk_E37A74
                mov     ebx, offset unk_E37A74
                cmp     esi, ebx
                jnb     short loc_E35B5E
                push    edi

loc_E35B46:                             ; CODE XREF: sub_E35B35+26↓j
                mov     edi, [esi]
                test    edi, edi
                jz      short loc_E35B56
                mov     ecx, edi
                call    ds:___guard_check_icall_fptr
                call    edi

loc_E35B56:                             ; CODE XREF: sub_E35B35+15↑j
                add     esi, 4
                cmp     esi, ebx
                jb      short loc_E35B46
                pop     edi

loc_E35B5E:                             ; CODE XREF: sub_E35B35+E↑j
                pop     esi
                pop     ebx
                retn
sub_E35B35      endp


; =============== S U B R O U T I N E =======================================


; void __cdecl sub_E35B61()
sub_E35B61      proc near               ; DATA XREF: pre_c_initialization(void)+37↑o
                push    ebx
                push    esi
                mov     esi, offset unk_E37A7C
                mov     ebx, offset unk_E37A7C
                cmp     esi, ebx
                jnb     short loc_E35B8A
                push    edi

loc_E35B72:                             ; CODE XREF: sub_E35B61+26↓j
                mov     edi, [esi]
                test    edi, edi
                jz      short loc_E35B82
                mov     ecx, edi
                call    ds:___guard_check_icall_fptr
                call    edi

loc_E35B82:                             ; CODE XREF: sub_E35B61+15↑j
                add     esi, 4
                cmp     esi, ebx
                jb      short loc_E35B72
                pop     edi

loc_E35B8A:                             ; CODE XREF: sub_E35B61+E↑j
                pop     esi
                pop     ebx
                retn
sub_E35B61      endp

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
; [0000002D BYTES: COLLAPSED FUNCTION iCrucialEncode. PRESS CTRL-NUMPAD+ TO EXPAND]
                align 10h

__ftoui3:
                cmp     dword_E390E8, 6
                jl      short loc_E36130
                vcvttss2usi eax, xmm0
                retn
; ---------------------------------------------------------------------------

loc_E36130:                             ; CODE XREF: .text:00E36127↑j
                movd    eax, xmm0
                shl     eax, 1
                jb      short loc_E36153
                cmp     eax, 9E000000h
                jnb     short loc_E36144

loc_E3613F:                             ; CODE XREF: .text:00E36158↓j
                cvttss2si eax, xmm0
                retn
; ---------------------------------------------------------------------------

loc_E36144:                             ; CODE XREF: .text:00E3613D↑j
                cmp     eax, 9F000000h
                jnb     short loc_E3615A
                shl     eax, 7
                bts     eax, 1Fh
                retn
; ---------------------------------------------------------------------------

loc_E36153:                             ; CODE XREF: .text:00E36136↑j
                cmp     eax, 7F000000h
                jb      short loc_E3613F

loc_E3615A:                             ; CODE XREF: .text:00E36149↑j
                cvttss2si ecx, ds:dword_E37400
                cmc
                sbb     eax, eax
                retn
; ---------------------------------------------------------------------------

__ftoul3:
                cmp     dword_E390E8, 6
                jl      short loc_E36189
                mov     eax, 1
                kmovb   k1, eax
                vcvttps2uqq xmm0{k1}{z}, xmm0
                vmovd   eax, xmm0
                vpextrd edx, xmm0, 1
                retn
; ---------------------------------------------------------------------------

loc_E36189:                             ; CODE XREF: .text:00E3616D↑j
                movd    eax, xmm0
                shl     eax, 1
                jb      short loc_E361C4
                cmp     eax, 9E000000h
                jnb     short loc_E3619F

loc_E36198:                             ; CODE XREF: .text:00E361C9↓j
                cvttss2si eax, xmm0
                xor     edx, edx
                retn
; ---------------------------------------------------------------------------

loc_E3619F:                             ; CODE XREF: .text:00E36196↑j
                cmp     eax, 0BF000000h
                jnb     short loc_E361CB
                mov     ecx, eax
                bts     eax, 18h
                shr     ecx, 18h
                shl     eax, 7
                sub     cl, 0BEh
                jns     short loc_E361BF
                xor     edx, edx
                shld    edx, eax, cl
                shl     eax, cl
                retn
; ---------------------------------------------------------------------------

loc_E361BF:                             ; CODE XREF: .text:00E361B5↑j
                mov     edx, eax
                xor     eax, eax
                retn
; ---------------------------------------------------------------------------

loc_E361C4:                             ; CODE XREF: .text:00E3618F↑j
                cmp     eax, 7F000000h
                jb      short loc_E36198

loc_E361CB:                             ; CODE XREF: .text:00E361A4↑j
                cvttss2si ecx, ds:dword_E37400
                cmc
                sbb     eax, eax
                cdq
                retn
; ---------------------------------------------------------------------------

__ftol3:
                cmp     dword_E390E8, 6
                jl      short loc_E361FB
                mov     eax, 1
                kmovb   k1, eax
                vcvttps2qq xmm0{k1}{z}, xmm0
                vmovd   eax, xmm0
                vpextrd edx, xmm0, 1
                retn
; ---------------------------------------------------------------------------

loc_E361FB:                             ; CODE XREF: .text:00E361DF↑j
                movd    eax, xmm0
                cdq
                shl     eax, 1
                cmp     eax, 9E000000h
                jnb     short loc_E3620F
                cvttss2si eax, xmm0
                cdq
                retn
; ---------------------------------------------------------------------------

loc_E3620F:                             ; CODE XREF: .text:00E36207↑j
                cmp     eax, 0BE000000h
                jnb     short loc_E3622F
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

loc_E3622F:                             ; CODE XREF: .text:00E36214↑j
                jnz     short loc_E36235
                test    edx, edx
                js      short loc_E3623D

loc_E36235:                             ; CODE XREF: .text:loc_E3622F↑j
                cvttss2si ecx, ds:dword_E37400

loc_E3623D:                             ; CODE XREF: .text:00E36233↑j
                mov     edx, 80000000h
                xor     eax, eax
                retn
; ---------------------------------------------------------------------------

__dtoui3:
                cmp     dword_E390E8, 6
                jl      short loc_E36255
                vcvttsd2usi eax, xmm0
                retn
; ---------------------------------------------------------------------------

loc_E36255:                             ; CODE XREF: .text:00E3624C↑j
                mov     ecx, esp
                add     esp, 0FFFFFFF8h
                and     esp, 0FFFFFFF8h
                movsd   qword ptr [esp], xmm0
                mov     eax, [esp]
                mov     edx, [esp+4]
                mov     esp, ecx
                btr     edx, 1Fh
                jb      short loc_E3629E
                cmp     edx, 41E00000h
                jnb     short loc_E3627E
                cvttsd2si eax, xmm0
                retn
; ---------------------------------------------------------------------------

loc_E3627E:                             ; CODE XREF: .text:00E36277↑j
                cmp     edx, 41F00000h
                jnb     short loc_E362AD
                test    eax, 1FFFFFh
                jz      short loc_E36295
                cvttss2si ecx, ds:dword_E37404

loc_E36295:                             ; CODE XREF: .text:00E3628B↑j
                shrd    eax, edx, 15h
                bts     eax, 1Fh
                retn
; ---------------------------------------------------------------------------

loc_E3629E:                             ; CODE XREF: .text:00E3626F↑j
                cmp     edx, 3FF00000h
                jnb     short loc_E362AD
                cvttsd2si eax, xmm0
                xor     eax, eax
                retn
; ---------------------------------------------------------------------------

loc_E362AD:                             ; CODE XREF: .text:00E36284↑j
                                        ; .text:00E362A4↑j
                cvttss2si ecx, ds:dword_E37400
                xor     eax, eax
                dec     eax
                retn
; ---------------------------------------------------------------------------

__dtoul3:
                cmp     dword_E390E8, 6
                jl      short loc_E362D7
                vmovq   xmm0, xmm0
                vcvttpd2uqq xmm0, xmm0
                vmovd   eax, xmm0
                vpextrd edx, xmm0, 1
                retn
; ---------------------------------------------------------------------------

loc_E362D7:                             ; CODE XREF: .text:00E362C0↑j
                mov     ecx, esp
                add     esp, 0FFFFFFF8h
                and     esp, 0FFFFFFF8h
                movsd   qword ptr [esp], xmm0
                mov     eax, [esp]
                mov     edx, [esp+4]
                mov     esp, ecx
                btr     edx, 1Fh
                jb      short loc_E3633D
                cmp     edx, 41E00000h
                jnb     short loc_E36302
                cvttsd2si eax, xmm0
                xor     edx, edx
                retn
; ---------------------------------------------------------------------------

loc_E36302:                             ; CODE XREF: .text:00E362F9↑j
                mov     ecx, edx
                bts     edx, 14h
                shr     ecx, 14h
                and     edx, 1FFFFFh
                sub     ecx, 433h
                jge     short loc_E36332
                neg     ecx
                push    ebx
                xor     ebx, ebx
                shrd    ebx, eax, cl
                jz      short loc_E3632B
                cvttss2si ebx, ds:dword_E37404

loc_E3632B:                             ; CODE XREF: .text:00E36321↑j
                pop     ebx
                shrd    eax, edx, cl
                shr     edx, cl
                retn
; ---------------------------------------------------------------------------

loc_E36332:                             ; CODE XREF: .text:00E36317↑j
                cmp     ecx, 0Ch
                jnb     short loc_E3634E
                shld    edx, eax, cl
                shl     eax, cl
                retn
; ---------------------------------------------------------------------------

loc_E3633D:                             ; CODE XREF: .text:00E362F1↑j
                cmp     edx, 3FF00000h
                jnb     short loc_E3634E
                cvttsd2si eax, xmm0
                xor     eax, eax
                xor     edx, edx
                retn
; ---------------------------------------------------------------------------

loc_E3634E:                             ; CODE XREF: .text:00E36335↑j
                                        ; .text:00E36343↑j
                cvttss2si ecx, ds:dword_E37400
                xor     eax, eax
                dec     eax
                cdq
                retn
; ---------------------------------------------------------------------------

__dtol3:
                cmp     dword_E390E8, 6
                jl      short loc_E36379
                vmovq   xmm0, xmm0
                vcvttpd2qq xmm0, xmm0
                vmovd   eax, xmm0
                vpextrd edx, xmm0, 1
                retn
; ---------------------------------------------------------------------------

loc_E36379:                             ; CODE XREF: .text:00E36362↑j
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
                jnb     short loc_E363D9
                cvttsd2si eax, xmm0
                cdq
                retn

; =============== S U B R O U T I N E =======================================


; unsigned __int64 __usercall sub_E363A3@<edx:eax>(unsigned __int64@<edx:eax>)
sub_E363A3      proc near               ; CODE XREF: .text:00E363E3↓j
                                        ; .text:00E363E5↓p
                mov     ecx, edx
                bts     edx, 14h
                shr     ecx, 14h
                and     edx, 1FFFFFh
                sub     ecx, 433h
                jge     short loc_E363D3
                neg     ecx
                push    ebx
                xor     ebx, ebx
                shrd    ebx, eax, cl
                jz      short loc_E363CC
                cvttss2si ebx, ds:dword_E37404

loc_E363CC:                             ; CODE XREF: sub_E363A3+1F↑j
                pop     ebx
                shrd    eax, edx, cl
                shr     edx, cl
                retn
; ---------------------------------------------------------------------------

loc_E363D3:                             ; CODE XREF: sub_E363A3+15↑j
                shld    edx, eax, cl
                shl     eax, cl
                retn
sub_E363A3      endp

; ---------------------------------------------------------------------------

loc_E363D9:                             ; CODE XREF: .text:00E3639B↑j
                cmp     edx, 43E00000h
                jnb     short loc_E363F2
                test    ecx, ecx
                jz      short sub_E363A3
                call    sub_E363A3
                neg     eax
                adc     edx, 0
                neg     edx
                retn
; ---------------------------------------------------------------------------

loc_E363F2:                             ; CODE XREF: .text:00E363DF↑j
                jecxz   short loc_E363FA
                ja      short loc_E363FA
                test    eax, eax
                jz      short loc_E36402

loc_E363FA:                             ; CODE XREF: .text:loc_E363F2↑j
                                        ; .text:00E363F4↑j
                cvttss2si ecx, ds:dword_E37400

loc_E36402:                             ; CODE XREF: .text:00E363F8↑j
                mov     edx, 80000000h
                xor     eax, eax
                retn
; ---------------------------------------------------------------------------
                align 10h

__ultod3:
                cmp     dword_E390E8, 6
                jl      short loc_E3642A
                vmovd   xmm0, ecx
                vpinsrd xmm0, xmm0, edx, 1
                vcvtuqq2pd xmm0, xmm0
                retn
; ---------------------------------------------------------------------------

loc_E3642A:                             ; CODE XREF: .text:00E36417↑j
                xorps   xmm0, xmm0
                cvtsi2sd xmm0, ecx
                shr     ecx, 1Fh
                addsd   xmm0, ds:qword_E37408[ecx*8]
                test    edx, edx
                jz      short locret_E36460
                xorps   xmm1, xmm1
                cvtsi2sd xmm1, edx
                shr     edx, 1Fh
                addsd   xmm1, ds:qword_E37408[edx*8]
                mulsd   xmm1, ds:qword_E37410
                addsd   xmm0, xmm1

locret_E36460:                          ; CODE XREF: .text:00E3643F↑j
                retn
; ---------------------------------------------------------------------------
                align 10h
; [00000041 BYTES: COLLAPSED FUNCTION __ltod3. PRESS CTRL-NUMPAD+ TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION memcpy. PRESS CTRL-NUMPAD+ TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION memmove. PRESS CTRL-NUMPAD+ TO EXPAND]
; ---------------------------------------------------------------------------
; START OF FUNCTION CHUNK FOR sub_E318BC

loc_E364BD:                             ; DATA XREF: .rdata:stru_E37AA4↓o
                mov     ecx, [ebp-18h]
                jmp     sub_E31E5B
; END OF FUNCTION CHUNK FOR sub_E318BC
; ---------------------------------------------------------------------------
                db 5 dup(0CCh)
; ---------------------------------------------------------------------------
; START OF FUNCTION CHUNK FOR sub_E318BC

loc_E364CA:                             ; DATA XREF: sub_E318BC+17↑o
                                        ; .rdata:00E376FC↓o
                nop
                nop
                mov     eax, offset stru_E37A80
                jmp     __CxxFrameHandler3
; END OF FUNCTION CHUNK FOR sub_E318BC
; ---------------------------------------------------------------------------
; START OF FUNCTION CHUNK FOR cEncode__bCrucialEncode
;   ADDITIONAL PARENT FUNCTION sub_E32216
;   ADDITIONAL PARENT FUNCTION mEncode
;   ADDITIONAL PARENT FUNCTION sub_E32D9C
;   ADDITIONAL PARENT FUNCTION sub_E33751

SEH_403751:                             ; DATA XREF: cEncode__bCrucialEncode+5↑o
                                        ; sub_E32216+5↑o ...
SEH_402D9C:
                nop
                nop
                mov     eax, offset stru_E37AAC
                jmp     __CxxFrameHandler3
; END OF FUNCTION CHUNK FOR cEncode__bCrucialEncode
; ---------------------------------------------------------------------------
; START OF FUNCTION CHUNK FOR sub_E31000
;   ADDITIONAL PARENT FUNCTION sub_E3105D
;   ADDITIONAL PARENT FUNCTION sub_E310BA
;   ADDITIONAL PARENT FUNCTION sub_E31117
;   ADDITIONAL PARENT FUNCTION sub_E31174
;   ADDITIONAL PARENT FUNCTION sub_E311D1
;   ADDITIONAL PARENT FUNCTION sub_E3122E
;   ADDITIONAL PARENT FUNCTION sub_E3128B

loc_E364E2:                             ; DATA XREF: .rdata:stru_E37AF4↓o
                lea     ecx, [ebp+var_24]
                jmp     gEncode
; END OF FUNCTION CHUNK FOR sub_E31000
; ---------------------------------------------------------------------------
                db 5 dup(0CCh)
; ---------------------------------------------------------------------------
; START OF FUNCTION CHUNK FOR sub_E31000
;   ADDITIONAL PARENT FUNCTION sub_E3105D
;   ADDITIONAL PARENT FUNCTION sub_E310BA
;   ADDITIONAL PARENT FUNCTION sub_E31117
;   ADDITIONAL PARENT FUNCTION sub_E31174
;   ADDITIONAL PARENT FUNCTION sub_E311D1
;   ADDITIONAL PARENT FUNCTION sub_E3122E
;   ADDITIONAL PARENT FUNCTION sub_E3128B

SEH_401000:                             ; DATA XREF: sub_E31000+5↑o
                                        ; sub_E3105D+5↑o ...
                nop
                nop
                mov     eax, offset stru_E37AD0
                jmp     __CxxFrameHandler3
; END OF FUNCTION CHUNK FOR sub_E31000
; ---------------------------------------------------------------------------
; START OF FUNCTION CHUNK FOR aGetInput

loc_E364FB:                             ; DATA XREF: .rdata:stru_E37B20↓o
                lea     ecx, [ebp+UserInput]
                jmp     gEncode
; END OF FUNCTION CHUNK FOR aGetInput
; ---------------------------------------------------------------------------
                align 8
; START OF FUNCTION CHUNK FOR aGetInput

SEH_4019EF:                             ; DATA XREF: aGetInput+5↑o
                                        ; .rdata:00E37708↓o
                nop
                nop
                mov     eax, offset stru_E37AFC
                jmp     __CxxFrameHandler3
; END OF FUNCTION CHUNK FOR aGetInput
; ---------------------------------------------------------------------------
; START OF FUNCTION CHUNK FOR eEncode

loc_E36514:                             ; DATA XREF: .rdata:stru_E37B4C↓o
                lea     ecx, [ebp+var_54]
                jmp     sub_E31E5B
; END OF FUNCTION CHUNK FOR eEncode
; ---------------------------------------------------------------------------
                db 5 dup(0CCh)
; ---------------------------------------------------------------------------
; START OF FUNCTION CHUNK FOR eEncode

SEH_401A6B:                             ; DATA XREF: eEncode+5↑o
                                        ; .rdata:00E3770C↓o
                nop
                nop
                mov     eax, offset stru_E37B28
                jmp     __CxxFrameHandler3
; END OF FUNCTION CHUNK FOR eEncode
; ---------------------------------------------------------------------------
; START OF FUNCTION CHUNK FOR _main

loc_E3652D:                             ; DATA XREF: .rdata:stru_E37B78↓o
                lea     ecx, [ebp+var_24]
                jmp     sub_E319DE
; END OF FUNCTION CHUNK FOR _main
; ---------------------------------------------------------------------------
                db 5 dup(0CCh)
; ---------------------------------------------------------------------------
; START OF FUNCTION CHUNK FOR _main

_main_SEH:                              ; DATA XREF: _main+5↑o
                                        ; .rdata:00E37710↓o
                nop
                nop
                mov     eax, offset stru_E37B54
                jmp     __CxxFrameHandler3
; END OF FUNCTION CHUNK FOR _main
; ---------------------------------------------------------------------------
; START OF FUNCTION CHUNK FOR dEncode

loc_E36546:                             ; DATA XREF: .rdata:stru_E37BA4↓o
                lea     ecx, [ebp+var_28]
                jmp     jEncode
; END OF FUNCTION CHUNK FOR dEncode
; ---------------------------------------------------------------------------
                db 5 dup(0CCh)
; ---------------------------------------------------------------------------
; START OF FUNCTION CHUNK FOR dEncode

SEH_401E6C:                             ; DATA XREF: dEncode+5↑o
                                        ; .rdata:00E37714↓o
                nop
                nop
                mov     eax, offset stru_E37B80
                jmp     __CxxFrameHandler3
; END OF FUNCTION CHUNK FOR dEncode
; ---------------------------------------------------------------------------
; START OF FUNCTION CHUNK FOR sub_E320BA

loc_E3655F:                             ; DATA XREF: .rdata:stru_E37BD0↓o
                mov     ecx, [ebp+var_14]
                jmp     hEncode
; END OF FUNCTION CHUNK FOR sub_E320BA
; ---------------------------------------------------------------------------
                db 5 dup(0CCh)
; ---------------------------------------------------------------------------
; START OF FUNCTION CHUNK FOR sub_E320BA

SEH_4020BA:                             ; DATA XREF: sub_E320BA+5↑o
                                        ; .rdata:00E37718↓o
                nop
                nop
                mov     eax, offset stru_E37BAC
                jmp     __CxxFrameHandler3
; END OF FUNCTION CHUNK FOR sub_E320BA
; ---------------------------------------------------------------------------
; START OF FUNCTION CHUNK FOR sub_E32823

loc_E36578:                             ; DATA XREF: .rdata:stru_E37BFC↓o
                lea     ecx, [ebp+var_24]
                jmp     ds:??1_Lockit@std@@QAE@XZ ; std::_Lockit::~_Lockit(void)
; ---------------------------------------------------------------------------

loc_E36581:                             ; DATA XREF: .rdata:00E37C04↓o
                lea     ecx, [ebp+var_1C]
                jmp     sub_E32E13
; END OF FUNCTION CHUNK FOR sub_E32823
; ---------------------------------------------------------------------------
                db 5 dup(0CCh)
; ---------------------------------------------------------------------------
; START OF FUNCTION CHUNK FOR sub_E32823

SEH_402823:                             ; DATA XREF: sub_E32823+5↑o
                                        ; .rdata:00E3771C↓o
                nop
                nop
                mov     eax, offset stru_E37BD8
                jmp     __CxxFrameHandler3
; END OF FUNCTION CHUNK FOR sub_E32823
; ---------------------------------------------------------------------------
; START OF FUNCTION CHUNK FOR sub_E32F66

loc_E3659A:                             ; DATA XREF: .rdata:stru_E37C30↓o
                lea     ecx, [ebp+var_74]
                jmp     sub_E33618
; ---------------------------------------------------------------------------

loc_E365A2:                             ; DATA XREF: .rdata:00E37C38↓o
                lea     ecx, [ebp+var_7C]
                jmp     sub_E316D8
; END OF FUNCTION CHUNK FOR sub_E32F66
; ---------------------------------------------------------------------------
                db 5 dup(0CCh)
; ---------------------------------------------------------------------------
; START OF FUNCTION CHUNK FOR sub_E32F66

SEH_402F66:                             ; DATA XREF: sub_E32F66+5↑o
                                        ; .rdata:00E37720↓o
                nop
                nop
                mov     eax, offset stru_E37C0C
                jmp     __CxxFrameHandler3
; END OF FUNCTION CHUNK FOR sub_E32F66
; ---------------------------------------------------------------------------
; START OF FUNCTION CHUNK FOR sub_E33363

SEH_403363:                             ; DATA XREF: sub_E33363+5↑o
                                        ; .rdata:00E37724↓o
                nop
                nop
                mov     eax, offset stru_E37C74
                jmp     __CxxFrameHandler3
; END OF FUNCTION CHUNK FOR sub_E33363
; ---------------------------------------------------------------------------
; START OF FUNCTION CHUNK FOR tEncode

loc_E365C7:                             ; DATA XREF: .rdata:stru_E37CF0↓o
                lea     ecx, [ebp+var_20]
                jmp     sub_E33643
; END OF FUNCTION CHUNK FOR tEncode
; ---------------------------------------------------------------------------
                db 5 dup(0CCh)
; ---------------------------------------------------------------------------
; START OF FUNCTION CHUNK FOR tEncode

SEH_40349C:                             ; DATA XREF: tEncode+5↑o
                                        ; .rdata:00E37728↓o
                nop
                nop
                mov     eax, offset stru_E37CCC
                jmp     __CxxFrameHandler3
; END OF FUNCTION CHUNK FOR tEncode
; ---------------------------------------------------------------------------
; START OF FUNCTION CHUNK FOR sub_E335AC

loc_E365E0:                             ; DATA XREF: .rdata:stru_E37D1C↓o
                lea     ecx, [ebp+var_1C]
                jmp     sub_E33643
; END OF FUNCTION CHUNK FOR sub_E335AC
; ---------------------------------------------------------------------------
                db 5 dup(0CCh)
; ---------------------------------------------------------------------------
; START OF FUNCTION CHUNK FOR sub_E335AC

SEH_4035AC:                             ; DATA XREF: sub_E335AC+5↑o
                                        ; .rdata:00E3772C↓o
                nop
                nop
                mov     eax, offset stru_E37CF8
                jmp     __CxxFrameHandler3
; END OF FUNCTION CHUNK FOR sub_E335AC
; ---------------------------------------------------------------------------
; START OF FUNCTION CHUNK FOR sub_E336F6

loc_E365F9:                             ; DATA XREF: .rdata:stru_E37D48↓o
                mov     ecx, [ebp+var_10]
                jmp     sub_E33751
; END OF FUNCTION CHUNK FOR sub_E336F6
; ---------------------------------------------------------------------------
                db 5 dup(0CCh)
; ---------------------------------------------------------------------------
; START OF FUNCTION CHUNK FOR sub_E336F6

SEH_4036F6:                             ; DATA XREF: sub_E336F6+5↑o
                                        ; .rdata:00E37730↓o
                nop
                nop
                mov     eax, offset stru_E37D24
                jmp     __CxxFrameHandler3
; END OF FUNCTION CHUNK FOR sub_E336F6

; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; void __cdecl sub_E36612()
sub_E36612      proc near               ; DATA XREF: sub_E31000+46↑o
                push    ebp
                mov     ebp, esp
                mov     ecx, offset dword_E3944C
                call    sub_E319DE
                pop     ebp
                retn
sub_E36612      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; void __cdecl sub_E36621()
sub_E36621      proc near               ; DATA XREF: sub_E3105D+46↑o
                push    ebp
                mov     ebp, esp
                mov     ecx, offset dword_E39458
                call    sub_E319DE
                pop     ebp
                retn
sub_E36621      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; void __cdecl sub_E36630()
sub_E36630      proc near               ; DATA XREF: sub_E310BA+46↑o
                push    ebp
                mov     ebp, esp
                mov     ecx, offset dword_E394A0
                call    sub_E319DE
                pop     ebp
                retn
sub_E36630      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; void __cdecl sub_E3663F()
sub_E3663F      proc near               ; DATA XREF: sub_E31117+46↑o
                push    ebp
                mov     ebp, esp
                mov     ecx, offset dword_E39440
                call    sub_E319DE
                pop     ebp
                retn
sub_E3663F      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; void __cdecl sub_E3664E()
sub_E3664E      proc near               ; DATA XREF: sub_E31174+46↑o
                push    ebp
                mov     ebp, esp
                mov     ecx, offset dword_E39464
                call    sub_E319DE
                pop     ebp
                retn
sub_E3664E      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; void __cdecl sub_E3665D()
sub_E3665D      proc near               ; DATA XREF: sub_E311D1+46↑o
                push    ebp
                mov     ebp, esp
                mov     ecx, offset dword_E39494
                call    sub_E319DE
                pop     ebp
                retn
sub_E3665D      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; void __cdecl sub_E3666C()
sub_E3666C      proc near               ; DATA XREF: sub_E3122E+46↑o
                push    ebp
                mov     ebp, esp
                mov     ecx, offset dword_E39434
                call    sub_E319DE
                pop     ebp
                retn
sub_E3666C      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; void __cdecl sub_E3667B()
sub_E3667B      proc near               ; DATA XREF: sub_E3128B+46↑o
                push    ebp
                mov     ebp, esp
                mov     ecx, offset dword_E39488
                call    sub_E319DE
                pop     ebp
                retn
sub_E3667B      endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; void __cdecl sub_E3668A()
sub_E3668A      proc near               ; DATA XREF: sub_E312E8+12↑o
                push    ebp
                mov     ebp, esp
                mov     ecx, offset dword_E39470
                call    gEncode
                pop     ebp
                retn
sub_E3668A      endp


; =============== S U B R O U T I N E =======================================


; void __cdecl sub_E36699()
sub_E36699      proc near               ; DATA XREF: sub_E31307↑o
                mov     ecx, offset unk_E390BC ; this
                jmp     ??1_Fac_tidy_reg_t@std@@QAE@XZ ; std::_Fac_tidy_reg_t::~_Fac_tidy_reg_t(void)
sub_E36699      endp

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
                                        ; CODE XREF: sub_E35ACA+5↑p
                                        ; DATA XREF: sub_E35ACA+5↑r
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
                                        ; sub_E3592E+5↑p ...
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
                                        ; CODE XREF: sub_E32F66+1F3↑p
                                        ; sub_E32F66+24B↑p
                                        ; DATA XREF: ...
; int __thiscall std::ios::rdbuf(_DWORD, _DWORD, _DWORD)
                extrn ?rdbuf@?$basic_ios@DU?$char_traits@D@std@@@std@@QBEPAV?$basic_streambuf@DU?$char_traits@D@std@@@2@XZ:dword
                                        ; CODE XREF: sub_E32F66+11A↑p
                                        ; sub_E32F66+149↑p ...
; int __thiscall std::streambuf::sgetc(_DWORD)
                extrn ?sgetc@?$basic_streambuf@DU?$char_traits@D@std@@@std@@QAEHXZ:dword
                                        ; CODE XREF: sub_E32F66+126↑p
                                        ; DATA XREF: sub_E32F66+126↑r
; int __thiscall std::ios_base::getloc(_DWORD, _DWORD)
                extrn ?getloc@ios_base@std@@QBE?AVlocale@2@XZ:dword
                                        ; CODE XREF: sub_E32F66+63↑p
                                        ; DATA XREF: sub_E32F66+63↑r
; int __thiscall std::streambuf::snextc(_DWORD)
                extrn ?snextc@?$basic_streambuf@DU?$char_traits@D@std@@@std@@QAEHXZ:dword
                                        ; CODE XREF: sub_E32F66+155↑p
                                        ; DATA XREF: sub_E32F66+155↑r
; public: __int64 __thiscall std::ios_base::width(void)const
                extrn ?width@ios_base@std@@QBE_JXZ:dword
                                        ; CODE XREF: sub_E32F66+A7↑p
                                        ; sub_E32F66+CC↑p ...
; int __cdecl std::ctype<char>::_Getcat(_DWORD, _DWORD)
                extrn ?_Getcat@?$ctype@D@std@@SAIPAPBVfacet@locale@2@PBV42@@Z:dword
                                        ; CODE XREF: sub_E32823+6A↑p
                                        ; DATA XREF: sub_E32823+6A↑r
; int __thiscall std::ctype<char>::is(_DWORD, _DWORD, _DWORD)
                extrn ?is@?$ctype@D@std@@QBE_NFD@Z:dword
                                        ; CODE XREF: sub_E32F66+1A8↑p
                                        ; DATA XREF: sub_E32F66+1A8↑r
; int __thiscall std::locale::id::operator unsigned int(_DWORD)
                extrn ??Bid@locale@std@@QAEIXZ:dword
                                        ; CODE XREF: sub_E32823+38↑p
                                        ; DATA XREF: sub_E32823+38↑r
; int __thiscall std::istream::_Ipfx(_DWORD, _DWORD)
                extrn ?_Ipfx@?$basic_istream@DU?$char_traits@D@std@@@std@@QAE_N_N@Z:dword
                                        ; CODE XREF: sub_E336F6+3A↑p
                                        ; DATA XREF: sub_E336F6+3A↑r
; __int64 (__cdecl *Xtime_get_ticks)()
                extrn _Xtime_get_ticks:dword ; CODE XREF: sub_E31797+6↑p
                                        ; DATA XREF: sub_E31797+6↑r
; __int64 (__cdecl *Query_perf_frequency)()
                extrn _Query_perf_frequency:dword
                                        ; CODE XREF: sub_E317C3+6↑p
                                        ; DATA XREF: sub_E317C3+6↑r
; __int64 (__cdecl *Query_perf_counter)()
                extrn _Query_perf_counter:dword
                                        ; CODE XREF: sub_E317C3+12↑p
                                        ; DATA XREF: sub_E317C3+12↑r
; void (__cdecl *Thrd_sleep)(const xtime *)
                extrn _Thrd_sleep:dword ; CODE XREF: sub_E33230+4A↑p
                                        ; DATA XREF: sub_E33230+4A↑r
; void __cdecl std::_Xlength_error(char const *)
                extrn ?_Xlength_error@std@@YAXPBD@Z:dword
                                        ; CODE XREF: sub_E31664+8↑p
                                        ; sub_E337AD+8↑p
                                        ; DATA XREF: ...
; unsigned int __cdecl std::_Random_device(void)
                extrn ?_Random_device@std@@YAIXZ:dword
                                        ; CODE XREF: kCrucialEncode+7↑p
                                        ; DATA XREF: kCrucialEncode+7↑r
; public: static class std::locale::id std::ctype<char>::id
                extrn ?id@?$ctype@D@std@@2V0locale@2@A:dword
                                        ; DATA XREF: sub_E32823+32↑r
; void __cdecl std::_Xout_of_range(char const *)
                extrn ?_Xout_of_range@std@@YAXPBD@Z:dword
                                        ; CODE XREF: sub_E32813+8↑p
                                        ; DATA XREF: sub_E32813+8↑r
; class std::basic_istream<char, struct std::char_traits<char>> std::cin
                extrn ?cin@std@@3V?$basic_istream@DU?$char_traits@D@std@@@1@A:dword
                                        ; DATA XREF: aGetInput+3F↑r
; int std::locale::_Getgloballocale(void)
                extrn ?_Getgloballocale@locale@std@@CAPAV_Locimp@12@XZ:dword
                                        ; CODE XREF: sub_E31721:loc_E3176F↑p
                                        ; DATA XREF: sub_E31721:loc_E3176F↑r
; public: __thiscall std::_Lockit::_Lockit(int)
                extrn ??0_Lockit@std@@QAE@H@Z:dword
                                        ; CODE XREF: sub_E32823+20↑p
                                        ; DATA XREF: sub_E32823+20↑r
; public: __thiscall std::_Lockit::~_Lockit(void)
                extrn ??1_Lockit@std@@QAE@XZ:dword
                                        ; CODE XREF: sub_E32823+D6↑p
                                        ; DATA XREF: sub_E32823+D6↑r ...
; public: __int64 __thiscall std::ios_base::width(__int64)
                extrn ?width@ios_base@std@@QAE_J_J@Z:dword
                                        ; CODE XREF: sub_E32F66+21E↑p
                                        ; DATA XREF: sub_E32F66+21E↑r

;
; Imports from VCRUNTIME140.dll
;
; void *(__cdecl *memmove)(void *, const void *Src, size_t Size)
                extrn __imp_memmove:dword ; DATA XREF: memmove↑r
                                        ; .rdata:00E37E78↓o
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
                                        ; CODE XREF: sub_E313C7+2B↑p
                                        ; DATA XREF: sub_E313C7+2B↑r
                extrn __imp___CxxFrameHandler3:dword
                                        ; DATA XREF: __CxxFrameHandler3↑r
; void *(__cdecl *memcpy)(void *, const void *Src, size_t Size)
                extrn __imp_memcpy:dword ; DATA XREF: memcpy↑r
; int __cdecl _std_exception_destroy(_DWORD)
                extrn __std_exception_destroy:dword
                                        ; CODE XREF: sub_E31401+17↑p
                                        ; DATA XREF: sub_E31401+17↑r

;
; Imports from api-ms-win-crt-heap-l1-1-0.dll
;
; int (__cdecl *_set_new_mode)(int NewMode)
                extrn __imp__set_new_mode:dword
                                        ; DATA XREF: _set_new_mode↑r
                                        ; .rdata:00E37EB4↓o
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
                                        ; .rdata:00E37EDC↓o

;
; Imports from api-ms-win-crt-math-l1-1-0.dll
;
; void (__cdecl *__setusermatherr)(_UserMathErrorFunctionPointer UserMathErrorFunction)
                extrn __imp___setusermatherr:dword
                                        ; DATA XREF: __setusermatherr↑r
                                        ; .rdata:00E37EC8↓o

;
; Imports from api-ms-win-crt-runtime-l1-1-0.dll
;
; void (__cdecl *_c_exit)()
                extrn __imp__c_exit:dword ; DATA XREF: _c_exit↑r
                                        ; .rdata:00E37EA0↓o
; void (__cdecl *_register_thread_local_exe_atexit_callback)(_tls_callback_type Callback)
                extrn __imp__register_thread_local_exe_atexit_callback:dword
                                        ; DATA XREF: _register_thread_local_exe_atexit_callback↑r
; int *(__cdecl *__p___argc)()
                extrn __imp___p___argc:dword ; DATA XREF: __p___argc↑r
; void (__cdecl __noreturn *invalid_parameter_noinfo_noreturn)()
                extrn _invalid_parameter_noinfo_noreturn:dword
                                        ; CODE XREF: sub_E315D8:loc_E31622↑p
                                        ; sub_E33533:loc_E33563↑p
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
                                        ; .rdata:00E37E8C↓o
; int (__cdecl *getchar)()
                extrn getchar:dword     ; CODE XREF: _main+C2↑p
                                        ; _main+C8↑p
                                        ; DATA XREF: ...
; int (__cdecl *_stdio_common_vfprintf)(unsigned __int64 Options, FILE *Stream, const char *Format, _locale_t Locale, va_list ArgList)
                extrn __stdio_common_vfprintf:dword
                                        ; CODE XREF: sub_E31339+19↑p
                                        ; DATA XREF: sub_E31339+19↑r
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
                ;org 0E37150h
___guard_check_icall_fptr dd offset nullsub_1
                                        ; DATA XREF: std::_Fac_node::~_Fac_node(void)+C↑r
                                        ; std::_Fac_node::~_Fac_node(void)+24↑r ...
; const _PVFV dword_E37154
dword_E37154    dd 0                    ; DATA XREF: __scrt_common_main_seh(void)+72↑o
                dd offset sub_E353F6
                dd offset sub_E31307
                dd offset sub_E31000
                dd offset sub_E3105D
                dd offset sub_E310BA
                dd offset sub_E31117
                dd offset sub_E31174
                dd offset sub_E311D1
                dd offset sub_E3122E
                dd offset sub_E3128B
                dd offset sub_E312E8
; const _PVFV dword_E37184
dword_E37184    dd 0                    ; DATA XREF: __scrt_common_main_seh(void):loc_E35475↑o
; const _PIFV First
First           dd 0                    ; DATA XREF: __scrt_common_main_seh(void)+4C↑o
                dd offset ?pre_c_initialization@@YAHXZ ; pre_c_initialization(void)
                dd offset sub_E353EE
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
??_7type_info@@6B@ dd offset sub_E35320 ; DATA XREF: sub_E35320+A↑o
                                        ; .data:type_info `RTTI Type Descriptor'↓o ...
                dd offset ??_R4exception@std@@6B@ ; const std::exception::`RTTI Complete Object Locator'
; const std::exception::`vftable'
??_7exception@std@@6B@ dd offset sub_E31449 ; DATA XREF: sub_E3139A+A↑o
                                        ; sub_E313C7+A↑o ...
                dd offset sub_E31421
                dd offset ??_R4bad_alloc@std@@6B@ ; const std::bad_alloc::`RTTI Complete Object Locator'
; const std::bad_alloc::`vftable'
??_7bad_alloc@std@@6B@ dd offset sub_E31497 ; DATA XREF: sub_E31473+17↑o
                                        ; sub_E3156F+15↑o ...
                dd offset sub_E31421
aBadAllocation  db 'bad allocation',0   ; DATA XREF: sub_E35597+A↑o
                align 10h
                dd offset ??_R4bad_array_new_length@std@@6B@ ; const std::bad_array_new_length::`RTTI Complete Object Locator'
; const std::bad_array_new_length::`vftable'
??_7bad_array_new_length@std@@6B@ dd offset sub_E314F4
                                        ; DATA XREF: sub_E314D2+17↑o
                                        ; sub_E3154D+15↑o
                dd offset sub_E31421
; const struct _EXCEPTION_POINTERS ExceptionInfo
ExceptionInfo   _EXCEPTION_POINTERS <offset dword_E39108, offset dword_E39158>
                                        ; DATA XREF: ___report_gsfailure+ED↑o
aUnknownExcepti db 'Unknown exception',0
                                        ; DATA XREF: sub_E31421:loc_E3143D↑o
                align 4
aBadArrayNewLen db 'bad array new length',0 ; DATA XREF: sub_E314D2+7↑o
                align 10h
aStringTooLong  db 'string too long',0  ; DATA XREF: sub_E31664+3↑o
aBadCast        db 'bad cast',0         ; DATA XREF: sub_E31674+9↑o
                align 4
aHttpsDiscordGg db 'https://discord.gg/fmhw85T5zM',0
                                        ; DATA XREF: sub_E31000+1B↑o
                align 4
aV1rtu4lall0c   db 'V1rtu4lAll0c',0     ; DATA XREF: sub_E3105D+1B↑o
                align 4
aJpofwejfdslfkj db 'jpofwejfdslfkjdslkfghiphap332oiu',0
                                        ; DATA XREF: sub_E310BA+1B↑o
                align 10h
aOhu3mndslwoxfe db 'Ohu3mNdslwoxfedlo34',0 ; DATA XREF: sub_E31117+1B↑o
a2Mk43xxy01k    db '2-mk43xxy0.1k',0    ; DATA XREF: sub_E31174+1B↑o
                align 4
a324265339152   db ';32;42;65;33;91;52',0 ; DATA XREF: sub_E311D1+1B↑o
                align 4
aSDY9DVk        db 'S`=d`Y9{]D}_vK$#.',0 ; DATA XREF: sub_E3122E+1B↑o
                align 4
aXxxxxgot75Huh9 db 'xxxxxGot7.5_HUH?98rjoi2r3oifjdsoigfogdfs',0
                                        ; DATA XREF: sub_E3128B+1B↑o
                align 4
aH4ndy51mpl30bf db 'H4ndy51mpL30bFusC4tI0NL1bR4RybYM3mB3R_TH4nKs',0
                                        ; DATA XREF: sub_E312E8+3↑o
                align 4
aPassword       db 'Password: ',0       ; DATA XREF: aGetInput+1F↑o
                align 4
aV2             db 'v2',0               ; DATA XREF: aGetInput+2A↑o
                align 4
aMain           db 'main',0             ; DATA XREF: _main+23↑o
                align 10h
aS              db '%s()',0Ah,0         ; DATA XREF: _main+28↑o
                align 4
aFindCorrectPas db 'Find correct password',0Ah,0 ; DATA XREF: _main+34↑o
                align 10h
aIncorrectLlu   db 'Incorrect!(%llu)',0Ah,0 ; DATA XREF: _main+82↑o
                align 4
aCorrectPleaseS db 'Correct!',0Ah       ; DATA XREF: _main:loc_E31C80↑o
                db 'Please send DM with PW.',0Ah,0
                align 4
aInvalidStringP db 'invalid string position',0
                                        ; DATA XREF: sub_E32813+3↑o
aVectorTooLong  db 'vector too long',0  ; DATA XREF: sub_E337AD+3↑o
                dd offset ??_R4bad_cast@std@@6B@ ; const std::bad_cast::`RTTI Complete Object Locator'
; const std::bad_cast::`vftable'
??_7bad_cast@std@@6B@ dd offset sub_E31497 ; DATA XREF: sub_E31674+19↑o
                                        ; sub_E316B6+15↑o
                dd offset sub_E31421
                align 10h
qword_E373E0    dq 3FF0000000000000h    ; DATA XREF: sub_E34E45+7C↑r
                                        ; sub_E34E45+B4↑r ...
qword_E373E8    dq 412A5E0000000000h    ; DATA XREF: sub_E33C80+15↑r
qword_E373F0    dq 41CDCD6500000000h    ; DATA XREF: sub_E34E45+48↑r
                                        ; sub_E34E45+AC↑r
                align 10h
dword_E37400    dd 0FFFFFFFFh           ; DATA XREF: .text:loc_E3615A↑r
                                        ; .text:loc_E361CB↑r ...
dword_E37404    dd 3FC00000h            ; DATA XREF: .text:00E3628D↑r
                                        ; .text:00E36323↑r ...
qword_E37408    dq 0                    ; DATA XREF: .text:00E36434↑r
                                        ; .text:00E3644B↑r ...
qword_E37410    dq 41F0000000000000h    ; DATA XREF: .text:00E36454↑r
                                        ; __ltod3+2B↑r
; Debug Directory entries
                dd 0                    ; Characteristics
                dd 601D544Dh            ; TimeDateStamp: Fri Feb 05 14:21:01 2021
                dw 0                    ; MajorVersion
                dw 0                    ; MinorVersion
                dd 2                    ; Type: IMAGE_DEBUG_TYPE_CODEVIEW
                dd 4Dh                  ; SizeOfData
                dd rva asc_E37734       ; AddressOfRawData
                dd 6334h                ; PointerToRawData
                dd 0                    ; Characteristics
                dd 601D544Dh            ; TimeDateStamp: Fri Feb 05 14:21:01 2021
                dw 0                    ; MajorVersion
                dw 0                    ; MinorVersion
                dd 0Ch                  ; Type: IMAGE_DEBUG_TYPE_VC_FEATURE
                dd 14h                  ; SizeOfData
                dd rva unk_E37784       ; AddressOfRawData
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
??_R4type_info@@6B@ dd 0                ; DATA XREF: .rdata:00E371B0↑o
                                        ; signature
                dd 0                    ; offset of this vtable in complete class (from top)
                dd 0                    ; offset of constructor displacement
                dd offset ??_R0?AVtype_info@@@8 ; reference to type description
                dd offset ??_R3type_info@@8 ; reference to hierarchy description
; type_info::`RTTI Class Hierarchy Descriptor'
??_R3type_info@@8 dd 0                  ; DATA XREF: .rdata:00E37590↑o
                                        ; .rdata:00E375C4↓o
                                        ; signature
                dd 0                    ; attributes
                dd 1                    ; # of items in the array of base classes
                dd offset ??_R2type_info@@8 ; reference to the array of base classes
; type_info::`RTTI Base Class Array'
??_R2type_info@@8 dd offset ??_R1A@?0A@EA@type_info@@8
                                        ; DATA XREF: .rdata:00E375A0↑o
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
??_R4exception@std@@6B@ dd 0            ; DATA XREF: .rdata:00E371B8↑o
                                        ; signature
                dd 0                    ; offset of this vtable in complete class (from top)
                dd 0                    ; offset of constructor displacement
                dd offset ??_R0?AVexception@std@@@8 ; reference to type description
                dd offset ??_R3exception@std@@8 ; reference to hierarchy description
; std::bad_array_new_length::`RTTI Base Class Array'
??_R2bad_array_new_length@std@@8 dd offset ??_R1A@?0A@EA@bad_array_new_length@std@@8
                                        ; DATA XREF: .rdata:00E376B4↓o
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
                                        ; DATA XREF: .rdata:00E376C4↓o
                                        ; reference to base class decription 1
                dd offset ??_R1A@?0A@EA@exception@std@@8 ; reference to base class decription 2
                db    0
                db    0
                db    0
                db    0
; std::exception::`RTTI Base Class Descriptor at (0, -1, 0, 64)'
??_R1A@?0A@EA@exception@std@@8 dd offset ??_R0?AVexception@std@@@8
                                        ; DATA XREF: .rdata:00E375E4↑o
                                        ; .rdata:00E3760C↑o ...
                                        ; reference to type description
                dd 0                    ; # of sub elements within base class array
                dd 0                    ; member displacement
                dd 4294967295           ; vftable displacement
                dd 0                    ; displacement within vftable
                dd 40h                  ; base class attributes
                dd offset ??_R3exception@std@@8 ; reference to class hierarchy descriptor
; std::bad_alloc::`RTTI Base Class Descriptor at (0, -1, 0, 64)'
??_R1A@?0A@EA@bad_alloc@std@@8 dd offset ??_R0?AVbad_alloc@std@@@8
                                        ; DATA XREF: .rdata:00E375E0↑o
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
                                        ; DATA XREF: .rdata:00E3767C↓o
                                        ; reference to base class decription 1
                dd offset ??_R1A@?0A@EA@exception@std@@8 ; reference to base class decription 2
                align 8
; std::exception::`RTTI Base Class Array'
??_R2exception@std@@8 dd offset ??_R1A@?0A@EA@exception@std@@8
                                        ; DATA XREF: .rdata:00E3766C↓o
                                        ; reference to base class decription 1
                align 10h
; std::exception::`RTTI Class Hierarchy Descriptor'
??_R3exception@std@@8 dd 0              ; DATA XREF: .rdata:00E375D8↑o
                                        ; .rdata:00E3762C↑o
                                        ; signature
                dd 0                    ; attributes
                dd 1                    ; # of items in the array of base classes
                dd offset ??_R2exception@std@@8 ; reference to the array of base classes
; std::bad_cast::`RTTI Class Hierarchy Descriptor'
??_R3bad_cast@std@@8 dd 0               ; DATA XREF: .rdata:00E37604↑o
                                        ; .rdata:00E376A4↓o
                                        ; signature
                dd 0                    ; attributes
                dd 2                    ; # of items in the array of base classes
                dd offset ??_R2bad_cast@std@@8 ; reference to the array of base classes
; const std::bad_alloc::`RTTI Complete Object Locator'
??_R4bad_alloc@std@@6B@ dd 0            ; DATA XREF: .rdata:00E371C4↑o
                                        ; signature
                dd 0                    ; offset of this vtable in complete class (from top)
                dd 0                    ; offset of constructor displacement
                dd offset ??_R0?AVbad_alloc@std@@@8 ; reference to type description
                dd offset ??_R3bad_alloc@std@@8 ; reference to hierarchy description
; const std::bad_cast::`RTTI Complete Object Locator'
??_R4bad_cast@std@@6B@ dd 0             ; DATA XREF: .rdata:00E373D0↑o
                                        ; signature
                dd 0                    ; offset of this vtable in complete class (from top)
                dd 0                    ; offset of constructor displacement
                dd offset ??_R0?AVbad_cast@std@@@8 ; reference to type description
                dd offset ??_R3bad_cast@std@@8 ; reference to hierarchy description
; std::bad_array_new_length::`RTTI Class Hierarchy Descriptor'
??_R3bad_array_new_length@std@@8 dd 0   ; DATA XREF: .rdata:00E376D8↓o
                                        ; .rdata:00E376F4↓o
                                        ; signature
                dd 0                    ; attributes
                dd 3                    ; # of items in the array of base classes
                dd offset ??_R2bad_array_new_length@std@@8 ; reference to the array of base classes
; std::bad_alloc::`RTTI Class Hierarchy Descriptor'
??_R3bad_alloc@std@@8 dd 0              ; DATA XREF: .rdata:00E37648↑o
                                        ; .rdata:00E37690↑o
                                        ; signature
                dd 0                    ; attributes
                dd 2                    ; # of items in the array of base classes
                dd offset ??_R2bad_alloc@std@@8 ; reference to the array of base classes
; const std::bad_array_new_length::`RTTI Complete Object Locator'
??_R4bad_array_new_length@std@@6B@ dd 0 ; DATA XREF: .rdata:00E371E0↑o
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
                                        ; DATA XREF: .rdata:00E374C8↑o
                dd rva loc_E364CA
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
asc_E37734      db 'RSDS'               ; DATA XREF: .rdata:00E3742C↑o
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
unk_E37784      db    0                 ; DATA XREF: .rdata:00E37448↑o
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
aGctl           db 'GCTL',0             ; DATA XREF: .rdata:00E37464↑o
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
unk_E37A74      db    0                 ; DATA XREF: sub_E35B35+2↑o
                                        ; sub_E35B35+7↑o
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
unk_E37A7C      db    0                 ; DATA XREF: sub_E35B61+2↑o
                                        ; sub_E35B61+7↑o
                db    0
                db    0
                db    0
stru_E37A80     FuncInfo <19930522h, 1, offset stru_E37AA4, 0, 0, 0, 0, 0, 1>
                                        ; DATA XREF: sub_E318BC+4C10↑o
stru_E37AA4     UnwindMapEntry <-1, offset loc_E364BD>
                                        ; DATA XREF: .rdata:stru_E37A80↑o
stru_E37AAC     FuncInfo <19930522h, 0, 0, 0, 0, 0, 0, 0, 5>
                                        ; DATA XREF: cEncode__bCrucialEncode+4B37↑o
stru_E37AD0     FuncInfo <19930522h, 1, offset stru_E37AF4, 0, 0, 0, 0, 0, 1>
                                        ; DATA XREF: sub_E31000+54F1↑o
stru_E37AF4     UnwindMapEntry <-1, offset loc_E364E2>
                                        ; DATA XREF: .rdata:stru_E37AD0↑o
stru_E37AFC     FuncInfo <19930522h, 1, offset stru_E37B20, 0, 0, 0, 0, 0, 1>
                                        ; DATA XREF: aGetInput+4B1B↑o
stru_E37B20     UnwindMapEntry <-1, offset loc_E364FB>
                                        ; DATA XREF: .rdata:stru_E37AFC↑o
stru_E37B28     FuncInfo <19930522h, 1, offset stru_E37B4C, 0, 0, 0, 0, 0, 1>
                                        ; DATA XREF: eEncode+4AB8↑o
stru_E37B4C     UnwindMapEntry <-1, offset loc_E36514>
                                        ; DATA XREF: .rdata:stru_E37B28↑o
stru_E37B54     FuncInfo <19930522h, 1, offset stru_E37B78, 0, 0, 0, 0, 0, 1>
                                        ; DATA XREF: _main+4973↑o
stru_E37B78     UnwindMapEntry <-1, offset loc_E3652D>
                                        ; DATA XREF: .rdata:stru_E37B54↑o
stru_E37B80     FuncInfo <19930522h, 1, offset stru_E37BA4, 0, 0, 0, 0, 0, 1>
                                        ; DATA XREF: dEncode+46E9↑o
stru_E37BA4     UnwindMapEntry <-1, offset loc_E36546>
                                        ; DATA XREF: .rdata:stru_E37B80↑o
stru_E37BAC     FuncInfo <19930522h, 1, offset stru_E37BD0, 0, 0, 0, 0, 0, 1>
                                        ; DATA XREF: sub_E320BA+44B4↑o
stru_E37BD0     UnwindMapEntry <-1, offset loc_E3655F>
                                        ; DATA XREF: .rdata:stru_E37BAC↑o
stru_E37BD8     FuncInfo <19930522h, 2, offset stru_E37BFC, 0, 0, 0, 0, 0, 1>
                                        ; DATA XREF: sub_E32823+3D6D↑o
stru_E37BFC     UnwindMapEntry <-1, offset loc_E36578>
                                        ; DATA XREF: .rdata:stru_E37BD8↑o
                UnwindMapEntry <0, offset loc_E36581>
stru_E37C0C     FuncInfo <19930522h, 4, offset stru_E37C30, 1, offset stru_E37C50, 0, \
                                        ; DATA XREF: sub_E32F66+364B↑o
                          0, 0, 1>
stru_E37C30     UnwindMapEntry <-1, offset loc_E3659A>
                                        ; DATA XREF: .rdata:stru_E37C0C↑o
                UnwindMapEntry <0, offset loc_E365A2>
                UnwindMapEntry <0>
                UnwindMapEntry <0>
stru_E37C50     TryBlockMapEntry <2, 2, 3, 1, offset stru_E37C64>
                                        ; DATA XREF: .rdata:stru_E37C0C↑o
stru_E37C64     HandlerType <40h, 0, 0, offset loc_E33144>
                                        ; DATA XREF: .rdata:stru_E37C50↑o
stru_E37C74     FuncInfo <19930522h, 2, offset stru_E37C98, 1, offset stru_E37CA8, 0, \
                                        ; DATA XREF: sub_E33363+325A↑o
                          0, 0, 1>
stru_E37C98     UnwindMapEntry <-1, 0>  ; DATA XREF: .rdata:stru_E37C74↑o
                UnwindMapEntry <-1, 0>
stru_E37CA8     TryBlockMapEntry <0, 0, 1, 1, offset stru_E37CBC>
                                        ; DATA XREF: .rdata:stru_E37C74↑o
stru_E37CBC     HandlerType <40h, 0, 0, offset loc_E33435>
                                        ; DATA XREF: .rdata:stru_E37CA8↑o
stru_E37CCC     FuncInfo <19930522h, 1, offset stru_E37CF0, 0, 0, 0, 0, 0, 1>
                                        ; DATA XREF: tEncode+313A↑o
stru_E37CF0     UnwindMapEntry <-1, offset loc_E365C7>
                                        ; DATA XREF: .rdata:stru_E37CCC↑o
stru_E37CF8     FuncInfo <19930522h, 1, offset stru_E37D1C, 0, 0, 0, 0, 0, 1>
                                        ; DATA XREF: sub_E335AC+3043↑o
stru_E37D1C     UnwindMapEntry <-1, offset loc_E365E0>
                                        ; DATA XREF: .rdata:stru_E37CF8↑o
stru_E37D24     FuncInfo <19930522h, 1, offset stru_E37D48, 0, 0, 0, 0, 0, 1>
                                        ; DATA XREF: sub_E336F6+2F12↑o
stru_E37D48     UnwindMapEntry <-1, offset loc_E365F9>
                                        ; DATA XREF: .rdata:stru_E37D24↑o
stru_E37D50     dd 0FFFFFFFEh           ; GSCookieOffset
                                        ; DATA XREF: ___scrt_is_nonwritable_in_current_image+2↑o
                dd 0                    ; GSCookieXOROffset
                dd 0FFFFFFD8h           ; EHCookieOffset
                dd 0                    ; EHCookieXOROffset
                dd 0FFFFFFFEh           ; ScopeRecord.EnclosingLevel
                dd offset loc_E3525C    ; ScopeRecord.FilterFunc
                dd offset loc_E3526F    ; ScopeRecord.HandlerFunc
                align 10h
stru_E37D70     dd 0FFFFFFFEh           ; GSCookieOffset
                                        ; DATA XREF: __scrt_common_main_seh(void)+2↑o
                dd 0                    ; GSCookieXOROffset
                dd 0FFFFFFCCh           ; EHCookieOffset
                dd 0                    ; EHCookieXOROffset
                dd 0FFFFFFFEh           ; ScopeRecord.EnclosingLevel
                dd offset loc_E3552F    ; ScopeRecord.FilterFunc
                dd offset loc_E35543    ; ScopeRecord.HandlerFunc
; const _ThrowInfo _TI2_AVbad_alloc_std__
__TI2?AVbad_alloc@std@@ dd 0            ; DATA XREF: sub_E355AF+E↑o
                                        ; attributes
                dd offset sub_E314C1    ; destructor of exception object
                dd 0                    ; forward compatibility frame handler
                dd offset __CTA2?AVbad_alloc@std@@ ; address of catchable types array
__CTA2?AVbad_alloc@std@@ dd 2           ; DATA XREF: .rdata:00E37D98↑o
                                        ; count of catchable type addresses following
                dd offset __CT??_R0?AVbad_alloc@std@@@8_40156F ; catchable type 'class std::bad_alloc'
                dd offset __CT??_R0?AVexception@std@@@8_4013C7 ; catchable type 'class std::exception'
__CTA3?AVbad_array_new_length@std@@ dd 3 ; DATA XREF: .rdata:00E37E34↓o
                                        ; count of catchable type addresses following
                dd offset __CT??_R0?AVbad_array_new_length@std@@@8_40154D ; catchable type 'class std::bad_array_new_length'
                dd offset __CT??_R0?AVbad_alloc@std@@@8_40156F ; catchable type 'class std::bad_alloc'
                dd offset __CT??_R0?AVexception@std@@@8_4013C7 ; catchable type 'class std::exception'
__CT??_R0?AVbad_alloc@std@@@8_40156F dd CT_IsStdBadAlloc
                                        ; DATA XREF: .rdata:00E37DA0↑o
                                        ; .rdata:00E37DB0↑o
                                        ; attributes
                dd offset ??_R0?AVbad_alloc@std@@@8 ; std::bad_alloc `RTTI Type Descriptor'
                dd 0                    ; mdisp
                dd 4294967295           ; pdisp
                dd 0                    ; vdisp
                dd 12                   ; size of thrown object
                dd offset sub_E3156F    ; reference to optional copy constructor
__CTA2?AVbad_cast@std@@ dd 2            ; DATA XREF: .rdata:00E37E08↓o
                                        ; count of catchable type addresses following
                dd offset __CT??_R0?AVbad_cast@std@@@8_4016B6 ; catchable type 'class std::bad_cast'
                dd offset __CT??_R0?AVexception@std@@@8_4013C7 ; catchable type 'class std::exception'
__CT??_R0?AVbad_cast@std@@@8_4016B6 dd 0 ; DATA XREF: .rdata:00E37DD8↑o
                                        ; attributes
                dd offset ??_R0?AVbad_cast@std@@@8 ; std::bad_cast `RTTI Type Descriptor'
                dd 0                    ; mdisp
                dd 4294967295           ; pdisp
                dd 0                    ; vdisp
                dd 12                   ; size of thrown object
                dd offset sub_E316B6    ; reference to optional copy constructor
; const _ThrowInfo _TI2_AVbad_cast_std__
__TI2?AVbad_cast@std@@ dd 0             ; DATA XREF: sub_E31698+E↑o
                                        ; attributes
                dd offset sub_E314C1    ; destructor of exception object
                dd 0                    ; forward compatibility frame handler
                dd offset __CTA2?AVbad_cast@std@@ ; address of catchable types array
__CT??_R0?AVexception@std@@@8_4013C7 dd 0 ; DATA XREF: .rdata:00E37DA4↑o
                                        ; .rdata:00E37DB4↑o ...
                                        ; attributes
                dd offset ??_R0?AVexception@std@@@8 ; std::exception `RTTI Type Descriptor'
                dd 0                    ; mdisp
                dd 4294967295           ; pdisp
                dd 0                    ; vdisp
                dd 12                   ; size of thrown object
                dd offset sub_E313C7    ; reference to optional copy constructor
; const _ThrowInfo _TI3_AVbad_array_new_length_std__
__TI3?AVbad_array_new_length@std@@ dd 0 ; DATA XREF: sub_E3152F+E↑o
                                        ; sub_E355CC+E↑o
                                        ; attributes
                dd offset sub_E3151E    ; destructor of exception object
                dd 0                    ; forward compatibility frame handler
                dd offset __CTA3?AVbad_array_new_length@std@@ ; address of catchable types array
__CT??_R0?AVbad_array_new_length@std@@@8_40154D dd 0
                                        ; DATA XREF: .rdata:00E37DAC↑o
                                        ; attributes
                dd offset ??_R0?AVbad_array_new_length@std@@@8 ; std::bad_array_new_length `RTTI Type Descriptor'
                dd 0                    ; mdisp
                dd 4294967295           ; pdisp
                dd 0                    ; vdisp
                dd 12                   ; size of thrown object
                dd offset sub_E3154D    ; reference to optional copy constructor
__IMPORT_DESCRIPTOR_MSVCP140 dd rva off_E37F3C ; Import Name Table
                dd 0                    ; Time stamp
                dd 0                    ; Forwarder Chain
                dd rva aMsvcp140Dll     ; DLL Name
                dd rva ?setstate@?$basic_ios@DU?$char_traits@D@std@@@std@@QAEXH_N@Z ; Import Address Table
__IMPORT_DESCRIPTOR_VCRUNTIME140 dd rva off_E37F9C ; Import Name Table
                dd 0                    ; Time stamp
                dd 0                    ; Forwarder Chain
                dd rva aVcruntime140Dl  ; DLL Name
                dd rva __imp_memmove    ; Import Address Table
                dd rva off_E38040       ; Import Name Table
                dd 0                    ; Time stamp
                dd 0                    ; Forwarder Chain
                dd rva aApiMsWinCrtStd  ; DLL Name
                dd rva __imp__set_fmode ; Import Address Table
                dd rva off_E37FEC       ; Import Name Table
                dd 0                    ; Time stamp
                dd 0                    ; Forwarder Chain
                dd rva aApiMsWinCrtRun  ; DLL Name
                dd rva __imp__c_exit    ; Import Address Table
                dd rva off_E37FC8       ; Import Name Table
                dd 0                    ; Time stamp
                dd 0                    ; Forwarder Chain
                dd rva aApiMsWinCrtHea  ; DLL Name
                dd rva __imp__set_new_mode ; Import Address Table
                dd rva off_E37FE4       ; Import Name Table
                dd 0                    ; Time stamp
                dd 0                    ; Forwarder Chain
                dd rva aApiMsWinCrtMat  ; DLL Name
                dd rva __imp___setusermatherr ; Import Address Table
                dd rva off_E37FDC       ; Import Name Table
                dd 0                    ; Time stamp
                dd 0                    ; Forwarder Chain
                dd rva aApiMsWinCrtLoc  ; DLL Name
                dd rva __imp__configthreadlocale ; Import Address Table
__IMPORT_DESCRIPTOR_KERNEL32 dd rva off_E37F08 ; Import Name Table
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
off_E37F08      dd rva word_E388D4      ; DATA XREF: .rdata:__IMPORT_DESCRIPTOR_KERNEL32↑o
                dd rva word_E387CC
                dd rva word_E387E8
                dd rva word_E387FC
                dd rva word_E388C0
                dd rva word_E388AA
                dd rva word_E38890
                dd rva word_E3887A
                dd rva word_E38818
                dd rva word_E38864
                dd rva word_E3884A
                dd rva word_E38836
                dd 0
;
; Import names for MSVCP140.dll
;
off_E37F3C      dd rva word_E3824C      ; DATA XREF: .rdata:__IMPORT_DESCRIPTOR_MSVCP140↑o
                dd rva word_E3828C
                dd rva word_E382F4
                dd rva word_E38334
                dd rva word_E3820C
                dd rva word_E38380
                dd rva word_E383A0
                dd rva word_E383DA
                dd rva word_E383FA
                dd rva word_E381CC
                dd rva word_E381B8
                dd rva word_E38058
                dd rva word_E381A2
                dd rva word_E38194
                dd rva word_E38174
                dd rva word_E38156
                dd rva word_E38132
                dd rva word_E38112
                dd rva word_E380D8
                dd rva word_E380A4
                dd rva word_E3808A
                dd rva word_E38070
                dd rva word_E3835E
                dd 0
;
; Import names for VCRUNTIME140.dll
;
off_E37F9C      dd rva word_E38900      ; DATA XREF: .rdata:__IMPORT_DESCRIPTOR_VCRUNTIME140↑o
                dd rva word_E384C0
                dd rva word_E384B6
                dd rva word_E38498
                dd rva word_E38482
                dd rva word_E3846C
                dd rva word_E38454
                dd rva word_E38424
                dd rva word_E388F6
                dd rva word_E3843A
                dd 0
;
; Import names for api-ms-win-crt-heap-l1-1-0.dll
;
off_E37FC8      dd rva word_E386E4      ; DATA XREF: .rdata:00E37EA4↑o
                dd rva word_E38548
                dd rva word_E38554
                dd rva word_E38710
                dd 0
;
; Import names for api-ms-win-crt-locale-l1-1-0.dll
;
off_E37FDC      dd rva word_E386CE      ; DATA XREF: .rdata:00E37ECC↑o
                dd 0
;
; Import names for api-ms-win-crt-math-l1-1-0.dll
;
off_E37FE4      dd rva word_E3860C      ; DATA XREF: .rdata:00E37EB8↑o
                dd 0
;
; Import names for api-ms-win-crt-runtime-l1-1-0.dll
;
off_E37FEC      dd rva word_E38696      ; DATA XREF: .rdata:00E37E90↑o
                dd rva word_E386A0
                dd rva word_E3867A
                dd rva word_E38522
                dd rva word_E38704
                dd rva word_E38664
                dd rva word_E38718
                dd rva word_E3855E
                dd rva word_E38578
                dd rva word_E3865C
                dd rva word_E38688
                dd rva word_E3864E
                dd rva word_E38642
                dd rva word_E38620
                dd rva word_E385FC
                dd rva word_E385EA
                dd rva word_E385E0
                dd rva word_E385D2
                dd rva word_E3859A
                dd rva word_E385B6
                dd 0
;
; Import names for api-ms-win-crt-stdio-l1-1-0.dll
;
off_E38040      dd rva word_E3866C      ; DATA XREF: .rdata:00E37E7C↑o
                dd rva word_E38518
                dd rva word_E384FE
                dd rva word_E384EC
                dd rva word_E386F4
                dd 0
word_E38058     dw 591h                 ; DATA XREF: .rdata:00E37F68↑o
                db '_Query_perf_frequency',0
word_E38070     dw 0A5h                 ; DATA XREF: .rdata:00E37F90↑o
                db '??1_Lockit@std@@QAE@XZ',0
                align 2
word_E3808A     dw 6Dh                  ; DATA XREF: .rdata:00E37F8C↑o
                db '??0_Lockit@std@@QAE@H@Z',0
word_E380A4     dw 1D5h                 ; DATA XREF: .rdata:00E37F88↑o
                db '?_Getgloballocale@locale@std@@CAPAV_Locimp@12@XZ',0
                align 4
word_E380D8     dw 2A3h                 ; DATA XREF: .rdata:00E37F84↑o
                db '?cin@std@@3V?$basic_istream@DU?$char_traits@D@std@@@1@A',0
word_E38112     dw 28Fh                 ; DATA XREF: .rdata:00E37F80↑o
                db '?_Xout_of_range@std@@YAXPBD@Z',0
word_E38132     dw 3CFh                 ; DATA XREF: .rdata:00E37F7C↑o
                db '?id@?$ctype@D@std@@2V0locale@2@A',0
                align 2
word_E38156     dw 25Dh                 ; DATA XREF: .rdata:00E37F78↑o
                db '?_Random_device@std@@YAIXZ',0
                align 4
word_E38174     dw 28Eh                 ; DATA XREF: .rdata:00E37F74↑o
                db '?_Xlength_error@std@@YAXPBD@Z',0
word_E38194     dw 5B6h                 ; DATA XREF: .rdata:00E37F70↑o
                db '_Thrd_sleep',0
word_E381A2     dw 590h                 ; DATA XREF: .rdata:00E37F6C↑o
                db '_Query_perf_counter',0
word_E381B8     dw 5CCh                 ; DATA XREF: .rdata:00E37F64↑o
                db '_Xtime_get_ticks',0
                align 4
word_E381CC     dw 219h                 ; DATA XREF: .rdata:00E37F60↑o
                db '?_Ipfx@?$basic_istream@DU?$char_traits@D@std@@@std@@QAE_N_N@Z',0
word_E3820C     dw 4D8h                 ; DATA XREF: .rdata:00E37F4C↑o
                db '?snextc@?$basic_streambuf@DU?$char_traits@D@std@@@std@@QAEHXZ',0
word_E3824C     dw 4C5h                 ; DATA XREF: .rdata:off_E37F3C↑o
                db '?setstate@?$basic_ios@DU?$char_traits@D@std@@@std@@QAEXH_N@Z',0
                align 4
word_E3828C     dw 487h                 ; DATA XREF: .rdata:00E37F40↑o
                db '?rdbuf@?$basic_ios@DU?$char_traits@D@std@@@std@@QBEPAV?$basic_str'
                db 'eambuf@DU?$char_traits@D@std@@@2@XZ',0
                align 4
word_E382F4     dw 4CFh                 ; DATA XREF: .rdata:00E37F44↑o
                db '?sgetc@?$basic_streambuf@DU?$char_traits@D@std@@@std@@QAEHXZ',0
                align 4
word_E38334     dw 3C3h                 ; DATA XREF: .rdata:00E37F48↑o
                db '?getloc@ios_base@std@@QBE?AVlocale@2@XZ',0
word_E3835E     dw 53Dh                 ; DATA XREF: .rdata:00E37F94↑o
                db '?width@ios_base@std@@QAE_J_J@Z',0
                align 10h
word_E38380     dw 53Eh                 ; DATA XREF: .rdata:00E37F50↑o
                db '?width@ios_base@std@@QBE_JXZ',0
                align 10h
word_E383A0     dw 1B6h                 ; DATA XREF: .rdata:00E37F54↑o
                db '?_Getcat@?$ctype@D@std@@SAIPAPBVfacet@locale@2@PBV42@@Z',0
word_E383DA     dw 40Fh                 ; DATA XREF: .rdata:00E37F58↑o
                db '?is@?$ctype@D@std@@QBE_NFD@Z',0
                align 2
word_E383FA     dw 131h                 ; DATA XREF: .rdata:00E37F5C↑o
                db '??Bid@locale@std@@QAEIXZ',0
                align 2
aMsvcp140Dll    db 'MSVCP140.dll',0     ; DATA XREF: .rdata:00E37E60↑o
                align 4
word_E38424     dw 10h                  ; DATA XREF: .rdata:00E37FB8↑o
                db '__CxxFrameHandler3',0
                align 2
word_E3843A     dw 22h                  ; DATA XREF: .rdata:00E37FC0↑o
                db '__std_exception_destroy',0
word_E38454     dw 21h                  ; DATA XREF: .rdata:00E37FB4↑o
                db '__std_exception_copy',0
                align 4
word_E3846C     dw 1                    ; DATA XREF: .rdata:00E37FB0↑o
                db '_CxxThrowException',0
                align 2
word_E38482     dw 1Ch                  ; DATA XREF: .rdata:00E37FAC↑o
                db '__current_exception',0
word_E38498     dw 1Dh                  ; DATA XREF: .rdata:00E37FA8↑o
                db '__current_exception_context',0
word_E384B6     dw 48h                  ; DATA XREF: .rdata:00E37FA4↑o
                db 'memset',0
                align 10h
word_E384C0     dw 35h                  ; DATA XREF: .rdata:00E37FA0↑o
                db '_except_handler4_common',0
aVcruntime140Dl db 'VCRUNTIME140.dll',0 ; DATA XREF: .rdata:00E37E74↑o
                align 4
word_E384EC     dw 0                    ; DATA XREF: .rdata:00E3804C↑o
                db '__acrt_iob_func',0
word_E384FE     dw 3                    ; DATA XREF: .rdata:00E38048↑o
                db '__stdio_common_vfprintf',0
word_E38518     dw 8Ch                  ; DATA XREF: .rdata:00E38044↑o
                db 'getchar',0
word_E38522     dw 3Bh                  ; DATA XREF: .rdata:00E37FF8↑o
                db '_invalid_parameter_noinfo_noreturn',0
                align 4
word_E38548     dw 8                    ; DATA XREF: .rdata:00E37FCC↑o
                db '_callnewh',0
word_E38554     dw 19h                  ; DATA XREF: .rdata:00E37FD0↑o
                db 'malloc',0
                align 2
word_E3855E     dw 19h                  ; DATA XREF: .rdata:00E38008↑o
                db '_configure_narrow_argv',0
                align 4
word_E38578     dw 35h                  ; DATA XREF: .rdata:00E3800C↑o
                db '_initialize_narrow_environment',0
                align 2
word_E3859A     dw 36h                  ; DATA XREF: .rdata:00E38034↑o
                db '_initialize_onexit_table',0
                align 2
word_E385B6     dw 3Eh                  ; DATA XREF: .rdata:00E38038↑o
                db '_register_onexit_function',0
word_E385D2     dw 1Fh                  ; DATA XREF: .rdata:00E38030↑o
                db '_crt_atexit',0
word_E385E0     dw 17h                  ; DATA XREF: .rdata:00E3802C↑o
                db '_cexit',0
                align 2
word_E385EA     dw 42h                  ; DATA XREF: .rdata:00E38028↑o
                db '_seh_filter_exe',0
word_E385FC     dw 44h                  ; DATA XREF: .rdata:00E38024↑o
                db '_set_app_type',0
word_E3860C     dw 2Eh                  ; DATA XREF: .rdata:off_E37FE4↑o
                db '__setusermatherr',0
                align 10h
word_E38620     dw 2Ah                  ; DATA XREF: .rdata:00E38020↑o
                db '_get_initial_narrow_environment',0
word_E38642     dw 38h                  ; DATA XREF: .rdata:00E3801C↑o
                db '_initterm',0
word_E3864E     dw 39h                  ; DATA XREF: .rdata:00E38018↑o
                db '_initterm_e',0
word_E3865C     dw 58h                  ; DATA XREF: .rdata:00E38010↑o
                db 'exit',0
                align 4
word_E38664     dw 25h                  ; DATA XREF: .rdata:00E38000↑o
                db '_exit',0
word_E3866C     dw 54h                  ; DATA XREF: .rdata:off_E38040↑o
                db '_set_fmode',0
                align 2
word_E3867A     dw 5                    ; DATA XREF: .rdata:00E37FF4↑o
                db '__p___argc',0
                align 4
word_E38688     dw 6                    ; DATA XREF: .rdata:00E38014↑o
                db '__p___argv',0
                align 2
word_E38696     dw 16h                  ; DATA XREF: .rdata:off_E37FEC↑o
                db '_c_exit',0
word_E386A0     dw 3Fh                  ; DATA XREF: .rdata:00E37FF0↑o
                db '_register_thread_local_exe_atexit_callback',0
                align 2
word_E386CE     dw 8                    ; DATA XREF: .rdata:off_E37FDC↑o
                db '_configthreadlocale',0
word_E386E4     dw 16h                  ; DATA XREF: .rdata:off_E37FC8↑o
                db '_set_new_mode',0
word_E386F4     dw 1                    ; DATA XREF: .rdata:00E38050↑o
                db '__p__commode',0
                align 4
word_E38704     dw 6Ah                  ; DATA XREF: .rdata:00E37FFC↑o
                db 'terminate',0
word_E38710     dw 18h                  ; DATA XREF: .rdata:00E37FD4↑o
                db 'free',0
                align 4
word_E38718     dw 1Dh                  ; DATA XREF: .rdata:00E38004↑o
                db '_controlfp_s',0
                align 4
aApiMsWinCrtStd db 'api-ms-win-crt-stdio-l1-1-0.dll',0
                                        ; DATA XREF: .rdata:00E37E88↑o
aApiMsWinCrtRun db 'api-ms-win-crt-runtime-l1-1-0.dll',0
                                        ; DATA XREF: .rdata:00E37E9C↑o
aApiMsWinCrtHea db 'api-ms-win-crt-heap-l1-1-0.dll',0
                                        ; DATA XREF: .rdata:00E37EB0↑o
                align 2
aApiMsWinCrtMat db 'api-ms-win-crt-math-l1-1-0.dll',0
                                        ; DATA XREF: .rdata:00E37EC4↑o
                align 2
aApiMsWinCrtLoc db 'api-ms-win-crt-locale-l1-1-0.dll',0
                                        ; DATA XREF: .rdata:00E37ED8↑o
                align 4
word_E387CC     dw 389h                 ; DATA XREF: .rdata:00E37F0C↑o
                db 'IsProcessorFeaturePresent',0
word_E387E8     dw 382h                 ; DATA XREF: .rdata:00E37F10↑o
                db 'IsDebuggerPresent',0
word_E387FC     dw 5B1h                 ; DATA XREF: .rdata:00E37F14↑o
                db 'UnhandledExceptionFilter',0
                align 4
word_E38818     dw 571h                 ; DATA XREF: .rdata:00E37F28↑o
                db 'SetUnhandledExceptionFilter',0
word_E38836     dw 27Bh                 ; DATA XREF: .rdata:00E37F34↑o
                db 'GetModuleHandleW',0
                align 2
word_E3884A     dw 44Fh                 ; DATA XREF: .rdata:00E37F30↑o
                db 'QueryPerformanceCounter',0
word_E38864     dw 21Bh                 ; DATA XREF: .rdata:00E37F2C↑o
                db 'GetCurrentProcessId',0
word_E3887A     dw 21Fh                 ; DATA XREF: .rdata:00E37F24↑o
                db 'GetCurrentThreadId',0
                align 10h
word_E38890     dw 2ECh                 ; DATA XREF: .rdata:00E37F20↑o
                db 'GetSystemTimeAsFileTime',0
word_E388AA     dw 366h                 ; DATA XREF: .rdata:00E37F1C↑o
                db 'InitializeSListHead',0
word_E388C0     dw 21Ah                 ; DATA XREF: .rdata:00E37F18↑o
                db 'GetCurrentProcess',0
word_E388D4     dw 590h                 ; DATA XREF: .rdata:off_E37F08↑o
                db 'TerminateProcess',0
                align 4
aKernel32Dll    db 'KERNEL32.dll',0     ; DATA XREF: .rdata:00E37EEC↑o
                align 2
word_E388F6     dw 46h                  ; DATA XREF: .rdata:00E37FBC↑o
                db 'memcpy',0
                align 10h
word_E38900     dw 47h                  ; DATA XREF: .rdata:off_E37F9C↑o
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
                ;org 0E39000h
                db 0FFh
                db 0FFh
                db 0FFh
                db 0FFh
dword_E39004    dd 1                    ; DATA XREF: ___isa_available_init+D↑w
                                        ; ___isa_available_init:loc_E356FC↑r ...
                align 10h
dword_E39010    dd 1                    ; DATA XREF: sub_E35B1D+2↑r
dword_E39014    dd 44BF19B1h            ; DATA XREF: ___security_init_cookie+43↑w
                                        ; ___report_gsfailure+E3↑r
; uintptr_t __security_cookie
___security_cookie dd 0BB40E64Eh        ; DATA XREF: __SEH_prolog4+1C↑r
                                        ; __except_handler4+1F↑o ...
dword_E3901C    dd 1                    ; DATA XREF: ___scrt_is_ucrt_dll_in_use+2↑r
                db  75h ; u
                db  98h
                db    0
                db    0
; public class type_info /* mdisp:0 */
; public class type_info /* mdisp:0 */
; class type_info `RTTI Type Descriptor'
??_R0?AVtype_info@@@8 dd offset ??_7type_info@@6B@
                                        ; DATA XREF: .rdata:00E3758C↑o
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
                                        ; .rdata:00E3768C↑o ...
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
                                        ; .rdata:00E376A0↑o ...
                                        ; reference to RTTI's vftable
                dd 0                    ; internal runtime reference
aAvbadCastStd   db '.?AVbad_cast@std@@',0 ; type descriptor name
                align 4
; public class std::exception /* mdisp:0 */
; public class std::exception /* mdisp:0 */
; class std::exception `RTTI Type Descriptor'
??_R0?AVexception@std@@@8 dd offset ??_7type_info@@6B@
                                        ; DATA XREF: .rdata:00E375D4↑o
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
                                        ; DATA XREF: .rdata:00E376D4↑o
                                        ; .rdata:std::bad_array_new_length::`RTTI Base Class Descriptor at (0,-1,0,64)'↑o ...
                                        ; reference to RTTI's vftable
                dd 0                    ; internal runtime reference
aAvbadArrayNewL db '.?AVbad_array_new_length@std@@',0 ; type descriptor name
                align 4
; std::_Fac_node *Block
Block           dd 0                    ; DATA XREF: std::_Fac_tidy_reg_t::~_Fac_tidy_reg_t(void)+7↑w
                                        ; std::_Fac_tidy_reg_t::~_Fac_tidy_reg_t(void):loc_E35059↑r ...
; std::_Fac_tidy_reg_t unk_E390BC
unk_E390BC      db    0                 ; DATA XREF: sub_E36699↑o
                db    0
                db    0
                db    0
dword_E390C0    dd 0                    ; DATA XREF: __scrt_common_main_seh(void)+2D↑r
                                        ; __scrt_common_main_seh(void)+41↑w ...
unk_E390C4      db    0                 ; DATA XREF: ___scrt_acquire_startup_lock+10↑o
                                        ; ___scrt_release_startup_lock+14↑o
                db    0
                db    0
                db    0
byte_E390C8     db 0                    ; DATA XREF: ___scrt_initialize_crt+9↑w
                                        ; ___scrt_uninitialize_crt+3↑r
byte_E390C9     db 0                    ; DATA XREF: ___scrt_initialize_onexit_tables+3↑r
                                        ; ___scrt_initialize_onexit_tables:loc_E351E3↑w
                align 4
; _onexit_table_t Table
Table           _onexit_table_t <0>     ; DATA XREF: ___scrt_initialize_onexit_tables+2A↑o
                                        ; ___scrt_initialize_onexit_tables+4F↑w ...
; _onexit_table_t stru_E390D8
stru_E390D8     _onexit_table_t <0>     ; DATA XREF: ___scrt_initialize_onexit_tables+39↑o
                                        ; ___scrt_initialize_onexit_tables+61↑w ...
___castguard_check_failure_os_handled_fptr db    0
                                        ; DATA XREF: .rdata:00E37540↑o
                db    0
                db    0
                db    0
dword_E390E8    dd 0                    ; DATA XREF: ___isa_available_init+3↑w
                                        ; ___isa_available_init+11B↑w ...
dword_E390EC    dd 0                    ; DATA XREF: ___isa_available_init:loc_E356A5↑r
                                        ; ___isa_available_init+C5↑w ...
dword_E390F0    dd 0                    ; DATA XREF: sub_E35990↑w
                align 8
; union _SLIST_HEADER ListHead
ListHead        _SLIST_HEADER <0>       ; DATA XREF: sub_E35ACA↑o
unk_E39100      db    0                 ; DATA XREF: sub_E35AFA↑o
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
dword_E39108    dd 0                    ; DATA XREF: ___report_gsfailure+9F↑w
                                        ; .rdata:ExceptionInfo↑o
dword_E3910C    dd 0                    ; DATA XREF: ___report_gsfailure+A9↑w
                db    0
                db    0
                db    0
                db    0
dword_E39114    dd 0                    ; DATA XREF: ___report_gsfailure+9A↑w
dword_E39118    dd 0                    ; DATA XREF: ___report_gsfailure+B3↑w
dword_E3911C    dd 0                    ; DATA XREF: ___report_gsfailure+C3↑w
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
dword_E39158    dd 0                    ; DATA XREF: ___report_gsfailure+8B↑w
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
word_E391E4     dw 0                    ; DATA XREF: ___report_gsfailure+5F↑w
                align 4
word_E391E8     dw 0                    ; DATA XREF: ___report_gsfailure+58↑w
                align 4
word_E391EC     dw 0                    ; DATA XREF: ___report_gsfailure+51↑w
                align 10h
word_E391F0     dw 0                    ; DATA XREF: ___report_gsfailure+4A↑w
                align 4
dword_E391F4    dd 0                    ; DATA XREF: ___report_gsfailure+36↑w
dword_E391F8    dd 0                    ; DATA XREF: ___report_gsfailure+30↑w
dword_E391FC    dd 0                    ; DATA XREF: ___report_gsfailure+2A↑w
dword_E39200    dd ?                    ; DATA XREF: ___report_gsfailure+24↑w
dword_E39204    dd ?                    ; DATA XREF: ___report_gsfailure+1E↑w
dword_E39208    dd ?                    ; DATA XREF: ___report_gsfailure:loc_E35BDF↑w
dword_E3920C    dd ?                    ; DATA XREF: ___report_gsfailure+70↑w
dword_E39210    dd ?                    ; DATA XREF: ___report_gsfailure+78↑w
                                        ; ___report_gsfailure+95↑r
word_E39214     dw ?                    ; DATA XREF: ___report_gsfailure+43↑w
                align 4
dword_E39218    dd ?                    ; DATA XREF: ___report_gsfailure+67↑w
dword_E3921C    dd ?                    ; DATA XREF: ___report_gsfailure+80↑w
word_E39220     dw ?                    ; DATA XREF: ___report_gsfailure+3C↑w
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
unk_E39428      db    ? ;               ; DATA XREF: sub_E3132F+3↑o
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
dword_E39430    dd ?                    ; DATA XREF: sub_E32823+2A↑r
                                        ; sub_E32823+AA↑w
; int dword_E39434[3]
dword_E39434    dd 3 dup(?)             ; DATA XREF: sub_E3122E+30↑o
                                        ; eEncode+30↑o ...
; int dword_E39440[3]
dword_E39440    dd 3 dup(?)             ; DATA XREF: sub_E31117+30↑o
                                        ; sub_E3663F+3↑o
; int dword_E3944C[3]
dword_E3944C    dd 3 dup(?)             ; DATA XREF: sub_E31000+30↑o
                                        ; sub_E36612+3↑o
; int dword_E39458[3]
dword_E39458    dd 3 dup(?)             ; DATA XREF: sub_E3105D+30↑o
                                        ; sub_E36621+3↑o
; int dword_E39464[3]
dword_E39464    dd 3 dup(?)             ; DATA XREF: sub_E31174+30↑o
                                        ; sub_E3664E+3↑o
; unsigned int dword_E39470[6]
dword_E39470    dd 6 dup(?)             ; DATA XREF: sub_E312E8+8↑o
                                        ; sub_E3668A+3↑o
; int dword_E39488[3]
dword_E39488    dd 3 dup(?)             ; DATA XREF: sub_E3128B+30↑o
                                        ; sub_E3667B+3↑o
; int dword_E39494[3]
dword_E39494    dd 3 dup(?)             ; DATA XREF: sub_E311D1+30↑o
                                        ; sub_E3665D+3↑o
; int dword_E394A0[3]
dword_E394A0    dd 3 dup(?)             ; DATA XREF: sub_E310BA+30↑o
                                        ; sub_E36630+3↑o
unk_E394AC      db    ? ;               ; DATA XREF: sub_E35B2F↑o
                db    ? ;
                db    ? ;
                db    ? ;
unk_E394B0      db    ? ;               ; DATA XREF: sub_E35B29↑o
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
                db    ? ;
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
