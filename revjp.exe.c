#include <windows.h>
#include <defs.h>

#include <stdarg.h>


//-------------------------------------------------------------------------
// Function declarations

#define __thiscall __cdecl // Test compile in C mode

int sub_791000();
int sub_79105D();
int sub_7910BA();
int sub_791117();
int sub_791174();
int sub_7911D1();
int sub_79122E();
int sub_79128B();
int sub_7912E8();
int sub_791307();
// void *__cdecl operator new(unsigned int, void *); idb
char sub_791328();
void *sub_79132F();
int __cdecl sub_791339(FILE *Stream, char *Format, _locale_t Locale, va_list ArgList); // idb
int printf(char *a1, ...);
_DWORD *__thiscall sub_79139A(_DWORD *this, int a2, int a3);
_DWORD *__thiscall sub_7913C7(_DWORD *this, int a2);
int __thiscall sub_791401(_DWORD *this);
const char *__thiscall sub_791421(_DWORD *this);
_DWORD *__thiscall sub_791449(_DWORD *this, char a2);
_DWORD *__thiscall sub_791473(_DWORD *this, int a2);
_DWORD *__thiscall sub_791497(_DWORD *this, char a2);
int __thiscall sub_7914C1(_DWORD *this);
_DWORD *__thiscall sub_7914D2(_DWORD *this);
_DWORD *__thiscall sub_7914F4(_DWORD *this, char a2);
int __thiscall sub_79151E(_DWORD *this);
void __cdecl __noreturn sub_79152F();
_DWORD *__thiscall sub_79154D(_DWORD *this, int a2);
_DWORD *__thiscall sub_79156F(_DWORD *this, int a2);
// int std::numeric_limits<int>::min(void); weak
// int unknown_libname_1(void); weak
// int __scrt_stub_for_initialize_mta();
// int unknown_libname_2(void); weak
__int64 sub_7915B6();
__int64 sub_7915BF();
// void *__cdecl operator new(size_t Size);
_DWORD *__cdecl sub_7915D8(_DWORD *a1, _DWORD *a2);
// int __cdecl unknown_libname_3(int a1);
void sub_791642();
void __stdcall sub_79164B(int a1);
void *__thiscall sub_791656(void *this, int a2, int a3);
void __noreturn sub_791664();
_DWORD *__thiscall sub_791674(_DWORD *this);
void __noreturn sub_791698();
_DWORD *__thiscall sub_7916B6(_DWORD *this, int a2);
int (__thiscall ***__thiscall sub_7916D8(_DWORD **this))(_DWORD, int);
int __thiscall sub_791721(_DWORD *this, unsigned int a2);
_DWORD *__cdecl sub_791797(_DWORD *a1);
_DWORD *__cdecl sub_7917C3(_DWORD *a1);
_DWORD *__thiscall sub_791864(_DWORD *this, _DWORD *a2);
__int64 __thiscall sub_791882(void *this);
double __thiscall sub_791893(void *this);
void *__thiscall sub_7918A1(void *this);
unsigned int sub_7918AD();
// int *__userpurge sub_7918BC@<eax>(int *a1@<ecx>, int a2@<ebp>, _DWORD *a3);
int __thiscall sub_791984(_DWORD *this, int a2);
int *__thiscall BProcessor(int *this, int *a2);
int *__thiscall sub_7919DE(int *this);
int *__cdecl sub_7919EF(int *a1);
char __cdecl Process_Input3(int *a1);
int __cdecl main(int argc, const char **argv, const char **envp);
__int64 __thiscall sub_791CA5(_QWORD *this);
_QWORD *__thiscall sub_791CC5(_QWORD *this);
int *__thiscall sub_791CF9(int *this);
int __thiscall sub_791D23(unsigned __int16 *this);
bool __thiscall Process_Input2(unsigned __int16 *this, unsigned __int16 *a2);
unsigned __int16 *__thiscall sub_791D73(unsigned __int16 *this);
__int16 *__thiscall sub_791D9F(__int16 *this, __int16 a2);
int __thiscall sub_791DCB(_DWORD *this);
int *__thiscall sub_791DDF(int *this, int a2);
int __thiscall sub_791E05(_DWORD *this, int a2);
int __thiscall AProcessor(_DWORD *this);
void __thiscall sub_791E40(int *this, unsigned int a2);
int *__thiscall sub_791E5B(int *this);
int *__thiscall sub_791E6C(int *this, int *a2);
_DWORD *__thiscall sub_791F52(_DWORD *this);
_DWORD *__thiscall sub_791F83(_DWORD *this, _DWORD *a2);
_DWORD *__thiscall sub_791FA1(_DWORD *this, _DWORD *a2);
int __thiscall sub_791FBF(_DWORD *this);
unsigned int *__thiscall sub_791FCE(size_t *this, char a2);
_BYTE *__stdcall sub_792042(_BYTE *a1, _BYTE *Src, size_t Size, char a4);
char *__thiscall sub_79208B(_DWORD *this, int a2);
void __thiscall Process_Input(void **this);
unsigned int *__thiscall sub_7920BA(unsigned int *this, char *Src);
void sub_792131();
void sub_792142();
int *__thiscall sub_792153(int **this);
int *__thiscall sub_79216E(_QWORD *this, int *a2, _QWORD *a3);
int *__thiscall sub_7921A2(int *this, int a2, int a3);
__int16 *__thiscall sub_7921D4(unsigned __int16 *this, __int16 *a2, unsigned __int16 *a3);
void *__thiscall sub_792205(void *this);
int *__thiscall sub_792216(int *this);
int __thiscall sub_7922C8(int *this, unsigned int a2);
_BYTE *__thiscall sub_79232A(void **this);
_BYTE *__thiscall sub_7923C9(int this);
unsigned int *__thiscall sub_7923FD(unsigned int *this, char *Src);
unsigned int *__thiscall sub_792424(unsigned int *this, char *Src, size_t Size);
_BYTE *__stdcall sub_79248D(_BYTE *a1, size_t Size, _BYTE *Src);
int *__thiscall sub_7924C0(int *this);
// int __cdecl std::numeric_limits<unsigned int>::max(_DWORD); weak
bool __cdecl sub_7924F8(_DWORD *a1, _DWORD *a2);
// _DWORD __cdecl std::_Narrow_char_traits<char,int>::to_char_type(_DWORD); weak
_BYTE *__cdecl sub_792524(_BYTE *a1, _BYTE *a2);
unsigned int __cdecl sub_792533(const char *a1);
_BYTE *__cdecl sub_792565(_BYTE *a1, _BYTE *Src, size_t Size);
void __thiscall sub_7925B7(void *this, int a2, int a3);
int __stdcall sub_7925D9(unsigned int a1);
_DWORD *__cdecl sub_7925F4(_DWORD *a1, _DWORD *a2);
void __stdcall sub_79261E(void *Block, int a2);
_BYTE *__thiscall sub_79263A(int *this, int a2);
int __thiscall sub_792677(void *this);
bool __thiscall sub_7926CF(_DWORD *this);
char *__cdecl sub_7926F2(char *a1, char *Src, size_t Size);
void *__stdcall sub_7927C5(int a1);
void __stdcall sub_7927E0(void *Block, int a2);
void __thiscall sub_7927F8(_DWORD *this, unsigned int a2);
void sub_792813();
struct std::_Facet_base *__cdecl sub_792823(_DWORD *a1);
int __cdecl sub_79290E(int a1, _DWORD *a2);
_QWORD *__thiscall sub_792927(_QWORD *this, int *a2);
BOOL __cdecl sub_792943(void *a1);
int sub_79296C();
__int16 sub_79299E();
int sub_7929C4();
void __thiscall sub_7929E8(int *this, unsigned int a2, unsigned __int8 *a3);
_DWORD *__thiscall sub_792ABF(_DWORD *this, int a2, int a3);
int __thiscall sub_792ADE(void *this, int a2, int a3, int a4);
_DWORD *__thiscall sub_792B03(_DWORD *this, int a2);
_DWORD *__cdecl sub_792B21(_DWORD *a1, _DWORD *a2);
unsigned int *__thiscall sub_792B4B(size_t *this, size_t a2, char a3, char a4);
_DWORD *__thiscall sub_792C45(_DWORD *this, int a2);
void sub_792C63();
unsigned int *__thiscall sub_792C68(unsigned int *this, size_t Size, char a3, _BYTE *Src);
int __cdecl sub_792D1E(int a1, int a2);
unsigned int __cdecl sub_792D4A(unsigned int a1);
void *__cdecl sub_792D70(unsigned int Size);
void __cdecl sub_792D9C(void *Block, unsigned int a2);
int __cdecl sub_792DEA(int a1);
int __thiscall sub_792DF7(int *this);
int (__thiscall ***__thiscall sub_792E13(int (__thiscall ****this)(_DWORD, int)))(_DWORD, int);
_DWORD *__thiscall sub_792E44(_DWORD *this);
void __stdcall sub_792E64(int a1, int a2);
int __thiscall sub_792E6F(void *this, int a2, int a3, int a4);
unsigned int __thiscall sub_792E91(unsigned int *this, int a2);
_DWORD *__thiscall sub_792EC3(_DWORD *this);
int (__thiscall ***__stdcall sub_792EE5(int (__thiscall ***a1)(_DWORD, int)))(_DWORD, int);
unsigned int __cdecl sub_792F19(int a1, unsigned int a2, unsigned int a3);
int __cdecl sub_792F66(int a1, _DWORD *a2);
_DWORD *__thiscall sub_7931DB(_DWORD *this, char a2);
_DWORD *__cdecl sub_793200(_DWORD *a1, _DWORD *a2, void *a3);
BOOL __cdecl sub_793230(_DWORD *a1);
int __cdecl sub_793285(int a1, int a2, int a3, int a4);
__int16 __cdecl sub_7932D3(__int16 a1, __int16 a2);
int __cdecl sub_79331B(int a1, int a2);
int __thiscall sub_793363(int *this, unsigned int a2, unsigned __int8 *a3);
int __cdecl sub_79349C(int a1, int a2, int a3, int a4);
// _DWORD __cdecl unknown_libname_4(_DWORD); weak
unsigned int __cdecl sub_793533(unsigned int a1);
int __cdecl sub_793591(int *a1, int *a2);
int __cdecl sub_7935AC(int a1, int a2, int a3);
int __thiscall sub_793618(_DWORD *this);
int __thiscall sub_793629(_DWORD *this);
void sub_793643();
_DWORD *__thiscall sub_793665(_DWORD *this, int a2, int a3);
_DWORD *__thiscall sub_79368D(_DWORD *this, int a2, int a3);
_WORD *__thiscall sub_7936A9(_WORD *this, __int16 a2, __int16 a3);
_DWORD *__thiscall sub_7936C5(_DWORD *this, int a2, int a3, int a4, int a5);
char __thiscall sub_7936E7(_BYTE *this);
_DWORD *__thiscall sub_7936F6(_DWORD *this, int a2, int a3);
int __thiscall sub_793751(_DWORD *this);
void __noreturn sub_7937AD();
int __thiscall sub_7937BD(void **this, void *a2, int a3, int a4);
unsigned int __thiscall sub_79385F(_DWORD *this, unsigned int a2);
int __thiscall sub_7938B1(void *this, int a2, int a3, int a4);
int __thiscall sub_7938D6(void *this);
_DWORD *__thiscall sub_79390C(_DWORD *this, unsigned int a2);
int *__thiscall sub_79392C(int *this, unsigned int a2);
_DWORD *__thiscall sub_793957(_DWORD *this, int a2, int a3);
_WORD *__thiscall sub_79397A(_WORD *this, __int16 a2, __int16 a3);
_DWORD *__thiscall sub_79399D(_DWORD *this, int a2, int a3, int a4, int a5);
int __thiscall sub_7939C6(_DWORD *this, int a2);
int __thiscall sub_793A0B(void *this, int a2, int a3, int a4, int a5);
int __thiscall sub_793A30(_DWORD *this);
int sub_793A4E();
_DWORD *__thiscall sub_793A58(_DWORD *this, unsigned int a2, int a3, int a4);
_DWORD *__thiscall sub_793A80(_DWORD *this, int a2, int a3);
_WORD *__thiscall sub_793A9C(_WORD *this, __int16 a2, __int16 a3);
_DWORD *__thiscall sub_793AB8(_DWORD *this, int a2, int a3, int a4, int a5);
_DWORD *__thiscall sub_793ADA(_DWORD *this, unsigned int a2, int a3);
_DWORD *__thiscall sub_793B49(_DWORD *this, int a2, int a3);
_WORD *__thiscall sub_793B65(_WORD *this, __int16 a2, __int16 a3);
_DWORD *__thiscall sub_793B85(_DWORD *this, int a2, int a3, int a4, int a5);
_DWORD *__thiscall sub_793BAD(_DWORD *this, int a2, int a3);
_DWORD *__cdecl sub_793BCB(_DWORD *a1, int *a2, void *a3);
bool __cdecl sub_793C1C(_DWORD *a1, _DWORD *a2);
_DWORD *__cdecl sub_793C46(_DWORD *a1, _DWORD *a2, _DWORD *a3);
bool __cdecl sub_793C80(int a1, void *a2);
int __thiscall sub_793D4C(int *this, int a2);
__int16 __thiscall sub_793D73(__int16 *this, int a2);
int __thiscall sub_793D98(int *this, int a2);
int __thiscall sub_793DB9(_DWORD *this, int a2);
int __thiscall sub_793E0A(_DWORD *this);
_QWORD *__thiscall sub_793E49(_QWORD *this, _QWORD *a2);
_QWORD *__thiscall sub_793E6F(_QWORD *this, _QWORD *a2);
_DWORD *__cdecl sub_793E95(_DWORD *a1, void *a2);
__int64 *__thiscall sub_793F52(__int64 *this, void *a2);
__int64 *__thiscall sub_793F7F(__int64 *this, void *a2);
bool __cdecl sub_793FAC(_DWORD *a1, _DWORD *a2);
_DWORD *__cdecl sub_793FDF(_DWORD *a1, int *a2, int *a3);
__int64 *__thiscall sub_794034(__int64 *this, void *a2);
bool __cdecl sub_794061(void *a1, void *a2);
_DWORD *__cdecl sub_7940BD(_DWORD *a1, void *a2);
int __thiscall sub_79415C(void *this, int a2, int a3, int a4, int a5, int a6);
__int16 __thiscall sub_7941FE(void *this, int a2, __int16 a3, __int16 a4);
int __thiscall sub_794278(void *this, int a2, int a3, int a4);
_DWORD *__cdecl sub_7942E0(int a1, void *a2, int a3);
int *__cdecl sub_79430D(int a1, void *a2);
unsigned int __thiscall sub_79432A(_DWORD *this);
unsigned int __thiscall sub_79437B(_DWORD *this, unsigned int a2);
_DWORD *__thiscall sub_79441A(_DWORD *this, int a2);
__int16 __thiscall sub_794478(_DWORD *this, unsigned __int16 a2);
__int64 __thiscall sub_794528(int this);
unsigned __int64 __thiscall sub_79459A(int this, unsigned __int64 a2);
_DWORD *__thiscall sub_794700(_DWORD *this, int a2);
int __cdecl sub_79478F(int a1);
__int16 __cdecl sub_7947A8(__int16 a1);
int __cdecl sub_7947C1(int a1, int a2);
_DWORD *__thiscall sub_7947DE(_DWORD *this, _DWORD *a2);
int *__thiscall sub_794802(int *this);
unsigned int __thiscall sub_794823(_DWORD *this);
__int64 __thiscall sub_794857(_QWORD *this);
int __cdecl sub_7948A7(int a1);
__int16 __cdecl sub_7948D1(__int16 a1);
// _DWORD __cdecl operator"" _l(_DWORD, _DWORD); weak
unsigned int __thiscall sub_7948E5(_DWORD *this);
unsigned int __thiscall sub_79497E(_DWORD *this);
_BYTE *__thiscall sub_794A02(_BYTE *this);
_DWORD *__cdecl sub_794B5C(_DWORD *a1, void *a2);
_DWORD *__cdecl sub_794C18(_DWORD *a1, void *a2);
bool __cdecl sub_794CD4(int *a1, int *a2);
_DWORD *__cdecl sub_794D3E(_DWORD *a1, void *a2);
double *__thiscall sub_794DF1(double *this, void *a2);
double *__thiscall sub_794E1B(double *this, void *a2);
_QWORD *__cdecl sub_794E45(_QWORD *a1, void *a2);
_QWORD *__cdecl sub_794F17(_QWORD *a1, void *a2);
_QWORD *__thiscall sub_794FF1(_QWORD *this, _QWORD *a2);
// void __thiscall std::_Fac_tidy_reg_t::~_Fac_tidy_reg_t(std::_Fac_tidy_reg_t *__hidden this); idb
// void __cdecl std::_Facet_Register(struct std::_Facet_base *); idb
// void *__cdecl operator new(size_t Size); idb
// _DWORD __cdecl __scrt_initialize_onexit_tables(_DWORD); weak
// int __cdecl atexit(void (__cdecl *)());
void __cdecl sub_795312(void *Block);
_DWORD *__thiscall sub_795320(_DWORD *Block, char a2);
// int __cdecl pre_c_initialization(); idb
int sub_7953EE();
int sub_7953F6();
int nullsub_1(void); // weak
_DWORD *__thiscall sub_795597(_DWORD *this);
void __noreturn sub_7955AF(); // weak
void __noreturn sub_7955CC(); // weak
int sub_7957B9();
// _DWORD __cdecl __scrt_fastfail(_DWORD); weak
int __cdecl j_UserMathErrorFunction(struct _exception *); // idb
int __cdecl UserMathErrorFunction();
LPTOP_LEVEL_EXCEPTION_FILTER sub_79592E();
// LONG __stdcall __scrt_unhandled_exception_filter(struct _EXCEPTION_POINTERS *ExceptionInfo); idb
void sub_795990();
void __cdecl j_free(void *Block);
// int _get_startup_file_mode(void); weak
void sub_795ACA();
char sub_795AD6();
// int _initialize_default_precision(void); weak
void *sub_795AFA();
// int __scrt_initialize_default_local_stdio_options(void); weak
BOOL sub_795B1D();
void *sub_795B29();
void *sub_795B2F();
void sub_795B35();
void __cdecl sub_795B61(); // idb
// void __stdcall __noreturn CxxThrowException(void *pExceptionObject, _ThrowInfo *pThrowInfo);
// errno_t __cdecl configure_narrow_argv(_crt_argv_mode mode);
// int __cdecl initialize_narrow_environment();
// void __cdecl set_app_type(_crt_app_type Type);
// void __cdecl _setusermatherr(_UserMathErrorFunctionPointer UserMathErrorFunction);
// errno_t __cdecl set_fmode(int Mode);
// int __cdecl configthreadlocale(int Flag);
// int __cdecl set_new_mode(int NewMode);
// int *__cdecl _p__commode();
// unsigned __int64 __usercall sub_7963A3@<edx:eax>(unsigned __int64 a1@<edx:eax>);
// void *__cdecl memcpy(void *, const void *Src, size_t Size);
// void *__cdecl memmove(void *, const void *Src, size_t Size);
void __cdecl sub_796612(); // idb
void __cdecl sub_796621(); // idb
void __cdecl sub_796630(); // idb
void __cdecl sub_79663F(); // idb
void __cdecl sub_79664E(); // idb
void __cdecl sub_79665D(); // idb
void __cdecl sub_79666C(); // idb
void __cdecl sub_79667B(); // idb
void __cdecl sub_79668A(); // idb
void __cdecl sub_796699(); // idb
// int __thiscall std::ios::setstate(_DWORD, _DWORD, _DWORD, _DWORD, _DWORD, _DWORD, _DWORD, _DWORD, _DWORD, _DWORD, _DWORD, _DWORD, _DWORD, _DWORD, _DWORD, _DWORD, _DWORD, _DWORD, _DWORD, _DWORD, _DWORD, _DWORD, _DWORD, _DWORD, _DWORD, _DWORD, _DWORD, _DWORD, _DWORD, _DWORD, _DWORD, _DWORD, _DWORD, _DWORD, _DWORD, _DWORD, _DWORD); weak
// int __thiscall std::ios::rdbuf(_DWORD, _DWORD, _DWORD); weak
// int __thiscall std::streambuf::sgetc(_DWORD); weak
// int __thiscall std::ios_base::getloc(_DWORD, _DWORD); weak
// int __thiscall std::streambuf::snextc(_DWORD); weak
// __int64 __thiscall std::ios_base::width(std::ios_base *__hidden this); weak
// int __cdecl std::ctype<char>::_Getcat(_DWORD, _DWORD); weak
// int __thiscall std::ctype<char>::is(_DWORD, _DWORD, _DWORD); weak
// int __thiscall std::locale::id::operator unsigned int(_DWORD); weak
// int __thiscall std::istream::_Ipfx(_DWORD, _DWORD); weak
// void __cdecl __noreturn std::_Xlength_error(const char *); weak
// unsigned int __cdecl std::_Random_device(); weak
// void __cdecl std::_Xout_of_range(const char *); weak
// int std::locale::_Getgloballocale(void); weak
// _DWORD __thiscall std::_Lockit::_Lockit(std::_Lockit *__hidden this, _DWORD); weak
// void __thiscall std::_Lockit::~_Lockit(std::_Lockit *__hidden this); weak
// __int64 __thiscall std::ios_base::width(std::ios_base *__hidden this, __int64); weak
// int __cdecl _std_exception_copy(_DWORD, _DWORD); weak
// int __cdecl _std_exception_destroy(_DWORD); weak

//-------------------------------------------------------------------------
// Data declarations

_UNKNOWN loc_7964CA; // weak
// extern void (__stdcall *InitializeSListHead)(PSLIST_HEADER ListHead);
// extern LPTOP_LEVEL_EXCEPTION_FILTER (__stdcall *SetUnhandledExceptionFilter)(LPTOP_LEVEL_EXCEPTION_FILTER lpTopLevelExceptionFilter);
// extern __int64 (__cdecl *Xtime_get_ticks)();
// extern __int64 (__cdecl *Query_perf_frequency)();
// extern __int64 (__cdecl *Query_perf_counter)();
// extern void (__cdecl *Thrd_sleep)(const xtime *);
// extern _UNKNOWN std::ctype<char>::id; weak
// extern _UNKNOWN std::cin; weak
// extern void (__cdecl __noreturn *invalid_parameter_noinfo_noreturn)();
// extern int (__cdecl *getchar)();
// extern int (__cdecl *_stdio_common_vfprintf)(unsigned __int64 Options, FILE *Stream, const char *Format, _locale_t Locale, va_list ArgList);
// extern FILE *(__cdecl *_acrt_iob_func)(unsigned int Ix);
void *type_info::`vftable' = &sub_795320; // weak
void *std::exception::`vftable' = &sub_791449; // weak
void *std::bad_alloc::`vftable' = &sub_791497; // weak
void *std::bad_array_new_length::`vftable' = &sub_7914F4; // weak
void *std::bad_cast::`vftable' = &sub_791497; // weak
const _ThrowInfo _TI2_AVbad_alloc_std__ = { 0u, &sub_7914C1, NULL, &_CTA2_AVbad_alloc_std__ }; // idb
const _ThrowInfo _TI2_AVbad_cast_std__ = { 0u, &sub_7914C1, NULL, &_CTA2_AVbad_cast_std__ }; // idb
const _ThrowInfo _TI3_AVbad_array_new_length_std__ = { 0u, &sub_79151E, NULL, &_CTA3_AVbad_array_new_length_std__ }; // idb
int dword_799010 = 1; // weak
_UNKNOWN unk_7990BC; // weak
int dword_7990F0 = 0; // weak
union _SLIST_HEADER ListHead = { 0ui64 }; // idb
_UNKNOWN unk_799100; // weak
_UNKNOWN unk_799428; // weak
int dword_799430; // weak
int dword_799434[3]; // weak
int dword_799440[3]; // weak
int dword_79944C[3]; // weak
int dword_799458[3]; // weak
int dword_799464[3]; // weak
unsigned int dword_799470[6]; // weak
int dword_799488[3]; // weak
int dword_799494[3]; // weak
int dword_7994A0[3]; // weak
_UNKNOWN unk_7994AC; // weak
_UNKNOWN unk_7994B0; // weak


//----- (00791000) --------------------------------------------------------
int sub_791000()
{
  void *v1[6]; // [esp+0h] [ebp-24h] BYREF
  int v2; // [esp+20h] [ebp-4h]
  int savedregs; // [esp+24h] [ebp+0h] BYREF

  sub_7920BA((unsigned int *)v1, "https://discord.gg/fmhw85T5zM");
  v2 = 0;
  sub_7918BC(dword_79944C, (int)&savedregs, v1);
  v2 = -1;
  Process_Input(v1);
  return atexit(sub_796612);
}
// 79944C: using guessed type int dword_79944C[3];

//----- (0079105D) --------------------------------------------------------
int sub_79105D()
{
  void *v1[6]; // [esp+0h] [ebp-24h] BYREF
  int v2; // [esp+20h] [ebp-4h]
  int savedregs; // [esp+24h] [ebp+0h] BYREF

  sub_7920BA((unsigned int *)v1, "V1rtu4lAll0c");
  v2 = 0;
  sub_7918BC(dword_799458, (int)&savedregs, v1);
  v2 = -1;
  Process_Input(v1);
  return atexit(sub_796621);
}
// 799458: using guessed type int dword_799458[3];

//----- (007910BA) --------------------------------------------------------
int sub_7910BA()
{
  void *v1[6]; // [esp+0h] [ebp-24h] BYREF
  int v2; // [esp+20h] [ebp-4h]
  int savedregs; // [esp+24h] [ebp+0h] BYREF

  sub_7920BA((unsigned int *)v1, "jpofwejfdslfkjdslkfghiphap332oiu");
  v2 = 0;
  sub_7918BC(dword_7994A0, (int)&savedregs, v1);
  v2 = -1;
  Process_Input(v1);
  return atexit(sub_796630);
}
// 7994A0: using guessed type int dword_7994A0[3];

//----- (00791117) --------------------------------------------------------
int sub_791117()
{
  void *v1[6]; // [esp+0h] [ebp-24h] BYREF
  int v2; // [esp+20h] [ebp-4h]
  int savedregs; // [esp+24h] [ebp+0h] BYREF

  sub_7920BA((unsigned int *)v1, "Ohu3mNdslwoxfedlo34");
  v2 = 0;
  sub_7918BC(dword_799440, (int)&savedregs, v1);
  v2 = -1;
  Process_Input(v1);
  return atexit(sub_79663F);
}
// 799440: using guessed type int dword_799440[3];

//----- (00791174) --------------------------------------------------------
int sub_791174()
{
  void *v1[6]; // [esp+0h] [ebp-24h] BYREF
  int v2; // [esp+20h] [ebp-4h]
  int savedregs; // [esp+24h] [ebp+0h] BYREF

  sub_7920BA((unsigned int *)v1, "2-mk43xxy0.1k");
  v2 = 0;
  sub_7918BC(dword_799464, (int)&savedregs, v1);
  v2 = -1;
  Process_Input(v1);
  return atexit(sub_79664E);
}
// 799464: using guessed type int dword_799464[3];

//----- (007911D1) --------------------------------------------------------
int sub_7911D1()
{
  void *v1[6]; // [esp+0h] [ebp-24h] BYREF
  int v2; // [esp+20h] [ebp-4h]
  int savedregs; // [esp+24h] [ebp+0h] BYREF

  sub_7920BA((unsigned int *)v1, ";32;42;65;33;91;52");
  v2 = 0;
  sub_7918BC(dword_799494, (int)&savedregs, v1);
  v2 = -1;
  Process_Input(v1);
  return atexit(sub_79665D);
}
// 799494: using guessed type int dword_799494[3];

//----- (0079122E) --------------------------------------------------------
int sub_79122E()
{
  void *v1[6]; // [esp+0h] [ebp-24h] BYREF
  int v2; // [esp+20h] [ebp-4h]
  int savedregs; // [esp+24h] [ebp+0h] BYREF

  sub_7920BA((unsigned int *)v1, "S`=d`Y9{]D}_vK$#.");
  v2 = 0;
  sub_7918BC(dword_799434, (int)&savedregs, v1);
  v2 = -1;
  Process_Input(v1);
  return atexit(sub_79666C);
}
// 799434: using guessed type int dword_799434[3];

//----- (0079128B) --------------------------------------------------------
int sub_79128B()
{
  void *v1[6]; // [esp+0h] [ebp-24h] BYREF
  int v2; // [esp+20h] [ebp-4h]
  int savedregs; // [esp+24h] [ebp+0h] BYREF

  sub_7920BA((unsigned int *)v1, "xxxxxGot7.5_HUH?98rjoi2r3oifjdsoigfogdfs");
  v2 = 0;
  sub_7918BC(dword_799488, (int)&savedregs, v1);
  v2 = -1;
  Process_Input(v1);
  return atexit(sub_79667B);
}
// 799488: using guessed type int dword_799488[3];

//----- (007912E8) --------------------------------------------------------
int sub_7912E8()
{
  sub_7920BA(dword_799470, "H4ndy51mpL30bFusC4tI0NL1bR4RybYM3mB3R_TH4nKs");
  return atexit(sub_79668A);
}
// 799470: using guessed type unsigned int dword_799470[6];

//----- (00791307) --------------------------------------------------------
int sub_791307()
{
  return atexit(sub_796699);
}

//----- (00791328) --------------------------------------------------------
char sub_791328()
{
  return 0;
}

//----- (0079132F) --------------------------------------------------------
void *sub_79132F()
{
  return &unk_799428;
}

//----- (00791339) --------------------------------------------------------
int __cdecl sub_791339(FILE *Stream, char *Format, _locale_t Locale, va_list ArgList)
{
  unsigned __int64 *v4; // eax

  v4 = (unsigned __int64 *)sub_79132F();
  return _stdio_common_vfprintf(*v4, Stream, Format, Locale, ArgList);
}

//----- (0079135D) --------------------------------------------------------
int sub_79135D(char *a1, ...)
{
  FILE *Stream; // [esp+4h] [ebp-Ch]
  va_list va; // [esp+1Ch] [ebp+Ch] BYREF

  va_start(va, a1);
  Stream = _acrt_iob_func(1u);
  return sub_791339(Stream, a1, 0, va);
}

//----- (0079139A) --------------------------------------------------------
_DWORD *__thiscall sub_79139A(_DWORD *this, int a2, int a3)
{
  _DWORD *v3; // ecx

  *this = &std::exception::`vftable';
  v3 = this + 1;
  *v3 = 0;
  v3[1] = 0;
  this[1] = a2;
  return this;
}
// 7971BC: using guessed type void *std::exception::`vftable';

//----- (007913C7) --------------------------------------------------------
_DWORD *__thiscall sub_7913C7(_DWORD *this, int a2)
{
  _DWORD *v2; // ecx

  *this = &std::exception::`vftable';
  v2 = this + 1;
  *v2 = 0;
  v2[1] = 0;
  _std_exception_copy(a2 + 4, v2);
  return this;
}
// 7970AC: using guessed type int __cdecl _std_exception_copy(_DWORD, _DWORD);
// 7971BC: using guessed type void *std::exception::`vftable';

//----- (00791401) --------------------------------------------------------
int __thiscall sub_791401(_DWORD *this)
{
  *this = &std::exception::`vftable';
  return _std_exception_destroy(this + 1);
}
// 7970B8: using guessed type int __cdecl _std_exception_destroy(_DWORD);
// 7971BC: using guessed type void *std::exception::`vftable';

//----- (00791421) --------------------------------------------------------
const char *__thiscall sub_791421(_DWORD *this)
{
  if ( this[1] )
    return (const char *)this[1];
  else
    return "Unknown exception";
}

//----- (00791449) --------------------------------------------------------
_DWORD *__thiscall sub_791449(_DWORD *this, char a2)
{
  sub_791401(this);
  if ( (a2 & 1) != 0 )
    sub_795312(this);
  return this;
}

//----- (00791473) --------------------------------------------------------
_DWORD *__thiscall sub_791473(_DWORD *this, int a2)
{
  sub_79139A(this, a2, 1);
  *this = &std::bad_alloc::`vftable';
  return this;
}
// 7971C8: using guessed type void *std::bad_alloc::`vftable';

//----- (00791497) --------------------------------------------------------
_DWORD *__thiscall sub_791497(_DWORD *this, char a2)
{
  sub_7914C1(this);
  if ( (a2 & 1) != 0 )
    sub_795312(this);
  return this;
}

//----- (007914C1) --------------------------------------------------------
int __thiscall sub_7914C1(_DWORD *this)
{
  return sub_791401(this);
}

//----- (007914D2) --------------------------------------------------------
_DWORD *__thiscall sub_7914D2(_DWORD *this)
{
  sub_791473(this, (int)"bad array new length");
  *this = &std::bad_array_new_length::`vftable';
  return this;
}
// 7971E4: using guessed type void *std::bad_array_new_length::`vftable';

//----- (007914F4) --------------------------------------------------------
_DWORD *__thiscall sub_7914F4(_DWORD *this, char a2)
{
  sub_79151E(this);
  if ( (a2 & 1) != 0 )
    sub_795312(this);
  return this;
}

//----- (0079151E) --------------------------------------------------------
int __thiscall sub_79151E(_DWORD *this)
{
  return sub_7914C1(this);
}

//----- (0079152F) --------------------------------------------------------
void __cdecl __noreturn sub_79152F()
{
  int pExceptionObject[3]; // [esp+0h] [ebp-Ch] BYREF

  sub_7914D2(pExceptionObject);
  CxxThrowException(pExceptionObject, (_ThrowInfo *)&_TI3_AVbad_array_new_length_std__);
}
// 79152F: using guessed type _DWORD pExceptionObject[3];

//----- (0079154D) --------------------------------------------------------
_DWORD *__thiscall sub_79154D(_DWORD *this, int a2)
{
  sub_79156F(this, a2);
  *this = &std::bad_array_new_length::`vftable';
  return this;
}
// 7971E4: using guessed type void *std::bad_array_new_length::`vftable';

//----- (0079156F) --------------------------------------------------------
_DWORD *__thiscall sub_79156F(_DWORD *this, int a2)
{
  sub_7913C7(this, a2);
  *this = &std::bad_alloc::`vftable';
  return this;
}
// 7971C8: using guessed type void *std::bad_alloc::`vftable';

//----- (007915B6) --------------------------------------------------------
__int64 sub_7915B6()
{
  return 0i64;
}

//----- (007915BF) --------------------------------------------------------
__int64 sub_7915BF()
{
  return -1i64;
}

//----- (007915D8) --------------------------------------------------------
_DWORD *__cdecl sub_7915D8(_DWORD *a1, _DWORD *a2)
{
  _DWORD *result; // eax
  int v3; // [esp+8h] [ebp-8h]
  unsigned int v4; // [esp+Ch] [ebp-4h]

  *a2 += 35;
  v3 = *(_DWORD *)(*a1 - 4);
  v4 = *a1 - v3;
  if ( v4 < 4 || v4 > 0x23 )
    invalid_parameter_noinfo_noreturn();
  result = a1;
  *a1 = v3;
  return result;
}

//----- (00791642) --------------------------------------------------------
void sub_791642()
{
  ;
}

//----- (0079164B) --------------------------------------------------------
void __stdcall sub_79164B(int a1)
{
  ;
}

//----- (00791656) --------------------------------------------------------
void *__thiscall sub_791656(void *this, int a2, int a3)
{
  return this;
}

//----- (00791664) --------------------------------------------------------
void __noreturn sub_791664()
{
  std::_Xlength_error("string too long");
}
// 79706C: using guessed type void __cdecl __noreturn std::_Xlength_error(const char *);

//----- (00791674) --------------------------------------------------------
_DWORD *__thiscall sub_791674(_DWORD *this)
{
  sub_79139A(this, (int)"bad cast", 1);
  *this = &std::bad_cast::`vftable';
  return this;
}
// 7973D4: using guessed type void *std::bad_cast::`vftable';

//----- (00791698) --------------------------------------------------------
void __noreturn sub_791698()
{
  int pExceptionObject[3]; // [esp+0h] [ebp-Ch] BYREF

  sub_791674(pExceptionObject);
  CxxThrowException(pExceptionObject, (_ThrowInfo *)&_TI2_AVbad_cast_std__);
}
// 791698: using guessed type _DWORD pExceptionObject[3];

//----- (007916B6) --------------------------------------------------------
_DWORD *__thiscall sub_7916B6(_DWORD *this, int a2)
{
  sub_7913C7(this, a2);
  *this = &std::bad_cast::`vftable';
  return this;
}
// 7973D4: using guessed type void *std::bad_cast::`vftable';

//----- (007916D8) --------------------------------------------------------
int (__thiscall ***__thiscall sub_7916D8(_DWORD **this))(_DWORD, int)
{
  int (__thiscall ***result)(_DWORD, int); // eax

  result = (int (__thiscall ***)(_DWORD, int))this;
  if ( this[1] )
  {
    result = (int (__thiscall ***)(_DWORD, int))(*(int (__thiscall **)(_DWORD *))(*this[1] + 8))(this[1]);
    if ( result )
      return (int (__thiscall ***)(_DWORD, int))(**result)(result, 1);
  }
  return result;
}

//----- (00791721) --------------------------------------------------------
int __thiscall sub_791721(_DWORD *this, unsigned int a2)
{
  int v3; // [esp+0h] [ebp-10h]
  int v4; // [esp+8h] [ebp-8h]

  if ( a2 >= *(_DWORD *)(this[1] + 12) )
    v4 = 0;
  else
    v4 = *(_DWORD *)(*(_DWORD *)(this[1] + 8) + 4 * a2);
  if ( v4 || !*(_BYTE *)(this[1] + 20) )
    return v4;
  v3 = std::locale::_Getgloballocale();
  if ( a2 >= *(_DWORD *)(v3 + 12) )
    return 0;
  else
    return *(_DWORD *)(*(_DWORD *)(v3 + 8) + 4 * a2);
}
// 797080: using guessed type int std::locale::_Getgloballocale(void);

//----- (00791797) --------------------------------------------------------
_DWORD *__cdecl sub_791797(_DWORD *a1)
{
  _DWORD *v1; // eax
  int v3; // [esp+0h] [ebp-10h] BYREF
  __int64 ticks; // [esp+8h] [ebp-8h] BYREF

  ticks = Xtime_get_ticks();
  v1 = sub_791864(&v3, &ticks);
  sub_791F83(a1, v1);
  return a1;
}

//----- (007917C3) --------------------------------------------------------
_DWORD *__cdecl sub_7917C3(_DWORD *a1)
{
  _DWORD *v1; // eax
  int v3; // [esp+0h] [ebp-30h] BYREF
  __int64 v4; // [esp+8h] [ebp-28h] BYREF
  __int64 v5; // [esp+10h] [ebp-20h]
  __int64 v6; // [esp+18h] [ebp-18h]
  __int64 perf_counter; // [esp+20h] [ebp-10h]
  __int64 perf_frequency; // [esp+28h] [ebp-8h]

  perf_frequency = Query_perf_frequency();
  perf_counter = Query_perf_counter();
  v6 = 1000000000 * (perf_counter / perf_frequency);
  v5 = 1000000000 * (perf_counter % perf_frequency) / perf_frequency;
  v4 = v5 + v6;
  v1 = sub_791864(&v3, &v4);
  sub_791F83(a1, v1);
  return a1;
}

//----- (00791864) --------------------------------------------------------
_DWORD *__thiscall sub_791864(_DWORD *this, _DWORD *a2)
{
  int v3; // ecx

  v3 = a2[1];
  *this = *a2;
  this[1] = v3;
  return this;
}

//----- (00791882) --------------------------------------------------------
__int64 __thiscall sub_791882(void *this)
{
  return *(_QWORD *)this;
}

//----- (00791893) --------------------------------------------------------
double __thiscall sub_791893(void *this)
{
  return *(double *)this;
}

//----- (007918A1) --------------------------------------------------------
void *__thiscall sub_7918A1(void *this)
{
  return this;
}

//----- (007918AD) --------------------------------------------------------
unsigned int sub_7918AD()
{
  return std::_Random_device();
}
// 797070: using guessed type unsigned int __cdecl std::_Random_device();

//----- (007918BC) --------------------------------------------------------
int *__userpurge sub_7918BC@<eax>(int *a1@<ecx>, int a2@<ebp>, _DWORD *a3)
{
  int v3; // eax
  unsigned int v4; // eax
  char *v5; // eax
  int *v6; // eax
  int v7; // ecx
  int v8; // eax
  int *v9; // eax
  int v10; // edx
  int v12; // [esp-30h] [ebp-3Ch] BYREF
  int v13; // [esp-28h] [ebp-34h]
  int v14; // [esp-24h] [ebp-30h]
  int *v15; // [esp-20h] [ebp-2Ch]
  int *v16; // [esp-1Ch] [ebp-28h]
  int *v17; // [esp-18h] [ebp-24h]
  unsigned int i; // [esp-14h] [ebp-20h]
  int *v19; // [esp-10h] [ebp-1Ch]
  struct _EXCEPTION_REGISTRATION_RECORD *ExceptionList; // [esp-Ch] [ebp-18h]
  void *v21; // [esp-8h] [ebp-14h]
  int v22; // [esp-4h] [ebp-10h]
  int v23; // [esp+0h] [ebp-Ch]
  int v24; // [esp+4h] [ebp-8h]
  int v25; // [esp+8h] [ebp-4h] BYREF
  int retaddr; // [esp+Ch] [ebp+0h]

  v23 = a2;
  v24 = retaddr;
  v22 = -1;
  v21 = &loc_7964CA;
  ExceptionList = NtCurrentTeb()->NtTib.ExceptionList;
  v19 = &v25;
  v17 = a1;
  sub_791F52(a1);
  v22 = 0;
  v16 = v17;
  v3 = sub_791FBF(a3);
  sub_791E40(v17, v3);
  for ( i = 0; ; ++i )
  {
    v4 = sub_791FBF(a3);
    if ( i >= v4 )
      break;
    v5 = sub_79208B(a3, i);
    v6 = sub_791DDF(&v12, *v5);
    v7 = *v6;
    v8 = v6[1];
    v13 = v7;
    v14 = v8;
    v15 = v17;
    v9 = (int *)sub_791E05(v17, i);
    v10 = v14;
    *v9 = v13;
    v9[1] = v10;
  }
  return v17;
}

//----- (00791984) --------------------------------------------------------
int __thiscall sub_791984(_DWORD *this, int a2)
{
  return sub_791E05(this, a2);
}

//----- (007919A1) --------------------------------------------------------
int *__thiscall sub_7919A1(int *this, int *a2)
{
  sub_791E6C(a2, this);
  return a2;
}

//----- (007919DE) --------------------------------------------------------
int *__thiscall sub_7919DE(int *this)
{
  return sub_791E5B(this);
}

//----- (007919EF) --------------------------------------------------------
int *__cdecl sub_7919EF(int *a1)
{
  void *GETInput_Coordinates[6]; // [esp+0h] [ebp-28h] BYREF
  int v3; // [esp+18h] [ebp-10h]
  int v4; // [esp+24h] [ebp-4h]
  int savedregs; // [esp+28h] [ebp+0h] BYREF

  v3 = 0;
  printf("Coordinates: ");
  sub_7920BA((unsigned int *)GETInput_Coordinates, "v2");
  v4 = 0;
  sub_79290E(std::cin, GETInput_Coordinates);
  sub_7918BC(a1, (int)&savedregs, GETInput_Coordinates);
  v3 |= 1u;
  v4 = -1;
  Process_Input(GETInput_Coordinates);
  return a1;
}

//----- (00791A6B) --------------------------------------------------------
char __cdecl Process_Input3(int *a1)
{
  int v1; // esi
  __int16 v3; // ax
  unsigned __int16 v4; // ax
  _DWORD *v5; // eax
  int v6; // esi
  int v7; // edi
  unsigned __int16 v8; // ax
  _DWORD *v9; // eax
  int v10[3]; // [esp+8h] [ebp-54h] BYREF
  int v11[3]; // [esp+14h] [ebp-48h] BYREF
  int v12[3]; // [esp+20h] [ebp-3Ch] BYREF
  __int16 Processed2; // [esp+2Ch] [ebp-30h] BYREF
  int *v14; // [esp+30h] [ebp-2Ch]
  int *v15; // [esp+34h] [ebp-28h]
  int *v16; // [esp+38h] [ebp-24h]
  int *v17; // [esp+3Ch] [ebp-20h]
  __int16 v18; // [esp+40h] [ebp-1Ch] BYREF
  BOOL v19; // [esp+44h] [ebp-18h]
  __int16 Processed1[3]; // [esp+48h] [ebp-14h] BYREF
  bool LastBool; // [esp+4Eh] [ebp-Eh]
  bool Failure1; // [esp+4Fh] [ebp-Dh]
  int v23; // [esp+58h] [ebp-4h]

  v16 = BProcessor(a1, v11);
  v17 = BProcessor(dword_799434, v12);
  v1 = AProcessor(v17);
  v19 = AProcessor(v16) != v1;
  Failure1 = v19;
  sub_791E5B(v12);
  sub_791E5B(v11);
  if ( !Failure1 )
    return 0;
  sub_791D9F(Processed1, 0);
  sub_791D9F(&v18, 7);
  while ( 1 )
  {
    v15 = BProcessor(dword_799434, v10);
    v14 = v15;
    v23 = 0;
    v3 = AProcessor(v15);
    sub_791D9F(&Processed2, v3);
    LastBool = Process_Input2((unsigned __int16 *)Processed1, (unsigned __int16 *)&Processed2);
    v23 = -1;
    sub_791E5B(v10);
    if ( !LastBool )
      break;
    v4 = sub_791D23((unsigned __int16 *)Processed1);
    v5 = (_DWORD *)sub_791984(a1, v4);
    v6 = sub_791DCB(v5);
    v7 = (unsigned __int16)sub_791D23((unsigned __int16 *)&v18);
    v8 = sub_791D23((unsigned __int16 *)Processed1);
    v9 = (_DWORD *)sub_791984(dword_799434, v8);
    if ( v6 != (sub_791DCB(v9) ^ v7) )
      return 0;
    sub_791D73((unsigned __int16 *)Processed1);
    sub_791D73((unsigned __int16 *)&v18);
  }
  return 1;
}
// 799434: using guessed type int dword_799434[3];
// 791A6B: using guessed type int var_48[3];
// 791A6B: using guessed type int var_3C[3];
// 791A6B: using guessed type unsigned __int16 Processed1[3];
// 791A6B: using guessed type int var_54[3];

//----- (00791BC9) --------------------------------------------------------
int __cdecl main(int argc, const char **argv, const char **envp)
{
  _QWORD *v3; // eax
  __int64 v4; // rax
  _QWORD *v5; // eax
  int v7[4]; // [esp+0h] [ebp-34h] BYREF
  int Input_Coordinates[3]; // [esp+10h] [ebp-24h] BYREF
  __int64 v9; // [esp+1Ch] [ebp-18h] BYREF
  int v10; // [esp+24h] [ebp-10h] BYREF
  int v11; // [esp+30h] [ebp-4h]

  sub_791CF9(v7);
  printf("%s()\n", "main");
  printf("Find correct Coordinates\n");
  while ( 1 )
  {
    sub_7919EF(Input_Coordinates);
    v11 = 0;
    if ( Process_Input3(Input_Coordinates) )
      break;
    v3 = sub_791CC5(v7);
    v4 = sub_791CA5(v3);
    printf("Incorrect!(%llu)\n", v4);
    v10 = 200;
    v5 = sub_792927(&v9, &v10);
    sub_792943(v5);
    v11 = -1;
    sub_7919DE(Input_Coordinates);
  }
  v11 = -1;
  sub_7919DE(Input_Coordinates);
  printf("Correct!\nPlease send DM Coordinates.\n");
  getchar();
  getchar();
  return 0;
}
// 791BC9: using guessed type int var_34[4];
// 791BC9: using guessed type int var_24[3];

//----- (00791CA5) --------------------------------------------------------
__int64 __thiscall sub_791CA5(_QWORD *this)
{
  return *this ^ this[1];
}

//----- (00791CC5) --------------------------------------------------------
_QWORD *__thiscall sub_791CC5(_QWORD *this)
{
  int *v1; // eax
  int *v2; // eax
  _DWORD *v3; // edi
  int v5[4]; // [esp+8h] [ebp-24h] BYREF
  int v6[4]; // [esp+18h] [ebp-14h] BYREF
  _QWORD *v7; // [esp+28h] [ebp-4h]

  v7 = this;
  v1 = sub_7921A2(v6, 1, 0);
  v2 = sub_79216E(v7, v5, v1);
  v3 = v7;
  *(_DWORD *)v7 = *v2;
  *++v3 = v2[1];
  *++v3 = v2[2];
  v3[1] = v2[3];
  return v7;
}
// 791CC5: using guessed type int var_14[4];
// 791CC5: using guessed type int var_24[4];

//----- (00791CF9) --------------------------------------------------------
int *__thiscall sub_791CF9(int *this)
{
  int v1; // edx
  int v2; // ecx

  *this = sub_79296C();
  this[1] = v1;
  v2 = this[1];
  this[2] = *this;
  this[3] = v2;
  return this;
}
// 791D0A: variable 'v1' is possibly undefined

//----- (00791D23) --------------------------------------------------------
int __thiscall sub_791D23(unsigned __int16 *this)
{
  return *this ^ this[1];
}

//----- (00791D3B) --------------------------------------------------------
bool __thiscall Process_Input2(unsigned __int16 *this, unsigned __int16 *a2)
{
  int v2; // esi

  v2 = (unsigned __int16)sub_791D23(this);
  return v2 < (unsigned __int16)sub_791D23(a2);
}

//----- (00791D73) --------------------------------------------------------
unsigned __int16 *__thiscall sub_791D73(unsigned __int16 *this)
{
  __int16 *v1; // eax
  __int16 *v2; // eax
  __int16 v4; // [esp+0h] [ebp-Ch] BYREF
  __int16 v5; // [esp+4h] [ebp-8h] BYREF
  unsigned __int16 *v6; // [esp+8h] [ebp-4h]

  v6 = this;
  v1 = sub_791D9F(&v5, 1);
  v2 = sub_7921D4(v6, &v4, (unsigned __int16 *)v1);
  *(_DWORD *)v6 = *(_DWORD *)v2;
  return v6;
}

//----- (00791D9F) --------------------------------------------------------
__int16 *__thiscall sub_791D9F(__int16 *this, __int16 a2)
{
  *this = sub_79299E();
  this[1] = *this ^ a2;
  return this;
}

//----- (00791DCB) --------------------------------------------------------
int __thiscall sub_791DCB(_DWORD *this)
{
  return *this ^ this[1];
}

//----- (00791DDF) --------------------------------------------------------
int *__thiscall sub_791DDF(int *this, int a2)
{
  *this = sub_7929C4();
  this[1] = *this ^ a2;
  return this;
}

//----- (00791E05) --------------------------------------------------------
int __thiscall sub_791E05(_DWORD *this, int a2)
{
  return *this + 8 * a2;
}

//----- (00791E22) --------------------------------------------------------
int __thiscall sub_791E22(_DWORD *this)
{
  return (this[1] - *this) >> 3;
}

//----- (00791E40) --------------------------------------------------------
void __thiscall sub_791E40(int *this, unsigned int a2)
{
  unsigned __int8 v2; // [esp+7h] [ebp-1h] BYREF

  sub_7929E8(this, a2, &v2);
}

//----- (00791E5B) --------------------------------------------------------
int *__thiscall sub_791E5B(int *this)
{
  return sub_792216(this);
}

//----- (00791E6C) --------------------------------------------------------
int *__thiscall sub_791E6C(int *this, int *a2)
{
  int v4; // [esp+8h] [ebp-30h]
  int v5; // [esp+Ch] [ebp-2Ch]
  int *v6[2]; // [esp+10h] [ebp-28h] BYREF
  int *v7; // [esp+18h] [ebp-20h]
  int v8; // [esp+1Ch] [ebp-1Ch]
  int v9; // [esp+20h] [ebp-18h]
  int *v10; // [esp+24h] [ebp-14h]
  char v11[2]; // [esp+28h] [ebp-10h] BYREF
  char v12; // [esp+2Ah] [ebp-Eh] BYREF
  char v13; // [esp+2Bh] [ebp-Dh] BYREF
  int v14; // [esp+34h] [ebp-4h]

  v10 = this;
  sub_792205(a2);
  v5 = unknown_libname_3(&v12);
  LOBYTE(v4) = v11[1];
  sub_792ABF(this, v4, v5);
  v7 = v10;
  v6[1] = a2;
  v8 = *a2;
  v9 = a2[1];
  sub_791656(&v13, (int)v11, (int)v10);
  if ( v8 != v9 )
  {
    sub_7922C8(v10, (v9 - v8) >> 3);
    v6[0] = v10;
    v14 = 0;
    v7[1] = sub_792ADE(v10, v8, v9, *v7);
    v6[0] = 0;
    v14 = -1;
    sub_792153(v6);
  }
  sub_791642();
  return v10;
}
// 791EB6: variable 'v4' is possibly undefined
// 79163A: using guessed type _DWORD __cdecl unknown_libname_3(_DWORD);

//----- (00791F52) --------------------------------------------------------
_DWORD *__thiscall sub_791F52(_DWORD *this)
{
  int v2; // [esp+0h] [ebp-14h]
  char v4; // [esp+13h] [ebp-1h] BYREF

  sub_792B03(this, v2);
  sub_79164B((int)&v4);
  return this;
}
// 791F67: variable 'v2' is possibly undefined

//----- (00791F83) --------------------------------------------------------
_DWORD *__thiscall sub_791F83(_DWORD *this, _DWORD *a2)
{
  int v2; // eax

  v2 = a2[1];
  *this = *a2;
  this[1] = v2;
  return this;
}

//----- (00791FA1) --------------------------------------------------------
_DWORD *__thiscall sub_791FA1(_DWORD *this, _DWORD *a2)
{
  int v2; // eax

  v2 = this[1];
  *a2 = *this;
  a2[1] = v2;
  return a2;
}

//----- (00791FBF) --------------------------------------------------------
int __thiscall sub_791FBF(_DWORD *this)
{
  return this[4];
}

//----- (00791FCE) --------------------------------------------------------
unsigned int *__thiscall sub_791FCE(size_t *this, char a2)
{
  char v3; // [esp+0h] [ebp-14h]
  _DWORD *v4; // [esp+4h] [ebp-10h]
  size_t v5; // [esp+8h] [ebp-Ch]
  char v6; // [esp+13h] [ebp-1h] BYREF

  v5 = this[4];
  if ( v5 >= this[5] )
    return sub_792B4B(this, 1u, v3, a2);
  this[4] = v5 + 1;
  v4 = sub_7924C0(this);
  sub_792524((_BYTE *)v4 + v5, &a2);
  v6 = 0;
  return (unsigned int *)sub_792524((_BYTE *)v4 + v5 + 1, &v6);
}
// 792039: variable 'v3' is possibly undefined

//----- (00792042) --------------------------------------------------------
_BYTE *__stdcall sub_792042(_BYTE *a1, _BYTE *Src, size_t Size, char a4)
{
  char v5; // [esp+7h] [ebp-1h] BYREF

  sub_792565(a1, Src, Size);
  sub_792524(&a1[Size], &a4);
  v5 = 0;
  return sub_792524(&a1[Size + 1], &v5);
}

//----- (0079208B) --------------------------------------------------------
char *__thiscall sub_79208B(_DWORD *this, int a2)
{
  return (char *)sub_7924C0(this) + a2;
}

//----- (007920A1) --------------------------------------------------------
void __thiscall Process_Input(void **this)
{
  sub_79232A(this);
  sub_792131();
}

//----- (007920BA) --------------------------------------------------------
unsigned int *__thiscall sub_7920BA(unsigned int *this, char *Src)
{
  int v3; // [esp+0h] [ebp-20h]
  char v5; // [esp+12h] [ebp-Eh] BYREF
  char v6; // [esp+13h] [ebp-Dh] BYREF
  int v7; // [esp+1Ch] [ebp-4h]

  sub_792C45(this, v3);
  v7 = 0;
  sub_791656(&v6, (int)&v5, (int)this);
  sub_7923C9((int)this);
  sub_7923FD(this, Src);
  sub_791642();
  return this;
}
// 7920E4: variable 'v3' is possibly undefined

//----- (00792131) --------------------------------------------------------
void sub_792131()
{
  sub_792142();
}

//----- (00792142) --------------------------------------------------------
void sub_792142()
{
  sub_791642();
}

//----- (00792153) --------------------------------------------------------
int *__thiscall sub_792153(int **this)
{
  int *result; // eax

  result = (int *)this;
  if ( *this )
    return sub_792216(*this);
  return result;
}

//----- (0079216E) --------------------------------------------------------
int *__thiscall sub_79216E(_QWORD *this, int *a2, _QWORD *a3)
{
  __int64 v3; // kr00_8
  __int64 v4; // rax

  v3 = sub_791CA5(this);
  v4 = sub_791CA5(a3);
  sub_7921A2(a2, v4 + v3, (unsigned __int64)(v4 + v3) >> 32);
  return a2;
}

//----- (007921A2) --------------------------------------------------------
int *__thiscall sub_7921A2(int *this, int a2, int a3)
{
  int v3; // edx
  int v4; // edx

  *this = sub_79296C();
  this[1] = v3;
  v4 = this[1] ^ a3;
  this[2] = *this ^ a2;
  this[3] = v4;
  return this;
}
// 7921B3: variable 'v3' is possibly undefined

//----- (007921D4) --------------------------------------------------------
__int16 *__thiscall sub_7921D4(unsigned __int16 *this, __int16 *a2, unsigned __int16 *a3)
{
  __int16 v3; // si
  __int16 v4; // ax

  v3 = sub_791D23(this);
  v4 = sub_791D23(a3);
  sub_791D9F(a2, v4 + v3);
  return a2;
}

//----- (00792205) --------------------------------------------------------
void *__thiscall sub_792205(void *this)
{
  return sub_7918A1(this);
}

//----- (00792216) --------------------------------------------------------
int *__thiscall sub_792216(int *this)
{
  int *result; // eax
  int *v2; // [esp+Ch] [ebp-20h]
  int *v3; // [esp+10h] [ebp-1Ch]

  v3 = this + 1;
  v2 = this + 2;
  sub_791642();
  result = this;
  if ( *this )
  {
    sub_7925B7(this, *this, *v3);
    sub_792205(this);
    sub_79261E((void *)*this, (*v2 - *this) >> 3);
    *this = 0;
    *v3 = 0;
    result = v2;
    *v2 = 0;
  }
  return result;
}

//----- (007922C8) --------------------------------------------------------
int __thiscall sub_7922C8(int *this, unsigned int a2)
{
  int v2; // eax
  int result; // eax
  int *v4; // [esp+0h] [ebp-1Ch]
  int *v5; // [esp+4h] [ebp-18h]

  v5 = this + 1;
  v4 = this + 2;
  sub_792205(this);
  v2 = sub_7925D9(a2);
  *this = v2;
  *v5 = v2;
  result = v2 + 8 * a2;
  *v4 = result;
  return result;
}

//----- (0079232A) --------------------------------------------------------
_BYTE *__thiscall sub_79232A(void **this)
{
  void *Block; // [esp+4h] [ebp-18h]
  char v4; // [esp+Fh] [ebp-Dh] BYREF

  sub_791642();
  if ( sub_7926CF(this) )
  {
    Block = *this;
    sub_792205(this);
    sub_792C63();
    sub_7927E0(Block, (int)this[5] + 1);
  }
  this[4] = 0;
  this[5] = (void *)15;
  v4 = 0;
  return sub_792524(this, &v4);
}

//----- (007923C9) --------------------------------------------------------
_BYTE *__thiscall sub_7923C9(int this)
{
  char v2; // [esp+7h] [ebp-1h] BYREF

  *(_DWORD *)(this + 16) = 0;
  *(_DWORD *)(this + 20) = 15;
  v2 = 0;
  return sub_792524((_BYTE *)this, &v2);
}

//----- (007923FD) --------------------------------------------------------
unsigned int *__thiscall sub_7923FD(unsigned int *this, char *Src)
{
  int v2; // eax
  int v3; // eax

  v2 = sub_792533(Src);
  v3 = unknown_libname_3(v2);
  return sub_792424(this, Src, v3);
}

//----- (00792424) --------------------------------------------------------
unsigned int *__thiscall sub_792424(unsigned int *this, char *Src, size_t Size)
{
  char v4; // [esp+0h] [ebp-10h]
  char *v5; // [esp+4h] [ebp-Ch]
  char v7; // [esp+Fh] [ebp-1h] BYREF

  if ( Size > this[5] )
    return sub_792C68(this, Size, v4, Src);
  v5 = (char *)sub_7924C0(this);
  this[4] = Size;
  sub_7926F2(v5, Src, Size);
  v7 = 0;
  sub_792524(&v5[Size], &v7);
  return this;
}
// 792484: variable 'v4' is possibly undefined

//----- (0079248D) --------------------------------------------------------
_BYTE *__stdcall sub_79248D(_BYTE *a1, size_t Size, _BYTE *Src)
{
  char v4; // [esp+7h] [ebp-1h] BYREF

  sub_792565(a1, Src, Size);
  v4 = 0;
  return sub_792524(&a1[Size], &v4);
}

//----- (007924C0) --------------------------------------------------------
int *__thiscall sub_7924C0(int *this)
{
  int *v2; // [esp+0h] [ebp-8h]

  v2 = this;
  if ( sub_7926CF(this) )
    return (int *)unknown_libname_3(*this);
  return v2;
}

//----- (007924F8) --------------------------------------------------------
bool __cdecl sub_7924F8(_DWORD *a1, _DWORD *a2)
{
  return *a1 == *a2;
}

//----- (00792524) --------------------------------------------------------
_BYTE *__cdecl sub_792524(_BYTE *a1, _BYTE *a2)
{
  _BYTE *result; // eax

  result = a1;
  *a1 = *a2;
  return result;
}

//----- (00792533) --------------------------------------------------------
unsigned int __cdecl sub_792533(const char *a1)
{
  return strlen(a1);
}

//----- (00792565) --------------------------------------------------------
_BYTE *__cdecl sub_792565(_BYTE *a1, _BYTE *Src, size_t Size)
{
  size_t i; // [esp+0h] [ebp-4h]

  if ( sub_791328() )
  {
    for ( i = 0; i < Size; ++i )
      a1[i] = Src[i];
    return a1;
  }
  else
  {
    memcpy(a1, Src, Size);
    return a1;
  }
}

//----- (007925B7) --------------------------------------------------------
void __thiscall sub_7925B7(void *this, int a2, int a3)
{
  sub_792205(this);
  sub_792C63();
}

//----- (007925D9) --------------------------------------------------------
int __stdcall sub_7925D9(unsigned int a1)
{
  int v1; // eax

  v1 = sub_792D4A(a1);
  return sub_792D70(v1);
}
// 792D70: using guessed type int __cdecl sub_792D70(_DWORD);

//----- (007925F4) --------------------------------------------------------
_DWORD *__cdecl sub_7925F4(_DWORD *a1, _DWORD *a2)
{
  if ( *a1 >= *a2 )
    return a1;
  else
    return a2;
}

//----- (0079261E) --------------------------------------------------------
void __stdcall sub_79261E(void *Block, int a2)
{
  sub_792D9C(Block, 8 * a2);
}

//----- (0079263A) --------------------------------------------------------
_BYTE *__thiscall sub_79263A(int *this, int a2)
{
  int *v3; // [esp+4h] [ebp-Ch]
  char v5; // [esp+Fh] [ebp-1h] BYREF

  v5 = 0;
  v3 = sub_7924C0(this);
  this[4] = a2;
  return sub_792524((_BYTE *)v3 + a2, &v5);
}

//----- (00792677) --------------------------------------------------------
int __thiscall sub_792677(void *this)
{
  void *v1; // eax
  int v3; // [esp+0h] [ebp-18h] BYREF
  int v4; // [esp+4h] [ebp-14h] BYREF
  int v5; // [esp+8h] [ebp-10h]
  int v6; // [esp+Ch] [ebp-Ch] BYREF
  int v7[2]; // [esp+10h] [ebp-8h] BYREF

  v7[1] = (int)this;
  v1 = sub_792205(this);
  v6 = std::numeric_limits<unsigned int>::max(v1);
  v7[0] = 16;
  v5 = *sub_7925F4(&v6, v7);
  v4 = v5 - 1;
  v3 = unknown_libname_1();
  return *sub_792B21(&v3, &v4);
}
// 79159B: using guessed type int unknown_libname_1(void);
// 7924F0: using guessed type int __cdecl std::numeric_limits<unsigned int>::max(_DWORD);

//----- (007926CF) --------------------------------------------------------
bool __thiscall sub_7926CF(_DWORD *this)
{
  return this[5] >= 0x10u;
}

//----- (007926F2) --------------------------------------------------------
char *__cdecl sub_7926F2(char *a1, char *Src, size_t Size)
{
  char *i; // [esp+4h] [ebp-10h]
  size_t k; // [esp+8h] [ebp-Ch]
  size_t j; // [esp+Ch] [ebp-8h]
  char v7; // [esp+13h] [ebp-1h]

  if ( sub_791328() )
  {
    if ( a1 == Src )
    {
      return a1;
    }
    else
    {
      v7 = 1;
      for ( i = Src; i != &Src[Size]; ++i )
      {
        if ( a1 == i )
        {
          v7 = 0;
          break;
        }
      }
      if ( v7 )
      {
        for ( j = 0; j < Size; ++j )
          a1[j] = Src[j];
      }
      else
      {
        for ( k = 0; k < Size; ++k )
          a1[Size - 1 - k] = Src[Size - 1 - k];
      }
      return a1;
    }
  }
  else
  {
    memmove(a1, Src, Size);
    return a1;
  }
}

//----- (007927C5) --------------------------------------------------------
void *__stdcall sub_7927C5(int a1)
{
  int v1; // eax

  v1 = sub_792DEA(a1);
  return sub_792D70(v1);
}

//----- (007927E0) --------------------------------------------------------
void __stdcall sub_7927E0(void *Block, int a2)
{
  sub_792D9C(Block, a2);
}

//----- (007927F8) --------------------------------------------------------
void __thiscall sub_7927F8(_DWORD *this, unsigned int a2)
{
  if ( this[4] < a2 )
    sub_792813();
}

//----- (00792813) --------------------------------------------------------
void sub_792813()
{
  std::_Xout_of_range("invalid string position");
}
// 797078: using guessed type void __cdecl std::_Xout_of_range(const char *);

//----- (00792823) --------------------------------------------------------
struct std::_Facet_base *__cdecl sub_792823(_DWORD *a1)
{
  struct std::_Facet_base *v2; // [esp+0h] [ebp-28h]
  char v3[4]; // [esp+4h] [ebp-24h] BYREF
  unsigned int v4; // [esp+8h] [ebp-20h]
  int (__thiscall ***v5)(_DWORD, int); // [esp+Ch] [ebp-1Ch] BYREF
  struct std::_Facet_base *v6; // [esp+10h] [ebp-18h]
  struct std::_Facet_base *v7; // [esp+14h] [ebp-14h]
  struct std::_Facet_base *v8; // [esp+18h] [ebp-10h] BYREF
  int v9; // [esp+24h] [ebp-4h]

  std::_Lockit::_Lockit((std::_Lockit *)v3, 0);
  v9 = 0;
  v8 = (struct std::_Facet_base *)dword_799430;
  v4 = std::locale::id::operator unsigned int(std::ctype<char>::id);
  v6 = (struct std::_Facet_base *)sub_791721(a1, v4);
  if ( !v6 )
  {
    if ( v8 )
    {
      v6 = v8;
    }
    else
    {
      if ( std::ctype<char>::_Getcat(&v8, a1) == -1 )
        sub_791698();
      v7 = v8;
      sub_7931DB(&v5, (char)v8);
      LOBYTE(v9) = 1;
      std::_Facet_Register(v7);
      (*(void (__thiscall **)(struct std::_Facet_base *))(*(_DWORD *)v7 + 4))(v7);
      dword_799430 = (int)v8;
      v6 = v8;
      sub_792DF7((int *)&v5);
      LOBYTE(v9) = 0;
      sub_792E13(&v5);
    }
  }
  v2 = v6;
  v9 = -1;
  std::_Lockit::~_Lockit((std::_Lockit *)v3);
  return v2;
}
// 79704C: using guessed type int __cdecl std::ctype<char>::_Getcat(_DWORD, _DWORD);
// 797054: using guessed type int __thiscall std::locale::id::operator unsigned int(_DWORD);
// 797084: using guessed type _DWORD __thiscall std::_Lockit::_Lockit(std::_Lockit *__hidden this, _DWORD);
// 797088: using guessed type void __thiscall std::_Lockit::~_Lockit(std::_Lockit *__hidden this);
// 799430: using guessed type int dword_799430;
// 792823: using guessed type char var_24[4];

//----- (0079290E) --------------------------------------------------------
int __cdecl sub_79290E(int a1, _DWORD *a2)
{
  int v2; // eax

  v2 = unknown_libname_3(a1);
  return sub_792F66(v2, a2);
}

//----- (00792927) --------------------------------------------------------
_QWORD *__thiscall sub_792927(_QWORD *this, int *a2)
{
  *this = *a2;
  return this;
}

//----- (00792943) --------------------------------------------------------
BOOL __cdecl sub_792943(void *a1)
{
  _DWORD *v1; // eax
  _DWORD *v2; // eax
  int v4; // [esp+0h] [ebp-10h] BYREF
  int v5; // [esp+8h] [ebp-8h] BYREF

  v1 = sub_7917C3(&v5);
  v2 = sub_793200(&v4, v1, a1);
  return sub_793230(v2);
}

//----- (0079296C) --------------------------------------------------------
int sub_79296C()
{
  __int64 v1; // [esp+0h] [ebp-10h]
  __int64 v2; // [esp+8h] [ebp-8h]

  v2 = sub_7915BF();
  v1 = sub_7915B6();
  return sub_793285(v1, SHIDWORD(v1), v2, SHIDWORD(v2));
}

//----- (0079299E) --------------------------------------------------------
__int16 sub_79299E()
{
  __int16 v0; // ax
  __int16 v2; // [esp+4h] [ebp-4h]

  v2 = unknown_libname_2();
  v0 = __scrt_stub_for_initialize_mta();
  return sub_7932D3(v0, v2);
}
// 7915AC: using guessed type int unknown_libname_2(void);

//----- (007929C4) --------------------------------------------------------
int sub_7929C4()
{
  int v1; // [esp+0h] [ebp-8h]
  int v2; // [esp+4h] [ebp-4h]

  v2 = unknown_libname_1();
  v1 = std::numeric_limits<int>::min();
  return sub_79331B(v1, v2);
}
// 791591: using guessed type int std::numeric_limits<int>::min(void);
// 79159B: using guessed type int unknown_libname_1(void);

//----- (007929E8) --------------------------------------------------------
void __thiscall sub_7929E8(int *this, unsigned int a2, unsigned __int8 *a3)
{
  int v3; // [esp+4h] [ebp-1Ch]
  unsigned int v4; // [esp+8h] [ebp-18h]
  int v5; // [esp+14h] [ebp-Ch]
  int *v7; // [esp+1Ch] [ebp-4h]

  v7 = this + 1;
  v4 = (this[1] - *this) >> 3;
  if ( a2 >= v4 )
  {
    if ( a2 > v4 )
    {
      if ( a2 <= (this[2] - *this) >> 3 )
      {
        v3 = *v7;
        *v7 = sub_792E6F(this, *v7, a2 - v4, *a3);
        sub_792E64(v3, v3);
      }
      else
      {
        sub_793363(this, a2, a3);
      }
    }
  }
  else
  {
    v5 = *this + 8 * a2;
    sub_792E64(v5, *v7);
    sub_7925B7(this, v5, *v7);
    *v7 = v5;
  }
}

//----- (00792ABF) --------------------------------------------------------
_DWORD *__thiscall sub_792ABF(_DWORD *this, int a2, int a3)
{
  unknown_libname_3(a3);
  sub_792E44(this);
  return this;
}

//----- (00792ADE) --------------------------------------------------------
int __thiscall sub_792ADE(void *this, int a2, int a3, int a4)
{
  void *v4; // eax

  v4 = sub_792205(this);
  return sub_79349C(a2, a3, a4, (int)v4);
}

//----- (00792B03) --------------------------------------------------------
_DWORD *__thiscall sub_792B03(_DWORD *this, int a2)
{
  sub_7918A1(this);
  sub_792E44(this);
  return this;
}

//----- (00792B21) --------------------------------------------------------
_DWORD *__cdecl sub_792B21(_DWORD *a1, _DWORD *a2)
{
  if ( *a2 >= *a1 )
    return a1;
  else
    return a2;
}

//----- (00792B4B) --------------------------------------------------------
unsigned int *__thiscall sub_792B4B(size_t *this, size_t a2, char a3, char a4)
{
  _BYTE *v4; // eax
  _BYTE *v5; // eax
  _BYTE *v7; // [esp+0h] [ebp-28h]
  void *Block; // [esp+8h] [ebp-20h]
  unsigned int v9; // [esp+Ch] [ebp-1Ch]
  unsigned int v10; // [esp+10h] [ebp-18h]
  void *v11; // [esp+18h] [ebp-10h] BYREF
  size_t Size; // [esp+1Ch] [ebp-Ch]
  unsigned int *v13; // [esp+20h] [ebp-8h]
  void *Src; // [esp+24h] [ebp-4h]

  v13 = this;
  Src = this;
  Size = this[4];
  if ( sub_792677(this) - Size < a2 )
    sub_791664();
  v9 = *((_DWORD *)Src + 5);
  v10 = sub_792E91(v13, a2 + Size);
  sub_792205(v13);
  v11 = sub_7927C5(v10 + 1);
  sub_791642();
  *((_DWORD *)Src + 4) = a2 + Size;
  *((_DWORD *)Src + 5) = v10;
  v4 = (_BYTE *)unknown_libname_3((int)v11);
  v7 = v4;
  if ( v9 < 0x10 )
  {
    sub_792042(v4, Src, Size, a4);
    sub_792D1E((int)Src, (int)&v11);
  }
  else
  {
    Block = *(void **)Src;
    v5 = (_BYTE *)unknown_libname_3(*(_DWORD *)Src);
    sub_792042(v7, v5, Size, a4);
    sub_7927E0(Block, v9 + 1);
    *(_DWORD *)Src = v11;
  }
  return v13;
}

//----- (00792C45) --------------------------------------------------------
_DWORD *__thiscall sub_792C45(_DWORD *this, int a2)
{
  sub_7918A1(this);
  sub_792EC3(this);
  return this;
}

//----- (00792C63) --------------------------------------------------------
void sub_792C63()
{
  ;
}

//----- (00792C68) --------------------------------------------------------
unsigned int *__thiscall sub_792C68(unsigned int *this, size_t Size, char a3, _BYTE *Src)
{
  _BYTE *v4; // eax
  unsigned int v6; // [esp+4h] [ebp-10h]
  unsigned int v7; // [esp+8h] [ebp-Ch]
  void *v8; // [esp+Ch] [ebp-8h] BYREF
  unsigned int *v9; // [esp+10h] [ebp-4h]

  v9 = this;
  if ( Size > sub_792677(this) )
    sub_791664();
  v6 = v9[5];
  v7 = sub_792E91(v9, Size);
  sub_792205(v9);
  v8 = sub_7927C5(v7 + 1);
  sub_791642();
  v9[4] = Size;
  v9[5] = v7;
  v4 = (_BYTE *)unknown_libname_3((int)v8);
  sub_79248D(v4, Size, Src);
  if ( v6 < 0x10 )
  {
    sub_792D1E((int)v9, (int)&v8);
  }
  else
  {
    sub_7927E0((void *)*v9, v6 + 1);
    *v9 = (unsigned int)v8;
  }
  return v9;
}

//----- (00792D1E) --------------------------------------------------------
int __cdecl sub_792D1E(int a1, int a2)
{
  void *v2; // eax
  int result; // eax
  _DWORD *v4; // [esp+0h] [ebp-4h]

  v2 = (void *)unknown_libname_3(a1);
  v4 = operator new(4u, v2);
  result = *(_DWORD *)unknown_libname_3(a2);
  *v4 = result;
  return result;
}

//----- (00792D4A) --------------------------------------------------------
unsigned int __cdecl sub_792D4A(unsigned int a1)
{
  if ( a1 > 0x1FFFFFFF )
    sub_79152F();
  return 8 * a1;
}

//----- (00792D70) --------------------------------------------------------
void *__cdecl sub_792D70(unsigned int Size)
{
  if ( Size >= 0x1000 )
    return (void *)sub_793533(Size);
  if ( Size )
    return operator new(Size);
  return 0;
}

//----- (00792D9C) --------------------------------------------------------
void __cdecl sub_792D9C(void *Block, unsigned int a2)
{
  if ( a2 >= 0x1000 )
    sub_7915D8(&Block, &a2);
  sub_795312(Block);
}

//----- (00792DEA) --------------------------------------------------------
int __cdecl sub_792DEA(int a1)
{
  return a1;
}

//----- (00792DF7) --------------------------------------------------------
int __thiscall sub_792DF7(int *this)
{
  int v2; // [esp+4h] [ebp-4h] BYREF

  v2 = 0;
  return sub_793591(this, &v2);
}

//----- (00792E13) --------------------------------------------------------
int (__thiscall ***__thiscall sub_792E13(int (__thiscall ****this)(_DWORD, int)))(_DWORD, int)
{
  int (__thiscall ***result)(_DWORD, int); // eax

  result = (int (__thiscall ***)(_DWORD, int))this;
  if ( *this )
  {
    sub_7918A1(this);
    return sub_792EE5(*this);
  }
  return result;
}

//----- (00792E44) --------------------------------------------------------
_DWORD *__thiscall sub_792E44(_DWORD *this)
{
  *this = 0;
  this[1] = 0;
  this[2] = 0;
  return this;
}

//----- (00792E64) --------------------------------------------------------
void __stdcall sub_792E64(int a1, int a2)
{
  ;
}

//----- (00792E6F) --------------------------------------------------------
int __thiscall sub_792E6F(void *this, int a2, int a3, int a4)
{
  void *v4; // eax

  v4 = sub_792205(this);
  return sub_7935AC(a2, a3, (int)v4);
}

//----- (00792E91) --------------------------------------------------------
unsigned int __thiscall sub_792E91(unsigned int *this, int a2)
{
  int v3; // [esp+4h] [ebp-8h]

  v3 = sub_792677(this);
  return sub_792F19(a2, this[5], v3);
}

//----- (00792EC3) --------------------------------------------------------
_DWORD *__thiscall sub_792EC3(_DWORD *this)
{
  sub_7918A1(this);
  this[4] = 0;
  this[5] = 0;
  return this;
}

//----- (00792EE5) --------------------------------------------------------
int (__thiscall ***__stdcall sub_792EE5(int (__thiscall ***a1)(_DWORD, int)))(_DWORD, int)
{
  int (__thiscall ***result)(_DWORD, int); // eax

  result = a1;
  if ( a1 )
    return (int (__thiscall ***)(_DWORD, int))(**a1)(a1, 1);
  return result;
}

//----- (00792F19) --------------------------------------------------------
unsigned int __cdecl sub_792F19(int a1, unsigned int a2, unsigned int a3)
{
  int v4; // [esp+0h] [ebp-8h] BYREF
  int v5; // [esp+4h] [ebp-4h] BYREF

  v5 = a1 | 0xF;
  if ( (a1 | 0xFu) > a3 )
    return a3;
  if ( a2 > a3 - (a2 >> 1) )
    return a3;
  v4 = a2 + (a2 >> 1);
  return *sub_7925F4(&v5, &v4);
}

//----- (00792F66) --------------------------------------------------------
int __cdecl sub_792F66(int a1, _DWORD *a2)
{
  unsigned int v2; // eax
  unsigned __int8 v3; // al
  char v4; // al
  int v6; // [esp+0h] [ebp-88h] BYREF
  int v7; // [esp+4h] [ebp-84h]
  int v8; // [esp+8h] [ebp-80h]
  _DWORD *v9[2]; // [esp+Ch] [ebp-7Ch] BYREF
  int v10[2]; // [esp+14h] [ebp-74h] BYREF
  __int64 v11; // [esp+1Ch] [ebp-6Ch]
  __int64 v12; // [esp+24h] [ebp-64h]
  __int64 v13; // [esp+2Ch] [ebp-5Ch]
  int v14; // [esp+34h] [ebp-54h]
  std::ios_base *v15; // [esp+3Ch] [ebp-4Ch]
  int v16; // [esp+40h] [ebp-48h]
  struct std::_Facet_base *v17; // [esp+44h] [ebp-44h]
  int v18; // [esp+48h] [ebp-40h] BYREF
  int v19; // [esp+4Ch] [ebp-3Ch]
  int v20; // [esp+50h] [ebp-38h]
  int v21; // [esp+54h] [ebp-34h]
  int v22; // [esp+58h] [ebp-30h]
  _DWORD *v23; // [esp+5Ch] [ebp-2Ch]
  _DWORD *v24; // [esp+60h] [ebp-28h]
  int v25; // [esp+64h] [ebp-24h]
  int v26; // [esp+68h] [ebp-20h] BYREF
  int v27; // [esp+6Ch] [ebp-1Ch]
  int v28; // [esp+70h] [ebp-18h]
  int v29; // [esp+74h] [ebp-14h]
  int *v30; // [esp+78h] [ebp-10h]
  int v31; // [esp+7Ch] [ebp-Ch]
  int v32; // [esp+80h] [ebp-8h]
  int v33; // [esp+84h] [ebp-4h]

  v30 = &v6;
  v28 = 0;
  HIBYTE(v29) = 0;
  sub_7936F6(v10, a1, 0);
  v33 = 0;
  if ( sub_7936E7(v10) )
  {
    v25 = *(_DWORD *)(*(_DWORD *)a1 + 4) + a1;
    v24 = (_DWORD *)std::ios_base::getloc(v25, v9);
    v23 = v24;
    LOBYTE(v33) = 1;
    v17 = sub_792823(v24);
    LOBYTE(v33) = 0;
    sub_7916D8(v9);
    sub_79392C(a2, 0);
    LOBYTE(v33) = 2;
    v13 = std::ios_base::width((std::ios_base *)(*(_DWORD *)(*(_DWORD *)a1 + 4) + a1));
    if ( v13 <= 0
      || (v12 = std::ios_base::width((std::ios_base *)(*(_DWORD *)(*(_DWORD *)a1 + 4) + a1)),
          v2 = sub_792677(a2),
          (unsigned int)v12 >= v2) )
    {
      v27 = sub_792677(a2);
    }
    else
    {
      v11 = std::ios_base::width((std::ios_base *)(*(_DWORD *)(*(_DWORD *)a1 + 4) + a1));
      v27 = v11;
    }
    v22 = std::ios::rdbuf(*(_DWORD *)(*(_DWORD *)a1 + 4) + a1, v6, v7);
    v21 = std::streambuf::sgetc(v22);
    v26 = v21;
    while ( v27 )
    {
      v18 = std::numeric_limits<unsigned int>::max(v6);
      if ( sub_7924F8(&v18, &v26) )
      {
        v28 |= 1u;
        break;
      }
      v3 = std::_Narrow_char_traits<char,int>::to_char_type(&v26);
      BYTE2(v29) = std::ctype<char>::is(v17, 72, v3);
      if ( BYTE2(v29) )
        break;
      v4 = std::_Narrow_char_traits<char,int>::to_char_type(&v26);
      sub_791FCE(a2, v4);
      HIBYTE(v29) = 1;
      --v27;
      v20 = std::ios::rdbuf(*(_DWORD *)(*(_DWORD *)a1 + 4) + a1, v6, v7);
      v19 = std::streambuf::snextc(v20);
      v26 = v19;
    }
    v33 = 0;
  }
  v15 = (std::ios_base *)(*(_DWORD *)(*(_DWORD *)a1 + 4) + a1);
  std::ios_base::width(v15, 0i64);
  if ( !HIBYTE(v29) )
    v28 |= 2u;
  std::ios::setstate(
    *(_DWORD *)(*(_DWORD *)a1 + 4) + a1,
    v28,
    0,
    v6,
    v7,
    v8,
    v9[0],
    v9[1],
    v10[0],
    v10[1],
    v11,
    HIDWORD(v11),
    v12,
    HIDWORD(v12),
    v13,
    HIDWORD(v13),
    v14,
    *(_DWORD *)(*(_DWORD *)a1 + 4) + a1,
    v15,
    v16,
    v17,
    v18,
    v19,
    v20,
    v21,
    v22,
    v23,
    v24,
    v25,
    v26,
    v27,
    v28,
    v29,
    v30,
    v31,
    v32,
    v33);
  v14 = a1;
  v33 = -1;
  sub_793618(v10);
  return v14;
}
// 7924F0: using guessed type int __cdecl std::numeric_limits<unsigned int>::max(_DWORD);
// 79251A: using guessed type _DWORD __cdecl std::_Narrow_char_traits<char,int>::to_char_type(_DWORD);
// 797034: using guessed type int __thiscall std::ios::setstate(_DWORD, _DWORD, _DWORD, _DWORD, _DWORD, _DWORD, _DWORD, _DWORD, _DWORD, _DWORD, _DWORD, _DWORD, _DWORD, _DWORD, _DWORD, _DWORD, _DWORD, _DWORD, _DWORD, _DWORD, _DWORD, _DWORD, _DWORD, _DWORD, _DWORD, _DWORD, _DWORD, _DWORD, _DWORD, _DWORD, _DWORD, _DWORD, _DWORD, _DWORD, _DWORD, _DWORD, _DWORD);
// 797038: using guessed type int __thiscall std::ios::rdbuf(_DWORD, _DWORD, _DWORD);
// 79703C: using guessed type int __thiscall std::streambuf::sgetc(_DWORD);
// 797040: using guessed type int __thiscall std::ios_base::getloc(_DWORD, _DWORD);
// 797044: using guessed type int __thiscall std::streambuf::snextc(_DWORD);
// 797048: using guessed type __int64 __thiscall std::ios_base::width(std::ios_base *__hidden this);
// 797050: using guessed type int __thiscall std::ctype<char>::is(_DWORD, _DWORD, _DWORD);
// 79708C: using guessed type __int64 __thiscall std::ios_base::width(std::ios_base *__hidden this, __int64);
// 792F66: using guessed type _DWORD var_74[2];

//----- (007931DB) --------------------------------------------------------
_DWORD *__thiscall sub_7931DB(_DWORD *this, char a2)
{
  int v3; // [esp+0h] [ebp-Ch]

  sub_793BAD(this, v3, (int)&a2);
  return this;
}
// 7931F4: variable 'v3' is possibly undefined

//----- (00793200) --------------------------------------------------------
_DWORD *__cdecl sub_793200(_DWORD *a1, _DWORD *a2, void *a3)
{
  int *v3; // eax
  _DWORD *v4; // eax
  int v6; // [esp+0h] [ebp-10h] BYREF
  int v7; // [esp+8h] [ebp-8h] BYREF

  v3 = sub_791FA1(a2, &v7);
  v4 = sub_793BCB(&v6, v3, a3);
  sub_791F83(a1, v4);
  return a1;
}

//----- (00793230) --------------------------------------------------------
BOOL __cdecl sub_793230(_DWORD *a1)
{
  BOOL result; // eax
  _DWORD *v2; // eax
  xtime v3; // [esp+0h] [ebp-20h] BYREF
  int v4; // [esp+10h] [ebp-10h] BYREF
  int v5[2]; // [esp+18h] [ebp-8h] BYREF

  while ( 1 )
  {
    sub_7917C3(v5);
    result = sub_793C1C(a1, v5);
    if ( result )
      break;
    v2 = sub_793C46(&v4, a1, v5);
    sub_793C80((int)&v3, v2);
    Thrd_sleep(&v3);
  }
  return result;
}
// 793230: using guessed type _DWORD var_8[2];

//----- (00793285) --------------------------------------------------------
int __cdecl sub_793285(int a1, int a2, int a3, int a4)
{
  unsigned int v4; // eax
  int v6[1250]; // [esp+0h] [ebp-139Ch] BYREF
  int v7[4]; // [esp+1388h] [ebp-14h] BYREF
  char v8; // [esp+139Bh] [ebp-1h] BYREF

  sub_7918A1(&v8);
  v4 = sub_7918AD();
  sub_79390C(v6, v4);
  sub_7936C5(v7, a1, a2, a3, a4);
  return sub_793D4C(v7, (int)v6);
}
// 793285: using guessed type _DWORD var_139C[1250];
// 793285: using guessed type int var_14[4];

//----- (007932D3) --------------------------------------------------------
__int16 __cdecl sub_7932D3(__int16 a1, __int16 a2)
{
  unsigned int v2; // eax
  int v4[1250]; // [esp+0h] [ebp-1390h] BYREF
  __int16 v5[3]; // [esp+1388h] [ebp-8h] BYREF
  char v6; // [esp+138Fh] [ebp-1h] BYREF

  sub_7918A1(&v6);
  v2 = sub_7918AD();
  sub_79390C(v4, v2);
  sub_7936A9(v5, a1, a2);
  return sub_793D73(v5, (int)v4);
}
// 7932D3: using guessed type _DWORD var_1390[1250];
// 7932D3: using guessed type __int16 var_8[3];

//----- (0079331B) --------------------------------------------------------
int __cdecl sub_79331B(int a1, int a2)
{
  unsigned int v2; // eax
  int v4[1250]; // [esp+0h] [ebp-1394h] BYREF
  int v5[2]; // [esp+1388h] [ebp-Ch] BYREF
  char v6; // [esp+1393h] [ebp-1h] BYREF

  sub_7918A1(&v6);
  v2 = sub_7918AD();
  sub_79390C(v4, v2);
  sub_79368D(v5, a1, a2);
  return sub_793D98(v5, (int)v4);
}
// 79331B: using guessed type _DWORD var_1394[1250];

//----- (00793363) --------------------------------------------------------
int __thiscall sub_793363(int *this, unsigned int a2, unsigned __int8 *a3)
{
  int v4; // [esp+0h] [ebp-4Ch] BYREF
  int v5; // [esp+10h] [ebp-3Ch]
  void *v6; // [esp+14h] [ebp-38h]
  int v7; // [esp+18h] [ebp-34h]
  int *v8; // [esp+1Ch] [ebp-30h]
  int *v9; // [esp+20h] [ebp-2Ch]
  int v10; // [esp+24h] [ebp-28h]
  int *v11; // [esp+28h] [ebp-24h]
  int v12; // [esp+2Ch] [ebp-20h]
  int v13; // [esp+30h] [ebp-1Ch]
  void *Block; // [esp+34h] [ebp-18h]
  int *v15; // [esp+38h] [ebp-14h]
  int *v16; // [esp+3Ch] [ebp-10h]
  int v17; // [esp+48h] [ebp-4h]

  v16 = &v4;
  v15 = this;
  if ( a2 > sub_7938D6(this) )
    sub_7937AD();
  v11 = v15;
  v8 = v15;
  v9 = v15 + 1;
  v10 = (v15[1] - *v15) >> 3;
  v12 = sub_79385F(v15, a2);
  v6 = sub_792205(v15);
  Block = (void *)sub_7925D9(v12);
  v13 = (int)Block + 8 * v10;
  v7 = v13;
  v17 = 0;
  v5 = sub_792E6F(v15, v13, a2 - v10, *a3);
  v7 = v5;
  sub_7938B1(v15, *v8, *v9, (int)Block);
  v17 = -1;
  return sub_7937BD((void **)v15, Block, a2, v12);
}

//----- (0079349C) --------------------------------------------------------
int __cdecl sub_79349C(int a1, int a2, int a3, int a4)
{
  int v5[3]; // [esp+0h] [ebp-20h] BYREF
  int v6; // [esp+Ch] [ebp-14h]
  int v7; // [esp+10h] [ebp-10h]
  int v8; // [esp+1Ch] [ebp-4h]

  v7 = unknown_libname_4(&a1);
  v6 = unknown_libname_4(&a2);
  sub_793665(v5, a3, a4);
  v8 = 0;
  while ( v7 != v6 )
  {
    sub_793DB9(v5, v7);
    v7 += 8;
  }
  a3 = sub_793629(v5);
  v8 = -1;
  sub_793643();
  return a3;
}
// 793529: using guessed type _DWORD __cdecl unknown_libname_4(_DWORD);
// 79349C: using guessed type _DWORD var_20[3];

//----- (00793533) --------------------------------------------------------
unsigned int __cdecl sub_793533(unsigned int a1)
{
  void *v1; // eax

  if ( a1 + 35 <= a1 )
    sub_79152F();
  v1 = operator new(a1 + 35);
  if ( !v1 )
    invalid_parameter_noinfo_noreturn();
  *(_DWORD *)((((unsigned int)v1 + 35) & 0xFFFFFFE0) - 4) = v1;
  return ((unsigned int)v1 + 35) & 0xFFFFFFE0;
}

//----- (00793591) --------------------------------------------------------
int __cdecl sub_793591(int *a1, int *a2)
{
  int v3; // [esp+0h] [ebp-4h]

  v3 = *a1;
  *a1 = *a2;
  return v3;
}

//----- (007935AC) --------------------------------------------------------
int __cdecl sub_7935AC(int a1, int a2, int a3)
{
  int v4[3]; // [esp+0h] [ebp-1Ch] BYREF
  int v5; // [esp+Ch] [ebp-10h]
  int v6; // [esp+18h] [ebp-4h]

  sub_793665(v4, a1, a3);
  v6 = 0;
  while ( a2 )
  {
    sub_793E0A(v4);
    --a2;
  }
  v5 = sub_793629(v4);
  v6 = -1;
  sub_793643();
  return v5;
}
// 7935AC: using guessed type _DWORD var_1C[3];

//----- (00793618) --------------------------------------------------------
int __thiscall sub_793618(_DWORD *this)
{
  return sub_793751(this);
}

//----- (00793629) --------------------------------------------------------
int __thiscall sub_793629(_DWORD *this)
{
  *this = this[1];
  return this[1];
}

//----- (00793643) --------------------------------------------------------
void sub_793643()
{
  sub_792C63();
}

//----- (00793665) --------------------------------------------------------
_DWORD *__thiscall sub_793665(_DWORD *this, int a2, int a3)
{
  *this = a2;
  this[1] = a2;
  this[2] = a3;
  return this;
}

//----- (0079368D) --------------------------------------------------------
_DWORD *__thiscall sub_79368D(_DWORD *this, int a2, int a3)
{
  sub_793957(this, a2, a3);
  return this;
}

//----- (007936A9) --------------------------------------------------------
_WORD *__thiscall sub_7936A9(_WORD *this, __int16 a2, __int16 a3)
{
  sub_79397A(this, a2, a3);
  return this;
}

//----- (007936C5) --------------------------------------------------------
_DWORD *__thiscall sub_7936C5(_DWORD *this, int a2, int a3, int a4, int a5)
{
  sub_79399D(this, a2, a3, a4, a5);
  return this;
}

//----- (007936E7) --------------------------------------------------------
char __thiscall sub_7936E7(_BYTE *this)
{
  return this[4];
}

//----- (007936F6) --------------------------------------------------------
_DWORD *__thiscall sub_7936F6(_DWORD *this, int a2, int a3)
{
  sub_7939C6(this, a2);
  *((_BYTE *)this + 4) = std::istream::_Ipfx(*this, a3);
  return this;
}
// 797058: using guessed type int __thiscall std::istream::_Ipfx(_DWORD, _DWORD);

//----- (00793751) --------------------------------------------------------
// positive sp value has been detected, the output may be wrong!
int __thiscall sub_793751(_DWORD *this)
{
  int result; // eax

  result = ((int (__thiscall *)(int))std::ios::rdbuf)(*(_DWORD *)(*(_DWORD *)*this + 4) + *this);
  if ( result )
    return (*(int (__thiscall **)(int, _DWORD *))(*(_DWORD *)result + 8))(result, this);
  return result;
}
// 7937A7: positive sp value 8 has been found
// 797038: using guessed type int __thiscall std::ios::rdbuf(_DWORD, _DWORD, _DWORD);

//----- (007937AD) --------------------------------------------------------
void __noreturn sub_7937AD()
{
  std::_Xlength_error("vector too long");
}
// 79706C: using guessed type void __cdecl __noreturn std::_Xlength_error(const char *);

//----- (007937BD) --------------------------------------------------------
int __thiscall sub_7937BD(void **this, void *a2, int a3, int a4)
{
  int result; // eax
  int *v5; // [esp+Ch] [ebp-14h]
  int *v6; // [esp+10h] [ebp-10h]

  v6 = (int *)(this + 1);
  v5 = (int *)(this + 2);
  sub_791642();
  if ( *this )
  {
    sub_7925B7(this, (int)*this, *v6);
    sub_792205(this);
    sub_79261E(*this, (*v5 - (int)*this) >> 3);
  }
  *this = a2;
  *v6 = (int)a2 + 8 * a3;
  result = (int)a2 + 8 * a4;
  *v5 = result;
  return result;
}

//----- (0079385F) --------------------------------------------------------
unsigned int __thiscall sub_79385F(_DWORD *this, unsigned int a2)
{
  int v3; // [esp+4h] [ebp-Ch]
  unsigned int v5; // [esp+Ch] [ebp-4h]

  v5 = sub_793A30(this);
  v3 = sub_7938D6(this);
  if ( v5 > v3 - (v5 >> 1) )
    return v3;
  if ( v5 + (v5 >> 1) >= a2 )
    return v5 + (v5 >> 1);
  return a2;
}

//----- (007938B1) --------------------------------------------------------
int __thiscall sub_7938B1(void *this, int a2, int a3, int a4)
{
  int v5; // [esp+4h] [ebp-4h]

  LOBYTE(v5) = 0;
  return sub_793A0B(this, a2, a3, a4, v5);
}
// 7938CD: variable 'v5' is possibly undefined

//----- (007938D6) --------------------------------------------------------
int __thiscall sub_7938D6(void *this)
{
  int v2; // [esp+0h] [ebp-Ch] BYREF
  int v3[2]; // [esp+4h] [ebp-8h] BYREF

  v3[1] = (int)this;
  sub_792205(this);
  v3[0] = sub_793A4E();
  v2 = unknown_libname_1();
  return *sub_792B21(&v2, v3);
}
// 79159B: using guessed type int unknown_libname_1(void);

//----- (0079390C) --------------------------------------------------------
_DWORD *__thiscall sub_79390C(_DWORD *this, unsigned int a2)
{
  sub_793A58(this, a2, -1, 1812433253);
  return this;
}

//----- (0079392C) --------------------------------------------------------
int *__thiscall sub_79392C(int *this, unsigned int a2)
{
  sub_7927F8(this, a2);
  sub_79263A(this, a2);
  return this;
}

//----- (00793957) --------------------------------------------------------
_DWORD *__thiscall sub_793957(_DWORD *this, int a2, int a3)
{
  sub_793A80(this, a2, a3);
  return this;
}

//----- (0079397A) --------------------------------------------------------
_WORD *__thiscall sub_79397A(_WORD *this, __int16 a2, __int16 a3)
{
  sub_793A9C(this, a2, a3);
  return this;
}

//----- (0079399D) --------------------------------------------------------
_DWORD *__thiscall sub_79399D(_DWORD *this, int a2, int a3, int a4, int a5)
{
  sub_793AB8(this, a2, a3, a4, a5);
  return this;
}

//----- (007939C6) --------------------------------------------------------
int __thiscall sub_7939C6(_DWORD *this, int a2)
{
  int v3; // [esp+4h] [ebp-8h]
  int v4; // [esp+8h] [ebp-4h]

  *this = a2;
  v4 = std::ios::rdbuf(*(_DWORD *)(*(_DWORD *)*this + 4) + *this, *this, this);
  if ( v4 )
    (*(void (__thiscall **)(int))(*(_DWORD *)v4 + 4))(v4);
  return v3;
}
// 793A04: variable 'v3' is possibly undefined
// 797038: using guessed type int __thiscall std::ios::rdbuf(_DWORD, _DWORD, _DWORD);

//----- (00793A0B) --------------------------------------------------------
int __thiscall sub_793A0B(void *this, int a2, int a3, int a4, int a5)
{
  void *v5; // eax

  v5 = sub_792205(this);
  return sub_79349C(a2, a3, a4, (int)v5);
}

//----- (00793A30) --------------------------------------------------------
int __thiscall sub_793A30(_DWORD *this)
{
  return (this[2] - *this) >> 3;
}

//----- (00793A4E) --------------------------------------------------------
int sub_793A4E()
{
  return 0x1FFFFFFF;
}

//----- (00793A58) --------------------------------------------------------
_DWORD *__thiscall sub_793A58(_DWORD *this, unsigned int a2, int a3, int a4)
{
  this[1249] = a3;
  sub_793ADA(this, a2, a4);
  return this;
}

//----- (00793A80) --------------------------------------------------------
_DWORD *__thiscall sub_793A80(_DWORD *this, int a2, int a3)
{
  sub_793B49(this, a2, a3);
  return this;
}

//----- (00793A9C) --------------------------------------------------------
_WORD *__thiscall sub_793A9C(_WORD *this, __int16 a2, __int16 a3)
{
  sub_793B65(this, a2, a3);
  return this;
}

//----- (00793AB8) --------------------------------------------------------
_DWORD *__thiscall sub_793AB8(_DWORD *this, int a2, int a3, int a4, int a5)
{
  sub_793B85(this, a2, a3, a4, a5);
  return this;
}

//----- (00793ADA) --------------------------------------------------------
_DWORD *__thiscall sub_793ADA(_DWORD *this, unsigned int a2, int a3)
{
  int v3; // eax
  _DWORD *result; // eax
  unsigned int v5; // [esp+8h] [ebp-8h]
  unsigned int i; // [esp+Ch] [ebp-4h]

  this[1] = a2;
  v5 = a2;
  for ( i = 1; i < 0x270; ++i )
  {
    v3 = a3 * (v5 ^ (v5 >> 30));
    this[i + 1] = v3 + i;
    v5 = v3 + i;
  }
  result = this;
  *this = 624;
  return result;
}

//----- (00793B49) --------------------------------------------------------
_DWORD *__thiscall sub_793B49(_DWORD *this, int a2, int a3)
{
  _DWORD *result; // eax

  *this = a2;
  result = this;
  this[1] = a3;
  return result;
}

//----- (00793B65) --------------------------------------------------------
_WORD *__thiscall sub_793B65(_WORD *this, __int16 a2, __int16 a3)
{
  _WORD *result; // eax

  *this = a2;
  result = this;
  this[1] = a3;
  return result;
}

//----- (00793B85) --------------------------------------------------------
_DWORD *__thiscall sub_793B85(_DWORD *this, int a2, int a3, int a4, int a5)
{
  _DWORD *result; // eax

  *this = a2;
  this[1] = a3;
  result = this;
  this[2] = a4;
  this[3] = a5;
  return result;
}

//----- (00793BAD) --------------------------------------------------------
_DWORD *__thiscall sub_793BAD(_DWORD *this, int a2, int a3)
{
  *this = *(_DWORD *)unknown_libname_3(a3);
  return this;
}

//----- (00793BCB) --------------------------------------------------------
_DWORD *__cdecl sub_793BCB(_DWORD *a1, int *a2, void *a3)
{
  int v3; // eax
  __int64 v4; // kr00_8
  __int64 *v5; // eax
  __int64 v7; // [esp+8h] [ebp-18h] BYREF
  __int64 v8; // [esp+10h] [ebp-10h] BYREF
  int v9[2]; // [esp+18h] [ebp-8h] BYREF

  v3 = a2[1];
  v9[0] = *a2;
  v9[1] = v3;
  v4 = sub_791882(v9);
  v5 = sub_793F7F(&v7, a3);
  v8 = sub_791882(v5) + v4;
  sub_791864(a1, &v8);
  return a1;
}

//----- (00793C1C) --------------------------------------------------------
bool __cdecl sub_793C1C(_DWORD *a1, _DWORD *a2)
{
  return !sub_793FAC(a2, a1);
}

//----- (00793C46) --------------------------------------------------------
_DWORD *__cdecl sub_793C46(_DWORD *a1, _DWORD *a2, _DWORD *a3)
{
  int v4; // [esp+0h] [ebp-18h] BYREF
  int v5; // [esp+8h] [ebp-10h] BYREF
  int *v6; // [esp+10h] [ebp-8h]
  int *v7; // [esp+14h] [ebp-4h]

  v7 = sub_791FA1(a3, &v5);
  v6 = sub_791FA1(a2, &v4);
  sub_793FDF(a1, v6, v7);
  return a1;
}

//----- (00793C80) --------------------------------------------------------
bool __cdecl sub_793C80(int a1, void *a2)
{
  _DWORD *v2; // eax
  _QWORD *v3; // eax
  int v5; // [esp+0h] [ebp-48h] BYREF
  int v6; // [esp+8h] [ebp-40h] BYREF
  int v7; // [esp+10h] [ebp-38h] BYREF
  __int64 v8; // [esp+18h] [ebp-30h] BYREF
  __int64 v9; // [esp+20h] [ebp-28h] BYREF
  int v10[2]; // [esp+28h] [ebp-20h] BYREF
  __int64 v11; // [esp+30h] [ebp-18h] BYREF
  __int64 v12; // [esp+38h] [ebp-10h] BYREF
  _DWORD *v13; // [esp+40h] [ebp-8h]
  bool v14; // [esp+47h] [ebp-1h]

  v11 = 864000000000000i64;
  v9 = 0x412A5E0000000000i64;
  v13 = sub_791797(&v7);
  v2 = sub_791FA1(v13, &v6);
  sub_794034(&v12, v2);
  v14 = sub_794061(&v9, a2);
  if ( v14 )
  {
    sub_793E6F(&v12, &v11);
  }
  else
  {
    v3 = sub_7940BD(&v5, a2);
    sub_793E6F(&v12, v3);
  }
  sub_793E95(v10, &v12);
  *(_QWORD *)a1 = sub_791882(v10);
  sub_793F52(&v8, v10);
  sub_793E49(&v12, &v8);
  *(_DWORD *)(a1 + 8) = sub_791882(&v12);
  return v14;
}
// 793C80: using guessed type _DWORD var_20[2];

//----- (00793D4C) --------------------------------------------------------
int __thiscall sub_793D4C(int *this, int a2)
{
  return sub_79415C(this, a2, *this, this[1], this[2], this[3]);
}

//----- (00793D73) --------------------------------------------------------
__int16 __thiscall sub_793D73(__int16 *this, int a2)
{
  return sub_7941FE(this, a2, *this, this[1]);
}

//----- (00793D98) --------------------------------------------------------
int __thiscall sub_793D98(int *this, int a2)
{
  return sub_794278(this, a2, *this, this[1]);
}

//----- (00793DB9) --------------------------------------------------------
int __thiscall sub_793DB9(_DWORD *this, int a2)
{
  int result; // eax
  void *v3; // [esp+4h] [ebp-Ch]
  int v4; // [esp+8h] [ebp-8h]

  v4 = unknown_libname_3(a2);
  v3 = (void *)unknown_libname_3(this[1]);
  sub_7942E0(this[2], v3, v4);
  result = this[1] + 8;
  this[1] = result;
  return result;
}

//----- (00793E0A) --------------------------------------------------------
int __thiscall sub_793E0A(_DWORD *this)
{
  int result; // eax
  void *v2; // [esp+4h] [ebp-8h]

  v2 = (void *)unknown_libname_3(this[1]);
  sub_79430D(this[2], v2);
  result = this[1] + 8;
  this[1] = result;
  return result;
}

//----- (00793E49) --------------------------------------------------------
_QWORD *__thiscall sub_793E49(_QWORD *this, _QWORD *a2)
{
  *this -= *a2;
  return this;
}

//----- (00793E6F) --------------------------------------------------------
_QWORD *__thiscall sub_793E6F(_QWORD *this, _QWORD *a2)
{
  *this += *a2;
  return this;
}

//----- (00793E95) --------------------------------------------------------
_DWORD *__cdecl sub_793E95(_DWORD *a1, void *a2)
{
  __int64 v3; // [esp+8h] [ebp-1Ch] BYREF
  char v4; // [esp+22h] [ebp-2h]
  char v5; // [esp+23h] [ebp-1h]

  v5 = 1;
  v4 = 0;
  v3 = sub_791882(a2) / 1000000000;
  sub_791864(a1, &v3);
  return a1;
}

//----- (00793F52) --------------------------------------------------------
__int64 *__thiscall sub_793F52(__int64 *this, void *a2)
{
  _DWORD *v2; // eax
  __int64 v3; // rax
  int v5; // [esp+0h] [ebp-Ch] BYREF
  __int64 *v6; // [esp+8h] [ebp-4h]

  v6 = this;
  v2 = sub_794B5C(&v5, a2);
  v3 = sub_791882(v2);
  *v6 = v3;
  return v6;
}

//----- (00793F7F) --------------------------------------------------------
__int64 *__thiscall sub_793F7F(__int64 *this, void *a2)
{
  _DWORD *v2; // eax
  __int64 v3; // rax
  int v5; // [esp+0h] [ebp-Ch] BYREF
  __int64 *v6; // [esp+8h] [ebp-4h]

  v6 = this;
  v2 = sub_794C18(&v5, a2);
  v3 = sub_791882(v2);
  *v6 = v3;
  return v6;
}

//----- (00793FAC) --------------------------------------------------------
bool __cdecl sub_793FAC(_DWORD *a1, _DWORD *a2)
{
  int v3; // [esp+0h] [ebp-18h] BYREF
  int v4; // [esp+8h] [ebp-10h] BYREF
  int *v5; // [esp+10h] [ebp-8h]
  int *v6; // [esp+14h] [ebp-4h]

  v6 = sub_791FA1(a2, &v4);
  v5 = sub_791FA1(a1, &v3);
  return sub_794CD4(v5, v6);
}

//----- (00793FDF) --------------------------------------------------------
_DWORD *__cdecl sub_793FDF(_DWORD *a1, int *a2, int *a3)
{
  int v3; // eax
  int v4; // eax
  __int64 v5; // rax
  __int64 v7; // [esp+8h] [ebp-18h] BYREF
  int v8[2]; // [esp+10h] [ebp-10h] BYREF
  int v9[2]; // [esp+18h] [ebp-8h] BYREF

  v3 = a2[1];
  v9[0] = *a2;
  v9[1] = v3;
  v4 = a3[1];
  v8[0] = *a3;
  v8[1] = v4;
  v5 = sub_791882(v9);
  v7 = v5 - sub_791882(v8);
  sub_791864(a1, &v7);
  return a1;
}

//----- (00794034) --------------------------------------------------------
__int64 *__thiscall sub_794034(__int64 *this, void *a2)
{
  _DWORD *v2; // eax
  __int64 v3; // rax
  int v5; // [esp+0h] [ebp-Ch] BYREF
  __int64 *v6; // [esp+8h] [ebp-4h]

  v6 = this;
  v2 = sub_794D3E(&v5, a2);
  v3 = sub_791882(v2);
  *v6 = v3;
  return v6;
}

//----- (00794061) --------------------------------------------------------
bool __cdecl sub_794061(void *a1, void *a2)
{
  double *v2; // eax
  double *v3; // eax
  double v5; // [esp+0h] [ebp-2Ch] BYREF
  double v6; // [esp+8h] [ebp-24h] BYREF
  double v7; // [esp+10h] [ebp-1Ch]
  double v8; // [esp+18h] [ebp-14h]
  double v9; // [esp+20h] [ebp-Ch]

  v2 = sub_794DF1(&v6, a1);
  v9 = sub_791893(v2);
  v7 = v9;
  v3 = sub_794E1B(&v5, a2);
  v8 = sub_791893(v3);
  return v8 > v7;
}
// 794061: using guessed type double var_24;
// 794061: using guessed type double var_2C;

//----- (007940BD) --------------------------------------------------------
_DWORD *__cdecl sub_7940BD(_DWORD *a1, void *a2)
{
  __int64 v3; // [esp+18h] [ebp-Ch] BYREF
  char v4; // [esp+22h] [ebp-2h]
  char v5; // [esp+23h] [ebp-1h]

  v5 = 1;
  v4 = 1;
  v3 = sub_791882(a2);
  sub_791864(a1, &v3);
  return a1;
}
// 7940BD: using guessed type __int64 var_C;

//----- (0079415C) --------------------------------------------------------
int __thiscall sub_79415C(void *this, int a2, int a3, int a4, int a5, int a6)
{
  __int64 v6; // rax
  __int64 v7; // rax
  int v9[4]; // [esp+0h] [ebp-34h] BYREF
  __int64 v10; // [esp+10h] [ebp-24h]
  unsigned __int64 v11; // [esp+18h] [ebp-1Ch]
  __int64 v12; // [esp+20h] [ebp-14h]
  __int64 v13; // [esp+28h] [ebp-Ch]
  void *v14; // [esp+30h] [ebp-4h]

  v14 = this;
  sub_794700(v9, a2);
  LODWORD(v6) = sub_7947C1(a3, a4);
  v13 = v6;
  LODWORD(v7) = sub_7947C1(a5, a6);
  v12 = v7;
  v10 = v7 - v13;
  if ( (HIDWORD(v10) & (unsigned int)v10) == -1 )
    v11 = sub_794528((int)v9);
  else
    v11 = sub_79459A((int)v9, v12 - v13 + 1);
  return sub_7947C1(v13 + v11, (v13 + v11) >> 32);
}
// 79417D: variable 'v6' is possibly undefined
// 794190: variable 'v7' is possibly undefined
// 79415C: using guessed type _DWORD var_34[4];

//----- (007941FE) --------------------------------------------------------
__int16 __thiscall sub_7941FE(void *this, int a2, __int16 a3, __int16 a4)
{
  _DWORD v5[4]; // [esp+0h] [ebp-1Ch] BYREF
  __int16 v6; // [esp+10h] [ebp-Ch]
  unsigned __int16 v7; // [esp+14h] [ebp-8h]
  unsigned __int16 v8; // [esp+18h] [ebp-4h]

  v5[3] = this;
  sub_79441A(v5, a2);
  v8 = sub_7947A8(a3);
  v7 = sub_7947A8(a4);
  if ( v7 - v8 == 0xFFFF )
    v6 = sub_79432A(v5);
  else
    v6 = sub_794478(v5, v7 - v8 + 1);
  return sub_7947A8(v8 + v6);
}

//----- (00794278) --------------------------------------------------------
int __thiscall sub_794278(void *this, int a2, int a3, int a4)
{
  _DWORD v5[4]; // [esp+0h] [ebp-1Ch] BYREF
  unsigned int v6; // [esp+10h] [ebp-Ch]
  int v7; // [esp+14h] [ebp-8h]
  int v8; // [esp+18h] [ebp-4h]

  v5[3] = this;
  sub_79441A(v5, a2);
  v8 = sub_79478F(a3);
  v7 = sub_79478F(a4);
  if ( v7 - v8 == -1 )
    v6 = sub_79432A(v5);
  else
    v6 = sub_79437B(v5, v7 - v8 + 1);
  return sub_79478F(v8 + v6);
}

//----- (007942E0) --------------------------------------------------------
_DWORD *__cdecl sub_7942E0(int a1, void *a2, int a3)
{
  _DWORD *v4; // [esp+0h] [ebp-8h]
  _DWORD *v5; // [esp+4h] [ebp-4h]

  v4 = operator new(8u, a2);
  v5 = (_DWORD *)unknown_libname_3(a3);
  return sub_7947DE(v4, v5);
}

//----- (0079430D) --------------------------------------------------------
int *__cdecl sub_79430D(int a1, void *a2)
{
  int *v3; // [esp+0h] [ebp-4h]

  v3 = (int *)operator new(8u, a2);
  return sub_794802(v3);
}

//----- (0079432A) --------------------------------------------------------
unsigned int __thiscall sub_79432A(_DWORD *this)
{
  unsigned int i; // [esp+4h] [ebp-8h]
  unsigned int v4; // [esp+8h] [ebp-4h]
  int v5; // [esp+8h] [ebp-4h]

  v4 = 0;
  for ( i = 0; i < 0x20; i += this[1] )
  {
    v5 = 2 * (v4 << (this[1] - 1));
    v4 = v5 | sub_794823(this);
  }
  return v4;
}

//----- (0079437B) --------------------------------------------------------
unsigned int __thiscall sub_79437B(_DWORD *this, unsigned int a2)
{
  unsigned int v4; // [esp+4h] [ebp-8h]
  int v5; // [esp+4h] [ebp-8h]
  unsigned int i; // [esp+8h] [ebp-4h]

  do
  {
    v4 = 0;
    for ( i = 0; i < a2 - 1; i = this[2] | (2 * (i << (this[1] - 1))) )
    {
      v5 = 2 * (v4 << (this[1] - 1));
      v4 = v5 | sub_794823(this);
    }
  }
  while ( v4 / a2 >= i / a2 && i % a2 != a2 - 1 );
  return v4 % a2;
}

//----- (0079441A) --------------------------------------------------------
_DWORD *__thiscall sub_79441A(_DWORD *this, int a2)
{
  int v2; // esi
  int v4; // [esp+0h] [ebp-8h]

  *this = a2;
  this[1] = 32;
  for ( this[2] = -1; ; this[2] >>= 1 )
  {
    v2 = std::numeric_limits<unsigned int>::max(v4);
    if ( (unsigned int)(v2 - __scrt_stub_for_initialize_mta()) >= this[2] )
      break;
    --this[1];
  }
  return this;
}
// 79444B: variable 'v4' is possibly undefined
// 7924F0: using guessed type int __cdecl std::numeric_limits<unsigned int>::max(_DWORD);

//----- (00794478) --------------------------------------------------------
__int16 __thiscall sub_794478(_DWORD *this, unsigned __int16 a2)
{
  unsigned int v4; // [esp+8h] [ebp-8h]
  int v5; // [esp+8h] [ebp-8h]
  unsigned int i; // [esp+Ch] [ebp-4h]

  do
  {
    v4 = 0;
    for ( i = 0; i < (unsigned int)a2 - 1; i = this[2] | (2 * (i << (this[1] - 1))) )
    {
      v5 = 2 * (v4 << (this[1] - 1));
      v4 = v5 | sub_794823(this);
    }
  }
  while ( v4 / a2 >= i / a2 && i % a2 != a2 - 1 );
  return v4 % a2;
}

//----- (00794528) --------------------------------------------------------
__int64 __thiscall sub_794528(int this)
{
  __int64 v2; // [esp+0h] [ebp-10h]
  __int64 v3; // [esp+0h] [ebp-10h]
  unsigned int i; // [esp+Ch] [ebp-4h]

  v2 = 0i64;
  for ( i = 0; i < 0x40; i += *(_DWORD *)(this + 4) )
  {
    v3 = 2 * (v2 << ((unsigned __int8)*(_DWORD *)(this + 4) - 1));
    v2 = v3 | sub_794857((_QWORD *)this);
  }
  return v2;
}

//----- (0079459A) --------------------------------------------------------
unsigned __int64 __thiscall sub_79459A(int this, unsigned __int64 a2)
{
  unsigned __int64 v3; // [esp+30h] [ebp-14h]
  __int64 v4; // [esp+30h] [ebp-14h]
  unsigned __int64 i; // [esp+38h] [ebp-Ch]

  do
  {
    v3 = 0i64;
    for ( i = 0i64; i < a2 - 1; i = *(_QWORD *)(this + 8) | (2 * (i << ((unsigned __int8)*(_DWORD *)(this + 4) - 1))) )
    {
      v4 = 2 * (v3 << ((unsigned __int8)*(_DWORD *)(this + 4) - 1));
      v3 = v4 | sub_794857((_QWORD *)this);
    }
  }
  while ( v3 / a2 >= i / a2 && i % a2 != a2 - 1 );
  return v3 % a2;
}

//----- (00794700) --------------------------------------------------------
_DWORD *__thiscall sub_794700(_DWORD *this, int a2)
{
  int v2; // esi
  int v4; // [esp+0h] [ebp-14h]

  *this = a2;
  this[1] = 64;
  this[2] = -1;
  this[3] = -1;
  while ( 1 )
  {
    v2 = std::numeric_limits<unsigned int>::max(v4);
    if ( (unsigned __int64)(unsigned int)(v2 - __scrt_stub_for_initialize_mta()) >= *((_QWORD *)this + 1) )
      break;
    --this[1];
    *((_QWORD *)this + 1) >>= 1;
  }
  return this;
}
// 794744: variable 'v4' is possibly undefined
// 7924F0: using guessed type int __cdecl std::numeric_limits<unsigned int>::max(_DWORD);

//----- (0079478F) --------------------------------------------------------
int __cdecl sub_79478F(int a1)
{
  return sub_7948A7(a1);
}

//----- (007947A8) --------------------------------------------------------
__int16 __cdecl sub_7947A8(__int16 a1)
{
  return sub_7948D1(a1);
}

//----- (007947C1) --------------------------------------------------------
int __cdecl sub_7947C1(int a1, int a2)
{
  return operator"" _l(a1, a2);
}
// 7948DA: using guessed type _DWORD __cdecl operator"" _l(_DWORD, _DWORD);

//----- (007947DE) --------------------------------------------------------
_DWORD *__thiscall sub_7947DE(_DWORD *this, _DWORD *a2)
{
  *this = *a2;
  this[1] = a2[1];
  return this;
}

//----- (00794802) --------------------------------------------------------
int *__thiscall sub_794802(int *this)
{
  *this = sub_7929C4();
  this[1] = *this;
  return this;
}

//----- (00794823) --------------------------------------------------------
unsigned int __thiscall sub_794823(_DWORD *this)
{
  unsigned int v1; // esi
  unsigned int v3; // [esp+4h] [ebp-8h]

  do
  {
    v1 = sub_7948E5((_DWORD *)*this);
    v3 = v1 - __scrt_stub_for_initialize_mta();
  }
  while ( v3 > this[2] );
  return v3;
}

//----- (00794857) --------------------------------------------------------
__int64 __thiscall sub_794857(_QWORD *this)
{
  unsigned int v1; // esi
  __int64 v3; // [esp+4h] [ebp-10h]

  do
  {
    v1 = sub_7948E5(*(_DWORD **)this);
    v3 = v1 - __scrt_stub_for_initialize_mta();
  }
  while ( (unsigned __int64)(unsigned int)v3 > this[1] );
  return v3;
}

//----- (007948A7) --------------------------------------------------------
int __cdecl sub_7948A7(int a1)
{
  return a1 + 0x80000000;
}

//----- (007948D1) --------------------------------------------------------
__int16 __cdecl sub_7948D1(__int16 a1)
{
  return a1;
}

//----- (007948E5) --------------------------------------------------------
unsigned int __thiscall sub_7948E5(_DWORD *this)
{
  unsigned int v2; // [esp+0h] [ebp-Ch]
  int v4; // [esp+8h] [ebp-4h]
  unsigned int v5; // [esp+8h] [ebp-4h]

  if ( *this == 624 )
  {
    sub_79497E(this);
  }
  else if ( *this >= 0x4E0u )
  {
    sub_794A02(this);
  }
  v2 = this[++*this];
  v4 = v2 ^ this[1249] & (v2 >> 11);
  v5 = v4 ^ (v4 << 7) & 0x9D2C5680 ^ ((v4 ^ (v4 << 7) & 0x9D2C5680) << 15) & 0xEFC60000;
  return v5 ^ (v5 >> 18);
}

//----- (0079497E) --------------------------------------------------------
unsigned int __thiscall sub_79497E(_DWORD *this)
{
  unsigned int result; // eax
  int v2; // [esp+0h] [ebp-10h]
  unsigned int i; // [esp+Ch] [ebp-4h]

  for ( i = 624; i < 0x4E0; ++i )
  {
    if ( (this[i - 622] & 1) != 0 )
      v2 = -1727483681;
    else
      v2 = 0;
    this[i + 1] = this[i - 226] ^ v2 ^ ((this[i - 622] & 0x7FFFFFFF | this[i - 623] & 0x80000000) >> 1);
    result = i + 1;
  }
  return result;
}

//----- (00794A02) --------------------------------------------------------
_BYTE *__thiscall sub_794A02(_BYTE *this)
{
  _BYTE *result; // eax
  int v2; // [esp+0h] [ebp-20h]
  int v3; // [esp+8h] [ebp-18h]
  int v4; // [esp+10h] [ebp-10h]
  unsigned int i; // [esp+1Ch] [ebp-4h]

  for ( i = 0; i < 0xE3; ++i )
  {
    if ( (this[4 * i + 2504] & 1) != 0 )
      v4 = -1727483681;
    else
      v4 = 0;
    *(_DWORD *)&this[4 * i + 4] = *(_DWORD *)&this[4 * i + 4088] ^ v4 ^ ((*(_DWORD *)&this[4 * i + 2504] & 0x7FFFFFFF | *(_DWORD *)&this[4 * i + 2500] & 0x80000000) >> 1);
  }
  while ( i < 0x26F )
  {
    if ( (this[4 * i + 2504] & 1) != 0 )
      v3 = -1727483681;
    else
      v3 = 0;
    *(_DWORD *)&this[4 * i + 4] = *(_DWORD *)&this[4 * i - 904] ^ v3 ^ ((*(_DWORD *)&this[4 * i + 2504] & 0x7FFFFFFF | *(_DWORD *)&this[4 * i + 2500] & 0x80000000) >> 1);
    ++i;
  }
  if ( (this[4] & 1) != 0 )
    v2 = -1727483681;
  else
    v2 = 0;
  *(_DWORD *)&this[4 * i + 4] = *((_DWORD *)this + 397) ^ v2 ^ ((*((_DWORD *)this + 1) & 0x7FFFFFFF | *(_DWORD *)&this[4 * i + 2500] & 0x80000000) >> 1);
  result = this;
  *(_DWORD *)this = 0;
  return result;
}

//----- (00794B5C) --------------------------------------------------------
_DWORD *__cdecl sub_794B5C(_DWORD *a1, void *a2)
{
  __int64 v3; // [esp+10h] [ebp-14h] BYREF
  char v4; // [esp+22h] [ebp-2h]
  char v5; // [esp+23h] [ebp-1h]

  v5 = 0;
  v4 = 1;
  v3 = 1000000000 * sub_791882(a2);
  sub_791864(a1, &v3);
  return a1;
}

//----- (00794C18) --------------------------------------------------------
_DWORD *__cdecl sub_794C18(_DWORD *a1, void *a2)
{
  __int64 v3; // [esp+10h] [ebp-14h] BYREF
  char v4; // [esp+22h] [ebp-2h]
  char v5; // [esp+23h] [ebp-1h]

  v5 = 0;
  v4 = 1;
  v3 = 1000000 * sub_791882(a2);
  sub_791864(a1, &v3);
  return a1;
}

//----- (00794CD4) --------------------------------------------------------
bool __cdecl sub_794CD4(int *a1, int *a2)
{
  int v2; // eax
  int v3; // eax
  __int64 v4; // kr00_8
  int v6[2]; // [esp+8h] [ebp-24h] BYREF
  int v7[2]; // [esp+10h] [ebp-1Ch] BYREF

  v2 = a1[1];
  v7[0] = *a1;
  v7[1] = v2;
  v3 = a2[1];
  v6[0] = *a2;
  v6[1] = v3;
  v4 = sub_791882(v7);
  return v4 < sub_791882(v6);
}

//----- (00794D3E) --------------------------------------------------------
_DWORD *__cdecl sub_794D3E(_DWORD *a1, void *a2)
{
  __int64 v3; // [esp+10h] [ebp-14h] BYREF
  char v4; // [esp+22h] [ebp-2h]
  char v5; // [esp+23h] [ebp-1h]

  v5 = 0;
  v4 = 1;
  v3 = 100 * sub_791882(a2);
  sub_791864(a1, &v3);
  return a1;
}

//----- (00794DF1) --------------------------------------------------------
double *__thiscall sub_794DF1(double *this, void *a2)
{
  _QWORD *v2; // eax
  double v3; // st7
  __int64 v5; // [esp+0h] [ebp-Ch] BYREF
  double *v6; // [esp+8h] [ebp-4h]

  v6 = this;
  v2 = sub_794E45(&v5, a2);
  v3 = sub_791893(v2);
  *v6 = v3;
  return v6;
}

//----- (00794E1B) --------------------------------------------------------
double *__thiscall sub_794E1B(double *this, void *a2)
{
  _QWORD *v2; // eax
  double v3; // st7
  __int64 v5; // [esp+0h] [ebp-Ch] BYREF
  double *v6; // [esp+8h] [ebp-4h]

  v6 = this;
  v2 = sub_794F17(&v5, a2);
  v3 = sub_791893(v2);
  *v6 = v3;
  return v6;
}

//----- (00794E45) --------------------------------------------------------
_QWORD *__cdecl sub_794E45(_QWORD *a1, void *a2)
{
  double v3; // [esp+20h] [ebp-1Ch] BYREF
  double v4; // [esp+28h] [ebp-14h]
  char v5; // [esp+3Ah] [ebp-2h]
  char v6; // [esp+3Bh] [ebp-1h]

  v6 = 0;
  v5 = 1;
  v4 = sub_791893(a2);
  v3 = v4 * 1000000000.0;
  sub_794FF1(a1, &v3);
  return a1;
}

//----- (00794F17) --------------------------------------------------------
_QWORD *__cdecl sub_794F17(_QWORD *a1, void *a2)
{
  double v3; // [esp+18h] [ebp-Ch] BYREF
  char v4; // [esp+22h] [ebp-2h]
  char v5; // [esp+23h] [ebp-1h]

  v5 = 1;
  v4 = 1;
  v3 = (double)sub_791882(a2);
  sub_794FF1(a1, &v3);
  return a1;
}
// 794F17: using guessed type double var_C;

//----- (00794FF1) --------------------------------------------------------
_QWORD *__thiscall sub_794FF1(_QWORD *this, _QWORD *a2)
{
  *this = *a2;
  return this;
}

//----- (00795312) --------------------------------------------------------
void __cdecl sub_795312(void *Block)
{
  j_free(Block);
}

//----- (00795320) --------------------------------------------------------
_DWORD *__thiscall sub_795320(_DWORD *Block, char a2)
{
  *Block = &type_info::`vftable';
  if ( (a2 & 1) != 0 )
    sub_795312(Block);
  return Block;
}
// 7971B4: using guessed type void *type_info::`vftable';

//----- (007953EE) --------------------------------------------------------
int sub_7953EE()
{
  __scrt_initialize_default_local_stdio_options();
  return 0;
}
// 795B00: using guessed type int __scrt_initialize_default_local_stdio_options(void);

//----- (007953F6) --------------------------------------------------------
int sub_7953F6()
{
  int v0; // eax

  sub_79592E();
  v0 = UserMathErrorFunction();
  return set_new_mode(v0);
}

//----- (00795597) --------------------------------------------------------
_DWORD *__thiscall sub_795597(_DWORD *this)
{
  _DWORD *result; // eax

  this[1] = 0;
  result = this;
  this[2] = 0;
  this[1] = "bad allocation";
  *this = &std::bad_alloc::`vftable';
  return result;
}
// 7971C8: using guessed type void *std::bad_alloc::`vftable';

//----- (007955AF) --------------------------------------------------------
void __noreturn sub_7955AF()
{
  int pExceptionObject[3]; // [esp+0h] [ebp-Ch] BYREF

  sub_795597(pExceptionObject);
  CxxThrowException(pExceptionObject, (_ThrowInfo *)&_TI2_AVbad_alloc_std__);
}
// 7955AF: using guessed type void __noreturn sub_7955AF();
// 7955AF: using guessed type _DWORD pExceptionObject[3];

//----- (007955CC) --------------------------------------------------------
void __noreturn sub_7955CC()
{
  int pExceptionObject[3]; // [esp+0h] [ebp-Ch] BYREF

  sub_7914D2(pExceptionObject);
  CxxThrowException(pExceptionObject, (_ThrowInfo *)&_TI3_AVbad_array_new_length_std__);
}
// 7955CC: using guessed type void __noreturn sub_7955CC();
// 7955CC: using guessed type _DWORD pExceptionObject[3];

//----- (007957B9) --------------------------------------------------------
int sub_7957B9()
{
  return 1;
}

//----- (007958E8) --------------------------------------------------------
int __cdecl UserMathErrorFunction()
{
  return 0;
}

//----- (0079592E) --------------------------------------------------------
LPTOP_LEVEL_EXCEPTION_FILTER sub_79592E()
{
  return SetUnhandledExceptionFilter(__scrt_unhandled_exception_filter);
}

//----- (00795990) --------------------------------------------------------
void sub_795990()
{
  dword_7990F0 = 0;
}
// 7990F0: using guessed type int dword_7990F0;

//----- (00795ACA) --------------------------------------------------------
void sub_795ACA()
{
  InitializeSListHead(&ListHead);
}

//----- (00795AD6) --------------------------------------------------------
char sub_795AD6()
{
  return 1;
}

//----- (00795AFA) --------------------------------------------------------
void *sub_795AFA()
{
  return &unk_799100;
}

//----- (00795B1D) --------------------------------------------------------
BOOL sub_795B1D()
{
  return dword_799010 == 0;
}
// 799010: using guessed type int dword_799010;

//----- (00795B29) --------------------------------------------------------
void *sub_795B29()
{
  return &unk_7994B0;
}

//----- (00795B2F) --------------------------------------------------------
void *sub_795B2F()
{
  return &unk_7994AC;
}

//----- (00795B35) --------------------------------------------------------
void sub_795B35()
{
  ;
}
// 795B35: could not find valid save-restore pair for edi

//----- (00795B61) --------------------------------------------------------
void __cdecl sub_795B61()
{
  ;
}
// 795B61: could not find valid save-restore pair for edi

//----- (007963A3) --------------------------------------------------------
unsigned __int64 __usercall sub_7963A3@<edx:eax>(unsigned __int64 a1@<edx:eax>)
{
  int v1; // ecx
  bool v2; // cc
  char v3; // cl

  v1 = HIDWORD(a1) >> 20;
  HIDWORD(a1) = HIDWORD(a1) & 0xFFFFF | 0x100000;
  v2 = v1 < 1075;
  v3 = v1 - 51;
  if ( v2 )
    return a1 >> (-v3 & 0x1F);
  else
    return a1 << (v3 & 0x1F);
}

//----- (00796612) --------------------------------------------------------
void __cdecl sub_796612()
{
  sub_7919DE(dword_79944C);
}
// 79944C: using guessed type int dword_79944C[3];

//----- (00796621) --------------------------------------------------------
void __cdecl sub_796621()
{
  sub_7919DE(dword_799458);
}
// 799458: using guessed type int dword_799458[3];

//----- (00796630) --------------------------------------------------------
void __cdecl sub_796630()
{
  sub_7919DE(dword_7994A0);
}
// 7994A0: using guessed type int dword_7994A0[3];

//----- (0079663F) --------------------------------------------------------
void __cdecl sub_79663F()
{
  sub_7919DE(dword_799440);
}
// 799440: using guessed type int dword_799440[3];

//----- (0079664E) --------------------------------------------------------
void __cdecl sub_79664E()
{
  sub_7919DE(dword_799464);
}
// 799464: using guessed type int dword_799464[3];

//----- (0079665D) --------------------------------------------------------
void __cdecl sub_79665D()
{
  sub_7919DE(dword_799494);
}
// 799494: using guessed type int dword_799494[3];

//----- (0079666C) --------------------------------------------------------
void __cdecl sub_79666C()
{
  sub_7919DE(dword_799434);
}
// 799434: using guessed type int dword_799434[3];

//----- (0079667B) --------------------------------------------------------
void __cdecl sub_79667B()
{
  sub_7919DE(dword_799488);
}
// 799488: using guessed type int dword_799488[3];

//----- (0079668A) --------------------------------------------------------
void __cdecl sub_79668A()
{
  Process_Input((void **)dword_799470);
}
// 799470: using guessed type unsigned int dword_799470[6];

//----- (00796699) --------------------------------------------------------
void __cdecl sub_796699()
{
  std::_Fac_tidy_reg_t::~_Fac_tidy_reg_t((std::_Fac_tidy_reg_t *)&unk_7990BC);
}

// nfuncs=356 queued=265 decompiled=265 lumina nreq=0 worse=0 better=0
// ALL OK, 265 function(s) have been successfully decompiled
