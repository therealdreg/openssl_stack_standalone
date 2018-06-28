/*
Standalone and Self-sufficient header in C for openssl stack use

STACK API
The stack library provides a generic way to handle collections of objects in OpenSSL.
A comparison function can be registered to sort the collection.

https://wiki.openssl.org/index.php/STACK_API

https://github.com/David-Reguera-Garcia-Dreg/openssl_stack_standalone

Contact: http://www.fr33project.org/ - dreg@fr33project.org - David Reguera Garcia aka Dreg
*/

/*
* Copyright 1995-2018 The OpenSSL Project Authors. All Rights Reserved.
*
* Licensed under the OpenSSL license (the "License").  You may not use
* this file except in compliance with the License.  You can obtain a copy
* in the file LICENSE in the source distribution or at
* https://www.openssl.org/source/license.html
*/


#ifndef _OPENSSL_STACK_STANDALONE__H_
#define _OPENSSL_STACK_STANDALONE__H_


#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#ifndef HEADER_OBJECTS_H
# define HEADER_OBJECTS_H

# define OBJ_NAME_TYPE_UNDEF             0x00
# define OBJ_NAME_TYPE_MD_METH           0x01
# define OBJ_NAME_TYPE_CIPHER_METH       0x02
# define OBJ_NAME_TYPE_PKEY_METH         0x03
# define OBJ_NAME_TYPE_COMP_METH         0x04
# define OBJ_NAME_TYPE_NUM               0x05

# define OBJ_NAME_ALIAS                  0x8000

# define OBJ_BSEARCH_VALUE_ON_NOMATCH            0x01
# define OBJ_BSEARCH_FIRST_VALUE_ON_MATCH        0x02


#ifdef  __cplusplus
extern "C" {
#endif

typedef struct obj_name_st
{
    int type;
    int alias;
    const char* name;
    const char* data;
} OBJ_NAME;

const void* OBJ_bsearch_ex_(const void* key, const void* base, int num,
                            int size,
                            int(*cmp) (const void*, const void*),
                            int flags);

# define _DECLARE_OBJ_BSEARCH_CMP_FN(scope, type1, type2, nm)    \
  static int nm##_cmp_BSEARCH_CMP_FN(const void *, const void *); \
  static int nm##_cmp(type1 const *, type2 const *); \
  scope type2 * OBJ_bsearch_##nm(type1 *key, type2 const *base, int num)

# define DECLARE_OBJ_BSEARCH_CMP_FN(type1, type2, cmp)   \
  _DECLARE_OBJ_BSEARCH_CMP_FN(static, type1, type2, cmp)
# define DECLARE_OBJ_BSEARCH_GLOBAL_CMP_FN(type1, type2, nm)     \
  type2 * OBJ_bsearch_##nm(type1 *key, type2 const *base, int num)

/*-
* Unsolved problem: if a type is actually a pointer type, like
* nid_triple is, then its impossible to get a const where you need
* it. Consider:
*
* typedef int nid_triple[3];
* const void *a_;
* const nid_triple const *a = a_;
*
* The assignment discards a const because what you really want is:
*
* const int const * const *a = a_;
*
* But if you do that, you lose the fact that a is an array of 3 ints,
* which breaks comparison functions.
*
* Thus we end up having to cast, sadly, or unpack the
* declarations. Or, as I finally did in this case, declare nid_triple
* to be a struct, which it should have been in the first place.
*
* Ben, August 2008.
*
* Also, strictly speaking not all types need be const, but handling
* the non-constness means a lot of complication, and in practice
* comparison routines do always not touch their arguments.
*/

# define IMPLEMENT_OBJ_BSEARCH_CMP_FN(type1, type2, nm)  \
  static int nm##_cmp_BSEARCH_CMP_FN(const void *a_, const void *b_)    \
      { \
      type1 const *a = a_; \
      type2 const *b = b_; \
      return nm##_cmp(a,b); \
      } \
  static type2 *OBJ_bsearch_##nm(type1 *key, type2 const *base, int num) \
      { \
      return (type2 *)OBJ_bsearch_(key, base, num, sizeof(type2), \
                                        nm##_cmp_BSEARCH_CMP_FN); \
      } \
      extern void dummy_prototype(void)

# define IMPLEMENT_OBJ_BSEARCH_GLOBAL_CMP_FN(type1, type2, nm)   \
  static int nm##_cmp_BSEARCH_CMP_FN(const void *a_, const void *b_)    \
      { \
      type1 const *a = a_; \
      type2 const *b = b_; \
      return nm##_cmp(a,b); \
      } \
  type2 *OBJ_bsearch_##nm(type1 *key, type2 const *base, int num) \
      { \
      return (type2 *)OBJ_bsearch_(key, base, num, sizeof(type2), \
                                        nm##_cmp_BSEARCH_CMP_FN); \
      } \
      extern void dummy_prototype(void)

# define OBJ_bsearch(type1,key,type2,base,num,cmp)                              \
  ((type2 *)OBJ_bsearch_(CHECKED_PTR_OF(type1,key),CHECKED_PTR_OF(type2,base), \
                         num,sizeof(type2),                             \
                         ((void)CHECKED_PTR_OF(type1,cmp##_type_1),     \
                          (void)CHECKED_PTR_OF(type2,cmp##_type_2),     \
                          cmp##_BSEARCH_CMP_FN)))

# define OBJ_bsearch_ex(type1,key,type2,base,num,cmp,flags)                      \
  ((type2 *)OBJ_bsearch_ex_(CHECKED_PTR_OF(type1,key),CHECKED_PTR_OF(type2,base), \
                         num,sizeof(type2),                             \
                         ((void)CHECKED_PTR_OF(type1,cmp##_type_1),     \
                          (void)type_2=CHECKED_PTR_OF(type2,cmp##_type_2), \
                          cmp##_BSEARCH_CMP_FN)),flags)

#if OPENSSL_API_COMPAT < 0x10100000L
# define OBJ_cleanup() while(0) continue
#endif

# ifdef  __cplusplus
}
# endif
#endif



const void* OBJ_bsearch_ex_(const void* key, const void* base_, int num,
                            int size,
                            int(*cmp) (const void*, const void*),
                            int flags)
{
    const char* base = base_;
    int l, h, i = 0, c = 0;
    const char* p = NULL;

    if (num == 0)
    {
        return NULL;
    }
    l = 0;
    h = num;
    while (l < h)
    {
        i = (l + h) / 2;
        p = &(base[i * size]);
        c = (*cmp) (key, p);
        if (c < 0)
        {
            h = i;
        }
        else if (c > 0)
        {
            l = i + 1;
        }
        else
        {
            break;
        }
    }
#ifdef CHARSET_EBCDIC
    /*
    * THIS IS A KLUDGE - Because the *_obj is sorted in ASCII order, and I
    * don't have perl (yet), we revert to a *LINEAR* search when the object
    * wasn't found in the binary search.
    */
    if (c != 0)
    {
        for (i = 0; i < num; ++i)
        {
            p = &(base[i * size]);
            c = (*cmp) (key, p);
            if (c == 0 || (c < 0 && (flags & OBJ_BSEARCH_VALUE_ON_NOMATCH)))
            {
                return p;
            }
        }
    }
#endif
    if (c != 0 && !(flags & OBJ_BSEARCH_VALUE_ON_NOMATCH))
    {
        p = NULL;
    }
    else if (c == 0 && (flags & OBJ_BSEARCH_FIRST_VALUE_ON_MATCH))
    {
        while (i > 0 && (*cmp) (key, &(base[(i - 1) * size])) == 0)
        {
            i--;
        }
        p = &(base[i * size]);
    }
    return p;
}



#ifndef HEADER_E_OS2_H
# define HEADER_E_OS2_H

#ifdef  __cplusplus
extern "C" {
#endif

/******************************************************************************
* Detect operating systems.  This probably needs completing.
* The result is that at least one OPENSSL_SYS_os macro should be defined.
* However, if none is defined, Unix is assumed.
**/

# define OPENSSL_SYS_UNIX

/* --------------------- Microsoft operating systems ---------------------- */

/*
* Note that MSDOS actually denotes 32-bit environments running on top of
* MS-DOS, such as DJGPP one.
*/
# if defined(OPENSSL_SYS_MSDOS)
#  undef OPENSSL_SYS_UNIX
# endif

/*
* For 32 bit environment, there seems to be the CygWin environment and then
* all the others that try to do the same thing Microsoft does...
*/
/*
* UEFI lives here because it might be built with a Microsoft toolchain and
* we need to avoid the false positive match on Windows.
*/
# if defined(OPENSSL_SYS_UEFI)
#  undef OPENSSL_SYS_UNIX
# elif defined(OPENSSL_SYS_UWIN)
#  undef OPENSSL_SYS_UNIX
#  define OPENSSL_SYS_WIN32_UWIN
# else
#  if defined(__CYGWIN__) || defined(OPENSSL_SYS_CYGWIN)
#   undef OPENSSL_SYS_UNIX
#   define OPENSSL_SYS_WIN32_CYGWIN
#  else
#   if defined(_WIN32) || defined(OPENSSL_SYS_WIN32)
#    undef OPENSSL_SYS_UNIX
#    if !defined(OPENSSL_SYS_WIN32)
#     define OPENSSL_SYS_WIN32
#    endif
#   endif
#   if defined(_WIN64) || defined(OPENSSL_SYS_WIN64)
#    undef OPENSSL_SYS_UNIX
#    if !defined(OPENSSL_SYS_WIN64)
#     define OPENSSL_SYS_WIN64
#    endif
#   endif
#   if defined(OPENSSL_SYS_WINNT)
#    undef OPENSSL_SYS_UNIX
#   endif
#   if defined(OPENSSL_SYS_WINCE)
#    undef OPENSSL_SYS_UNIX
#   endif
#  endif
# endif

/* Anything that tries to look like Microsoft is "Windows" */
# if defined(OPENSSL_SYS_WIN32) || defined(OPENSSL_SYS_WIN64) || defined(OPENSSL_SYS_WINNT) || defined(OPENSSL_SYS_WINCE)
#  undef OPENSSL_SYS_UNIX
#  define OPENSSL_SYS_WINDOWS
#  ifndef OPENSSL_SYS_MSDOS
#   define OPENSSL_SYS_MSDOS
#  endif
# endif

/*
* DLL settings.  This part is a bit tough, because it's up to the
* application implementor how he or she will link the application, so it
* requires some macro to be used.
*/
# ifdef OPENSSL_SYS_WINDOWS
#  ifndef OPENSSL_OPT_WINDLL
#   if defined(_WINDLL)         /* This is used when building OpenSSL to
    * indicate that DLL linkage should be used */
#    define OPENSSL_OPT_WINDLL
#   endif
#  endif
# endif

/* ------------------------------- OpenVMS -------------------------------- */
# if defined(__VMS) || defined(VMS) || defined(OPENSSL_SYS_VMS)
#  if !defined(OPENSSL_SYS_VMS)
#   undef OPENSSL_SYS_UNIX
#  endif
#  define OPENSSL_SYS_VMS
#  if defined(__DECC)
#   define OPENSSL_SYS_VMS_DECC
#  elif defined(__DECCXX)
#   define OPENSSL_SYS_VMS_DECC
#   define OPENSSL_SYS_VMS_DECCXX
#  else
#   define OPENSSL_SYS_VMS_NODECC
#  endif
# endif

/* -------------------------------- Unix ---------------------------------- */
# ifdef OPENSSL_SYS_UNIX
#  if defined(linux) || defined(__linux__) && !defined(OPENSSL_SYS_LINUX)
#   define OPENSSL_SYS_LINUX
#  endif
#  if defined(_AIX) && !defined(OPENSSL_SYS_AIX)
#   define OPENSSL_SYS_AIX
#  endif
# endif

/* -------------------------------- VOS ----------------------------------- */
# if defined(__VOS__) && !defined(OPENSSL_SYS_VOS)
#  define OPENSSL_SYS_VOS
#  ifdef __HPPA__
#   define OPENSSL_SYS_VOS_HPPA
#  endif
#  ifdef __IA32__
#   define OPENSSL_SYS_VOS_IA32
#  endif
# endif

/**
* That's it for OS-specific stuff
*****************************************************************************/

/* Specials for I/O an exit */
# ifdef OPENSSL_SYS_MSDOS
#  define OPENSSL_UNISTD_IO <io.h>
#  define OPENSSL_DECLARE_EXIT extern void exit(int);
# else
#  define OPENSSL_UNISTD_IO OPENSSL_UNISTD
#  define OPENSSL_DECLARE_EXIT  /* declared in unistd.h */
# endif

/*-
* OPENSSL_EXTERN is normally used to declare a symbol with possible extra
* attributes to handle its presence in a shared library.
* OPENSSL_EXPORT is used to define a symbol with extra possible attributes
* to make it visible in a shared library.
* Care needs to be taken when a header file is used both to declare and
* define symbols.  Basically, for any library that exports some global
* variables, the following code must be present in the header file that
* declares them, before OPENSSL_EXTERN is used:
*
* #ifdef SOME_BUILD_FLAG_MACRO
* # undef OPENSSL_EXTERN
* # define OPENSSL_EXTERN OPENSSL_EXPORT
* #endif
*
* The default is to have OPENSSL_EXPORT and OPENSSL_EXTERN
* have some generally sensible values.
*/

# if defined(OPENSSL_SYS_WINDOWS) && defined(OPENSSL_OPT_WINDLL)
#  define OPENSSL_EXPORT extern __declspec(dllexport)
#  define OPENSSL_EXTERN extern __declspec(dllimport)
# else
#  define OPENSSL_EXPORT extern
#  define OPENSSL_EXTERN extern
# endif

/*-
* Macros to allow global variables to be reached through function calls when
* required (if a shared library version requires it, for example.
* The way it's done allows definitions like this:
*
*      // in foobar.c
*      OPENSSL_IMPLEMENT_GLOBAL(int,foobar,0)
*      // in foobar.h
*      OPENSSL_DECLARE_GLOBAL(int,foobar);
*      #define foobar OPENSSL_GLOBAL_REF(foobar)
*/
# ifdef OPENSSL_EXPORT_VAR_AS_FUNCTION
#  define OPENSSL_IMPLEMENT_GLOBAL(type,name,value)                      \
        type *_shadow_##name(void)                                      \
        { static type _hide_##name=value; return &_hide_##name; }
#  define OPENSSL_DECLARE_GLOBAL(type,name) type *_shadow_##name(void)
#  define OPENSSL_GLOBAL_REF(name) (*(_shadow_##name()))
# else
#  define OPENSSL_IMPLEMENT_GLOBAL(type,name,value) type _shadow_##name=value;
#  define OPENSSL_DECLARE_GLOBAL(type,name) OPENSSL_EXPORT type _shadow_##name
#  define OPENSSL_GLOBAL_REF(name) _shadow_##name
# endif

# ifdef _WIN32
#  ifdef _WIN64
#   define ossl_ssize_t __int64
#   define OSSL_SSIZE_MAX _I64_MAX
#  else
#   define ossl_ssize_t int
#   define OSSL_SSIZE_MAX INT_MAX
#  endif
# endif

# if defined(OPENSSL_SYS_UEFI) && !defined(ossl_ssize_t)
#  define ossl_ssize_t INTN
#  define OSSL_SSIZE_MAX MAX_INTN
# endif

# ifndef ossl_ssize_t
#  define ossl_ssize_t ssize_t
#  if defined(SSIZE_MAX)
#   define OSSL_SSIZE_MAX SSIZE_MAX
#  elif defined(_POSIX_SSIZE_MAX)
#   define OSSL_SSIZE_MAX _POSIX_SSIZE_MAX
#  endif
# endif

# ifdef DEBUG_UNUSED
#  define __owur __attribute__((__warn_unused_result__))
# else
#  define __owur
# endif

/* Standard integer types */
# if defined(OPENSSL_SYS_UEFI)
typedef INT8 int8_t;
typedef UINT8 uint8_t;
typedef INT16 int16_t;
typedef UINT16 uint16_t;
typedef INT32 int32_t;
typedef UINT32 uint32_t;
typedef INT64 int64_t;
typedef UINT64 uint64_t;
# elif (defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901L) || \
     defined(__osf__) || defined(__sgi) || defined(__hpux) || \
     defined(OPENSSL_SYS_VMS) || defined (__OpenBSD__)
#  include <inttypes.h>
# elif defined(_MSC_VER) && _MSC_VER<=1500
/*
* minimally required typdefs for systems not supporting inttypes.h or
* stdint.h: currently just older VC++
*/
typedef signed char int8_t;
typedef unsigned char uint8_t;
typedef short int16_t;
typedef unsigned short uint16_t;
typedef int int32_t;
typedef unsigned int uint32_t;
typedef __int64 int64_t;
typedef unsigned __int64 uint64_t;
# else
#  include <stdint.h>
# endif

/* ossl_inline: portable inline definition usable in public headers */
# if !defined(inline) && !defined(__cplusplus)
#  if defined(__STDC_VERSION__) && __STDC_VERSION__>=199901L
/* just use inline */
#   define ossl_inline inline
#  elif defined(__GNUC__) && __GNUC__>=2
#   define ossl_inline __inline__
#  elif defined(_MSC_VER)
/*
* Visual Studio: inline is available in C++ only, however
* __inline is available for C, see
* http://msdn.microsoft.com/en-us/library/z8y1yy88.aspx
*/
#   define ossl_inline __inline
#  else
#   define ossl_inline
#  endif
# else
#  define ossl_inline inline
# endif

# if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
#  define ossl_noreturn _Noreturn
# elif defined(__GNUC__) && __GNUC__ >= 2
#  define ossl_noreturn __attribute__((noreturn))
# else
#  define ossl_noreturn
# endif

#ifdef  __cplusplus
}
#endif
#endif

#ifndef HEADER_STACK_H
# define HEADER_STACK_H

#ifdef  __cplusplus
extern "C" {
#endif

typedef struct stack_st OPENSSL_STACK; /* Use STACK_OF(...) instead */

typedef int(*OPENSSL_sk_compfunc)(const void*, const void*);
typedef void(*OPENSSL_sk_freefunc)(void*);
typedef void* (*OPENSSL_sk_copyfunc)(const void*);

int OPENSSL_sk_num(const OPENSSL_STACK*);
void* OPENSSL_sk_value(const OPENSSL_STACK*, int);

void* OPENSSL_sk_set(OPENSSL_STACK* st, int i, const void* data);

OPENSSL_STACK* OPENSSL_sk_new(OPENSSL_sk_compfunc cmp);
OPENSSL_STACK* OPENSSL_sk_new_null(void);
OPENSSL_STACK* OPENSSL_sk_new_reserve(OPENSSL_sk_compfunc c, int n);
int OPENSSL_sk_reserve(OPENSSL_STACK* st, int n);
void OPENSSL_sk_free(OPENSSL_STACK*);
void OPENSSL_sk_pop_free(OPENSSL_STACK* st, void(*func) (void*));
OPENSSL_STACK* OPENSSL_sk_deep_copy(const OPENSSL_STACK*,
                                    OPENSSL_sk_copyfunc c,
                                    OPENSSL_sk_freefunc f);
int OPENSSL_sk_insert(OPENSSL_STACK* sk, const void* data, int where);
void* OPENSSL_sk_delete(OPENSSL_STACK* st, int loc);
void* OPENSSL_sk_delete_ptr(OPENSSL_STACK* st, const void* p);
int OPENSSL_sk_find(OPENSSL_STACK* st, const void* data);
int OPENSSL_sk_find_ex(OPENSSL_STACK* st, const void* data);
int OPENSSL_sk_push(OPENSSL_STACK* st, const void* data);
int OPENSSL_sk_unshift(OPENSSL_STACK* st, const void* data);
void* OPENSSL_sk_shift(OPENSSL_STACK* st);
void* OPENSSL_sk_pop(OPENSSL_STACK* st);
void OPENSSL_sk_zero(OPENSSL_STACK* st);
OPENSSL_sk_compfunc OPENSSL_sk_set_cmp_func(OPENSSL_STACK* sk,
        OPENSSL_sk_compfunc cmp);
OPENSSL_STACK* OPENSSL_sk_dup(const OPENSSL_STACK* st);
void OPENSSL_sk_sort(OPENSSL_STACK* st);
int OPENSSL_sk_is_sorted(const OPENSSL_STACK* st);

# if OPENSSL_API_COMPAT < 0x10100000L
#  define _STACK OPENSSL_STACK
#  define sk_num OPENSSL_sk_num
#  define sk_value OPENSSL_sk_value
#  define sk_set OPENSSL_sk_set
#  define sk_new OPENSSL_sk_new
#  define sk_new_null OPENSSL_sk_new_null
#  define sk_free OPENSSL_sk_free
#  define sk_pop_free OPENSSL_sk_pop_free
#  define sk_deep_copy OPENSSL_sk_deep_copy
#  define sk_insert OPENSSL_sk_insert
#  define sk_delete OPENSSL_sk_delete
#  define sk_delete_ptr OPENSSL_sk_delete_ptr
#  define sk_find OPENSSL_sk_find
#  define sk_find_ex OPENSSL_sk_find_ex
#  define sk_push OPENSSL_sk_push
#  define sk_unshift OPENSSL_sk_unshift
#  define sk_shift OPENSSL_sk_shift
#  define sk_pop OPENSSL_sk_pop
#  define sk_zero OPENSSL_sk_zero
#  define sk_set_cmp_func OPENSSL_sk_set_cmp_func
#  define sk_dup OPENSSL_sk_dup
#  define sk_sort OPENSSL_sk_sort
#  define sk_is_sorted OPENSSL_sk_is_sorted
# endif

#ifdef  __cplusplus
}
#endif

#endif

#ifndef HEADER_SAFESTACK_H
# define HEADER_SAFESTACK_H

#ifdef __cplusplus
extern "C" {
#endif

# define STACK_OF(type) struct stack_st_##type

# define SKM_DEFINE_STACK_OF(t1, t2, t3) \
    STACK_OF(t1); \
    typedef int (*sk_##t1##_compfunc)(const t3 * const *a, const t3 *const *b); \
    typedef void (*sk_##t1##_freefunc)(t3 *a); \
    typedef t3 * (*sk_##t1##_copyfunc)(const t3 *a); \
    static ossl_inline int sk_##t1##_num(const STACK_OF(t1) *sk) \
    { \
        return OPENSSL_sk_num((const OPENSSL_STACK *)sk); \
    } \
    static ossl_inline t2 *sk_##t1##_value(const STACK_OF(t1) *sk, int idx) \
    { \
        return (t2 *)OPENSSL_sk_value((const OPENSSL_STACK *)sk, idx); \
    } \
    static ossl_inline STACK_OF(t1) *sk_##t1##_new(sk_##t1##_compfunc compare) \
    { \
        return (STACK_OF(t1) *)OPENSSL_sk_new((OPENSSL_sk_compfunc)compare); \
    } \
    static ossl_inline STACK_OF(t1) *sk_##t1##_new_null(void) \
    { \
        return (STACK_OF(t1) *)OPENSSL_sk_new_null(); \
    } \
    static ossl_inline STACK_OF(t1) *sk_##t1##_new_reserve(sk_##t1##_compfunc compare, int n) \
    { \
        return (STACK_OF(t1) *)OPENSSL_sk_new_reserve((OPENSSL_sk_compfunc)compare, n); \
    } \
    static ossl_inline int sk_##t1##_reserve(STACK_OF(t1) *sk, int n) \
    { \
        return OPENSSL_sk_reserve((OPENSSL_STACK *)sk, n); \
    } \
    static ossl_inline void sk_##t1##_free(STACK_OF(t1) *sk) \
    { \
        OPENSSL_sk_free((OPENSSL_STACK *)sk); \
    } \
    static ossl_inline void sk_##t1##_zero(STACK_OF(t1) *sk) \
    { \
        OPENSSL_sk_zero((OPENSSL_STACK *)sk); \
    } \
    static ossl_inline t2 *sk_##t1##_delete(STACK_OF(t1) *sk, int i) \
    { \
        return (t2 *)OPENSSL_sk_delete((OPENSSL_STACK *)sk, i); \
    } \
    static ossl_inline t2 *sk_##t1##_delete_ptr(STACK_OF(t1) *sk, t2 *ptr) \
    { \
        return (t2 *)OPENSSL_sk_delete_ptr((OPENSSL_STACK *)sk, \
                                           (const void *)ptr); \
    } \
    static ossl_inline int sk_##t1##_push(STACK_OF(t1) *sk, t2 *ptr) \
    { \
        return OPENSSL_sk_push((OPENSSL_STACK *)sk, (const void *)ptr); \
    } \
    static ossl_inline int sk_##t1##_unshift(STACK_OF(t1) *sk, t2 *ptr) \
    { \
        return OPENSSL_sk_unshift((OPENSSL_STACK *)sk, (const void *)ptr); \
    } \
    static ossl_inline t2 *sk_##t1##_pop(STACK_OF(t1) *sk) \
    { \
        return (t2 *)OPENSSL_sk_pop((OPENSSL_STACK *)sk); \
    } \
    static ossl_inline t2 *sk_##t1##_shift(STACK_OF(t1) *sk) \
    { \
        return (t2 *)OPENSSL_sk_shift((OPENSSL_STACK *)sk); \
    } \
    static ossl_inline void sk_##t1##_pop_free(STACK_OF(t1) *sk, sk_##t1##_freefunc freefunc) \
    { \
        OPENSSL_sk_pop_free((OPENSSL_STACK *)sk, (OPENSSL_sk_freefunc)freefunc); \
    } \
    static ossl_inline int sk_##t1##_insert(STACK_OF(t1) *sk, t2 *ptr, int idx) \
    { \
        return OPENSSL_sk_insert((OPENSSL_STACK *)sk, (const void *)ptr, idx); \
    } \
    static ossl_inline t2 *sk_##t1##_set(STACK_OF(t1) *sk, int idx, t2 *ptr) \
    { \
        return (t2 *)OPENSSL_sk_set((OPENSSL_STACK *)sk, idx, (const void *)ptr); \
    } \
    static ossl_inline int sk_##t1##_find(STACK_OF(t1) *sk, t2 *ptr) \
    { \
        return OPENSSL_sk_find((OPENSSL_STACK *)sk, (const void *)ptr); \
    } \
    static ossl_inline int sk_##t1##_find_ex(STACK_OF(t1) *sk, t2 *ptr) \
    { \
        return OPENSSL_sk_find_ex((OPENSSL_STACK *)sk, (const void *)ptr); \
    } \
    static ossl_inline void sk_##t1##_sort(STACK_OF(t1) *sk) \
    { \
        OPENSSL_sk_sort((OPENSSL_STACK *)sk); \
    } \
    static ossl_inline int sk_##t1##_is_sorted(const STACK_OF(t1) *sk) \
    { \
        return OPENSSL_sk_is_sorted((const OPENSSL_STACK *)sk); \
    } \
    static ossl_inline STACK_OF(t1) * sk_##t1##_dup(const STACK_OF(t1) *sk) \
    { \
        return (STACK_OF(t1) *)OPENSSL_sk_dup((const OPENSSL_STACK *)sk); \
    } \
    static ossl_inline STACK_OF(t1) *sk_##t1##_deep_copy(const STACK_OF(t1) *sk, \
                                                    sk_##t1##_copyfunc copyfunc, \
                                                    sk_##t1##_freefunc freefunc) \
    { \
        return (STACK_OF(t1) *)OPENSSL_sk_deep_copy((const OPENSSL_STACK *)sk, \
                                            (OPENSSL_sk_copyfunc)copyfunc, \
                                            (OPENSSL_sk_freefunc)freefunc); \
    } \
    static ossl_inline sk_##t1##_compfunc sk_##t1##_set_cmp_func(STACK_OF(t1) *sk, sk_##t1##_compfunc compare) \
    { \
        return (sk_##t1##_compfunc)OPENSSL_sk_set_cmp_func((OPENSSL_STACK *)sk, (OPENSSL_sk_compfunc)compare); \
    }

# define DEFINE_SPECIAL_STACK_OF(t1, t2) SKM_DEFINE_STACK_OF(t1, t2, t2)
# define DEFINE_STACK_OF(t) SKM_DEFINE_STACK_OF(t, t, t)
# define DEFINE_SPECIAL_STACK_OF_CONST(t1, t2) \
            SKM_DEFINE_STACK_OF(t1, const t2, t2)
# define DEFINE_STACK_OF_CONST(t) SKM_DEFINE_STACK_OF(t, const t, t)

/*-
* Strings are special: normally an lhash entry will point to a single
* (somewhat) mutable object. In the case of strings:
*
* a) Instead of a single char, there is an array of chars, NUL-terminated.
* b) The string may have be immutable.
*
* So, they need their own declarations. Especially important for
* type-checking tools, such as Deputy.
*
* In practice, however, it appears to be hard to have a const
* string. For now, I'm settling for dealing with the fact it is a
* string at all.
*/
typedef char* OPENSSL_STRING;
typedef const char* OPENSSL_CSTRING;

/*-
* Confusingly, LHASH_OF(STRING) deals with char ** throughout, but
* STACK_OF(STRING) is really more like STACK_OF(char), only, as mentioned
* above, instead of a single char each entry is a NUL-terminated array of
* chars. So, we have to implement STRING specially for STACK_OF. This is
* dealt with in the autogenerated macros below.
*/
DEFINE_SPECIAL_STACK_OF(OPENSSL_STRING, char)
DEFINE_SPECIAL_STACK_OF_CONST(OPENSSL_CSTRING, char)

/*
* Similarly, we sometimes use a block of characters, NOT nul-terminated.
* These should also be distinguished from "normal" stacks.
*/
typedef void* OPENSSL_BLOCK;
DEFINE_SPECIAL_STACK_OF(OPENSSL_BLOCK, void)

# ifdef  __cplusplus
}
# endif
#endif


#define OPENSSL_malloc(size) malloc(size)
#define OPENSSL_zalloc(size) calloc(1, size)
#define OPENSSL_free(mem) free(mem)
#define OPENSSL_realloc(block, size) realloc(block, size)

static const int min_nodes = 4;
static const int max_nodes = SIZE_MAX / sizeof(void*) < INT_MAX
                             ? (int)(SIZE_MAX / sizeof(void*))
                             : INT_MAX;

struct stack_st
{
    int num;
    const void** data;
    int sorted;
    int num_alloc;
    OPENSSL_sk_compfunc comp;
};

OPENSSL_sk_compfunc OPENSSL_sk_set_cmp_func(OPENSSL_STACK* sk, OPENSSL_sk_compfunc c)
{
    OPENSSL_sk_compfunc old = sk->comp;

    if (sk->comp != c)
    {
        sk->sorted = 0;
    }
    sk->comp = c;

    return old;
}

OPENSSL_STACK* OPENSSL_sk_dup(const OPENSSL_STACK* sk)
{
    OPENSSL_STACK* ret;

    if ((ret = OPENSSL_malloc(sizeof(*ret))) == NULL)
    {
        //        CRYPTOerr(CRYPTO_F_OPENSSL_SK_DUP, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    /* direct structure assignment */
    *ret = *sk;

    if (sk->num == 0)
    {
        /* postpone |ret->data| allocation */
        ret->data = NULL;
        ret->num_alloc = 0;
        return ret;
    }
    /* duplicate |sk->data| content */
    if ((ret->data = OPENSSL_malloc(sizeof(*ret->data) * sk->num_alloc)) == NULL)
    {
        goto err;
    }
    memcpy((void*)ret->data, (const void*)sk->data, sizeof(void*) * sk->num);
    return ret;
err:
    OPENSSL_sk_free(ret);
    return NULL;
}

OPENSSL_STACK* OPENSSL_sk_deep_copy(const OPENSSL_STACK* sk,
                                    OPENSSL_sk_copyfunc copy_func,
                                    OPENSSL_sk_freefunc free_func)
{
    OPENSSL_STACK* ret;
    int i;

    if ((ret = OPENSSL_malloc(sizeof(*ret))) == NULL)
    {
        //        CRYPTOerr(CRYPTO_F_OPENSSL_SK_DEEP_COPY, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    /* direct structure assignment */
    *ret = *sk;

    if (sk->num == 0)
    {
        /* postpone |ret| data allocation */
        ret->data = NULL;
        ret->num_alloc = 0;
        return ret;
    }

    ret->num_alloc = sk->num > min_nodes ? sk->num : min_nodes;
    ret->data = OPENSSL_zalloc(sizeof(*ret->data) * ret->num_alloc);
    if (ret->data == NULL)
    {
        OPENSSL_free(ret);
        return NULL;
    }

    for (i = 0; i < ret->num; ++i)
    {
        if (sk->data[i] == NULL)
        {
            continue;
        }
        if ((ret->data[i] = copy_func(sk->data[i])) == NULL)
        {
            while (--i >= 0)
                if (ret->data[i] != NULL)
                {
                    free_func((void*)ret->data[i]);
                }
            OPENSSL_sk_free(ret);
            return NULL;
        }
    }
    return ret;
}

OPENSSL_STACK* OPENSSL_sk_new_null(void)
{
    return OPENSSL_sk_new_reserve(NULL, 0);
}

OPENSSL_STACK* OPENSSL_sk_new(OPENSSL_sk_compfunc c)
{
    return OPENSSL_sk_new_reserve(c, 0);
}

/*
* Calculate the array growth based on the target size.
*
* The growth fraction is a rational number and is defined by a numerator
* and a denominator.  According to Andrew Koenig in his paper "Why Are
* Vectors Efficient?" from JOOP 11(5) 1998, this factor should be less
* than the golden ratio (1.618...).
*
* We use 3/2 = 1.5 for simplicity of calculation and overflow checking.
* Another option 8/5 = 1.6 allows for slightly faster growth, although safe
* computation is more difficult.
*
* The limit to avoid overflow is spot on.  The modulo three correction term
* ensures that the limit is the largest number than can be expanded by the
* growth factor without exceeding the hard limit.
*
* Do not call it with |current| lower than 2, or it will infinitely loop.
*/
static ossl_inline int compute_growth(int target, int current)
{
    const int limit = (max_nodes / 3) * 2 + (max_nodes % 3 ? 1 : 0);

    while (current < target)
    {
        /* Check to see if we're at the hard limit */
        if (current >= max_nodes)
        {
            return 0;
        }

        /* Expand the size by a factor of 3/2 if it is within range */
        current = current < limit ? current + current / 2 : max_nodes;
    }
    return current;
}

/* internal STACK storage allocation */
static int sk_reserve(OPENSSL_STACK* st, int n, int exact)
{
    const void** tmpdata;
    int num_alloc;

    /* Check to see the reservation isn't exceeding the hard limit */
    if (n > max_nodes - st->num)
    {
        return 0;
    }

    /* Figure out the new size */
    num_alloc = st->num + n;
    if (num_alloc < min_nodes)
    {
        num_alloc = min_nodes;
    }

    /* If |st->data| allocation was postponed */
    if (st->data == NULL)
    {
        /*
        * At this point, |st->num_alloc| and |st->num| are 0;
        * so |num_alloc| value is |n| or |min_nodes| if greater than |n|.
        */
        if ((st->data = OPENSSL_zalloc(sizeof(void*) * num_alloc)) == NULL)
        {
            //            CRYPTOerr(CRYPTO_F_SK_RESERVE, ERR_R_MALLOC_FAILURE);
            return 0;
        }
        st->num_alloc = num_alloc;
        return 1;
    }

    if (!exact)
    {
        if (num_alloc <= st->num_alloc)
        {
            return 1;
        }
        num_alloc = compute_growth(num_alloc, st->num_alloc);
        if (num_alloc == 0)
        {
            return 0;
        }
    }
    else if (num_alloc == st->num_alloc)
    {
        return 1;
    }

    tmpdata = OPENSSL_realloc((void*)st->data, sizeof(void*) * num_alloc);
    if (tmpdata == NULL)
    {
        return 0;
    }

    st->data = tmpdata;
    st->num_alloc = num_alloc;
    return 1;
}

OPENSSL_STACK* OPENSSL_sk_new_reserve(OPENSSL_sk_compfunc c, int n)
{
    OPENSSL_STACK* st = OPENSSL_zalloc(sizeof(OPENSSL_STACK));

    if (st == NULL)
    {
        return NULL;
    }

    st->comp = c;

    if (n <= 0)
    {
        return st;
    }

    if (!sk_reserve(st, n, 1))
    {
        OPENSSL_sk_free(st);
        return NULL;
    }

    return st;
}

int OPENSSL_sk_reserve(OPENSSL_STACK* st, int n)
{
    if (st == NULL)
    {
        return 0;
    }

    if (n < 0)
    {
        return 1;
    }
    return sk_reserve(st, n, 1);
}

int OPENSSL_sk_insert(OPENSSL_STACK* st, const void* data, int loc)
{
    if (st == NULL || st->num == max_nodes)
    {
        return 0;
    }

    if (!sk_reserve(st, 1, 0))
    {
        return 0;
    }

    if ((loc >= st->num) || (loc < 0))
    {
        st->data[st->num] = data;
    }
    else
    {
        memmove((void*)&st->data[loc + 1], (const void*)&st->data[loc],
                sizeof(st->data[0]) * (st->num - loc));
        st->data[loc] = data;
    }
    st->num++;
    st->sorted = 0;
    return st->num;
}

static ossl_inline void* internal_delete(OPENSSL_STACK* st, int loc)
{
    const void* ret = st->data[loc];

    if (loc != st->num - 1)
        memmove((void*)&st->data[loc], (const void*)&st->data[loc + 1],
                sizeof(st->data[0]) * (st->num - loc - 1));
    st->num--;

    return (void*)ret;
}

void* OPENSSL_sk_delete_ptr(OPENSSL_STACK* st, const void* p)
{
    int i;

    for (i = 0; i < st->num; i++)
        if (st->data[i] == p)
        {
            return internal_delete(st, i);
        }
    return NULL;
}

void* OPENSSL_sk_delete(OPENSSL_STACK* st, int loc)
{
    if (st == NULL || loc < 0 || loc >= st->num)
    {
        return NULL;
    }

    return internal_delete(st, loc);
}

static int internal_find(OPENSSL_STACK* st, const void* data,
                         int ret_val_options)
{
    const void* r;
    int i;

    if (st == NULL || st->num == 0)
    {
        return -1;
    }

    if (st->comp == NULL)
    {
        for (i = 0; i < st->num; i++)
            if (st->data[i] == data)
            {
                return i;
            }
        return -1;
    }

    if (!st->sorted)
    {
        if (st->num > 1)
        {
            qsort((void*)st->data, st->num, sizeof(void*), st->comp);
        }
        st->sorted = 1; /* empty or single-element stack is considered sorted */
    }
    if (data == NULL)
    {
        return -1;
    }
    r = OBJ_bsearch_ex_(&data, st->data, st->num, sizeof(void*), st->comp,
                        ret_val_options);

    return r == NULL ? -1 : (int)((const void**)r - st->data);
}

int OPENSSL_sk_find(OPENSSL_STACK* st, const void* data)
{
    return internal_find(st, data, OBJ_BSEARCH_FIRST_VALUE_ON_MATCH);
}

int OPENSSL_sk_find_ex(OPENSSL_STACK* st, const void* data)
{
    return internal_find(st, data, OBJ_BSEARCH_VALUE_ON_NOMATCH);
}

int OPENSSL_sk_push(OPENSSL_STACK* st, const void* data)
{
    if (st == NULL)
    {
        return -1;
    }
    return OPENSSL_sk_insert(st, data, st->num);
}

int OPENSSL_sk_unshift(OPENSSL_STACK* st, const void* data)
{
    return OPENSSL_sk_insert(st, data, 0);
}

void* OPENSSL_sk_shift(OPENSSL_STACK* st)
{
    if (st == NULL || st->num == 0)
    {
        return NULL;
    }
    return internal_delete(st, 0);
}

void* OPENSSL_sk_pop(OPENSSL_STACK* st)
{
    if (st == NULL || st->num == 0)
    {
        return NULL;
    }
    return internal_delete(st, st->num - 1);
}

void OPENSSL_sk_zero(OPENSSL_STACK* st)
{
    if (st == NULL || st->num == 0)
    {
        return;
    }
    memset((void*)st->data, 0, sizeof(*st->data) * st->num);
    st->num = 0;
}

void OPENSSL_sk_pop_free(OPENSSL_STACK* st, OPENSSL_sk_freefunc func)
{
    int i;

    if (st == NULL)
    {
        return;
    }
    for (i = 0; i < st->num; i++)
        if (st->data[i] != NULL)
        {
            func((char*)st->data[i]);
        }
    OPENSSL_sk_free(st);
}

void OPENSSL_sk_free(OPENSSL_STACK* st)
{
    if (st == NULL)
    {
        return;
    }
    OPENSSL_free((void*)st->data);
    OPENSSL_free((void*)st);
}

int OPENSSL_sk_num(const OPENSSL_STACK* st)
{
    return st == NULL ? -1 : st->num;
}

void* OPENSSL_sk_value(const OPENSSL_STACK* st, int i)
{
    if (st == NULL || i < 0 || i >= st->num)
    {
        return NULL;
    }
    return (void*)st->data[i];
}

void* OPENSSL_sk_set(OPENSSL_STACK* st, int i, const void* data)
{
    if (st == NULL || i < 0 || i >= st->num)
    {
        return NULL;
    }
    st->data[i] = data;
    st->sorted = 0;
    return (void*)st->data[i];
}

void OPENSSL_sk_sort(OPENSSL_STACK* st)
{
    if (st != NULL && !st->sorted && st->comp != NULL)
    {
        if (st->num > 1)
        {
            qsort((void*)st->data, st->num, sizeof(void*), (int(*)(const void*, const void*))st->comp);
        }
        st->sorted = 1; /* empty or single-element stack is considered sorted */
    }
}

int OPENSSL_sk_is_sorted(const OPENSSL_STACK* st)
{
    return st == NULL ? 1 : st->sorted;
}

#endif /* _OPENSSL_STACK_STANDALONE__H_ */