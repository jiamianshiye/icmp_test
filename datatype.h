#ifndef DATATYPE_H
#define DATATYPE_H

typedef int                INT;
typedef char               CHAR;
typedef unsigned char      BYTE;
typedef signed   char      SBYTE;
typedef unsigned char      BOOLEAN;
typedef void               VOID;
typedef void*              LPVOID;
typedef int                SOCKET;
typedef int                STATUS;
typedef char               INT8;
typedef short              INT16;
typedef int                INT32;
typedef long long          INT64;
typedef unsigned char      UINT8;
typedef unsigned short     UINT16;
typedef unsigned int       UINT32;
typedef unsigned long long UINT64;
typedef unsigned char      UCHAR;
typedef unsigned short     USHORT;
typedef unsigned int       UINT;
typedef unsigned long      ULONG;

typedef unsigned long      VOS_STATUS;

typedef void (*FUNCPTR)(void);
typedef void (*TaskEntryProto)(void);   


#undef NULL
#if defined(__cplusplus)
#define NULL 0
#else
#define NULL ((void *)0)
#endif

#if    (!defined(TRUE) || (TRUE!=1))
#undef TRUE
#define TRUE    1
#endif
#if    (!defined(FALSE) || (FALSE!=0))
#undef FALSE
#define FALSE   0
#endif

#define OK       0
#define ERROR   -1
#define PERR printf("error at line %d\n", __LINE__)

#define WAIT_FOREVER      ((UINT32)0xFFFFFFFF)
#define UINT_MAX_VALUE    ((UINT32)0xFFFFFFFF)
#define NO_WAIT           ((UINT32)0)
#endif

