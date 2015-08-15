#ifndef __URARLIB_H
#define __URARLIB_H

#ifdef __cplusplus
extern "C"
{
#endif
#include <windows.h>

#define _WIN_32                             /* Win32 with VisualC           */
#define _DEBUG_LOG_FILE "C:\\temp\\debug_unrar.txt" /* log file path        */
typedef unsigned char    UBYTE;             /* WIN32 definitions            */
typedef unsigned short   UWORD;
typedef unsigned long    UDWORD;


/* This structure is used for listing archive content                       */
struct RAR20_archive_entry                  /* These infos about files are  */
{                                           /* stored in RAR v2.0 archives  */
  char   *Name;
  UWORD  NameSize;
  UDWORD PackSize;
  UDWORD UnpSize;
  UBYTE  HostOS;                            /* MSDOS=0,OS2=1,WIN32=2,UNIX=3 */
  UDWORD FileCRC;
  UDWORD FileTime;
  UBYTE  UnpVer;
  UBYTE  Method;
  UDWORD FileAttr;
};

typedef struct  archivelist                 /* used to list archives        */
{
  struct RAR20_archive_entry item;
  struct archivelist         *next;
} ArchiveList_struct;

typedef struct  memory_file                 /* used to decompress files in  */
{                                           /* memory                       */
  void                       *data;         /* pointer to the file data     */
  unsigned long              size;          /* total size of the file data  */
  unsigned long              offset;        /* offset within "memory-file"  */
} MemoryFile;
#define MAXWINSIZE      0x100000
#define MAXWINMASK      (MAXWINSIZE-1)
#define UNP_MEMORY      MAXWINSIZE
#define Min(x,y) (((x)<(y)) ? (x):(y))
#define Max(x,y) (((x)>(y)) ? (x):(y))
#define NM  260

#define SIZEOF_MARKHEAD         7
#define SIZEOF_OLDMHD           7
#define SIZEOF_NEWMHD          13
#define SIZEOF_OLDLHD          21
#define SIZEOF_NEWLHD          32
#define SIZEOF_SHORTBLOCKHEAD   7
#define SIZEOF_LONGBLOCKHEAD   11
#define SIZEOF_COMMHEAD        13
#define SIZEOF_PROTECTHEAD     26


#define PACK_VER       20                   /* version of decompression code*/
#define UNP_VER        20
#define PROTECT_VER    20


enum { M_DENYREAD,M_DENYWRITE,M_DENYNONE,M_DENYALL };
enum { FILE_EMPTY,FILE_ADD,FILE_UPDATE,FILE_COPYOLD,FILE_COPYBLOCK };
enum { SUCCESS,WARNING,FATAL_ERROR,CRC_ERROR,LOCK_ERROR,WRITE_ERROR,
       OPEN_ERROR,USER_ERROR,MEMORY_ERROR,USER_BREAK=255,IMM_ABORT=0x8000 };
enum { EN_LOCK=1,EN_VOL=2 };
enum { SD_MEMORY=1,SD_FILES=2 };
enum { NAMES_DONTCHANGE };
enum { LOG_ARC=1,LOG_FILE=2 };
enum { OLD_DECODE=0,OLD_ENCODE=1,NEW_CRYPT=2 };
enum { OLD_UNPACK,NEW_UNPACK };


#define MHD_COMMENT        2
#define MHD_LOCK           4
#define MHD_PACK_COMMENT   16
#define MHD_AV             32
#define MHD_PROTECT        64

#define LHD_SPLIT_BEFORE   1
#define LHD_SPLIT_AFTER    2
#define LHD_PASSWORD       4
#define LHD_COMMENT        8
#define LHD_SOLID          16

#define LHD_WINDOWMASK     0x00e0
#define LHD_WINDOW64       0
#define LHD_WINDOW128      32
#define LHD_WINDOW256      64
#define LHD_WINDOW512      96
#define LHD_WINDOW1024     128
#define LHD_DIRECTORY      0x00e0

#define LONG_BLOCK         0x8000
#define READSUBBLOCK       0x8000

enum { ALL_HEAD=0,MARK_HEAD=0x72,MAIN_HEAD=0x73,FILE_HEAD=0x74,
       COMM_HEAD=0x75,AV_HEAD=0x76,SUB_HEAD=0x77,PROTECT_HEAD=0x78};
enum { EA_HEAD=0x100 };
enum { MS_DOS=0,OS2=1,WIN_32=2,UNIX=3 };


struct MarkHeader
{
  UBYTE Mark[7];
};


struct NewMainArchiveHeader
{
  UWORD HeadCRC;
  UBYTE HeadType;
  UWORD Flags;
  UWORD HeadSize;
  UWORD Reserved;
  UDWORD Reserved1;
};


struct NewFileHeader
{
  UWORD HeadCRC;
  UBYTE HeadType;
  UWORD Flags;
  UWORD HeadSize;
  UDWORD PackSize;
  UDWORD UnpSize;
  UBYTE HostOS;
  UDWORD FileCRC;
  UDWORD FileTime;
  UBYTE UnpVer;
  UBYTE Method;
  UWORD NameSize;
  UDWORD FileAttr;
};


struct BlockHeader
{
  UWORD HeadCRC;
  UBYTE HeadType;
  UWORD Flags;
  UWORD HeadSize;
  UDWORD DataSize;
};


struct Decode
{
  unsigned int MaxNum;
  unsigned int DecodeLen[16];
  unsigned int DecodePos[16];
  unsigned int DecodeNum[2];
};


/* -- global functions ---------------------------------------------------- */

/* urarlib_get:
 * decompresses and decrypt data from a RAR file to a buffer in system memory.
 *
 *   input: *output         pointer to an empty char*. This pointer will show
 *                          to the extracted data
 *          *size           shows where to write the size of the decompressed
 *                          file
 *                          (**NOTE: URARLib _does_ memory allocation etc.!**)
 *          *filename       pointer to string containing the file to decompress
 *          *rarfile        pointer to a string with the full name and path of
 *                          the RAR file or pointer to a RAR file in memory if
 *                          memory-to-memory decompression is active.
 *          *libpassword    pointer to a string with the password used to
 *                          en-/decrypt the RAR
 *   output: int            returns TRUE on success or FALSE on error
 *                          (FALSE=0, TRUE=1)
 */

extern int urarlib_get(void  *output,
                       unsigned long *size,
                       char *filename,
                       void *rarfile,
                       char *libpassword);


/* urarlib_list:
 * list the content of a RAR archive.
 *
 *   input: *rarfile        pointer to a string with the full name and path of
 *                          the RAR file or pointer to a RAR file in memory if
 *                          memory-to-memory decompression is active.
 *          *list           pointer to an ArchiveList_struct that can be
 *                          filled with details about the archive
 *                          to the extracted data
 *   output: int            number of files/directories within archive
 */

extern int urarlib_list(void *rarfile, ArchiveList_struct *list);


/* urarlib_freelist:
 * (after the suggestion and code of Duy Nguyen, Sean O'Blarney
 * and Johannes Winkelmann who independently wrote a patch)
 * free the memory of a ArchiveList_struct created by urarlib_list.
 *
 *    input: *list          pointer to an ArchiveList_struct
 *    output: -
 */

extern void urarlib_freelist(ArchiveList_struct *list);
extern void InitCRC(void);
extern BOOL ExtrFile(void);
extern int IsArchive(void);
extern int ReadBlock(int BlockType);

#ifdef __cplusplus
};
#endif

#endif

