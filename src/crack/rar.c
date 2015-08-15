#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "..\utils.h"
#include "unrarlib.h"

int filecounter = 0;
ArchiveList_struct *List = NULL;
char filename[_MAX_PATH];
MemoryFile mf;

#define NM  260
extern char Password[255];                         /* password to decrypt files    */
extern char ArgName[NM];                           /* current file in rar archive  */
extern MemoryFile *MemRARFile;                   /* pointer to RAR file in memory*/
extern unsigned char *temp_output_buffer;          /* extract files to this pointer*/
extern unsigned long *temp_output_buffer_offset;   /* size of temp. extract buffer */
int offset_org;
extern unsigned char *UnpMemory;
extern struct NewMainArchiveHeader NewMhd;
extern int MainHeadSize;
extern struct BlockHeader BlockHead;
int size;
extern struct NewFileHeader NewLhd;

static int
rar_open(CrackContext *ctx)
{
	ctx->input_fp = fopen(ctx->input_filename, "rb");
	if (ctx->input_fp == NULL)
		return -1;
	fseek(ctx->input_fp, 0, SEEK_END);
	mf.size = ftell(ctx->input_fp);
	mf.data = (unsigned char *)malloc(mf.size);
	mf.offset = 0;
	rewind(ctx->input_fp);
	fread(mf.data, 1, mf.size, ctx->input_fp);
	fclose(ctx->input_fp);
	
	filecounter = urarlib_list(&mf, (ArchiveList_struct*)&List);
	
	if(List->item.NameSize < 23)
	{
		strncpy(ArgName, List->item.Name, sizeof(filename));
	}
	
	urarlib_freelist(List);
	
	InitCRC();
	MemRARFile = &mf;
	
	
	MemRARFile->offset = 0;                   /* start reading from offset 0  */
	if (!IsArchive())
		return -1;
	
	if ((UnpMemory=malloc(UNP_MEMORY))==NULL)
		return -1;
	MemRARFile->offset+=NewMhd.HeadSize - MainHeadSize;
	
    if (ReadBlock(FILE_HEAD | READSUBBLOCK) <= 0)
		return FALSE;
    if (BlockHead.HeadType==SUB_HEAD)
		return FALSE;
	
	
	temp_output_buffer=malloc(NewLhd.UnpSize);/* allocate memory for the*/
	temp_output_buffer_offset = &size;
	*temp_output_buffer_offset=0;		
	if(temp_output_buffer == NULL)
		return FALSE;
	
	offset_org = MemRARFile->offset;
	return 0;
}

static int 
rar_crack(CrackContext *ctx, char *string, unsigned int len)
{
	MemRARFile->offset = offset_org;
	strcpy(Password, string);
	*temp_output_buffer_offset=0;		
	if(ExtrFile())
	{
		strcpy(ctx->pw, string);
		return 1;
	}
	
	return 0;
}

static int 
rar_close(CrackContext *ctx)
{
	free(temp_output_buffer);
	free(UnpMemory);
	UnpMemory=NULL;
	
	if (mf.data)
		free(mf.data);
	
	return 0;
}

Cracker rar_cracker = 
{
	"matrix rar cracker", 
	"rar", 
	CRACK_TYPE_DICTIONARY | CRACK_TYPE_BRUTEFORCE, 
	CRACK_ID_RAR, 
	0, 
	rar_open, 
	rar_crack, 
	rar_close, 
	NULL
};
