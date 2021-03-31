#include<stdio.h>
#include<stdlib.h>
#include<windows.h>

#define FILEPATH_IN       "C://notepad.exe"
#define FILEPATH_OUT      "C://notepad_new.exe"
#define SHELLCODELENGTH   0x12
#define MESSAGEBOXADDR    0x77D507EA //每个机器的有所不同


//全局声明
BYTE shellCode[]=
{
	0x6A,00,0x6A,00,0x6A,00,0x6A,00,
	0xE8,00,00,00,00,
	0xE9,00,00,00,00
};


DWORD ReadPEFile(IN LPSTR lpszFile,OUT LPVOID* pFileBuffer)		
{		
	FILE* pFile = NULL;	
	DWORD fileSize = 0;
	LPVOID TpFileBuffer = NULL;	
		
	//打开文件	
    pFile = fopen(lpszFile, "rb");		
	if(!pFile)	
	{	
		printf(" 无法打开 EXE 文件! ");
		return NULL;
	}	
    //读取文件大小		
	fseek(pFile, 0L, SEEK_END);	//#define SEEK_END    2
    fileSize = ftell(pFile);
    fseek(pFile, 0, SEEK_SET);
	
	//分配缓冲区	
	TpFileBuffer = malloc(fileSize);		
	if(!TpFileBuffer)	
	{	
		printf(" 分配空间失败! ");
		fclose(pFile);
		return NULL;
	}
	
	//将文件数据读取到缓冲区	
	size_t n = fread(TpFileBuffer, fileSize, 1, pFile);//typedef unsigned int size_t;

	if(!n)	
	{	
		printf(" 读取数据失败!");
		free(TpFileBuffer);
		fclose(pFile);
		return NULL;
	}
	
	//关闭文件
	*pFileBuffer=TpFileBuffer;

	//printf("%x\n",*(int*)pFileBuffer);

	TpFileBuffer=NULL;
	fclose(pFile);	
    return fileSize;	
}		

DWORD CopyFileBufferToImageBuffer(IN LPVOID pFileBuffer,OUT LPVOID* pImageBuffer)
{
	PIMAGE_DOS_HEADER			pDosHeader		=	NULL;	//用来接收DOS头信息
	PIMAGE_NT_HEADERS			pNTHeader		=	NULL;
	PIMAGE_FILE_HEADER			pPEHeader		=	NULL;
	PIMAGE_OPTIONAL_HEADER32	pOptionHeader	=	NULL;
	PIMAGE_SECTION_HEADER		pSectionHeader	=	NULL;
	LPVOID						pTemImageBuffer	=	NULL;

//判断传入的值是否有效
	if(!pFileBuffer)
	{
		printf("缓冲区指针无效");
		return 0;
	}

//判断是否为PE文件
	if(*((PWORD)pFileBuffer)	!=	IMAGE_DOS_SIGNATURE)//PWORD无符号两字节指针，（*PWORD）取前两个字节
	{
		printf("不是有效的MZ头\n");
		return 0;
	}

//获取头信息
	pDosHeader	=	(PIMAGE_DOS_HEADER)pFileBuffer;

	if(*((PDWORD)((DWORD)pFileBuffer + pDosHeader->e_lfanew))	!=	IMAGE_NT_SIGNATURE)
	{
		printf("不是有效的PE标志\n");
		return 0;
	}
	//NT头地址
	pNTHeader		=	(PIMAGE_NT_HEADERS)((DWORD)pFileBuffer	+	pDosHeader->e_lfanew);
	//标准PE头地址
	pPEHeader		=	(PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 0x4);
	//可选PE头地址
	pOptionHeader	=	(PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader	+	IMAGE_SIZEOF_FILE_HEADER);	
	//第一个节表地址
	pSectionHeader	=	(PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader	+	pPEHeader->SizeOfOptionalHeader);

	//申请缓冲区大小
	pTemImageBuffer = malloc(pOptionHeader->SizeOfImage);
	if(!pTemImageBuffer)
	{
		printf("分配空间失败");
		return 0;
	}
	//初始化缓冲区
	memset(pTemImageBuffer,0,pOptionHeader->SizeOfImage);
	//根据 SizeOfHeaders，先拷贝头
	memcpy(pTemImageBuffer,pDosHeader,pOptionHeader->SizeOfHeaders);
	//根据节表，循环拷贝节
	PIMAGE_SECTION_HEADER	pTempSectionHeader	=	pSectionHeader;
	for(int i=0;i<pPEHeader->NumberOfSections;i++,pTempSectionHeader++)
	{
		memcpy((void*)((DWORD)pTemImageBuffer + pTempSectionHeader->VirtualAddress),(void*)((DWORD)pFileBuffer + pTempSectionHeader->PointerToRawData),pTempSectionHeader->SizeOfRawData);
	}

	//返回数据
	*pImageBuffer = pTemImageBuffer;
	//printf("0x%x",(*pImageBuffer));
	pTemImageBuffer	=	NULL;
	return pOptionHeader->SizeOfImage;

}

DWORD CopyImageBufferToNewBuffer(IN LPVOID pImageBuffer,OUT LPVOID* pNewBuffer)
{

	PIMAGE_DOS_HEADER			pDosHeader		=	NULL;
	PIMAGE_NT_HEADERS			pNTHeader		=	NULL;
	PIMAGE_FILE_HEADER			pPEHeader		=	NULL;
	PIMAGE_OPTIONAL_HEADER32	pOptionHeader	=	NULL;
	PIMAGE_SECTION_HEADER		pSectionHeader	=	NULL;
	LPVOID						pTempNewBuffer	=	NULL;
	
	if(!pImageBuffer)
	{
		printf("缓冲区指针无效");
		return 0;
	}

	if(*((PWORD)pImageBuffer)	!=	IMAGE_DOS_SIGNATURE)
	{
		printf("不是有效的MZ头\n");
		return 0;
	}

	pDosHeader	=	(PIMAGE_DOS_HEADER)pImageBuffer;

	if(*((PDWORD)((DWORD)pImageBuffer + pDosHeader->e_lfanew))	!=	IMAGE_NT_SIGNATURE)
	{
		printf("不是有效的PE标志\n");
		return 0;
	}

	//NT头地址
	pNTHeader		=(PIMAGE_NT_HEADERS)((DWORD)pImageBuffer+pDosHeader->e_lfanew);
	//标准PE头地址
	pPEHeader		=(PIMAGE_FILE_HEADER)(((DWORD)pNTHeader)+0x4);
	//可选PE头地址
	pOptionHeader	=(PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader+IMAGE_SIZEOF_FILE_HEADER);	
	//第一个节表地址
	pSectionHeader	=(PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader+pPEHeader->SizeOfOptionalHeader);


	//数据大小
	DWORD FileSize=pOptionHeader->SizeOfHeaders;//所有头+节表文件对齐后的大小
	for (int j = 0; j < pPEHeader->NumberOfSections; j++)
	{
		FileSize += pSectionHeader[j].SizeOfRawData;  // pSectionHeader[i]另一种加法
	}
	//数据大小（最后一个节的文件偏移+最后一个节的真实大小+文件对齐）
	/*
	DWORD	FileSize = (
		  (pSectionHeader + pPEHeader->NumberOfSections-1)->PointerToRawData 
		+ (pSectionHeader + pPEHeader->NumberOfSections-1)->Misc.VirtualSize 
		+ pOptionHeader->FileAlignment
		)&(0 - pOptionHeader->FileAlignment);
		*/
	pTempNewBuffer = malloc(FileSize);
	if(!pTempNewBuffer)
	{
		printf("分配空间失败");
		return 0;
	}
	//初始化缓冲区
	memset(pTempNewBuffer,0,FileSize);

	memcpy(pTempNewBuffer,pDosHeader,pOptionHeader->SizeOfHeaders);
	//根据节表，循环拷贝节
	PIMAGE_SECTION_HEADER	pTempSectionHeader	=	pSectionHeader;
	for(int i=0;i<pPEHeader->NumberOfSections;i++,pTempSectionHeader++)
	{
		memcpy((void*)((DWORD)pTempNewBuffer + pTempSectionHeader->PointerToRawData),
			(void*)((DWORD)pImageBuffer + pTempSectionHeader->VirtualAddress),
			pTempSectionHeader->Misc.VirtualSize);
	}

	*pNewBuffer = pTempNewBuffer;
	pTempNewBuffer	=	NULL;
	return FileSize;
}

BOOL MemeryTOFile(LPVOID pMemBuffer,size_t size)
{
	FILE *fp = NULL;
	fp = fopen(FILEPATH_OUT,"wb");	
	if(!fp)
	{
		return FALSE;
	}
	fwrite(pMemBuffer,size,1,fp);	//向磁盘写入数据
	fclose(fp);	//关闭文件
	fp = NULL;
	return TRUE;	

}

void test1()
{
	LPVOID pFileBuffer=NULL;
	LPVOID pImageBuffer=NULL;
	LPVOID pNewBuffer=NULL;
	PIMAGE_DOS_HEADER pDosHeader=NULL;
	PIMAGE_NT_HEADERS pNTHeader=NULL;
	PIMAGE_FILE_HEADER pPEHeader=NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader=NULL;
	PIMAGE_SECTION_HEADER pSectionHeader=NULL;
	PBYTE codeBegin=NULL;
	BOOL isOK=FALSE;
	DWORD size =0;
  
	//file-->fileBuffer
	size=ReadPEFile(FILEPATH_IN,&pFileBuffer);
	if(size==0||!pFileBuffer)
	{
		printf("File-> FileBuffer失败");
		return;
	}

	//FileBuffer-->ImageBuffer
	CopyFileBufferToImageBuffer(pFileBuffer,&pImageBuffer);
	if(!pImageBuffer)
	{
		printf("FileBuffer-->ImageBuffer失败！");
		free(pFileBuffer);
		return;
	}

	//判断代码段空闲区是否足够存储shellCode代码

	//Dos头地址
	pDosHeader=(PIMAGE_DOS_HEADER)pImageBuffer;
	//NT头地址
	pNTHeader=(PIMAGE_NT_HEADERS)((DWORD)pImageBuffer+pDosHeader->e_lfanew);
	//标准PE头地址
	pPEHeader=(PIMAGE_FILE_HEADER)(((DWORD)pNTHeader)+0x4);
	//可选PE头地址
	pOptionHeader=(PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader+IMAGE_SIZEOF_FILE_HEADER);	
	//第一个节表地址
	pSectionHeader=(PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader+pPEHeader->SizeOfOptionalHeader);

	if(((pSectionHeader->SizeOfRawData)-(pSectionHeader->Misc.VirtualSize))<SHELLCODELENGTH)
	{
		printf("代码区空闲空间不足！");
		free(pFileBuffer);
		free(pImageBuffer);
	}
	//将代码复制到空闲区
	codeBegin=(PBYTE)((DWORD)pImageBuffer+pSectionHeader->VirtualAddress+pSectionHeader->Misc.VirtualSize);
	memcpy(codeBegin,shellCode,SHELLCODELENGTH);

	//修正E8
	DWORD callAddr=(MESSAGEBOXADDR-(pOptionHeader->ImageBase+((DWORD)(codeBegin+0xD)-(DWORD)pImageBuffer)));
	*((PDWORD)(codeBegin+0x9))=callAddr;
	
	//修正E9
	DWORD jmpAddr=((pOptionHeader->AddressOfEntryPoint)-((DWORD)codeBegin-(DWORD)pImageBuffer+SHELLCODELENGTH));
	*(PDWORD)(codeBegin+0xE)=jmpAddr;
	//printf("0x%x\n",(DWORD)((DWORD)codeBegin-(DWORD)pImageBuffer+SHELLCODELENGTH));

	//修正OEP
	pOptionHeader->AddressOfEntryPoint=(DWORD)codeBegin-(DWORD)pImageBuffer;
	
	//修正VirtualSize
	pSectionHeader->Misc.VirtualSize+=(DWORD)0x12;

	//ImageBuffer-->NewBuffer
	size=CopyImageBufferToNewBuffer(pImageBuffer,&pNewBuffer);
	if(size ==0 ||!pNewBuffer)
	{
		printf("ImageBuffer-->NewBuffer失败！");
		free(pFileBuffer);
		free(pImageBuffer);
		return;
	}
	//NewBuffer-->文件
	isOK = MemeryTOFile(pNewBuffer,size);
	if(isOK)
	{
		printf("存盘成功");
		free(pFileBuffer);
		free(pImageBuffer);
		free(pNewBuffer);
		return;
	}
	//释放内存
	free(pFileBuffer);
	free(pImageBuffer);
	free(pNewBuffer);
}

void test2()
{
	LPVOID pFileBuffer=NULL;
	LPVOID pImageBuffer=NULL;
	LPVOID pNewBuffer=NULL;
	PIMAGE_DOS_HEADER pDosHeader=NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader=NULL;
	PIMAGE_SECTION_HEADER pSectionHeader=NULL;
	BOOL isOK=FALSE;
	DWORD size =0;

	//file-->fileBuffer
	size=ReadPEFile(FILEPATH_IN,&pFileBuffer);
	if(size==0||!pFileBuffer)
	{
		printf("File-> FileBuffer失败");
		return;
	}

	//FileBuffer-->ImageBuffer
	CopyFileBufferToImageBuffer(pFileBuffer,&pImageBuffer);
	if(!pImageBuffer)
	{
		printf("FileBuffer-->ImageBuffer失败！");
		free(pFileBuffer);
		return;
	}

	//ImageBuffer-->NewBuffer
	size=CopyImageBufferToNewBuffer(pImageBuffer,&pNewBuffer);
	if(size ==0 ||!pNewBuffer)
	{
		printf("ImageBuffer-->NewBuffer失败！");
		free(pFileBuffer);
		free(pImageBuffer);
		return;
	}

	//NewBuffer-->文件
	isOK = MemeryTOFile(pNewBuffer,size);
	if(isOK)
	{
		printf("存盘成功");
		return;
	}

	//释放内存
	free(pFileBuffer);
	free(pImageBuffer);
	free(pNewBuffer);	
}

void main(int argc,char* argv[])
{
	test1();
	getchar();
	system("pause");
}
