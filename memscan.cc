#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#define WIN32_LEAN_AND_MEAN 1
#include <windows.h>

typedef uint8_t uint8;
typedef uintptr_t uintptr;

void PrintLastError(const char *Context){
	DWORD ErrorCode = GetLastError();
	char ErrorString[256];
	DWORD Ret = FormatMessageA(
		FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL, ErrorCode, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		ErrorString, sizeof(ErrorString), NULL);
	if(Ret == 0){
		strcpy(ErrorString, "unknown error");
	}
	printf("%s | error(%d): %s\n", Context, ErrorCode, ErrorString);
}

void DebugPrintBuf(uintptr Address, const uint8 *Buffer, int Count){
	const int BytesPerLine = 16;
	int FullLines = Count / BytesPerLine;
	int Remainder = Count % BytesPerLine;

	for(int i = 0; i < FullLines; i += 1){
		printf("%16" PRIXPTR " | ", (Address + i * BytesPerLine));

		for(int j = 0; j < BytesPerLine; j += 1){
			if(j > 0) putchar(' ');
			printf("%02X", Buffer[i * BytesPerLine + j]);
		}

		printf(" | ");

		for(int j = 0; j < BytesPerLine; j += 1){
			int ch = Buffer[i * BytesPerLine + j];
			printf("%c", isprint(ch) ? ch : '.');
		}

		putchar('\n');
	}

	if(Remainder > 0){
		printf("%16" PRIXPTR " | ", (Address + FullLines * BytesPerLine));

		for(int j = 0; j < BytesPerLine; j += 1){
			if(j > 0) putchar(' ');
			if(j < Remainder){
				printf("%02X", Buffer[FullLines * BytesPerLine + j]);
			}else{
				printf("  ");
			}
		}

		printf(" | ");

		for(int j = 0; j < BytesPerLine; j += 1){
			if(j < Remainder){
				int ch = Buffer[FullLines * BytesPerLine + j];
				printf("%c", isprint(ch) ? ch : '.');
			}else{
				printf(" ");
			}
		}

		putchar('\n');
	}
}

void DumpProcessMemory(HANDLE Process, uintptr BaseAddr, SIZE_T Size){
	uintptr Addr = BaseAddr;
	uintptr End = BaseAddr + Size;
	while(Addr < End){
		uint8 Buffer[32 * 1024];
		SIZE_T BytesToRead = End - Addr;
		if(BytesToRead > sizeof(Buffer)){
			BytesToRead = sizeof(Buffer);
		}

		SIZE_T BytesRead;
		if(!ReadProcessMemory(Process, (void*)Addr, Buffer, BytesToRead, &BytesRead)){
			PrintLastError("DumpProcessMemory>ReadProcessMemory");
			return;
		}

		DebugPrintBuf(Addr, Buffer, (int)BytesRead);
		Addr += BytesRead;
	}
}

int BufferFind(const uint8 *Buffer, int BufferSize, const uint8 *Data, int DataSize){
	for(int i = 0; i < (BufferSize - DataSize); i += 1){
		if(memcmp(Buffer + i, Data, DataSize) == 0){
			return i;
		}
	}
	return -1;
}

void ScanProcessMemory(HANDLE Process, uintptr BaseAddr, SIZE_T Size,
		const uint8 *Data, SIZE_T DataSize, int ContextWindow){
	uintptr Addr = BaseAddr;
	uintptr End = BaseAddr + Size;
	while(Addr < End){
		uint8 Buffer[32 * 1024];
		SIZE_T BytesToRead = End - Addr;
		if(BytesToRead > sizeof(Buffer)){
			BytesToRead = sizeof(Buffer);
		}

		SIZE_T BytesRead;
		if(!ReadProcessMemory(Process, (void*)Addr, Buffer, BytesToRead, &BytesRead)){
			PrintLastError("ScanProcessMemory>ReadProcessMemory");
			return;
		}

		// TODO(fusion): This will work most of the time but is not the best way
		// to scan for something because the data we're looking for may be split
		// between reads, depending on the size of `Buffer`.
		int Cursor = 0;
		while(true){
			int Offset = BufferFind(Buffer + Cursor, (int)BytesRead - Cursor, Data, (int)DataSize);
			if(Offset == -1){
				break;
			}

			Cursor += Offset;
			int PrintStart = Cursor - ContextWindow;
			int PrintEnd = Cursor + (int)DataSize + ContextWindow;

			if(PrintStart < 0){
				PrintStart = 0;
			}

			if(PrintEnd > (int)BytesRead){
				PrintEnd = (int)BytesRead;
			}

			DebugPrintBuf(Addr + PrintStart, Buffer + PrintStart, PrintEnd - PrintStart);
			Cursor += (int)DataSize;
		}

		Addr += BytesRead;
	}
}

int main(int argc, char **argv){
	uint8 Data[128];
	int DataSize = 0;
	int ContextWindow = 10;
	for(int i = 1; i < argc; i += 1){
		if(argv[i][0] == '-'){
			if((i + 1) >= argc){
				printf("missing \"%s\" value", argv[i]);
				break;
			}

			if(strcmp(argv[i], "-c") == 0){
				ContextWindow = atoi(argv[i + 1]);
			}else if(strcmp(argv[i], "-byte") == 0){
				int Num = atoi(argv[i + 1]);
				Data[0] = (uint8)Num;
				DataSize = 1;
			}else if(strcmp(argv[i], "-le16") == 0){
				int Num = atoi(argv[i + 1]);
				Data[0] = (uint8)(Num >> 0);
				Data[1] = (uint8)(Num >> 8);
				DataSize = 2;
			}else if(strcmp(argv[i], "-be16") == 0){
				int Num = atoi(argv[i + 1]);
				Data[0] = (uint8)(Num >> 8);
				Data[1] = (uint8)(Num >> 0);
				DataSize = 2;
			}else if(strcmp(argv[i], "-le32") == 0){
				int Num = atoi(argv[i + 1]);
				Data[0] = (uint8)(Num >> 0);
				Data[1] = (uint8)(Num >> 8);
				Data[2] = (uint8)(Num >> 16);
				Data[3] = (uint8)(Num >> 24);
				DataSize = 4;
			}else if(strcmp(argv[i], "-be32") == 0){
				int Num = atoi(argv[i + 1]);
				Data[0] = (uint8)(Num >> 24);
				Data[1] = (uint8)(Num >> 16);
				Data[2] = (uint8)(Num >> 8);
				Data[3] = (uint8)(Num >> 0);
				DataSize = 4;
			}

			i += 1;
		}else{
			DataSize = (int)strlen(argv[i]);
			if(DataSize > (int)sizeof(Data)){
				DataSize = (int)sizeof(Data);
			}
			memcpy(Data, argv[i], DataSize);
		}
	}

	if(DataSize == 0){
		printf("Invalid usage. See `memscan.cc`.\n");
		return 1;
	}

	HWND Window = FindWindowA("TibiaClient", NULL);
	if(Window == NULL){
		PrintLastError("FindWindowA");
		return -1;
	}

	DWORD ProcessID;
	GetWindowThreadProcessId(Window, &ProcessID);

	HANDLE Process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, ProcessID);
	if(Process == NULL){
		PrintLastError("OpenProcess");
		return -1;
	}

	uintptr BaseAddr = 0;
	MEMORY_BASIC_INFORMATION Info;
	while(VirtualQueryEx(Process, (void*)BaseAddr, &Info, sizeof(Info)) != 0){
		if((Info.State & MEM_COMMIT) && !(Info.Protect & PAGE_NOACCESS) && !(Info.Protect & PAGE_GUARD)){
			ScanProcessMemory(Process, (uintptr)Info.BaseAddress, Info.RegionSize, Data, DataSize, ContextWindow);
		}
		BaseAddr = (uintptr)Info.BaseAddress + Info.RegionSize;
	}
	CloseHandle(Process);
	return 0;
}
