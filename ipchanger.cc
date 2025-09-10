#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#define WIN32_LEAN_AND_MEAN 1
#include <windows.h>

#define NARRAY(Array) (int)(sizeof(Array) / sizeof(Array[0]))

typedef uint8_t uint8;
typedef uintptr_t uintptr;

struct ServerEntry{
	ServerEntry *Next;
	int Version;
	char Alias[100];
	char HostName[100];
	int Port;
	char RsaModulus[1024];
};

struct TibiaVersion{
	int Version;
	const char *VersionString;
	int NumLoginEndpoints;
	int LoginEndpointStride;
	int MaxHostNameSize;
	int MaxRsaModulusSize;
	uintptr VersionStringAddr;
	uintptr FirstLoginHostNameAddr;
	uintptr FirstLoginPortAddr;
	uintptr RsaModulusAddr;
};

struct AutoHandleClose{
private:
	HANDLE m_Handle;

public:
	AutoHandleClose(HANDLE Handle){
		m_Handle = Handle;
	}

	~AutoHandleClose(void){
		if(m_Handle != NULL){
			CloseHandle(m_Handle);
		}
	}
};

bool StringEqN(const char *A, const char *B, int N){
	int Index = 0;
	while(true){
		if(Index >= N){
			return true;
		}else if(A[Index] != B[Index] || A[Index] == 0){
			return false;
		}
		Index += 1;
	}
}

bool StringEqCI(const char *A, const char *B){
	int Index = 0;
	while(true){
		if(tolower(A[Index]) != tolower(B[Index])){
			return false;
		}else if(A[Index] == 0){
			return true;
		}
		Index += 1;
	}
}

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

bool ChangeIP(const TibiaVersion *V, const char *HostName, int Port, const char *RsaModulus){
	int HostNameSize = (int)strlen(HostName) + 1;
	if(HostNameSize > V->MaxHostNameSize){
		printf("ChangeIP: HostName size exceeds limit for version %d (%d > %d).\n",
				V->Version, HostNameSize, V->MaxHostNameSize);
		return false;
	}

	if(Port <= 0 || Port > 0xFFFF){
		printf("ChangeIP: Invalid port number %d.\n", Port);
		return false;
	}

	HWND Window = FindWindowA("TibiaClient", NULL);
	if(Window == NULL){
		printf("ChangeIP: No client running.\n");
		return false;
	}

	DWORD ProcessID;
	GetWindowThreadProcessId(Window, &ProcessID);

	HANDLE Process = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, FALSE, ProcessID);
	if(Process == NULL){
		PrintLastError("OpenProcess");
		return false;
	}

	AutoHandleClose HandleClose(Process);
	if(V->VersionString != NULL && V->VersionStringAddr != 0){
		uint8 VersionString[128];
		if(!ReadProcessMemory(Process, (void*)V->VersionStringAddr,
				VersionString, sizeof(VersionString), NULL)){
			PrintLastError("ReadProcessMemory(VersionString)");
			return false;
		}

		int VersionStringLen = (int)strlen(V->VersionString);
		if(!StringEqN(V->VersionString, (char*)VersionString, VersionStringLen)){
			printf("ChangeIP: Invalid client version.\n");
			return false;
		}
	}

	if(V->FirstLoginHostNameAddr != 0 && V->FirstLoginPortAddr != 0){
		uint8 HelpPort[4];
		HelpPort[0] = (uint8)(Port >>  0);
		HelpPort[1] = (uint8)(Port >>  8);
		HelpPort[2] = (uint8)(Port >> 16);
		HelpPort[3] = (uint8)(Port >> 24);

		for(int i = 0; i < V->NumLoginEndpoints; i += 1){
			uintptr HostNameAddr = V->FirstLoginHostNameAddr + i * V->LoginEndpointStride;
			uintptr PortAddr     = V->FirstLoginPortAddr     + i * V->LoginEndpointStride;

			if(!WriteProcessMemory(Process, (void*)HostNameAddr, HostName, HostNameSize, NULL)){
				PrintLastError("WriteProcessMemory(HostName)");
				return false;
			}

			if(!WriteProcessMemory(Process, (void*)PortAddr, HelpPort, sizeof(HelpPort), NULL)){
				PrintLastError("WriteProcessMemory(Port)");
				return false;
			}
		}
	}

	if(RsaModulus != NULL && V->RsaModulusAddr != 0){
		int RsaModulusSize = (int)strlen(RsaModulus) + 1;
		if(RsaModulusSize > V->MaxRsaModulusSize){
			printf("ChangeIP: RsaModulus size exceeds limit for version %d (%d > %d).\n",
					V->Version, RsaModulusSize, V->MaxRsaModulusSize);
			return false;
		}

		// NOTE(fusion): The RSA modulus lives in READONLY memory.
		DWORD OldProtection;
		if(!VirtualProtectEx(Process, (void*)V->RsaModulusAddr,
				V->MaxRsaModulusSize, PAGE_READWRITE, &OldProtection)){
			PrintLastError("VirtualProtectEx(RsaModulus, READWRITE)");
			return false;
		}

		if(!WriteProcessMemory(Process, (void*)V->RsaModulusAddr, RsaModulus, RsaModulusSize, NULL)){
			PrintLastError("WriteProcessMemory(RsaModulus)");
			return false;
		}

		DWORD Dummy;
		if(!VirtualProtectEx(Process, (void*)V->RsaModulusAddr,
				V->MaxRsaModulusSize, OldProtection, &Dummy)){
			PrintLastError("VirtualProtectEx(RsaModulus, OldProtection)");
			return false;
		}
	}

	return true;
}

int ReadLine(FILE *File, char *Buffer, int BufferSize, bool *OutEndOfFile, bool *OutClamped){
	int LineSize = 0;
	bool EndOfFile = false;
	bool Clamped = false;
	while(true){
		int ch = fgetc(File);
		if(ch == EOF || ch == '\n'){
			EndOfFile = (ch == EOF);
			break;
		}

		if(LineSize < BufferSize){
			Buffer[LineSize] = (char)ch;
		}

		LineSize += 1;
	}

	if(LineSize >= BufferSize){
		LineSize = BufferSize - 1;
		Clamped = true;
	}

	if(!EndOfFile && LineSize > 0 && Buffer[LineSize - 1] == '\r'){
		LineSize -= 1;
	}

	Buffer[LineSize] = 0;
	if(OutEndOfFile) *OutEndOfFile = EndOfFile;
	if(OutClamped) *OutClamped = Clamped;
	return LineSize;
}

void NextValue(const char *Line, int Delim, int *Cursor, char *Buffer, int BufferSize){
	int Size = 0;
	while(Line[*Cursor] != 0 && Line[*Cursor] != Delim){
		if(Size < BufferSize){
			Buffer[Size] = Line[*Cursor];
		}

		*Cursor += 1;
		Size += 1;
	}

	if(Line[*Cursor] != 0){
		*Cursor += 1;
	}

	if(Size >= BufferSize){
		Size = BufferSize - 1;
	}

	Buffer[Size] = 0;
}

ServerEntry *ParseServerEntry(const char *Line, int LineNumber){
	int LineStart = 0;
	while(Line[LineStart] != 0 && isspace(Line[LineStart])){
		LineStart += 1;
	}

	if(Line[LineStart] == 0 || Line[LineStart] == '#'){
		return NULL;
	}

	char HelpVersion[16];
	char HelpPort[16];
	int Cursor = LineStart;
	ServerEntry *Server = (ServerEntry*)calloc(1, sizeof(ServerEntry));
	NextValue(Line, ';', &Cursor, HelpVersion, sizeof(HelpVersion));
	NextValue(Line, ';', &Cursor, Server->Alias, sizeof(Server->Alias));
	NextValue(Line, ';', &Cursor, Server->HostName, sizeof(Server->HostName));
	NextValue(Line, ';', &Cursor, HelpPort, sizeof(HelpPort));
	NextValue(Line, ';', &Cursor, Server->RsaModulus, sizeof(Server->RsaModulus));
	Server->Version = atoi(HelpVersion);
	Server->Port = atoi(HelpPort);
	return Server;
}

ServerEntry *ReadServerList(const char *FileName){
	FILE *File = fopen(FileName, "r");
	if(File == NULL){
		printf("ReadServerList: Failed to open \"%s\" for reading.\n", FileName);
		return NULL;
	}

	ServerEntry *ServerList = NULL;
	for(int LineNumber = 1; true; LineNumber += 1){
		char Line[4096];
		bool EndOfFile;
		bool Clamped;
		int LineSize = ReadLine(File, Line, sizeof(Line), &EndOfFile, &Clamped);
		if(LineSize > 0){
			ServerEntry *Server = ParseServerEntry(Line, LineNumber);
			if(Server){
				Server->Next = ServerList;
				ServerList = Server;
			}
		}

		if(EndOfFile){
			break;
		}
	}

	fclose(File);
	return ServerList;
}

void CreateSampleServerList(const char *FileName){
	FILE *File = fopen(FileName, "w");
	if(File == NULL){
		printf("CreateSampleServerList: Failed to open \"%s\" for writing.\n", FileName);
		return;
	}

	fprintf(File,
		"# Each server entry should be in a SINGLE line and have the\n"
		"# format \"VERSION;ALIAS;HOSTNAME;PORT;RSAMODULUS\". Empty\n"
		"# lines and lines starting with # are discarded. The server\n"
		"# alias may be empty, meaning you'll need to specify its\n"
		"# host name instead. For versions without RSA encryption,\n"
		"# the RSA modulus is ignored.\n"
		"\n"
		"# Example for the default 7.7 tibia login server:\n"
		"770;tibia;server.tibia.com;7171;"
			"1429962396241639952007017738289889555079540334546615321747051608"
			"2934737582776038882967213386204600674145392845853859217990626450"
			"9724520840657286865659265687630979195970404721891201847792002125"
			"5354012927791239372074475745966927885136471792353355293072513505"
			"70728407373705564708871762033017096809910315212883967\n"
		"\n"
		"# Example for a regular 8.6 otserv:\n"
		"860;otserv;server.otserv.com;7171;"
			"1091201329673994292788609605089955415282375029027981291234687579"
			"3726629149257644633073969600111060390723088861007265581882535850"
			"3429057592827629436413108566029093628212635953836686562675849720"
			"6207862794310902180176810615217550567108238764764442605581471797"
			"07119674283982419152118103759076030616683978566631413\n");

	fclose(File);
}

int main(int argc, char **argv){
	// TODO(fusion): This could be loaded at runtime from some `versions.txt` file.
	static const TibiaVersion Versions[] = {
		{
			770,				// Version
			"Version 7.7",		// VersionString
			5,					// NumLoginEndpoints
			112,				// LoginEndpointStride
			100,				// MaxHostNameSize
			312,				// MaxRsaModulusSize
			0x51765D,			// VersionStringAddr
			0x6BB2F0,			// FirstLoginHostNameAddr
			0x6BB354,			// FirstLoginPortAddr
			0x516620,			// RsaModulusAddr
		},
		{
			810,				// Version
			"Version 8.10",		// VersionString
			10,					// NumLoginEndpoints
			112,				// LoginEndpointStride
			100,				// MaxHostNameSize
			312,				// MaxRsaModulusSize
			0x61B64D,			// VersionStringAddr
			0x763BB8,			// FirstLoginHostNameAddr
			0x763C1C,			// FirstLoginPortAddr
			0x597610,			// RsaModulusAddr
		},
		{
			860,				// Version
			"Version 8.60",		// VersionString
			10,					// NumLoginEndpoints
			112,				// LoginEndpointStride
			100,				// MaxHostNameSize
			312,				// MaxRsaModulusSize
			0x64C2AD,			// VersionStringAddr
			0x7947F8,			// FirstLoginHostNameAddr
			0x79485C,			// FirstLoginPortAddr
			0x5B8980,			// RsaModulusAddr
		},
	};

	if(argc <= 1 || argv[1][0] == 0 || argv[1][0] == '-'){
		if(argc > 1 && StringEqCI(argv[1], "-sample")){
			CreateSampleServerList("servers.txt");
			printf("The file `server.txt` was created/rewritten with"
					" instructions on how to add or modify servers.\n");
		}else{
			printf(
				"USAGE: ipchanger.exe ALIAS|HOSTNAME    # modify client\n"
				"       ipchanger.exe -sample           # create/reset `servers.txt`\n"
				"       ipchanger.exe -help             # print this message\n");
		}
		return EXIT_FAILURE;
	}

	ServerEntry *ServerList = ReadServerList("servers.txt");
	if(ServerList == NULL){
		printf("No server information was found.\n");
		return EXIT_FAILURE;
	}

	ServerEntry *Server = ServerList;
	const char *AliasOrHostName = argv[1];
	while(Server != NULL){
		if(StringEqCI(Server->Alias, AliasOrHostName)
		|| StringEqCI(Server->HostName, AliasOrHostName)){
			break;
		}

		Server = Server->Next;
	}

	if(Server == NULL){
		printf("No server with alias or hostname \"%s\" found.\n", AliasOrHostName);
		return EXIT_FAILURE;
	}

	const TibiaVersion *Version = NULL;
	for(int i = 0; i < NARRAY(Versions); i += 1){
		if(Versions[i].Version == Server->Version){
			Version = &Versions[i];
			break;
		}
	}

	if(Version == NULL){
		printf("Server \"%s\" is defined with version %d which is not"
				" currently supported.\n", AliasOrHostName, Version->Version);
		return EXIT_FAILURE;
	}

	if(!ChangeIP(Version, Server->HostName, Server->Port, Server->RsaModulus)){
		printf("There was a problem with changing the client's IP.\n");
		return EXIT_FAILURE;
	}

	printf("Client is now configured to connect to %s:%d.\n", Server->HostName, Server->Port);
	return EXIT_SUCCESS;
}
