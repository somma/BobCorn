
#define BackupPath L"C:\\Backup\\"

const PWSTR ScannerPortName = L"\\ScannerPort";

#define SCANNER_READ_BUFFER_SIZE   1024

typedef struct _SCANNER_NOTIFICATION {

	ULONG PathLength;
	ULONG Reserved;             // for quad-word alignement of the FilePath structure
	UCHAR PathBuffer[SCANNER_READ_BUFFER_SIZE];
	ULONGLONG FileSize;
	ULONGLONG FileOffset;
	ULONG BufferSize;
	ULONG Reserved2;
	UCHAR FileBuffer[SCANNER_READ_BUFFER_SIZE];

} SCANNER_NOTIFICATION, *PSCANNER_NOTIFICATION;

typedef struct _SCANNER_REPLY {

	BOOLEAN SafeToOpen;

} SCANNER_REPLY, *PSCANNER_REPLY;
