/*++

Copyright (c) 1999-2002  Microsoft Corporation

Module Name:

scanUser.c

Abstract:

This file contains the implementation for the main function of the
user application piece of scanner.  This function is responsible for
actually scanning file FilePath.

Environment:

User mode

--*/

#include <windows.h>
#include <stdlib.h>
#include <stdio.h>
#include <winioctl.h>
#include <string.h>
#include <crtdbg.h>
#include <assert.h>
#include <fltuser.h>
#include "../MiniFilterTestUserKernel.h"
#include <dontuse.h>
#include <share.h>
#include<locale.h>
#include<map>
#include <wincrypt.h>

using namespace std;

map<wstring, pair<PVOID,size_t>> backupfile;

#pragma pack(1)

typedef struct _SCANNER_MESSAGE {

	//
	//  Required structure header.
	//

	FILTER_MESSAGE_HEADER MessageHeader;


	//
	//  Private scanner-specific fields begin here.
	//

	SCANNER_NOTIFICATION Notification;

	//
	//  Overlapped structure: this is not really part of the message
	//  However we embed it instead of using a separately allocated overlap structure
	//

	OVERLAPPED Ovlp;

} SCANNER_MESSAGE, *PSCANNER_MESSAGE;

typedef struct _SCANNER_REPLY_MESSAGE {

	//
	//  Required structure header.
	//

	FILTER_REPLY_HEADER ReplyHeader;

	//
	//  Private scanner-specific fields begin here.
	//

	SCANNER_REPLY Reply;

} SCANNER_REPLY_MESSAGE, *PSCANNER_REPLY_MESSAGE;

//
//  Default and Maximum number of threads.
//

#define SCANNER_DEFAULT_REQUEST_COUNT       5
#define SCANNER_DEFAULT_THREAD_COUNT        2
#define SCANNER_MAX_THREAD_COUNT            64

//
//  Context passed to worker threads
//

typedef struct _SCANNER_THREAD_CONTEXT {

	HANDLE Port;
	HANDLE Completion;

} SCANNER_THREAD_CONTEXT, *PSCANNER_THREAD_CONTEXT;


VOID
Usage(
	VOID
)
/*++

Routine Description

Prints usage

Arguments

None

Return Value

None

--*/
{

	printf("Connects to the scanner filter and scans buffers \n");
	printf("Usage: scanuser [requests per thread] [number of threads(1-64)]\n");
}



#define SHA1_HASH_LEN 20

BOOL GetSha1HashW(LPCTSTR input, DWORD inputSize, LPWCH hash)
{
	HCRYPTPROV hCryptProv; // Handle to our context
	HCRYPTHASH hCryptHash; // Handle to our hash
	BYTE       bHashValue[SHA1_HASH_LEN]; // This will hold our SHA-1 hash
	DWORD     dwSize = SHA1_HASH_LEN, dwCount; // Size of output, and a count variable for a for loop
	BOOL       bSuccess = FALSE; // We change this to TRUE if we complete the operations
								 // Declare all the variables at the start of our code for C89 compatability

	if (CryptAcquireContext(&hCryptProv, NULL, 0, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
	{ // Initiate usage of the functions
		if (CryptCreateHash(hCryptProv, CALG_SHA1, 0, 0, &hCryptHash))
		{ // Create a SHA1 hash
			if (CryptHashData(hCryptHash, (PBYTE)input, inputSize, 0))
			{ // Update the hash, (process our password)
				if (CryptGetHashParam(hCryptHash, HP_HASHVAL, bHashValue, &dwSize, 0))
				{ // Extract the hash
					for (dwCount = 0, *hash = 0; dwCount < SHA1_HASH_LEN; dwCount++)
					{ // Format the hash into a big endian, hexadecimal string
						swprintf_s(
							hash + (dwCount * 2), SHA1_HASH_LEN*2- (dwCount * 2)+2,
							L"%02x",
							bHashValue[dwCount]
						);
					}
					bSuccess = TRUE;
				}
			}
			CryptDestroyHash(hCryptHash);
		}
		CryptReleaseContext(hCryptProv, 0);
	}

	return bSuccess;
}


VOID FlushFile(wstring filename)
{
	FILE* fp = NULL;
	errno_t err;
	WCHAR logPath[256]= L"Backup\\";
	WCHAR hash[256];
	printf("Path : %ws\n", filename.c_str());
	printf("Size : %llu\n", backupfile[filename].second);

	GetSha1HashW((char*)filename.c_str(), (DWORD)filename.length() * sizeof(wchar_t), hash);
	wcscat_s(logPath, hash);
	wcscat_s(logPath, L".log");

	err = _wfopen_s(&fp, logPath, L"r");
	if (!err)
	{
		fclose(fp);
	}
	else
	{
		swprintf_s(logPath, L"Backup\\List.log");
		err = _wfopen_s(&fp, logPath, L"a");
		if (!err)
		{
			fprintf(fp,"%ws : %ws\n",hash,filename.c_str());
			fclose(fp);
		}
		swprintf_s(logPath, L"Backup\\%ws.log", hash);
	}

	err = _wfopen_s(&fp, logPath, L"wb");
	if (!err)
	{
		fwrite(backupfile[filename].first, 1, backupfile[filename].second, fp);
		fclose(fp);
		printf("W close\n");
	}
	else
	{
		printf("fopen Fail\n");
	}
	backupfile[filename].second = 0;
	delete backupfile[filename].first;
}

DWORD
ScannerWorker(
	_In_ PSCANNER_THREAD_CONTEXT Context
)
/*++

Routine Description

This is a worker thread that


Arguments

Context  - This thread context has a pointer to the port handle we use to send/receive messages,
and a completion port handle that was already associated with the comm. port by the caller

Return Value

HRESULT indicating the status of thread exit.

--*/
{
	PSCANNER_NOTIFICATION notification;
	SCANNER_REPLY_MESSAGE replyMessage;
	PSCANNER_MESSAGE message;
	LPOVERLAPPED pOvlp;
	BOOL result;
	DWORD outSize;
	HRESULT hr;
	ULONG_PTR key;

#pragma warning(push)
#pragma warning(disable:4127) // conditional expression is constant

	while (TRUE) {

#pragma warning(pop)

		//
		//  Poll for messages from the filter component to scan.
		//

		result = GetQueuedCompletionStatus(Context->Completion, &outSize, &key, &pOvlp, INFINITE);

		//
		//  Obtain the message: note that the message we sent down via FltGetMessage() may NOT be
		//  the one dequeued off the completion queue: this is solely because there are multiple
		//  threads per single port handle. Any of the FilterGetMessage() issued messages can be
		//  completed in random order - and we will just dequeue a random one.
		//

		message = CONTAINING_RECORD(pOvlp, SCANNER_MESSAGE, Ovlp);

		if (!result) {

			//
			//  An error occured.
			//

			hr = HRESULT_FROM_WIN32(GetLastError());
			break;
		}


		notification = &message->Notification;

		assert(notification->PathLength <= SCANNER_READ_BUFFER_SIZE);
		_Analysis_assume_(notification->PathLength <= SCANNER_READ_BUFFER_SIZE);
		wstring filename=wstring((PWCH)notification->PathBuffer);
		if (!notification->FileOffset)
		{
			backupfile[filename].first = new UCHAR[notification->FileSize];
			backupfile[filename].second = notification->FileSize;
		}
		memcpy((UCHAR*)backupfile[filename].first + notification->FileOffset, notification->FileBuffer, notification->BufferSize);

		if (notification->FileOffset + notification->BufferSize == notification->FileSize)
		{
			FlushFile(filename);
		}
		result = TRUE;

		replyMessage.ReplyHeader.Status = 0;
		replyMessage.ReplyHeader.MessageId = message->MessageHeader.MessageId;

		//
		//  Need to invert the boolean -- result is true if found
		//  foul language, in which case SafeToOpen should be set to false.
		//

		replyMessage.Reply.SafeToOpen = !result;

		//printf("Replying message, SafeToOpen: %d\n", replyMessage.Reply.SafeToOpen);

		//Test
		hr = NO_ERROR;
			
		hr = FilterReplyMessage(Context->Port,
			(PFILTER_REPLY_HEADER)&replyMessage,
			sizeof(replyMessage));
			
		if (SUCCEEDED(hr)) {

			//printf("Replied message\n");

		}
		else {

			printf("Scanner: Error replying message. Error = 0x%X\n", hr);
			break;
		}

		memset(&message->Ovlp, 0, sizeof(OVERLAPPED));

		hr = FilterGetMessage(Context->Port,
			&message->MessageHeader,
			FIELD_OFFSET(SCANNER_MESSAGE, Ovlp),
			&message->Ovlp);

		if (hr != HRESULT_FROM_WIN32(ERROR_IO_PENDING)) {

			break;
		}
	}

	if (!SUCCEEDED(hr)) {

		if (hr == HRESULT_FROM_WIN32(ERROR_INVALID_HANDLE)) {

			//
			//  Scanner port disconncted.
			//

			printf("Scanner: Port is disconnected, probably due to scanner filter unloading.\n");

		}
		else {

			printf("Scanner: Unknown error occured. Error = 0x%X\n", hr);
		}
	}

	free(message);

	return hr;
}


int _cdecl
main(
	_In_ int argc,
	_In_reads_(argc) char *argv[]
)
{
	DWORD requestCount = SCANNER_DEFAULT_REQUEST_COUNT;
	DWORD threadCount = SCANNER_DEFAULT_THREAD_COUNT;
	HANDLE threads[SCANNER_MAX_THREAD_COUNT];
	SCANNER_THREAD_CONTEXT context;
	HANDLE port, completion;
	PSCANNER_MESSAGE msg;
	DWORD threadId;
	HRESULT hr;
	DWORD i, j;


	setlocale(LC_ALL, "");


	//
	//  Check how many threads and per thread requests are desired.
	//

	if (argc > 1) {

		requestCount = atoi(argv[1]);

		if (requestCount <= 0) {

			Usage();
			return 1;
		}

		if (argc > 2) {

			threadCount = atoi(argv[2]);
		}

		if (threadCount <= 0 || threadCount > 64) {

			Usage();
			return 1;
		}
	}

	//
	//  Open a commuication channel to the filter
	//

	printf("Scanner: Connecting to the filter ...\n");

	hr = FilterConnectCommunicationPort(ScannerPortName,
		0,
		NULL,
		0,
		NULL,
		&port);

	if (IS_ERROR(hr)) {

		printf("ERROR: Connecting to filter port: 0x%08x\n", hr);
		return 2;
	}

	//
	//  Create a completion port to associate with this handle.
	//

	completion = CreateIoCompletionPort(port,
		NULL,
		0,
		threadCount);

	if (completion == NULL) {

		printf("ERROR: Creating completion port: %d\n", GetLastError());
		CloseHandle(port);
		return 3;
	}

	printf("Scanner: Port = 0x%p Completion = 0x%p\n", port, completion);

	context.Port = port;
	context.Completion = completion;

	//
	//  Create specified number of threads.
	//

	for (i = 0; i < threadCount; i++) {

		threads[i] = CreateThread(NULL,
			0,
			(LPTHREAD_START_ROUTINE)ScannerWorker,
			&context,
			0,
			&threadId);

		if (threads[i] == NULL) {

			//
			//  Couldn't create thread.
			//

			hr = GetLastError();
			printf("ERROR: Couldn't create thread: %d\n", hr);
			goto main_cleanup;
		}

		for (j = 0; j < requestCount; j++) {

			//
			//  Allocate the message.
			//

#pragma prefast(suppress:__WARNING_MEMORY_LEAK, "msg will not be leaked because it is freed in ScannerWorker")
			msg = (PSCANNER_MESSAGE)malloc(sizeof(SCANNER_MESSAGE));

			if (msg == NULL) {

				hr = ERROR_NOT_ENOUGH_MEMORY;
				goto main_cleanup;
			}

			memset(&msg->Ovlp, 0, sizeof(OVERLAPPED));

			//
			//  Request messages from the filter driver.
			//

			hr = FilterGetMessage(port,
				&msg->MessageHeader,
				FIELD_OFFSET(SCANNER_MESSAGE, Ovlp),
				&msg->Ovlp);

			if (hr != HRESULT_FROM_WIN32(ERROR_IO_PENDING)) {

				free(msg);
				goto main_cleanup;
			}
		}
	}

	hr = S_OK;

	WaitForMultipleObjectsEx(i, threads, TRUE, INFINITE, FALSE);

main_cleanup:

	printf("Scanner:  All done. Result = 0x%08x\n", hr);

	CloseHandle(port);
	CloseHandle(completion);
	getchar();
	return hr;
}

