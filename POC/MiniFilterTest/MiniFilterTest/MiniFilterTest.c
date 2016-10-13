/*++

Module Name:

    MiniFilterTest.c

Abstract:

    This is the main module of the MiniFilterTest miniFilter driver.

Environment:

    Kernel mode

--*/


#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>
#include"../MiniFilterTestUserKernel.h"

#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")

PEPROCESS gUserProcess;
PFLT_PORT gClientPort;
PFLT_PORT gServerPort;
PFLT_FILTER gFilterHandle;
ULONG_PTR OperationStatusCtx = 1;
#define PTDBG_TRACE_ROUTINES            0x00000001
#define PTDBG_TRACE_OPERATION_STATUS    0x00000002

UNICODE_STRING ScannedExtensionDefault[] = { RTL_CONSTANT_STRING(L"txt"),RTL_CONSTANT_STRING(L"docx"),RTL_CONSTANT_STRING(L"doc"),RTL_CONSTANT_STRING(L"png"), RTL_CONSTANT_STRING(L"jpg"), };
ULONG ScannedExtensionCount = 5;

ULONG gTraceFlags = 0;

typedef struct _FILE_CONTEXT {
	BOOLEAN backuped;
}FILE_CONTEXT, *PFILE_CONTEXT;

#define PT_DBG_PRINT( _dbgLevel, _string )          \
    (FlagOn(gTraceFlags,(_dbgLevel)) ?              \
        DbgPrint _string :                          \
        ((int)0))

/*************************************************************************
    Prototypes
*************************************************************************/

EXTERN_C_START

DRIVER_INITIALIZE DriverEntry;
NTSTATUS
DriverEntry (
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    );

NTSTATUS
MiniFilterTestInstanceSetup (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
    );

VOID
MiniFilterTestInstanceTeardownStart (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    );

VOID
MiniFilterTestInstanceTeardownComplete (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    );

NTSTATUS
MiniFilterTestUnload (
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    );

NTSTATUS
MiniFilterTestInstanceQueryTeardown (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
    );

FLT_PREOP_CALLBACK_STATUS
MiniFilterTestPreOperation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    );

FLT_POSTOP_CALLBACK_STATUS
MiniFilterTestPostOperation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
    );


NTSTATUS
MiniFilterTestPortConnect(
	_In_ PFLT_PORT ClientPort,
	_In_opt_ PVOID ServerPortCookie,
	_In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
	_In_ ULONG SizeOfContext,
	_Outptr_result_maybenull_ PVOID *ConnectionCookie
);


VOID
MiniFilterTestPortDisconnect(
	_In_opt_ PVOID ConnectionCookie
);

BOOLEAN
MiniFilterTestFileIsBeingModified(
	PFLT_IO_PARAMETER_BLOCK Iopb
);

BOOLEAN
MiniFilterTestFileHasTargetExtention(
	PFLT_INSTANCE Instance,
	PFILE_OBJECT FileObject
);

BOOLEAN
MiniFilterTestBackupOnUserMode(
	_In_ PFLT_INSTANCE Instance,
	_In_ PFILE_OBJECT FileObject);

EXTERN_C_END

//
//  Assign text sections for each routine.
//

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, MiniFilterTestUnload)
#pragma alloc_text(PAGE, MiniFilterTestInstanceQueryTeardown)
#pragma alloc_text(PAGE, MiniFilterTestInstanceSetup)
#pragma alloc_text(PAGE, MiniFilterTestInstanceTeardownStart)
#pragma alloc_text(PAGE, MiniFilterTestInstanceTeardownComplete)
#endif

//
//  operation registration
//

CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
	{ IRP_MJ_CREATE,
	0,
	MiniFilterTestPreOperation,
	MiniFilterTestPostOperation },

	{ IRP_MJ_WRITE,
	0,
	MiniFilterTestPreOperation,
	MiniFilterTestPostOperation },

	{ IRP_MJ_READ,
	0,
	MiniFilterTestPreOperation,
	MiniFilterTestPostOperation },

	{ IRP_MJ_SET_INFORMATION,
	0,
	MiniFilterTestPreOperation,
	MiniFilterTestPostOperation },

	{ IRP_MJ_CLEANUP,
	0,
	MiniFilterTestPreOperation,
	MiniFilterTestPostOperation },


	{ IRP_MJ_FAST_IO_CHECK_IF_POSSIBLE,
	0,
	MiniFilterTestPreOperation,
	MiniFilterTestPostOperation },

	{ IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION,
	0,
	MiniFilterTestPreOperation,
	MiniFilterTestPostOperation },

	{ IRP_MJ_RELEASE_FOR_SECTION_SYNCHRONIZATION,
	0,
	MiniFilterTestPreOperation,
	MiniFilterTestPostOperation },

	{ IRP_MJ_ACQUIRE_FOR_MOD_WRITE,
	0,
	MiniFilterTestPreOperation,
	MiniFilterTestPostOperation },

	{ IRP_MJ_RELEASE_FOR_MOD_WRITE,
	0,
	MiniFilterTestPreOperation,
	MiniFilterTestPostOperation },

	{ IRP_MJ_ACQUIRE_FOR_CC_FLUSH,
	0,
	MiniFilterTestPreOperation,
	MiniFilterTestPostOperation },

	{ IRP_MJ_RELEASE_FOR_CC_FLUSH,
	0,
	MiniFilterTestPreOperation,
	MiniFilterTestPostOperation },


#if 0 // TODO - List all of the requests to filter.
    { IRP_MJ_CREATE_NAMED_PIPE,
      0,
      MiniFilterTestPreOperation,
      MiniFilterTestPostOperation },

    { IRP_MJ_CLOSE,
      0,
      MiniFilterTestPreOperation,
      MiniFilterTestPostOperation },

    { IRP_MJ_QUERY_INFORMATION,
      0,
      MiniFilterTestPreOperation,
      MiniFilterTestPostOperation },

    { IRP_MJ_QUERY_EA,
      0,
      MiniFilterTestPreOperation,
      MiniFilterTestPostOperation },

    { IRP_MJ_SET_EA,
      0,
      MiniFilterTestPreOperation,
      MiniFilterTestPostOperation },

    { IRP_MJ_FLUSH_BUFFERS,
      0,
      MiniFilterTestPreOperation,
      MiniFilterTestPostOperation },

    { IRP_MJ_QUERY_VOLUME_INFORMATION,
      0,
      MiniFilterTestPreOperation,
      MiniFilterTestPostOperation },

    { IRP_MJ_SET_VOLUME_INFORMATION,
      0,
      MiniFilterTestPreOperation,
      MiniFilterTestPostOperation },

    { IRP_MJ_DIRECTORY_CONTROL,
      0,
      MiniFilterTestPreOperation,
      MiniFilterTestPostOperation },

    { IRP_MJ_FILE_SYSTEM_CONTROL,
      0,
      MiniFilterTestPreOperation,
      MiniFilterTestPostOperation },

    { IRP_MJ_DEVICE_CONTROL,
      0,
      MiniFilterTestPreOperation,
      MiniFilterTestPostOperation },

    { IRP_MJ_INTERNAL_DEVICE_CONTROL,
      0,
      MiniFilterTestPreOperation,
      MiniFilterTestPostOperation },

    { IRP_MJ_SHUTDOWN,
      0,
      MiniFilterTestPreOperationNoPostOperation,
      NULL },                               //post operations not supported

    { IRP_MJ_LOCK_CONTROL,
      0,
      MiniFilterTestPreOperation,
      MiniFilterTestPostOperation },

    { IRP_MJ_CREATE_MAILSLOT,
      0,
      MiniFilterTestPreOperation,
      MiniFilterTestPostOperation },

    { IRP_MJ_QUERY_SECURITY,
      0,
      MiniFilterTestPreOperation,
      MiniFilterTestPostOperation },

    { IRP_MJ_SET_SECURITY,
      0,
      MiniFilterTestPreOperation,
      MiniFilterTestPostOperation },

    { IRP_MJ_QUERY_QUOTA,
      0,
      MiniFilterTestPreOperation,
      MiniFilterTestPostOperation },

    { IRP_MJ_SET_QUOTA,
      0,
      MiniFilterTestPreOperation,
      MiniFilterTestPostOperation },

    { IRP_MJ_PNP,
      0,
      MiniFilterTestPreOperation,
      MiniFilterTestPostOperation },


    { IRP_MJ_NETWORK_QUERY_OPEN,
      0,
      MiniFilterTestPreOperation,
      MiniFilterTestPostOperation },

    { IRP_MJ_MDL_READ,
      0,
      MiniFilterTestPreOperation,
      MiniFilterTestPostOperation },

    { IRP_MJ_MDL_READ_COMPLETE,
      0,
      MiniFilterTestPreOperation,
      MiniFilterTestPostOperation },

    { IRP_MJ_PREPARE_MDL_WRITE,
      0,
      MiniFilterTestPreOperation,
      MiniFilterTestPostOperation },

    { IRP_MJ_MDL_WRITE_COMPLETE,
      0,
      MiniFilterTestPreOperation,
      MiniFilterTestPostOperation },

    { IRP_MJ_VOLUME_MOUNT,
      0,
      MiniFilterTestPreOperation,
      MiniFilterTestPostOperation },

    { IRP_MJ_VOLUME_DISMOUNT,
      0,
      MiniFilterTestPreOperation,
      MiniFilterTestPostOperation },

#endif // TODO

    { IRP_MJ_OPERATION_END }
};

const FLT_CONTEXT_REGISTRATION ContextRegistration[] = {

	{ FLT_STREAM_CONTEXT,
	0,
	NULL,
	sizeof(FILE_CONTEXT),
	'chBS' },

	{ FLT_CONTEXT_END }
};


//
//  This defines what we want to filter with FltMgr
//

CONST FLT_REGISTRATION FilterRegistration = {

    sizeof( FLT_REGISTRATION ),         //  Size
    FLT_REGISTRATION_VERSION,           //  Version
    0,                                  //  Flags

	ContextRegistration,                //  Context
    Callbacks,                          //  Operation callbacks

    MiniFilterTestUnload,                           //  MiniFilterUnload

    MiniFilterTestInstanceSetup,                    //  InstanceSetup
    MiniFilterTestInstanceQueryTeardown,            //  InstanceQueryTeardown
    MiniFilterTestInstanceTeardownStart,            //  InstanceTeardownStart
    MiniFilterTestInstanceTeardownComplete,         //  InstanceTeardownComplete

    NULL,                               //  GenerateFileName
    NULL,                               //  GenerateDestinationFileName
    NULL                                //  NormalizeNameComponent

};



NTSTATUS
MiniFilterTestInstanceSetup (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
    )
/*++

Routine Description:

    This routine is called whenever a new instance is created on a volume. This
    gives us a chance to decide if we need to attach to this volume or not.

    If this routine is not defined in the registration structure, automatic
    instances are always created.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Flags describing the reason for this attach request.

Return Value:

    STATUS_SUCCESS - attach
    STATUS_FLT_DO_NOT_ATTACH - do not attach

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );
    UNREFERENCED_PARAMETER( VolumeDeviceType );
    UNREFERENCED_PARAMETER( VolumeFilesystemType );

    PAGED_CODE();
	if (VolumeDeviceType == FILE_DEVICE_NETWORK_FILE_SYSTEM) {

		return STATUS_FLT_DO_NOT_ATTACH;
	}

	DbgPrint(("MiniFilterTest!MiniFilterTestInstanceSetup: Entered\n") );

    return STATUS_SUCCESS;
}


NTSTATUS
MiniFilterTestInstanceQueryTeardown (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
    )
/*++

Routine Description:

    This is called when an instance is being manually deleted by a
    call to FltDetachVolume or FilterDetach thereby giving us a
    chance to fail that detach request.

    If this routine is not defined in the registration structure, explicit
    detach requests via FltDetachVolume or FilterDetach will always be
    failed.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Indicating where this detach request came from.

Return Value:

    Returns the status of this operation.

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("MiniFilterTest!MiniFilterTestInstanceQueryTeardown: Entered\n") );

    return STATUS_SUCCESS;
}


VOID
MiniFilterTestInstanceTeardownStart (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    )
/*++

Routine Description:

    This routine is called at the start of instance teardown.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Reason why this instance is being deleted.

Return Value:

    None.

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("MiniFilterTest!MiniFilterTestInstanceTeardownStart: Entered\n") );
}


VOID
MiniFilterTestInstanceTeardownComplete (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    )
/*++

Routine Description:

    This routine is called at the end of instance teardown.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Reason why this instance is being deleted.

Return Value:

    None.

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("MiniFilterTest!MiniFilterTestInstanceTeardownComplete: Entered\n") );
}


/*************************************************************************
    MiniFilter initialization and unload routines.
*************************************************************************/

NTSTATUS
DriverEntry (
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
/*++

Routine Description:

    This is the initialization routine for this miniFilter driver.  This
    registers with FltMgr and initializes all global data structures.

Arguments:

    DriverObject - Pointer to driver object created by the system to
        represent this driver.

    RegistryPath - Unicode string identifying where the parameters for this
        driver are located in the registry.

Return Value:

    Routine can return non success error codes.

--*/
{
	OBJECT_ATTRIBUTES oa;
	UNICODE_STRING uniString;
	PSECURITY_DESCRIPTOR sd;
	NTSTATUS status;

    UNREFERENCED_PARAMETER( RegistryPath );

	DbgPrint(("MiniFilterTest!DriverEntry: Entered\n") );

    //
    //  Register with FltMgr to tell it our callback routines
    //

    status = FltRegisterFilter( DriverObject,
                                &FilterRegistration,
                                &gFilterHandle );

    FLT_ASSERT( NT_SUCCESS( status ) );


	if (NT_SUCCESS(status)) {

		RtlInitUnicodeString(&uniString, ScannerPortName);

		//
		//  We secure the port so only ADMINs & SYSTEM can acecss it.
		//

		status = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);

		if (NT_SUCCESS(status)){

			//
			//	Create Port
			//

			InitializeObjectAttributes(&oa,
				&uniString,
				OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
				NULL,
				sd);

			status = FltCreateCommunicationPort(
				gFilterHandle,
				&gServerPort,
				&oa,
				NULL,
				MiniFilterTestPortConnect,
				MiniFilterTestPortDisconnect,
				NULL,
				1);

			//
			//  Free the security descriptor in all cases. It is not needed once
			//  the call to FltCreateCommunicationPort() is made.
			//

			FltFreeSecurityDescriptor(sd);
		}


		if (NT_SUCCESS(status)) {

			//
			//  Start filtering i/o
			//

			status = FltStartFiltering(gFilterHandle);
		}
		if (!NT_SUCCESS(status)) {
			FltUnregisterFilter(gFilterHandle);
			gFilterHandle = NULL;
		}
	}
    return status;
}

NTSTATUS
MiniFilterTestUnload (
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    )
/*++

Routine Description:

    This is the unload routine for this miniFilter driver. This is called
    when the minifilter is about to be unloaded. We can fail this unload
    request if this is not a mandatory unload indicated by the Flags
    parameter.

Arguments:

    Flags - Indicating if this is a mandatory unload.

Return Value:

    Returns STATUS_SUCCESS.

--*/
{
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

	DbgPrint(("MiniFilterTest!MiniFilterTestUnload: Entered\n") );


	if(gServerPort)
		FltCloseCommunicationPort(gServerPort);
	DbgPrint(("MiniFilterTest!MiniFilterTestUnload: FltCloseCommunicationPort\n"));

	if (gFilterHandle)
		FltUnregisterFilter(gFilterHandle);
	DbgPrint(("MiniFilterTest!MiniFilterTestUnload: FltUnregisterFilter\n"));

    return STATUS_SUCCESS;
}


/*************************************************************************
    MiniFilter callback routines.
*************************************************************************/
FLT_PREOP_CALLBACK_STATUS
MiniFilterTestPreOperation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    )
/*++

Routine Description:

    This routine is a pre-operation dispatch routine for this miniFilter.

    This is non-pageable because it could be called on the paging path

Arguments:

    Data - Pointer to the filter callbackData that is passed to us.

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance, its associated volume and
        file object.

    CompletionContext - The context for the completion routine for this
        operation.

Return Value:

    The return value is the status of the operation.

--*/
{
	//TODO Prevent Access
	//UNICODE_STRING BackupDir=RTL_CONSTANT_STRING(BackupPath);
	PFLT_IO_PARAMETER_BLOCK Iopb = Data->Iopb;
	PFLT_INSTANCE Instance = FltObjects->Instance;
	PFILE_OBJECT FileObject = FltObjects->FileObject;
	PFLT_VOLUME volume = NULL;
	OBJECT_ATTRIBUTES ObjectAttribute = { 0, };
	PFLT_FILE_NAME_INFORMATION nameInfo = NULL, newNameInfo = NULL;
	HANDLE	fileHandle=NULL;
	PVOID handleFileObject = NULL;
	IO_STATUS_BLOCK statusBlock;
	NTSTATUS status = STATUS_SUCCESS;
	PFLT_CONTEXT context = NULL, oldContext = NULL;
	FLT_PREOP_CALLBACK_STATUS result= FLT_PREOP_SUCCESS_NO_CALLBACK;
    UNREFERENCED_PARAMETER( CompletionContext );

	//
	//  If not client port just return.
	//

	if (gClientPort == NULL) {

		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	if (!FileObject) {
		DbgPrint("!!! MiniFilterTest.sys --- FileObject NULL\n");
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	if (KeGetCurrentIrql() != PASSIVE_LEVEL)
	{
		DbgPrint("!!! MiniFilterTest.sys --- IRQL is not PASSIVE_LEVEL\n");
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	if (PsGetCurrentProcessId() == (HANDLE)4)
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	if(!MiniFilterTestFileIsBeingModified(Iopb))
		return FLT_PREOP_SUCCESS_NO_CALLBACK;



	if (IoGetCurrentProcess() != gUserProcess)
	{
		//DbgPrint("Unknown Process id=%d\n", PsGetCurrentProcessId());

		status = FltGetFileNameInformation(Data,
			FLT_FILE_NAME_NORMALIZED |
			FLT_FILE_NAME_QUERY_DEFAULT,
			&nameInfo);


		if (NT_SUCCESS(status)) {
			FltParseFileNameInformation(nameInfo);

			try {


				//
				//  Obtain the volume object .
				//


				status = FltGetVolumeFromInstance(Instance, &volume);

				if (!NT_SUCCESS(status))
				{

					DbgPrint("!!! MiniFilterTest.sys --- FltGetVolumeFromInstance Fail\n");
					leave;
				}


				ObjectAttribute.ObjectName = 0;

				if ((Iopb->MajorFunction == IRP_MJ_SET_INFORMATION) &&
						(Iopb->Parameters.SetFileInformation.FileInformationClass == FileRenameInformation
						&&
						((PFILE_RENAME_INFORMATION)Iopb->Parameters.SetFileInformation.InfoBuffer)->ReplaceIfExists))
				{
					status = FltGetDestinationFileNameInformation(Instance, FltObjects->FileObject,
						((PFILE_RENAME_INFORMATION)Iopb->Parameters.SetFileInformation.InfoBuffer)->RootDirectory,
						((PFILE_RENAME_INFORMATION)Iopb->Parameters.SetFileInformation.InfoBuffer)->FileName,
						((PFILE_RENAME_INFORMATION)Iopb->Parameters.SetFileInformation.InfoBuffer)->FileNameLength,
						FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
						&newNameInfo);

					if (!NT_SUCCESS(status))
					{
						DbgPrint("!!! MiniFilterTest.sys --- FltGetDestinationFileNameInformation Fail\n");
						leave;
					}

					InitializeObjectAttributes(&ObjectAttribute, &newNameInfo->Name,
						OBJ_CASE_INSENSITIVE,
						NULL,
						NULL
					);
				}

				if (Iopb->MajorFunction == IRP_MJ_CREATE)
				{
					InitializeObjectAttributes(&ObjectAttribute, &nameInfo->Name,
						OBJ_CASE_INSENSITIVE,
						NULL,
						NULL
					);
				}

				if(ObjectAttribute.ObjectName)
				{
					status = FltCreateFile
					(gFilterHandle,
						Instance,
						&fileHandle,
						GENERIC_READ,
						&ObjectAttribute,
						&statusBlock, 
						0,
						FILE_ATTRIBUTE_NORMAL,
						0,
						FILE_OPEN,
						FILE_NON_DIRECTORY_FILE,
						NULL,
						0,
						0
					);
					if(NT_SUCCESS(status))
					{

						status = ObReferenceObjectByHandle(
							fileHandle,
							0,
							NULL,
							KernelMode,
							&handleFileObject,
							NULL);
						if (!NT_SUCCESS(status))
						{
							DbgPrint("ObReferenceObjectByHandle Fail\n");
							leave;
						}
					}
					else
					{
						DbgPrint("CreateFile Fail\n");
						leave;
					}
					result = FLT_PREOP_SUCCESS_WITH_CALLBACK;
				}
				else
				{
					status = FltGetStreamContext(Instance, FileObject, &context);
					if (NT_SUCCESS(status))
					{
						FltReleaseContext(context);
						leave;
					}
					else
					{
						status = FltAllocateContext(gFilterHandle, FLT_STREAM_CONTEXT, sizeof(FILE_CONTEXT), NonPagedPool, &context);
						if (NT_SUCCESS(status))
						{
							status = FltSetStreamContext(Instance, FileObject, FLT_SET_CONTEXT_REPLACE_IF_EXISTS,context, &oldContext);
							if (NT_SUCCESS(status))
							{
								if (oldContext)
								{
									FltReleaseContext(oldContext);
								}
							}
							else
								FltReleaseContext(context);
							FltReleaseContext(context);
						}
					}
				}

				if (handleFileObject)
				{
					if(MiniFilterTestFileHasTargetExtention(Instance, handleFileObject))
						MiniFilterTestBackupOnUserMode(Instance, handleFileObject);
				}
				else
				{
					if (MiniFilterTestFileHasTargetExtention(Instance, FileObject))
						MiniFilterTestBackupOnUserMode(Instance, FileObject);
				}
			}
			finally {

				if (newNameInfo)
					FltReleaseFileNameInformation(newNameInfo);

				if (handleFileObject)
					ObDereferenceObject(handleFileObject);

				if (fileHandle)
					FltClose(fileHandle);

				if (NULL != volume) {

					FltObjectDereference(volume);
				}

			}

			FltReleaseFileNameInformation(nameInfo);
		}
	}
	else
	{
		DbgPrint("User Process\n");
		DbgPrint("MJ : %0X\n", Data->Iopb->MajorFunction);
		DbgPrint("%wZ\n", &FltObjects->FileObject->FileName);
		status = FltGetFileNameInformation(Data,
			FLT_FILE_NAME_NORMALIZED |
			FLT_FILE_NAME_QUERY_DEFAULT,
			&nameInfo);
		if (NT_SUCCESS(status)) {
			DbgPrint("%wZ\n", &nameInfo->Name);
			FltReleaseFileNameInformation(nameInfo);
		}
	}
    return result;
}



FLT_POSTOP_CALLBACK_STATUS
MiniFilterTestPostOperation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
    )
/*++

Routine Description:

    This routine is the post-operation completion routine for this
    miniFilter.

    This is non-pageable because it may be called at DPC level.

Arguments:

    Data - Pointer to the filter callbackData that is passed to us.

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance, its associated volume and
        file object.

    CompletionContext - The completion context set in the pre-operation routine.

    Flags - Denotes whether the completion is successful or is being drained.

Return Value:

    The return value is the status of the operation.

--*/
{
	PFLT_INSTANCE Instance = FltObjects->Instance;
	PFILE_OBJECT FileObject = FltObjects->FileObject;
	PFLT_CONTEXT context=NULL,oldContext=NULL;
	NTSTATUS status;
    UNREFERENCED_PARAMETER( Data );
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( CompletionContext );
    UNREFERENCED_PARAMETER( Flags );

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("MiniFilterTest!MiniFilterTestPostOperation: Entered\n") );

	if (PsGetCurrentProcessId() == (HANDLE)4)
	{
		//		DbgPrint("System I/O\n");
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	if(FileObject==NULL)
		return FLT_POSTOP_FINISHED_PROCESSING;

	if (IoGetCurrentProcess() != gUserProcess)
	{
		if (Data->Iopb->MajorFunction == IRP_MJ_CREATE
			&&
			(((Data->Iopb->Parameters.Create.Options >> 24) & FILE_OVERWRITE) ||
			(Data->Iopb->Parameters.Create.Options & FILE_DELETE_ON_CLOSE)))
		{
			//TODO
			status = FltGetStreamContext(Instance, FileObject, &context);
			if (NT_SUCCESS(status))
			{
				FltReleaseContext(context);
			}
			else
			{
				status = FltAllocateContext(gFilterHandle, FLT_STREAM_CONTEXT, sizeof(FILE_CONTEXT), NonPagedPool, &context);
				if (NT_SUCCESS(status))
				{
					status = FltSetStreamContext(Instance, FileObject, FLT_SET_CONTEXT_REPLACE_IF_EXISTS, context, &oldContext);
					if (NT_SUCCESS(status))
					{
						if (oldContext)
						{
							FltReleaseContext(oldContext);
						}
					}
					else
						FltReleaseContext(context);
					FltReleaseContext(context);
				}
			}
		}
	}
	else
	{
		DbgPrint("User Process\n");
		DbgPrint("MJ : %0X\n", Data->Iopb->MajorFunction);
		DbgPrint("%wZ", &FltObjects->FileObject->FileName);
	}
    return FLT_POSTOP_FINISHED_PROCESSING;
}


NTSTATUS
MiniFilterTestPortConnect(
	_In_ PFLT_PORT ClientPort,
	_In_opt_ PVOID ServerPortCookie,
	_In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
	_In_ ULONG SizeOfContext,
	_Outptr_result_maybenull_ PVOID *ConnectionCookie
)
{
	PAGED_CODE();

	UNREFERENCED_PARAMETER(ServerPortCookie);
	UNREFERENCED_PARAMETER(ConnectionContext);
	UNREFERENCED_PARAMETER(SizeOfContext);
	UNREFERENCED_PARAMETER(ConnectionCookie = NULL);

	FLT_ASSERT(gClientPort == NULL);
	FLT_ASSERT(gUserProcess == NULL);

	//
	//  Set the user process and port. In a production filter it may
	//  be necessary to synchronize access to such fields with port
	//  lifetime. For instance, while filter manager will synchronize
	//  FltCloseClientPort with FltSendMessage's reading of the port 
	//  handle, synchronizing access to the UserProcess would be up to
	//  the filter.
	//

	gUserProcess = PsGetCurrentProcess();
	gClientPort = ClientPort;

	
	DbgPrint("!!! MiniFilterTest.sys --- connected, process id=%d, port=0x%p\n", PsGetCurrentProcessId(),ClientPort);

	return STATUS_SUCCESS;
}


VOID
MiniFilterTestPortDisconnect(
	_In_opt_ PVOID ConnectionCookie
)
{
	UNREFERENCED_PARAMETER(ConnectionCookie);

	PAGED_CODE();

	DbgPrint("!!! MiniFilterTest.sys --- disconnecting, port=0x%p\n", gClientPort);

	//
	//  Close our handle to the connection: note, since we limited max connections to 1,
	//  another connect will not be allowed until we return from the disconnect routine.
	//

	FltCloseClientPort(gFilterHandle, &gClientPort);

	//
	//  Reset the user-process field.
	//

	DbgPrint("!!! MiniFilterTest.sys --- disconnected, port=0x%p\n", gClientPort);

	gUserProcess = NULL;
}


BOOLEAN
MiniFilterTestFileIsBeingModified(
	PFLT_IO_PARAMETER_BLOCK Iopb
)
{
	if (		
		((Iopb->MajorFunction == IRP_MJ_SET_INFORMATION) &&
			(
			((Iopb->Parameters.SetFileInformation.FileInformationClass == FileDispositionInformation) &&
				(((PFILE_DISPOSITION_INFORMATION)Iopb->Parameters.SetFileInformation.InfoBuffer)->DeleteFile))
				||
				((Iopb->Parameters.SetFileInformation.FileInformationClass == FileRenameInformation) &&
				((PFILE_RENAME_INFORMATION)Iopb->Parameters.SetFileInformation.InfoBuffer)->ReplaceIfExists)
				)
			)
			||

			((Iopb->MajorFunction == IRP_MJ_CREATE) &&
			(((Iopb->Parameters.Create.Options >> 24) & FILE_OVERWRITE) ||
				(Iopb->Parameters.Create.Options & FILE_DELETE_ON_CLOSE))
				)
			||
			((Iopb->MajorFunction == IRP_MJ_WRITE))
			||
			((Iopb->MajorFunction == IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION)
				&&
				((Iopb->Parameters.AcquireForSectionSynchronization.SyncType == SyncTypeCreateSection)
					&&
					(Iopb->Parameters.AcquireForSectionSynchronization.PageProtection & PAGE_READWRITE)))
		)
		return TRUE;
	else
		return FALSE;
}


BOOLEAN
MiniFilterTestFileHasTargetExtention(
	PFLT_INSTANCE Instance,
	PFILE_OBJECT FileObject
)
{
	NTSTATUS status=0;
	PFILE_LINKS_INFORMATION fileLinkInformation = NULL;
	ULONG   Length= sizeof(FILE_LINKS_INFORMATION), LengthReturned=0;
	PFILE_LINK_ENTRY_INFORMATION fileLinkEntryInformation = NULL;
	BOOLEAN result = FALSE;
	UNICODE_STRING Path = { 0, }, Ext = { 0, };
	ULONG count;
	ULONG index;

	fileLinkInformation = FltAllocatePoolAlignedWithTag(Instance,
		NonPagedPool,
		Length,
		'fliS');

	if (fileLinkInformation)
	{
		FltQueryInformationFile(Instance, FileObject, fileLinkInformation, sizeof(FILE_LINKS_INFORMATION), FileHardLinkInformation, &LengthReturned);

		Length = fileLinkInformation->BytesNeeded;

		FltFreePoolAlignedWithTag(Instance, fileLinkInformation, 'fliS');
	}
	else
	{
		DbgPrint("FltAllocatePoolAlignedWithTag Fail\n");
		return result;
	}


	fileLinkInformation = FltAllocatePoolAlignedWithTag(Instance,
		NonPagedPool,
		Length,
		'fliS');

	if (fileLinkInformation)
	{
		status = FltQueryInformationFile(Instance, FileObject, fileLinkInformation, Length, FileHardLinkInformation, &LengthReturned);
		
		DbgPrint("Link List %d:\n",fileLinkInformation->EntriesReturned);
		fileLinkEntryInformation = &fileLinkInformation->Entry;
		for(count=0; count<fileLinkInformation->EntriesReturned;count++)
		{
			//TODO
			Path.Buffer = fileLinkEntryInformation->FileName;
			Path.Length = (USHORT)fileLinkEntryInformation->FileNameLength * sizeof(WCHAR);
			Path.MaximumLength = (USHORT)fileLinkEntryInformation->FileNameLength * sizeof(WCHAR);
			DbgPrint("%wZ\n", &Path);

			for (index = 0; index<ScannedExtensionCount; index++)
			{
				if (ScannedExtensionDefault[index].Length < Path.Length)
				{
					Ext.Buffer = (PWCH)(((PCHAR)Path.Buffer) + Path.Length - ScannedExtensionDefault[index].Length);
					Ext.Length = ScannedExtensionDefault[index].Length;
					Ext.MaximumLength = ScannedExtensionDefault[index].Length;
					if (!RtlCompareUnicodeString(&Ext, &ScannedExtensionDefault[index], TRUE))
					{
						result = TRUE;
						break;
					}
				}
			}
			
			fileLinkEntryInformation = (PFILE_LINK_ENTRY_INFORMATION)((PUCHAR)fileLinkEntryInformation+fileLinkEntryInformation->NextEntryOffset);
		}
		FltFreePoolAlignedWithTag(Instance, fileLinkInformation, 'fliS');
	}
	else
	{
		DbgPrint("FltAllocatePoolAlignedWithTag Fail\n");
		return result;
	}

	return result;
}


BOOLEAN
MiniFilterTestBackupOnUserMode(
	_In_ PFLT_INSTANCE Instance,
	_In_ PFILE_OBJECT FileObject)
{
	PFLT_VOLUME volume = NULL;
	PDEVICE_OBJECT deviceObject = NULL;
	UNICODE_STRING DosName = { 0, };
	PSCANNER_NOTIFICATION notification = NULL;
	NTSTATUS status = STATUS_SUCCESS;
	PVOID readBuffer = NULL;
	ULONG bytesRead;
	LARGE_INTEGER offset;
	ULONG replyLength;
	BOOLEAN SafeToOpen;
	FILE_STANDARD_INFORMATION fileStandardInformation;
	ULONG returnedLength;




	try {

		//
		//  Obtain the volume object .
		//


		status = FltGetVolumeFromInstance(Instance, &volume);

		if (!NT_SUCCESS(status)) {

			DbgPrint("!!! MiniFilterTest.sys --- FltGetVolumeFromInstance Fail\n");
			leave;
		}

		status = FltGetDiskDeviceObject(volume, &deviceObject);

		if (!NT_SUCCESS(status)) {

			DbgPrint("!!! MiniFilterTest.sys --- FltGetDeviceObject Fail\n");
			leave;
		}

		status = IoVolumeDeviceToDosName(deviceObject, &DosName);

		if (!NT_SUCCESS(status)) {

			DbgPrint("!!! MiniFilterTest.sys --- IoVolumeDeviceToDosName Fail\n");
			leave;
		}

		notification = FltAllocatePoolAlignedWithTag(Instance,
			NonPagedPool,
			sizeof(SCANNER_NOTIFICATION),
			'nacS');

		if (!notification)
		{
			DbgPrint("Memory Error\n");
			leave;
		}


		RtlZeroMemory(notification, sizeof(SCANNER_NOTIFICATION));

		RtlCopyMemory(&notification->PathBuffer,
			DosName.Buffer,
			min(DosName.Length, SCANNER_READ_BUFFER_SIZE));

		RtlCopyMemory((notification->PathBuffer + DosName.Length),
			FileObject->FileName.Buffer,
			min(FileObject->FileName.Length, SCANNER_READ_BUFFER_SIZE - DosName.Length));

		notification->PathBuffer[SCANNER_READ_BUFFER_SIZE - 1] = 0;

		FltQueryInformationFile(
			Instance, 
			FileObject,
			&fileStandardInformation,
			sizeof(FILE_STANDARD_INFORMATION),
			FileStandardInformation,
			&returnedLength
		);

		notification->FileSize = fileStandardInformation.EndOfFile.QuadPart;

		readBuffer = FltAllocatePoolAlignedWithTag(Instance,
			NonPagedPool,
			SCANNER_READ_BUFFER_SIZE,
			'nacS');

		if (!readBuffer)
		{
			DbgPrint("Memory Error\n");
			leave;
		}

		status = STATUS_SUCCESS;
		offset.QuadPart = bytesRead = 0;
		for (;NT_SUCCESS(status);)
		{
			status = FltReadFile(Instance,
				FileObject,
				&offset,
				SCANNER_READ_BUFFER_SIZE,
				readBuffer,
				FLTFL_IO_OPERATION_NON_CACHED |
				FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET,
				&bytesRead,
				NULL,
				NULL);


			if (STATUS_SUCCESS == status)
			{
				notification->BufferSize = bytesRead;
				RtlCopyMemory(notification->FileBuffer, readBuffer, bytesRead);
				notification->FileOffset = offset.QuadPart;
				offset.QuadPart += bytesRead;
			}
			if (STATUS_END_OF_FILE == status)
			{
				DbgPrint("EndOfFile\n");
				break;;
			}

			replyLength = sizeof(SCANNER_REPLY);
			status = FltSendMessage(gFilterHandle,
				&gClientPort,
				notification,
				sizeof(SCANNER_NOTIFICATION),
				notification,
				&replyLength,
				NULL);

			if (STATUS_SUCCESS == status) 
			{
				SafeToOpen = ((PSCANNER_REPLY)notification)->SafeToOpen;
			}
			else 
			{
				DbgPrint("!!! MiniFilterTest.sys --- couldn't send message to user-mode to scan file, status 0x%X\n", status);
			}
		}
	}
	finally {

		if (NULL != readBuffer) {

			ExFreePoolWithTag(readBuffer, 'nacS');
		}

		if (NULL != notification) {

			ExFreePoolWithTag(notification, 'nacS');
		}

		if (NULL != DosName.Buffer) {

			ExFreePool(DosName.Buffer);
		}

		if (NULL != deviceObject) {
			ObDereferenceObject(deviceObject);
		}

		if (NULL != volume) {

			FltObjectDereference(volume);
		}

	}		

	return TRUE;
}
