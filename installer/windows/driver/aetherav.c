/*
 * AetherAV minifilter - kernel-level on-access scanning for Windows.
 *
 * SCAFFOLD / BLUEPRINT. This is the path to TRUE pre-execution blocking on
 * Windows (the equivalent of Linux fanotify). It is a file-system minifilter:
 * it intercepts IRP_MJ_CREATE (file open / execute), asks the user-mode AetherAV
 * service to scan the file, and DENIES the open if the verdict is malicious -
 * before any code runs.
 *
 * BUILD: requires the Windows Driver Kit (WDK) + Visual Studio (Kernel Mode
 * Driver project). It does NOT build with a normal toolchain.
 * SIGN:  a kernel driver must be signed with an EV certificate and submitted to
 * the Microsoft Partner Center for attestation/WHQL signing to load on modern
 * Windows. See README.md.
 *
 * The user-mode side reuses the existing AetherAV engine (aether-core) behind a
 * small service that answers scan requests on the communication port below.
 */

#include <fltKernel.h>
#include <dontuse.h>

#define AETHER_PORT_NAME L"\\AetherAVPort"

typedef struct _AETHER_GLOBALS {
    PFLT_FILTER  Filter;
    PFLT_PORT    ServerPort;   // we listen here
    PFLT_PORT    ClientPort;   // the user-mode service connects here
} AETHER_GLOBALS;

static AETHER_GLOBALS g = { 0 };

/* Request/verdict exchanged with the user-mode scanner. */
typedef struct _AETHER_SCAN_REQUEST {
    WCHAR Path[520];
} AETHER_SCAN_REQUEST;

typedef struct _AETHER_SCAN_REPLY {
    ULONG Block;   // non-zero => deny the open (malware)
} AETHER_SCAN_REPLY;

/* ---- communication port: user-mode service connect/disconnect ---- */
static NTSTATUS AetherConnect(PFLT_PORT ClientPort, PVOID ServerCookie,
                              PVOID Context, ULONG Size, PVOID *ConnPortCookie) {
    UNREFERENCED_PARAMETER(ServerCookie);
    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(Size);
    UNREFERENCED_PARAMETER(ConnPortCookie);
    g.ClientPort = ClientPort;
    return STATUS_SUCCESS;
}
static VOID AetherDisconnect(PVOID ConnPortCookie) {
    UNREFERENCED_PARAMETER(ConnPortCookie);
    FltCloseClientPort(g.Filter, &g.ClientPort);
    g.ClientPort = NULL;
}

/* ---- ask user mode whether to block this file ---- */
static BOOLEAN AetherShouldBlock(PFLT_CALLBACK_DATA Data) {
    NTSTATUS status;
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    AETHER_SCAN_REQUEST req = { 0 };
    AETHER_SCAN_REPLY reply = { 0 };
    ULONG replyLen = sizeof(reply);

    if (g.ClientPort == NULL) {
        return FALSE; /* service not running -> fail open (don't break the box) */
    }
    status = FltGetFileNameInformation(
        Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo);
    if (!NT_SUCCESS(status)) {
        return FALSE;
    }
    RtlStringCbCopyNW(req.Path, sizeof(req.Path),
                      nameInfo->Name.Buffer, nameInfo->Name.Length);
    FltReleaseFileNameInformation(nameInfo);

    /* Synchronous scan request to the user-mode AetherAV service. */
    status = FltSendMessage(g.Filter, &g.ClientPort, &req, sizeof(req),
                            &reply, &replyLen, NULL);
    if (status == STATUS_SUCCESS && reply.Block) {
        return TRUE;
    }
    return FALSE;
}

/* ---- pre-create: the interception point ---- */
static FLT_PREOP_CALLBACK_STATUS AetherPreCreate(
        PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID *Ctx) {
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Ctx);

    if (Data->RequestorMode == KernelMode) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    if (AetherShouldBlock(Data)) {
        Data->IoStatus.Status = STATUS_VIRUS_INFECTED; /* deny the open */
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

static const FLT_OPERATION_REGISTRATION Callbacks[] = {
    { IRP_MJ_CREATE, 0, AetherPreCreate, NULL },
    { IRP_MJ_OPERATION_END }
};

static NTSTATUS AetherUnload(FLT_FILTER_UNLOAD_FLAGS Flags) {
    UNREFERENCED_PARAMETER(Flags);
    if (g.ServerPort) FltCloseCommunicationPort(g.ServerPort);
    if (g.Filter)     FltUnregisterFilter(g.Filter);
    return STATUS_SUCCESS;
}

static const FLT_REGISTRATION FilterRegistration = {
    sizeof(FLT_REGISTRATION), FLT_REGISTRATION_VERSION, 0,
    NULL, Callbacks,
    AetherUnload,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL
};

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    NTSTATUS status;
    UNICODE_STRING portName;
    PSECURITY_DESCRIPTOR sd;
    OBJECT_ATTRIBUTES oa;
    UNREFERENCED_PARAMETER(RegistryPath);

    status = FltRegisterFilter(DriverObject, &FilterRegistration, &g.Filter);
    if (!NT_SUCCESS(status)) return status;

    status = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);
    if (NT_SUCCESS(status)) {
        RtlInitUnicodeString(&portName, AETHER_PORT_NAME);
        InitializeObjectAttributes(&oa, &portName,
            OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, sd);
        status = FltCreateCommunicationPort(g.Filter, &g.ServerPort, &oa, NULL,
            AetherConnect, AetherDisconnect, NULL, 1);
        FltFreeSecurityDescriptor(sd);
    }
    if (NT_SUCCESS(status)) {
        status = FltStartFiltering(g.Filter);
    }
    if (!NT_SUCCESS(status)) {
        if (g.ServerPort) FltCloseCommunicationPort(g.ServerPort);
        FltUnregisterFilter(g.Filter);
    }
    return status;
}
