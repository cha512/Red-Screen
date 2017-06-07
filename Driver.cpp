#include "kernelhook.h"
#include<stdio.h>

//GetAddr

typedef VOID (*pInbvSolidColorFill)(ULONG,ULONG,ULONG,ULONG,ULONG);

pInbvSolidColorFill fnInbvSolidColorFill;

KERNEL_HOOK ISCFHook;
UNICODE_STRING		NtNameString;
UNICODE_STRING		Win32NameString;
	
extern "C"
{
	PVOID Hook(ULONG ServiceNumber,PVOID Hook);
	VOID NTAPI HookInbvSolidColorFill(ULONG Left,ULONG Top,ULONG Right,ULONG Bottom,IN ULONG Color);
	NTSTATUS DriverEntry(IN PDRIVER_OBJECT driverObj, IN PUNICODE_STRING registryPath);
	VOID NTAPI DriverUnload(IN PDRIVER_OBJECT driverObj);
	NTSTATUS NTAPI CreateCloseHandler(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);
	PVOID GetAddr(PCWSTR SourceString);
}
PVOID GetAddr(PCWSTR SourceString)
{
 	UNICODE_STRING DestinationString;
 	DbgPrint("%ws", SourceString);
 	RtlInitUnicodeString(&DestinationString, SourceString);
 	return MmGetSystemRoutineAddress(&DestinationString);
}

VOID HookInbvSolidColorFill(ULONG Left,ULONG Top,ULONG Right,ULONG Bottom,IN ULONG Color)
{
 	fnInbvSolidColorFill(Left,Top,Right,Bottom,9);
 	return;
}

NTSTATUS DriverEntry(IN PDRIVER_OBJECT driverObj, IN PUNICODE_STRING registryPath)
{
	PDEVICE_OBJECT		DeviceObject     = NULL;
	NTSTATUS			Status;
	int i;
	for(i=0;i<=27;i++)
		driverObj->MajorFunction[i] = (PDRIVER_DISPATCH)CreateCloseHandler;
	driverObj->DriverUnload = (PDRIVER_UNLOAD)DriverUnload;
	
	RtlInitUnicodeString( &NtNameString, L"\\Device\\MyDevice" );
	RtlInitUnicodeString( &Win32NameString , L"\\DosDevices\\MyDevice" );
	
	Status = IoCreateDevice(driverObj, 0, &NtNameString, FILE_DEVICE_UNKNOWN, 0, FALSE, &DeviceObject);
	if ( !NT_SUCCESS (Status) )
	{
		DbgPrint("IoCreateDevice Fail.");  
		return Status;
	}
	
	DbgPrint("IoCreateDevice Success.");

	Status = IoCreateSymbolicLink(&Win32NameString, &NtNameString); 
	if(!NT_SUCCESS(Status)) 
	{
		DbgPrint("IoCreateSymbolicLink Fail.");
		IoDeleteDevice(driverObj->DeviceObject);
		return Status;
	}
	DbgPrint("IoCreateSymbolicLink Success.");
	
	InitHook(&ISCFHook,GetAddr(L"InbvSolidColorFill"),HookInbvSolidColorFill); 
	fnInbvSolidColorFill=(pInbvSolidColorFill)ISCFHook.OrgFunc;
	StartHook(&ISCFHook);
  
	return STATUS_SUCCESS;
}
VOID NTAPI DriverUnload(IN PDRIVER_OBJECT driverObj)
{
	DbgPrint("Driver Unload Ok.");
	UnHook(&ISCFHook);
	RemoveHook(&ISCFHook);
	IoDeleteSymbolicLink(&Win32NameString);
	IoDeleteDevice(driverObj->DeviceObject);
}
NTSTATUS NTAPI CreateCloseHandler(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = STATUS_SUCCESS;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return 0;
}

