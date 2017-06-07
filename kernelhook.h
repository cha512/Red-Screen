#include <ntifs.h>
#include <ntddk.h>


#pragma pack(1)

typedef struct _KERNEL_HOOK
{
	PVOID FuncAddr;
	PVOID Hook;
	UCHAR JMP[5];
	UCHAR OrgBytes[5];
	PVOID OrgFunc;
}KERNEL_HOOK,*PKERNEL_HOOK;

#pragma pack()

#ifdef __cplusplus
	extern "C" 
	{
		VOID ClearWriteProtect(VOID);
		VOID SetWriteProtect(VOID);
		BOOLEAN InitHook(PKERNEL_HOOK Hook,PVOID Address,PVOID HookFunction);
		VOID StartHook(PKERNEL_HOOK Hook);
		VOID UnHook(PKERNEL_HOOK Hook);
		VOID RemoveHook(PKERNEL_HOOK Hook);
	}
#else
	VOID ClearWriteProtect(VOID);
	VOID SetWriteProtect(VOID);
	BOOLEAN InitHook(PKERNEL_HOOK Hook,PVOID Address,PVOID HookFunction);
	VOID StartHook(PKERNEL_HOOK Hook);
	VOID UnHook(PKERNEL_HOOK Hook);
	VOID RemoveHook(PKERNEL_HOOK Hook);	
#endif
 


BOOLEAN InitHook(PKERNEL_HOOK Hook,PVOID Address,PVOID HookFunction)
{
	ULONG OrgFunc,FuncAddr;

	Hook->FuncAddr=Address;
	Hook->OrgFunc=ExAllocatePool(NonPagedPool,4096);

	if(!Hook->OrgFunc)
		return FALSE;

	memcpy(Hook->OrgBytes,Address,5);
	memcpy(Hook->OrgFunc,Hook->OrgBytes,5);

	Hook->JMP[0]=0xe9;
	*(PULONG)&Hook->JMP[1]=(ULONG)HookFunction-(ULONG)Address-5;

	OrgFunc=(ULONG)Hook->OrgFunc+5;
	FuncAddr=(ULONG)Hook->FuncAddr+5;

	*(PUCHAR)((PUCHAR)Hook->OrgFunc+5)=0xe9;
	*(PULONG)((PUCHAR)Hook->OrgFunc+6)=FuncAddr-OrgFunc-5;

	return TRUE;
}

VOID StartHook(PKERNEL_HOOK Hook)
{
	ClearWriteProtect();
	memcpy(Hook->FuncAddr,Hook->JMP,5);
	SetWriteProtect();
}

VOID UnHook(PKERNEL_HOOK Hook)
{
	ClearWriteProtect();
	memcpy(Hook->FuncAddr,Hook->OrgBytes,5);
	SetWriteProtect();
}

VOID RemoveHook(PKERNEL_HOOK Hook)
{
	ExFreePool(Hook->OrgFunc);
	memset(Hook,0,sizeof(KERNEL_HOOK));
}

VOID ClearWriteProtect(VOID)
{
	__asm
	{
		cli
		push eax
		mov eax, CR0
		and eax, not 0x10000
		mov CR0, eax
		pop eax
	}
}

VOID SetWriteProtect(VOID)
{
	__asm
	{
		push eax
		mov eax, CR0
		or eax, 0x10000
		mov CR0, eax
		pop eax
		sti
	}
}
