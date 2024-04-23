#include "protect.h"
PVOID hRgistration = NULL;

NTSTATUS CreateCall(PDEVICE_OBJECT DeviceObject, PIRP irp) {
    UNREFERENCED_PARAMETER(DeviceObject);
    irp->IoStatus.Status = STATUS_SUCCESS;
    irp->IoStatus.Information = 0;

    IoCompleteRequest(irp, IO_NO_INCREMENT);// 드라이버 IRP 처리 완료 알림 함수


    return STATUS_SUCCESS;
}

NTSTATUS CloseCall(PDEVICE_OBJECT DeviceObject, PIRP irp) {
    UNREFERENCED_PARAMETER(DeviceObject);

    irp->IoStatus.Status = STATUS_SUCCESS;
    irp->IoStatus.Information = 0;


    IoCompleteRequest(irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}


NTSTATUS IoControl(PDEVICE_OBJECT DeviceObject, PIRP irp) {
    UNREFERENCED_PARAMETER(DeviceObject);
    NTSTATUS Status = STATUS_UNSUCCESSFUL;

    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);// I/O 스택 위치를 얻습니다. 이를 통해 IOCTL 코드를 포함한 요청의 상세 정보 접근

    ULONG Controlcode = stack->Parameters.DeviceIoControl.IoControlCode;



    if (Controlcode == IO_REQUEST_PROCESS_DEBUG_DETECTED)
        Status = AppendDebugProcess(irp);
    else if (Controlcode == IO_REQUEST_PROCESS_DEBUG_UNDETECTED))
        Status = RemoveDebugProcess(irp);
    

    return Status;
}

NTSTATUS InitObRegExample() {
    OB_CALLBACK_REGISTRATION obRegistration = { 0, };
    OB_OPERATION_REGISTRATION opRegistration = { 0, };

    obRegistration.Version = ObGetFilterVersion();
    obRegistration.OperationRegistrationCount = 1;
    RtlInitUnicodeString(&obRegistration.Altitude, L"12341234");
    obRegistration.RegistrationContext = NULL;

    opRegistration.ObjectType = PsProcessType;
    opRegistration.Operations = OB_OPERATION_HANDLE_CREATE;
    opRegistration.PreOperation = PreCallback;
    opRegistration.PostOperation = PostCallback;

    obRegistration.OperationRegistration = &opRegistration;

    return ObRegisterCallbacks(&obRegistration, &hRgistration);
}


NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath) {

    UNREFERENCED_PARAMETER(pRegistryPath);
    RtlZeroMemory(List, sizeof(List));
    UNICODE_STRING PsGetProcessDebufString;
    NTSTATUS ret;
    PsSetLoadImageNotifyRoutine(ImageLoadCallback);

    RtlInitUnicodeString(&dev, L"\\Device\\detectdebug");
    RtlInitUnicodeString(&dos, L"\\??\\detectdebug");

    IoCreateDevice(pDriverObject, 0, &dev, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &pDeviceObject);
    IoCreateSymbolicLink(&dos, &dev);


    pDriverObject->MajorFunction[IRP_MJ_CREATE] = CreateCall;
    pDriverObject->MajorFunction[IRP_MJ_CLOSE] = CloseCall;
    pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IoControl;
    pDriverObject->DriverUnload = UnloadDriver;
    DbgPrintEx(0, 0, "[*] start");

    if (GetOffset(PsGetCurrentProcess())) {
        RtlCreateUnicodeString(&PsGetProcessDebufString, PsGetProcessDebugPort_string);
        PsGetProcessDebugPort = (PsGetProcessDebugPort_t)MmGetSystemRoutineAddress(&PsGetProcessDebufString);
        
        ret = InitObRegExample();
        if (ret == STATUS_SUCCESS) {
            DbgPrintEx(0, 0, "[*] Success registerration");
        }
        else {
            DbgPrintEx(0, 0, "[*] Failed registerration %X\n", ret);
        }
    }

    pDeviceObject->Flags |= DO_DIRECT_IO;
    pDeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;
    DbgPrintEx(0, 0, "[*] load ");
    return STATUS_SUCCESS;
}

NTSTATUS UnloadDriver(PDRIVER_OBJECT pDriverObject) {
    UNREFERENCED_PARAMETER(pDriverObject);
    __try {
        if (hRgistration != NULL) {
            ObUnRegisterCallbacks(hRgistration);
            hRgistration = NULL;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint(0, 0, "[*] Unload Error!");
    }

    DbgPrintEx(0, 0, "[*] unload");
    PsRemoveLoadImageNotifyRoutine(ImageLoadCallback);
    IoDeleteSymbolicLink(&dos);
    IoDeleteDevice(pDriverObject->DeviceObject);


    return STATUS_SUCCESS;

}