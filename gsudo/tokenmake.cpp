#include <iostream>
#include <Windows.h>
#include <winioctl.h>
#include <string>
#include <windows.h>
#include <ntstatus.h>
#include <winternl.h>

#define IOCTL_IO_GETSYS CTL_CODE(FILE_DEVICE_UNKNOWN,0x800,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define IOCTL_IO_GETFASYS CTL_CODE(FILE_DEVICE_UNKNOWN,0x801,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define IOCTL_IO_COPY CTL_CODE(FILE_DEVICE_UNKNOWN,0x802,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define IOCTL_IO_PID CTL_CODE(FILE_DEVICE_UNKNOWN,0x803,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define IOCTL_IO_SAPID CTL_CODE(FILE_DEVICE_UNKNOWN,0x804,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define IOCTL_IO_SETPID CTL_CODE(FILE_DEVICE_UNKNOWN,0x805,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define IOCTL_IO_INFO CTL_CODE(FILE_DEVICE_UNKNOWN,0x806,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define IOCTL_IO_SUSPID CTL_CODE(FILE_DEVICE_UNKNOWN,0x807,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define IOCTL_IO_RESPID CTL_CODE(FILE_DEVICE_UNKNOWN,0x808,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define IOCTL_IO_KILLPID CTL_CODE(FILE_DEVICE_UNKNOWN,0x809,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define IOCTL_IO_RAMPID CTL_CODE(FILE_DEVICE_UNKNOWN,0x810,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define IOCTL_IO_REBOOT CTL_CODE(FILE_DEVICE_UNKNOWN,0x811,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define IOCTL_IO_SHUTDOWN CTL_CODE(FILE_DEVICE_UNKNOWN,0x812,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define IOCTL_IO_SETPA CTL_CODE(FILE_DEVICE_UNKNOWN,0x813,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define IOCTL_IO_GETALLPID CTL_CODE(FILE_DEVICE_UNKNOWN,0x814,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define IOCTL_IO_ROOTFULL CTL_CODE(FILE_DEVICE_UNKNOWN,0x815,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define IOCTL_IO_GETTIME CTL_CODE(FILE_DEVICE_UNKNOWN,0x816,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define IOCTL_IO_SHUTDOWNHAL CTL_CODE(FILE_DEVICE_UNKNOWN,0x817,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define IOCTL_IO_REBOTHAL CTL_CODE(FILE_DEVICE_UNKNOWN,0x818,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define IOCTL_IO_ADDPROPID CTL_CODE(FILE_DEVICE_UNKNOWN,0x819,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define IOCTL_IO_DELPROPID CTL_CODE(FILE_DEVICE_UNKNOWN,0x820,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define IOCTL_IO_LISTPROPID CTL_CODE(FILE_DEVICE_UNKNOWN,0x821,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define IOCTL_IO_ADDALLHPID CTL_CODE(FILE_DEVICE_UNKNOWN,0x822,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define IOCTL_IO_DELALLHPID CTL_CODE(FILE_DEVICE_UNKNOWN,0x823,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define IOCTL_IO_LISTALLHPID CTL_CODE(FILE_DEVICE_UNKNOWN,0x824,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define IOCTL_IO_OBREG CTL_CODE(FILE_DEVICE_UNKNOWN,0x825,METHOD_BUFFERED,FILE_ANY_ACCESS)
typedef struct {
    DWORD orgpid;
    DWORD newpid;
} newpiddata;

typedef struct
{
    DWORD pid;
    DWORD level;
}ppldata;

typedef struct
{
    int suc;
    DWORD father;
    DWORD token;
    DWORD ppl;
    DWORD timer;
    char* name[256];
    char* path[1024];
}pidinfo;

typedef struct
{
    int suc;
    DWORD pid;
    DWORD father;
    DWORD token;
    DWORD ppl;
    DWORD timer;
    char* name[256];
    char* path[1024];
    int end;
}pidall;

typedef struct
{
    DWORD pid1;
    DWORD pid2;
    DWORD pid3;
    DWORD pid4;
    DWORD pid5;
    DWORD pid6;
    DWORD pid7;
    DWORD pid8;
    DWORD pid9;
    DWORD pid10;
}procpidexlist;

typedef long NTSTATUS;

typedef enum _SHUTDOWN_ACTION
{
    ShutdownNoReboot,
    ShutdownReboot,
    ShutdownPowerOff
} SHUTDOWN_ACTION, * PSHUTDOWN_ACTION;

typedef NTSTATUS(NTAPI* NTSHUTDOWNSYSTEM)(SHUTDOWN_ACTION);

void shutdown()
{
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    printf("正在获取必要权限\n");
   
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        printf("OpenProcessToken failed. Error: %lu\n", GetLastError());
    }

   
    LookupPrivilegeValue(NULL, SE_SHUTDOWN_NAME, &tp.Privileges[0].Luid);
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

   
    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL)) {
        printf("AdjustTokenPrivileges failed. Error: %lu\n", GetLastError());
        CloseHandle(hToken);
    }

    printf("SE_SHUTDOWN_NAME privilege granted successfully.\n");
    CloseHandle(hToken);
    HMODULE hModule = GetModuleHandleW(L"ntdll.dll");
    if (hModule) {
        auto proc = (NTSHUTDOWNSYSTEM)GetProcAddress(hModule, "NtShutdownSystem");
        if (proc) {
            proc(ShutdownPowerOff);
        }
    }
}

void reboot()
{
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    printf("正在获取必要权限\n");
   
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        printf("OpenProcessToken failed. Error: %lu\n", GetLastError());
    }

   
    LookupPrivilegeValue(NULL, SE_SHUTDOWN_NAME, &tp.Privileges[0].Luid);
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

   
    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL)) {
        printf("AdjustTokenPrivileges failed. Error: %lu\n", GetLastError());
        CloseHandle(hToken);
    }

    printf("SE_SHUTDOWN_NAME privilege granted successfully.\n");
    CloseHandle(hToken);
    HMODULE hModule = GetModuleHandleW(L"ntdll.dll");
    if (hModule) {
        auto proc = (NTSHUTDOWNSYSTEM)GetProcAddress(hModule, "NtShutdownSystem");
        if (proc) {
            proc(ShutdownReboot);
        }
    }
}

void help() {
    std::cerr << "请提供操作类型和相应的PID参数." << std::endl;
    printf("操作: pid | copy | hide | setpid | ppl | suspend | resume | kill | ramclear | info | chain | listall | safe | unsafe | listsafe | gethandle | drophandle | listhandle | setobcallback | setparent | shutdown | reboot | kernelshutdown | kernelreboot | forcereboot | -i\n");
    printf("pid <PID> - 将指定PID的权限提升至SYSTEM32\n");
    printf("copy <PID1> <PID2> - 将PID1的权限设置成PID2的权限\n");
    printf("hide <PID> - 将指定PID隐藏\n");
    printf("setpid <PID1> <PID2> - 将PID1替换为PID2\n");
    printf("ppl <PID> <LEVEL 1-9> - 强制设置指定PID的PPL\n");
    printf("suspend <PID> - 将指定PID强行挂起\n");
    printf("resume <PID> - 将指定PID强行恢复运行\n");
    printf("kill <PID> - 将指定PID强行关闭\n");
    printf("ramclear <PID> - 将指定PID强行清除内存\n");
    printf("info <PID> - 获取指定PID的信息\n");
    printf("chain <PID> - 获取指定PID的进程链\n");
    printf("listall - 枚举所有进程\n");
    printf("safe - 保护指定PID\n");
    printf("unsafe - 取消保护指定PID\n");
    printf("listsafe - 列出受保护的PID列表\n");
    printf("gethandle - 绕过指定进程的保护\n");
    printf("drophandle - 取消绕过指定进程的保护\n");
    printf("listhandle - 列出绕过指定进程的保护列表\n");
    printf("setobcallback <1/0> - 设置保护开关\n");
    printf("setparent <PID> <PARENTPID> - 设置指定PID的父进程PID\n");
    printf("shutdown - 快速关机(NtShutdownSystem应用层)\n");
    printf("reboot - 快速重启(NtShutdownSystem应用层)\n");
    printf("kernelshutdown - 内核关机(调用内核向主板发送掉电关机信号)\n");
    printf("kernelreboot - 内核重启(调用内核向主板发送掉电重启信号)\n");
    printf("forcereboot - 掉电重启(直接对主板I/O掉电重启 注意该操作只支持较新主板否侧会陷入主板卡机)\n");
    printf("-i - 将当前进程(父进程)提升至SYSTEM32\n");

}

DWORD chainpid(DWORD pidin , HANDLE hDevice) {
    pidinfo pidinfo;
    DWORD pid = pidin;
    DWORD ref_len = 0;
    DeviceIoControl(hDevice, IOCTL_IO_INFO, &pid, sizeof(pid), &pidinfo, sizeof(pidinfo), &ref_len, NULL);
    if (pidinfo.suc == 1) {
        char str[15];
        printf("PID: %d\tImage name[14]: %s\n", pid, pidinfo.name);
        printf("Image path: %s\n", pidinfo.path);
        time_t timestamp = pidinfo.timer;
        struct tm* tm_info;
        tm_info = localtime(&timestamp);

       
        char buffertimer[26];
        strftime(buffertimer, sizeof(buffertimer), "%Y-%m-%d %H:%M:%S", tm_info);
        printf("CreateTime: %s\n", buffertimer);
        printf("Parent process pid: %d\n", pidinfo.father);
        printf("TOKEN: %p\n", pidinfo.token);
        printf("PPL: %p\n", pidinfo.ppl);
        int tmpppl = pidinfo.ppl & 0x00000000000000ff;
        switch (tmpppl) {
        case 0x0:
            printf("PPL LEVEL: 0 - PS_PROTECTED_NONE\n");
            break;
        case 0x11:
            printf("PPL LEVEL: 1 - PS_PROTECTED_AUTHENTICODE_LIGHT\n");
            break;
        case 0x21:
            printf("PPL LEVEL: 2 - PS_PROTECTED_AUTHENTICODE\n");
            break;
        case 0x31:
            printf("PPL LEVEL: 3 - PS_PROTECTED_ANTIMALWARE_LIGHT\n");
            break;
        case 0x41:
            printf("PPL LEVEL: 4 - PS_PROTECTED_LSA_LIGHT\n");
            break;
        case 0x51:
            printf("PPL LEVEL: 5 - PS_PROTECTED_WINDOWS_LIGHT\n");
            break;
        case 0x52:
            printf("PPL LEVEL: 6 - PS_PROTECTED_WINDOWS\n");
            break;
        case 0x61:
            printf("PPL LEVEL: 7 - PS_PROTECTED_WINTCB_LIGHT\n");
            break;
        case 0x62:
            printf("PPL LEVEL: 8 - PS_PROTECTED_WINTCB\n");
            break;
        case 0x72:
            printf("PPL LEVEL: 9 - PS_PROTECTED_SYSTEM\n");
            break;
        default:
            printf("UNKNOW LEVEL %p\n", tmpppl);
            break;
        }
        return pidinfo.father;
    }
    else {
        printf("PID: %d get info error\n", pid);
        return 0;
    }

}


DWORD getalltmp(DWORD pidin, HANDLE hDevice) {
    pidall pidinfo;
    DWORD pid = pidin;
    DWORD ref_len = 0;
    DeviceIoControl(hDevice, IOCTL_IO_GETALLPID, &pid, sizeof(pid), &pidinfo, sizeof(pidall), &ref_len, NULL);
    if (pidinfo.end == 0) {
        char str[15];
        printf("PID: %d\tImage name[14]: %s\n", pidinfo.pid, pidinfo.name);
        printf("Image path: %s\n", pidinfo.path);
        time_t timestamp = pidinfo.timer;
        struct tm* tm_info;
        tm_info = localtime(&timestamp);

       
        char buffertimer[26];
        strftime(buffertimer, sizeof(buffertimer), "%Y-%m-%d %H:%M:%S", tm_info);
        printf("CreateTime: %s\n", buffertimer);
        printf("Parent process pid: %d\n", pidinfo.father);
        printf("TOKEN: %p\n", pidinfo.token);
        printf("PPL: %p\n", pidinfo.ppl);
        DWORD tmpppl = pidinfo.ppl & 0x00000000000000ff;
        switch (tmpppl) {
        case 0x0:
            printf("PPL LEVEL: 0 - PS_PROTECTED_NONE\n");
            break;
        case 0x11:
            printf("PPL LEVEL: 1 - PS_PROTECTED_AUTHENTICODE_LIGHT\n");
            break;
        case 0x21:
            printf("PPL LEVEL: 2 - PS_PROTECTED_AUTHENTICODE\n");
            break;
        case 0x31:
            printf("PPL LEVEL: 3 - PS_PROTECTED_ANTIMALWARE_LIGHT\n");
            break;
        case 0x41:
            printf("PPL LEVEL: 4 - PS_PROTECTED_LSA_LIGHT\n");
            break;
        case 0x51:
            printf("PPL LEVEL: 5 - PS_PROTECTED_WINDOWS_LIGHT\n");
            break;
        case 0x52:
            printf("PPL LEVEL: 6 - PS_PROTECTED_WINDOWS\n");
            break;
        case 0x61:
            printf("PPL LEVEL: 7 - PS_PROTECTED_WINTCB_LIGHT\n");
            break;
        case 0x62:
            printf("PPL LEVEL: 8 - PS_PROTECTED_WINTCB\n");
            break;
        case 0x72:
            printf("PPL LEVEL: 9 - PS_PROTECTED_SYSTEM\n");
            break;
        default:
            printf("UNKNOW LEVEL %p\n", tmpppl);
            break;
        }
        return pidinfo.pid;
    }
    else {
        return 0;
    }

}


void handleDeviceIoControl(int argc, char* argv[]) {
    printf("Made by phtcloud\n");
    if (argc < 2) {
        help();
        return;
    }
    std::string operation = argv[1];
    HANDLE hDevice = CreateFileA("\\\\.\\IO::SYS", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hDevice == INVALID_HANDLE_VALUE) {
        std::cerr << "gsudo环境未安装或未启动" << std::endl;
        return;
    }
    DWORD output = 0, ref_len = 0;

    if (operation == "ppl") {
        if (argc < 4) {
            std::cerr << "请提供一个PID参数和PPL等级" << std::endl;
            printf("ppl <PID> <LEVEL 1-9> - 强制设置指定PID的PPL\n");
            printf("PPL LEVEL: 0 - PS_PROTECTED_NONE\n");
            printf("PPL LEVEL: 1 - PS_PROTECTED_AUTHENTICODE_LIGHT\n");
            printf("PPL LEVEL: 2 - PS_PROTECTED_AUTHENTICODE\n");
            printf("PPL LEVEL: 3 - PS_PROTECTED_ANTIMALWARE_LIGHT\n");
            printf("PPL LEVEL: 4 - PS_PROTECTED_LSA_LIGHT\n");
            printf("PPL LEVEL: 5 - PS_PROTECTED_WINDOWS_LIGHT\n");
            printf("PPL LEVEL: 6 - PS_PROTECTED_WINDOWS\n");
            printf("PPL LEVEL: 7 - PS_PROTECTED_WINTCB_LIGHT\n");
            printf("PPL LEVEL: 8 - PS_PROTECTED_WINTCB\n");
            printf("PPL LEVEL: 9 - PS_PROTECTED_SYSTEM\n");
            printf("该操作用于修改进程的保护等级\n注意开启PPL后的进程无法使用正常手段运行其他程序\n");
            CloseHandle(hDevice);
            return;
        }
        ppldata getppl;
        getppl = { (DWORD)strtoul(argv[2], NULL, 10), (DWORD)strtoul(argv[3], NULL, 10) };
        DeviceIoControl(hDevice, IOCTL_IO_SAPID, &getppl, sizeof(getppl), &output, sizeof(output), &ref_len, NULL);
        printf(output == 1 ? "PID %d PPL设置成功\n" : "PID %d PPL设置失败\n", getppl.pid);
    }
    else if (operation == "setparent") {
        if (argc < 4) {
            std::cerr << "请提供两个PID参数." << std::endl;
            printf("setparent <PID> <PARENTPID> - 设置指定PID的父进程PID\n");
            printf("该操作用于修改进程的父进程\n使用procexp等工具可查看效果\n");
            CloseHandle(hDevice);
            return;
        }
        newpiddata senddata = { (DWORD)strtoul(argv[2], NULL, 10), (DWORD)strtoul(argv[3], NULL, 10) };
        DeviceIoControl(hDevice, IOCTL_IO_SETPA, &senddata, sizeof(senddata), &output, sizeof(output), &ref_len, NULL);
        printf(output == 1 ? "PID %d 父进程修改成功\n" : "PID %d 父进程修改失败\n", senddata.orgpid);
    }
    else if (operation == "chain") {
        if (argc < 3) {
            std::cerr << "请提供一个PID参数." << std::endl;
            printf("chain <PID> - 获取指定PID的进程链\n");
            printf("该操作用于获取指定进程的完整进程链\n返回格式参考info选项\n");
            CloseHandle(hDevice);
            return;
        }
        pidinfo pidinfo;
        DWORD pid = (DWORD)strtoul(argv[2], NULL, 10);
        DWORD pid2 = 0;
        while (1) {
            printf("--------------------------------------------------\n", pid, pid2);
            pid = chainpid(pid, hDevice);
            if ((pid == 0) || (pid2 == pid)) {
                break;
            }
            pid2 = pid;
        }
    }
    else if (operation == "info") {
        if (argc < 3) {
            std::cerr << "请提供一个PID参数." << std::endl;
            printf("info <PID> - 获取指定PID的信息\n");
            printf("该操作用于获取指定进程的相关信息\n");
            printf("PID: int\n");
            printf("Parent process pid: int\n");
            printf("Image name[14]: char*\n");
            printf("Image path: char*\n");
            printf("TOKEN: HEX\n");
            printf("PPL: HEX\n");
            CloseHandle(hDevice);
            return;
        }
        pidinfo pidinfo;
        DWORD pid = (DWORD)strtoul(argv[2], NULL, 10);
        DeviceIoControl(hDevice, IOCTL_IO_INFO, &pid, sizeof(pid), &pidinfo, sizeof(pidinfo), &ref_len, NULL);
        if (pidinfo.suc == 1) {
            char str[15];
            printf("PID: %d\tImage name[14]: %s\n", pid, pidinfo.name);
            printf("Image path: %s\n", pidinfo.path);
            time_t timestamp = pidinfo.timer;
            struct tm* tm_info;
            tm_info = localtime(&timestamp);

           
            char buffertimer[26];
            strftime(buffertimer, sizeof(buffertimer), "%Y-%m-%d %H:%M:%S", tm_info);
            printf("CreateTime: %s\n", buffertimer);
            printf("Parent process pid: %d\n", pidinfo.father);
            printf("TOKEN: %p\n", pidinfo.token);
            printf("PPL: %p\n", pidinfo.ppl);
            int tmpppl = pidinfo.ppl & 0x00000000000000ff;
            switch (tmpppl) {
            case 0x0:
                printf("PPL LEVEL:  0 - PS_PROTECTED_NONE\n");
                break;
            case 0x11:
                printf("PPL LEVEL: 1 - PS_PROTECTED_AUTHENTICODE_LIGHT\n");
                break;
            case 0x21:
                printf("PPL LEVEL: 2 - PS_PROTECTED_AUTHENTICODE\n");
                break;
            case 0x31:
                printf("PPL LEVEL: 3 - PS_PROTECTED_ANTIMALWARE_LIGHT\n");
                break;
            case 0x41:
                printf("PPL LEVEL: 4 - PS_PROTECTED_LSA_LIGHT\n");
                break;
            case 0x51:
                printf("PPL LEVEL: 5 - PS_PROTECTED_WINDOWS_LIGHT\n");
                break;
            case 0x52:
                printf("PPL LEVEL: 6 - PS_PROTECTED_WINDOWS\n");
                break;
            case 0x61:
                printf("PPL LEVEL: 7 - PS_PROTECTED_WINTCB_LIGHT\n");
                break;
            case 0x62:
                printf("PPL LEVEL: 8 - PS_PROTECTED_WINTCB\n");
                break;
            case 0x72:
                printf("PPL LEVEL: 9 - PS_PROTECTED_SYSTEM\n");
                break;
            default:
                printf("UNKNOW LEVEL %p\n", tmpppl);
                break;
            }
        }
        else {
            printf("PID: %d get info error\n", pid);
        }
    }

    else if (operation == "listall") {
        DWORD pid = 4;
        DWORD toto = 0;
        while (1) {
            printf("--------------------------------------------------\n");
            pid = getalltmp(pid, hDevice);
            if (pid == 0) {
                printf("共%d个进程\n", toto);
                break;
            }
            pid = pid + 4;
            toto++;
        }
    }


    else if (operation == "rootfull") {
        DWORD pid = 1;
        DeviceIoControl(hDevice, IOCTL_IO_ROOTFULL, &pid, sizeof(pid), &output, sizeof(output), &ref_len, NULL);
    }
    else if (operation == "forcereboot") {
        DWORD pid = 1;
        DeviceIoControl(hDevice, IOCTL_IO_REBOOT, &pid, sizeof(pid), &output, sizeof(output), &ref_len, NULL);
    }

    else if (operation == "kernelshutdown") {
        DWORD pid = 1;
        DeviceIoControl(hDevice, IOCTL_IO_SHUTDOWNHAL, &pid, sizeof(pid), &output, sizeof(output), &ref_len, NULL);
    }
    else if (operation == "kernelreboot") {
        DWORD pid = 1;
        DeviceIoControl(hDevice, IOCTL_IO_REBOTHAL, &pid, sizeof(pid), &output, sizeof(output), &ref_len, NULL);
    }



    else if (operation == "suspend") {
        if (argc < 3) {
            std::cerr << "请提供一个PID参数." << std::endl;
            printf("suspend <PID> - 将指定PID强行挂起\n");
            printf("该操作用于挂起指定进程\n如果进程存在其他驱动的保护可能无效\n");
            CloseHandle(hDevice);
            return;
        }
        DWORD pid = (DWORD)strtoul(argv[2], NULL, 10);
        DeviceIoControl(hDevice, IOCTL_IO_SUSPID, &pid, sizeof(pid), &output, sizeof(output), &ref_len, NULL);
        printf(output == 1 ? "PID %d 强行挂起成功\n" : "PID %d 强行挂起失败\n", pid);
    }

    else if (operation == "setobcallback") {
        if (argc < 3) {
            std::cerr << "请提供一个参数." << std::endl;
            printf("setobcallback <1/0> - ON/OFF\n");
            CloseHandle(hDevice);
            return;
        }
        DWORD pid = (DWORD)strtoul(argv[2], NULL, 10);
        DeviceIoControl(hDevice, IOCTL_IO_OBREG, &pid, sizeof(pid), &output, sizeof(output), &ref_len, NULL);
        printf(output == 1 ? "CLALLBACK设置成功\n" : "CLALLBACK设置失败\n", pid);
    }
    else if (operation == "shutdown") {
        shutdown();
    }
    else if (operation == "reboot") {
        reboot();
    }
    else if (operation == "kill") {
        if (argc < 3) {
            std::cerr << "请提供一个PID参数." << std::endl;
            printf("kill <PID> - 将指定PID强行关闭\n");
            printf("该操作用于结束指定进程\n可用于结束需要高权限才能结束的进程\n强制结束系统进程可能造成BSoD");
            CloseHandle(hDevice);
            return;
        }
        DWORD pid = (DWORD)strtoul(argv[2], NULL, 10);
        DeviceIoControl(hDevice, IOCTL_IO_KILLPID, &pid, sizeof(pid), &output, sizeof(output), &ref_len, NULL);
        printf(output == 1 ? "PID %d 关闭成功\n" : "PID %d 关闭失败\n", pid);
    }

    else if (operation == "safe") {
        if (argc < 3) {
            std::cerr << "请提供一个PID参数." << std::endl;
            printf("safe <PID> - 保护指定PID\n");
            printf("保护指定PID不被结束/访问/修改\n只能做多保护10个PID");
            CloseHandle(hDevice);
            return;
        }
        DWORD pid = (DWORD)strtoul(argv[2], NULL, 10);
        DeviceIoControl(hDevice, IOCTL_IO_ADDPROPID, &pid, sizeof(pid), &output, sizeof(output), &ref_len, NULL);
        printf(output == 1 ? "PID %d 保护成功\n" : "PID %d 保护失败\n", pid);
    }
    else if (operation == "unsafe") {
        if (argc < 3) {
            std::cerr << "请提供一个PID参数." << std::endl;
            printf("safe <PID> - 取消保护指定PID\n");
            printf("safe的相反效果只能取消由gsudo保护的PID\n");
            CloseHandle(hDevice);
            return;
        }
        DWORD pid = (DWORD)strtoul(argv[2], NULL, 10);
        DeviceIoControl(hDevice, IOCTL_IO_DELPROPID, &pid, sizeof(pid), &output, sizeof(output), &ref_len, NULL);
        printf(output == 1 ? "PID %d 取消保护成功\n" : "PID %d 取消保护失败\n", pid);
    }
    else if (operation == "listsafe") {
        DWORD procpidex[] = { 0,0,0,0,0,0,0,0,0,0 };
        DWORD pid = 0;
        DeviceIoControl(hDevice, IOCTL_IO_LISTPROPID, &pid, sizeof(pid), &procpidex, sizeof(procpidex), &ref_len, NULL);
        printf("保护位1: %d\n", procpidex[0]);
        printf("保护位2: %d\n", procpidex[1]);
        printf("保护位3: %d\n", procpidex[2]);
        printf("保护位4: %d\n", procpidex[3]);
        printf("保护位5: %d\n", procpidex[4]);
        printf("保护位6: %d\n", procpidex[5]);
        printf("保护位7: %d\n", procpidex[6]);
        printf("保护位8: %d\n", procpidex[7]);
        printf("保护位9: %d\n", procpidex[8]);
        printf("保护位10: %d\n", procpidex[9]);
        }
    else if (operation == "gethandle") {
        if (argc < 3) {
            std::cerr << "请提供一个PID参数." << std::endl;
            printf("safe <PID> - 保护指定PID\n");
            printf("保护指定PID不被结束/访问/修改\n只能做多保护10个PID");
            CloseHandle(hDevice);
            return;
        }
        DWORD pid = (DWORD)strtoul(argv[2], NULL, 10);
        DeviceIoControl(hDevice, IOCTL_IO_ADDALLHPID, &pid, sizeof(pid), &output, sizeof(output), &ref_len, NULL);
        printf(output == 1 ? "PID %d 绕过保护成功\n" : "PID %d 绕过保护失败\n", pid);
        }
    else if (operation == "drophandle") {
            if (argc < 3) {
                std::cerr << "请提供一个PID参数." << std::endl;
                printf("safe <PID> - 取消保护指定PID\n");
                printf("safe的相反效果只能取消由gsudo保护的PID\n");
                CloseHandle(hDevice);
                return;
            }
            DWORD pid = (DWORD)strtoul(argv[2], NULL, 10);
            DeviceIoControl(hDevice, IOCTL_IO_DELALLHPID, &pid, sizeof(pid), &output, sizeof(output), &ref_len, NULL);
            printf(output == 1 ? "PID %d 取消绕过保护成功\n" : "PID %d 取消绕过保护失败\n", pid);
            }
    else if (operation == "listhandle") {
                DWORD procpidex[] = { 0,0,0,0,0,0,0,0,0,0 };
                DWORD pid = 0;
                DeviceIoControl(hDevice, IOCTL_IO_LISTALLHPID, &pid, sizeof(pid), &procpidex, sizeof(procpidex), &ref_len, NULL);
                printf("绕过保护位1: %d\n", procpidex[0]);
                printf("绕过保护位2: %d\n", procpidex[1]);
                printf("绕过保护位3: %d\n", procpidex[2]);
                printf("绕过保护位4: %d\n", procpidex[3]);
                printf("绕过保护位5: %d\n", procpidex[4]);
                printf("绕过保护位6: %d\n", procpidex[5]);
                printf("绕过保护位7: %d\n", procpidex[6]);
                printf("绕过保护位8: %d\n", procpidex[7]);
                printf("绕过保护位9: %d\n", procpidex[8]);
                printf("绕过保护位10: %d\n", procpidex[9]);
                }

    else if (operation == "ramclear") {
        if (argc < 3) {
            std::cerr << "请提供一个PID参数." << std::endl;
            printf("ramclear <PID> - 将指定PID强行清除内存\n");
            printf("该操作用于崩溃指定进程\n可用于退出检测原因的进程\n强制崩溃系统进程可能造成BSoD\n如果进程存在其他驱动的保护可能无效\n");
            CloseHandle(hDevice);
            return;
        }
        DWORD pid = (DWORD)strtoul(argv[2], NULL, 10);
        DeviceIoControl(hDevice, IOCTL_IO_RAMPID, &pid, sizeof(pid), &output, sizeof(output), &ref_len, NULL);
        printf(output == 1 ? "PID %d 强行清除内存成功\n" : "PID %d 强行清除内存失败\n", pid);
    }
    else if (operation == "resume") {
        if (argc < 3) {
            std::cerr << "请提供一个PID参数." << std::endl;
            printf("resume <PID> - 将指定PID强行恢复运行\n");
            printf("该操作用于取消挂起指定进程\n如果进程存在其他驱动的保护可能无效\n");
            CloseHandle(hDevice);
            return;
        }
        DWORD pid = (DWORD)strtoul(argv[2], NULL, 10);
        DeviceIoControl(hDevice, IOCTL_IO_RESPID, &pid, sizeof(pid), &output, sizeof(output), &ref_len, NULL);
        printf(output == 1 ? "PID %d 恢复运行成功\n" : "PID %d 恢复运行失败\n", pid);
    }
    else if (operation == "hide") {
        if (argc < 3) {
            std::cerr << "请提供一个PID参数." << std::endl;
            printf("hide <PID> - 将指定PID隐藏\n");
            printf("该操作用于将指定PID修改为0\n注意该操作仅修改应用层获取到的PID\n且进程可能会造成错误\n");
            CloseHandle(hDevice);
            return;
        }
        DWORD pid = (DWORD)strtoul(argv[2], NULL, 10);
        DeviceIoControl(hDevice, IOCTL_IO_PID, &pid, sizeof(pid), &output, sizeof(output), &ref_len, NULL);
        printf(output == 1 ? "PID %d 设置为 0 成功\n" : "PID %d 设置为 0 失败\n", pid);
    }
    else if (operation == "pid") {
        if (argc < 3) {
            std::cerr << "请提供一个PID参数." << std::endl;
            printf("pid <PID> - 将指定PID的权限提升至SYSTEM32\n");
            printf("该操作用于将指定PID权限/Token修改为System进程的\n");
            CloseHandle(hDevice);
            return;
        }
        DWORD pid = (DWORD)strtoul(argv[2], NULL, 10);
        DeviceIoControl(hDevice, IOCTL_IO_GETSYS, &pid, sizeof(pid), &output, sizeof(output), &ref_len, NULL);
        printf(output == 1 ? "PID %d 权限提升成功\n" : "PID %d 权限提升失败\n", pid);
    }
    else if (operation == "copy") {
        if (argc < 4) {
            std::cerr << "请提供两个PID参数." << std::endl;
            printf("copy <PID1> <PID2> - 将PID1的权限设置成PID2的权限\n");
            printf("该操作用于将指定PID1权限/Token修改为PID2进程的\n");
            CloseHandle(hDevice);
            return;
        }
        newpiddata senddata = { (DWORD)strtoul(argv[2], NULL, 10), (DWORD)strtoul(argv[3], NULL, 10) };
        DeviceIoControl(hDevice, IOCTL_IO_COPY, &senddata, sizeof(senddata), &output, sizeof(output), &ref_len, NULL);
        printf(output == 1 ? "PID %d 权限修改成功\n" : "PID %d 权限修改失败\n", senddata.orgpid);
    }
    else if (operation == "setpid") {
        if (argc < 4) {
            std::cerr << "请提供两个PID参数." << std::endl;
            printf("setpid <PID1> <PID2> - 将PID1替换为PID2\n");
            printf("该操作用于将指定PID1修改为PID2\n注意该操作仅修改应用层获取到的PID\n且进程可能会造成错误\n");
            CloseHandle(hDevice);
            return;
        }
        newpiddata senddata = { (DWORD)strtoul(argv[2], NULL, 10), (DWORD)strtoul(argv[3], NULL, 10) };
        DeviceIoControl(hDevice, IOCTL_IO_SETPID, &senddata, sizeof(senddata), &output, sizeof(output), &ref_len, NULL);
        printf(output == 1 ? "PID %d PID修改成功\n" : "PID %d PID修改失败\n", senddata.orgpid);
    }
    else if (operation == "-i") {
        DWORD pid = GetCurrentProcessId();
        DeviceIoControl(hDevice, IOCTL_IO_GETFASYS, &pid, sizeof(pid), &output, sizeof(output), &ref_len, NULL);
        printf(output ? "PID %d 权限提升成功\n" : "PID %d 权限提升失败\n", output);
    }
    else {
        help();
    }

    CloseHandle(hDevice);
}

int main(int argc, char* argv[]) {
    handleDeviceIoControl(argc, argv);
    return 0;
}
