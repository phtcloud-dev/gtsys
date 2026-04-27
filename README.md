# 操作手册

**Made by phtcloud**\
一个简易的内核级命令行进程管理器 适用于 蓝队应急响应溯源 红队后渗透阶段纯CLI操作\
支持内核版本 10.0.10240.* - 10.0.26200.*(或者更新)\
如遇蓝屏请开issues\
如果内核更新导致偏移量改动你可能需要自行使用WinDbg调试内核获取偏移量参考 FileName.c 中 VOID GetWindowsVersion() 的格式添加新版本的偏移量信息


请提供操作类型和相应的PID参数。

## 操作类型

- `pid` - 将指定PID的权限提升至SYSTEM
- `copy <PID1> <PID2>` - 将PID1的权限设置成PID2的权限
- `hide <PID>` - 将指定PID隐藏
- `setpid <PID1> <PID2>` - 将PID1替换为PID2
- `ppl <PID> <LEVEL 1-9>` - 强制设置指定PID的PPL
- `suspend <PID>` - 将指定PID强行挂起
- `resume <PID>` - 将指定PID强行恢复运行
- `kill <PID>` - 将指定PID强行关闭
- `killpath <PATH>` - 强制关闭所有路径含PATH的进程
- `ramclear <PID>` - 将指定PID强行清除内存
- `info <PID>` - 获取指定PID的信息
- `chain <PID>` - 获取指定PID的进程链
- `listall` - 枚举所有进程
- `forcelistall` - 暴力枚举所有进程
- `safe <PID>` - 保护指定PID
- `onlywindows` - 强制关闭除Windows路径下的所有进程
- `unsafe <PID>` - 取消保护指定PID
- `listsafe` - 列出受保护的PID列表
- `gethandle <PID>` - 绕过指定进程的保护
- `drophandle <PID>` - 取消绕过指定进程的保护
- `listhandle` - 列出绕过指定进程的保护列表
- `setobcallback <1/0>` - 设置保护开关
- `setparent <PID> <PARENTPID>` - 设置指定PID的父进程PID
- `shutdown` - 快速关机(NtShutdownSystem应用层)
- `reboot` - 快速重启(NtShutdownSystem应用层)
- `kernelshutdown` - 内核关机(调用内核向主板发送掉电关机信号)
- `kernelreboot` - 内核重启(调用内核向主板发送掉电重启信号)
- `forcereboot` - 掉电重启(直接对主板I/O掉电重启，注意该操作只支持较新主板，否则会陷入主板卡机)
- `-i` - 将当前进程(父进程)提升至SYSTEM32

![image](https://github.com/user-attachments/assets/549f8d41-cd7f-4566-a7f6-e60b89a8480b)
