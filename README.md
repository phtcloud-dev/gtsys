# 操作手册

**Made by phtcloud**

请提供操作类型和相应的PID参数。

## 操作类型

- `pid` - 将指定PID的权限提升至SYSTEM32
- `copy <PID1> <PID2>` - 将PID1的权限设置成PID2的权限
- `hide <PID>` - 将指定PID隐藏
- `setpid <PID1> <PID2>` - 将PID1替换为PID2
- `ppl <PID> <LEVEL 1-9>` - 强制设置指定PID的PPL
- `suspend <PID>` - 将指定PID强行挂起
- `resume <PID>` - 将指定PID强行恢复运行
- `kill <PID>` - 将指定PID强行关闭
- `ramclear <PID>` - 将指定PID强行清除内存
- `info <PID>` - 获取指定PID的信息
- `chain <PID>` - 获取指定PID的进程链
- `listall` - 枚举所有进程
- `safe <PID>` - 保护指定PID
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

