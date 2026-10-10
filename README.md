# KDProcDumper

KDProcDumper 现在由两个运行时组件组成：一个 `ProcDumper.sys` 内核后端和一个 `UMProcDumper.exe` CLI/TUI 前端。PE 修复、进程/模块枚举、驱动服务管理和 Dump 输出都已内置到前端，不再需要单独运行 `PeFileFixer`。

## 功能

- `dump` 自动加载驱动、打开设备、选择进程/模块、分块读取、修复 PE 并发布输出。
- 驱动通过 SCM 自动创建、启动、停止和删除；如果服务原本已存在，CLI 会校验它是否指向同一个 SYS。
- 交互模式支持键盘选择、过滤、分页和进度显示：直接运行 `UMProcDumper.exe` 或 `UMProcDumper.exe tui`。
- 内核会话固定进程句柄和镜像基址，协议带版本校验；读取采用最多 1 MiB 的分块，遇到不可读页会零填并统计。
- 输出先写入临时文件，成功后原子发布；`--strict` 遇到不可读页时丢弃结果。
- `fix` 仍可用于修复已有的内存布局 PE，但不再是 Dump 流程的外部步骤。

## 快速使用

```text
UMProcDumper.exe                         # TUI
UMProcDumper.exe processes
UMProcDumper.exe modules --pid 1234
UMProcDumper.exe dump --pid 1234 --module game.exe
UMProcDumper.exe dump --name game.exe --all --output .\Output --force
UMProcDumper.exe driver status
UMProcDumper.exe driver load --driver .\ProcDumper.sys
UMProcDumper.exe driver unload --remove
UMProcDumper.exe fix --input raw.bin --output fixed.exe --force
```

默认查找与 EXE 同目录的 `ProcDumper.sys`。`dump` 默认只导出主模块，默认输出到 `.\\Output\\<pid>_<module>.dump.exe`。`--raw` 保留原始内存布局，`--json` 输出机器可读结果，`--chunk-kib` 可设置 4 到 1024 KiB 的分块大小。

驱动加载和 Dump 需要管理员权限；Windows 仍会执行驱动签名策略。退出码为 `0` 完成、`1` 失败、`2` 产生了零填充的部分 Dump、`130` 用户取消。

## 签名

Release 构建完成后，使用仓库外部的签名脚本为驱动和前端签名。脚本会自动验证嵌入签名：

```bat
call O:\driver\ssde\SignDriver.bat O:\repos\kdprocdumper\x64\Release\ProcDumper.sys
call O:\driver\ssde\SignDriver.bat O:\repos\kdprocdumper\x64\Release\UMProcDumper.exe
```

驱动加载前请确认签名证书和当前系统的代码完整性策略都信任该签名链。

## 构建

在安装 Visual Studio、WDK 和 Windows SDK 后打开 `ProcDumper.sln`，选择 `Release|x64`。解决方案现在只包含 `ProcDumper` 和 `UMProcDumper` 两个项目；`PeFileFixer` 保留为历史实验代码，但不参与默认构建。

命令行构建示例：

```bat
call "%ProgramFiles%\Microsoft Visual Studio\18\Professional\VC\Auxiliary\Build\vcvars64.bat"
MSBuild ProcDumper.sln /m /p:Configuration=Release /p:Platform=x64
```

生成物位于：

```text
x64\Release\ProcDumper.sys
x64\Release\UMProcDumper.exe
```
