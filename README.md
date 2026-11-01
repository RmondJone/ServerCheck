# ServerCheck - Linux 服务器后门检测与爆破历史排查工具

> 一个专为 Linux 服务器设计的轻量级、开箱即用的安全应急排查与后门检测工具。通过 Python 3 原生标准库实现，**零第三方依赖**，拉取代码后即可**一键启动**，快速审计服务器是否遭受暴力破解、是否存在隐藏特权后门、挖矿木马、反弹 Shell 或持久化驻留项。

---

## 目录

- [核心特性](#-核心特性)
- [检测维度与能力](#-检测维度与能力)
- [快速开始](#-快速开始)
  - [1. 拉取代码到目标服务器](#1-拉取代码到目标服务器)
  - [2. 一键运行检测](#2-一键运行检测)
  - [3. 进阶用法与参数选项](#3-进阶用法与参数选项)
- [检测报告解读](#-检测报告解读)
  - [风险等级定义](#风险等级定义)
  - [报告输出位置](#报告输出位置)
- [工程结构说明](#-工程结构说明)
- [常见入侵应急处置建议](#-常见入侵应急处置建议)
- [许可证](#-许可证)

---

## 🌟 核心特性

- **⚡ 零第三方依赖**：纯基于 Python 3.6+ 内置标准库与 Linux 常见底层接口开发，**无需 `pip install` 任何库**，即使在完全断网/内网隔离的生产服务器上也能直接运行。
- **🚀 一键运行**：内置 `run.sh` 启动脚本，自动识别环境 Python 解释器并校验权限，开箱即用。
- **🛡️ 安全只读排查**：纯只读安全审计，**不擅自修改任何系统文件或强杀进程**，避免误伤正常生产业务。
- **📊 跨发行版兼容**：全面兼容 CentOS 7/8/Stream、RHEL、Rocky Linux、AlmaLinux、Ubuntu、Debian 等主流 Linux 发行版。
- **📑 双格式报告输出**：除了终端彩色高亮概览外，自动生成排版精致的 **Markdown** 报告与结构化 **JSON** 报告，便于运维审计归档与自动化采集。

---

## 🔍 检测维度与能力

| 模块名称 | 检测项与能力说明 | 风险等级 |
| :--- | :--- | :--- |
| **暴力破解与登录审计** (`bruteforce`) | • 分析 `/var/log/auth.log`、`/var/log/secure` 及 `journalctl`<br>• 统计 SSH 暴力破解总次数、Top 10 恶意攻击源 IP、受针对探测账号<br>• 审计当前在线活跃会话 (`who` / `w`)<br>• 审计最近登录历史与异常公网 IP 登录 (`last` / `lastb`) | HIGH / MEDIUM |
| **系统账号与后门账户** (`account`) | • 检查 **UID 为 0 的非 root 用户**（极其隐蔽的超级管理员后门）<br>• 检查空口令用户与影子文件异常 (`/etc/shadow`)<br>• 统计具备交互式登录 Shell 的系统服务账户<br>• 审计 Sudo 免密完全提权规则 (`NOPASSWD: ALL`)<br>• 审计所有用户目录下的 SSH 授权公钥 (`~/.ssh/authorized_keys`) | CRITICAL / HIGH |
| **恶意进程与反弹Shell** (`process`) | • 精准匹配已知挖矿木马关键词 (`xmrig`, `c3pool`, `kinsing`, `kdevtmpfsi` 等)<br>• 排查常见反弹 Shell 进程特征 (`bash -i >& /dev/tcp`, `nc -e`, `pty.spawn`)<br>• 排查在 `/tmp`, `/var/tmp`, `/dev/shm` 等可写临时目录运行的可疑进程<br>• 排查已删除原文件仍在内存中运行的隐蔽进程 (`(deleted)` 进程)<br>• 排查 CPU 持续占用 > 80% 的疑似挖矿进程 | CRITICAL / HIGH |
| **网络连接与可疑外联** (`network`) | • 排查本地 LISTEN 监听端口，重点识别常见后门与木马端口<br>• 排查 ESTABLISHED 外部连接，检测是否外联已知矿池或 C2 服务器<br>• 检测网卡是否开启混杂模式 (`PROMISC`)，防范流量嗅探窃听 | CRITICAL / HIGH |
| **持久化驻留与自启后门** (`persistence`) | • **检测 `/etc/ld.so.preload` 动态链接库劫持**（高级 Rootkit 核心手段）<br>• 扫描系统与用户定时任务 (`/etc/crontab`, `/etc/cron.*`, `/var/spool/cron/*`) 中包含 `curl|sh`, `base64` 等恶意特征<br>• 检查开机自启脚本 (`/etc/rc.local`, `/etc/init.d/`)<br>• 检查可疑的 Systemd 恶意自启服务单元<br>• 排查 Shell 启动配置文件 (`/etc/profile`, `~/.bashrc`) 环境变量与 alias 注入 | CRITICAL / HIGH |
| **敏感文件与提权后门** (`file`) | • 扫描 `/tmp`, `/var/tmp`, `/dev/shm` 中的可执行脚本与 ELF 二进制文件<br>• 扫描敏感路径下带 SUID/SGID 特殊权限的提权文件<br>• 扫描系统核心命令目录 (`/bin`, `/sbin`, `/usr/bin`) 近期被篡改修改的文件<br>• 检测采用 `...`、带空格伪装命名的障眼法隐藏目录 | HIGH / MEDIUM |

---

## 🚀 快速开始

### 1. 拉取代码到目标服务器

通过 Git 拉取或直接打包上传至待检测服务器：

```bash
# 方式一：Git 克隆
git clone <本仓库地址> serverCheck
cd serverCheck

# 方式二：离线环境直接将工程目录上传至服务器解压后进入
cd serverCheck
```

### 2. 一键运行检测

建议使用 **`sudo` 或 `root` 权限** 运行，以确保工具具有读取安全认证日志（`/var/log/secure` 或 `/var/log/auth.log`）、`/etc/shadow` 密码文件以及底层网络连接状态的完整权限：

```bash
# 赋予执行权限（首次）
chmod +x run.sh main.py

# 一键启动完整检测
sudo ./run.sh
```

或者直接使用 Python 启动：

```bash
sudo python3 main.py
```

> **注意**：如果不使用 sudo 以普通用户身份运行，工具仍会尽力执行所有非特权项的检测，并在终端提示部分涉及受限文件的项目被跳过。

---

### 3. 进阶用法与参数选项

```bash
# 查看帮助文档
python3 main.py --help

# 选项 1：只执行特定的检测模块
sudo python3 main.py -m bruteforce    # 仅检测暴力破解与登录历史
sudo python3 main.py -m account       # 仅检测账号安全与提权后门
sudo python3 main.py -m process       # 仅检测恶意进程与反弹Shell
sudo python3 main.py -m network       # 仅检测网络连接与高危端口
sudo python3 main.py -m persistence   # 仅检测定时任务与持久化驻留
sudo python3 main.py -m file          # 仅检测敏感文件与提权文件

# 选项 2：自定义检测报告的输出目录
sudo python3 main.py -o /tmp/security_reports
```

---

## 📊 检测报告解读

### 风险等级定义

每项检测结果均被打上明确的危害级别标识，协助安全管理员合理安排处置优先级：

- `[CRITICAL]` **严重危害**：确认存在后门特征（如非 root 的 UID 0 账号、动态库劫持、反弹 Shell 进程、已知挖矿木马运行），服务器极大概率已被入侵控制！**必须立即处置！**
- `[ HIGH ]` **高危风险**：遭受持续剧烈的 SSH 爆破攻击、存在高危持久化定时任务、临时目录发现未知可执行 ELF 文件、不合规的免密提权配置等。
- `[ MEDIUM ]` **中危隐患**：存在非常用公网 IP 成功登录、持续高 CPU 计算进程、系统命令文件近期有修改等，需结合实际业务排查。
- `[  LOW  ]` **低危提示**：轻微的偶发登录失败、自启脚本存在自定义指令等。
- `[  INFO  ]` **审计信息**：系统在线活跃会话、系统可登录用户基线、当前监听端口等日常信息。

### 报告输出位置

检测完成后，工具会在 `reports/` 目录下自动生成双格式报告：

```text
reports/
├── security_report_<hostname>_<YYYYMMDD_HHMMSS>.md    # Markdown 完整报告
└── security_report_<hostname>_<YYYYMMDD_HHMMSS>.json  # JSON 结构化数据
```

您可以直接通过 Cat / Less 在终端阅读 Markdown 报告，或下载至本地查看。

---

## 📁 工程结构说明

```text
serverCheck/
├── README.md               # 项目使用说明文档
├── run.sh                  # 一键启动脚本（自动环境校验与执行）
├── requirements.txt        # 依赖声明（说明纯原生标准库，免装依赖）
├── config.py               # 全局检测配置（检测阈值、黑名单关键字、敏感路径等）
├── main.py                 # 主执行程序（命令行参数解析、检测调度与汇总）
├── core/
│   ├── __init__.py
│   ├── base.py             # 检测基类与 Finding 数据模型
│   ├── reporter.py         # 控制台彩色输出、Markdown/JSON 报告生成引擎
│   └── utils.py            # 系统命令执行器、文件安全读取、平台判断与网络辅助
├── modules/
│   ├── __init__.py
│   ├── bruteforce_check.py # 暴力破解与异常登录历史审计
│   ├── account_check.py    # 账号安全、提权配置与 SSH 授权公钥排查
│   ├── process_check.py    # 挖矿木马、反弹 Shell 与异常高占用进程排查
│   ├── network_check.py    # 端口监听、外联连接与网络嗅探排查
│   ├── persistence_check.py# Crontab 定时任务、LD_PRELOAD 劫持与自启服务排查
│   └── file_check.py       # 临时目录文件、SUID 特殊提权与文件篡改痕迹排查
└── reports/                # 审计报告输出目录
    └── .gitkeep
```

---

## 🚨 常见入侵应急处置建议

当报告中出现 `CRITICAL` 或 `HIGH` 级别的告警时，可参考以下应急处置顺序：

1. **阻断外部网络连接**
   - 立即通过本地控制台或带外管理（如阿里云 VNC / 腾讯云 VNC / IPMI）接入。
   - 使用 `iptables` 阻断非必要的入站与出站连接，防止黑客继续下发指令或反弹 Shell：
     ```bash
     # 示例：仅允许管理员特定 IP 访问，其他全部 DROP
     sudo iptables -P INPUT DROP
     sudo iptables -P OUTPUT DROP
     ```
2. **清除反弹 Shell 与挖矿进程**
   - 记录可疑进程 PID、可执行文件软链接：`ls -l /proc/<PID>/exe`。
   - 强制杀灭进程：`sudo kill -9 <PID>`。
   - 删除临时目录或源文件：`sudo rm -f <恶意文件路径>`。
3. **拔除持久化后门与防复活项**
   - **清除 `/etc/ld.so.preload`**：如果存在劫持，执行 `> /etc/ld.so.preload`。
   - **清理定时任务**：查看并编辑 `crontab -e`、`/etc/cron*`，删除恶意远程下载指令。
   - **清理后门公钥**：排查并清空 `/root/.ssh/authorized_keys` 中非本单位管理员的陌生公钥。
   - **禁用后门用户**：`sudo passwd -l <username>` 锁定账户或 `sudo userdel -f <username>`。
4. **系统加固**
   - 修改 SSH 默认 22 端口为高位端口（如 22222）。
   - 禁止 root 远程密码直接登录：修改 `/etc/ssh/sshd_config` 中的 `PermitRootLogin prohibit-password`。
   - 禁用密码认证，强制使用安全强度高的 Ed25519 或 RSA 4096 密钥登录：`PasswordAuthentication no`。
   - 部署 `Fail2ban` 针对持续爆破 IP 自动拉黑。

---

## 📄 许可证

本项目遵循 MIT 开源许可证。
