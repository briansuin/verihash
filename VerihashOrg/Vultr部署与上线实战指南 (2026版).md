# **🚀 VeriHash.org \- Vultr 公网部署与避坑实战指南 (2026 最终版)**

本指南将带你把本地编译的 VeriHash 节点（包括珍贵的 SQLite 数据库），安全、稳定地部署到 Vultr 云服务器，并全自动配置 https://verihash.org 的域名与小绿锁。

*注：本指南已包含针对 Windows PowerShell 的特定避坑方案及 2026 年最新 Vultr 界面的适配。*

## **阶段一：建立“零密码”安全防线 (本地电脑操作)**

传统的账号密码登录极其容易被公网的扫描机器人暴力破解。我们将使用 SSH 密钥对（公钥+私钥）来打造绝对安全的免密登录。

### **1\. 生成 SSH 密钥对**

打开你本地电脑的 **终端 (Terminal)** 或 **PowerShell**，输入以下命令：

ssh-keygen \-t ed25519 \-C "brian\_verihash\_admin"

一路按回车（Enter）即可，不需要设置额外的 passphrase（密码短语）。

### **2\. 获取公钥**

生成完毕后，输入以下命令**查看你的公钥**：

* **Mac/Linux:** cat \~/.ssh/id\_ed25519.pub  
* **Windows:** type %USERPROFILE%\\.ssh\\id\_ed25519.pub

把屏幕上打印出来的那一长串以 ssh-ed25519 开头的文本**复制到剪贴板**备用。

## **阶段二：在 Vultr 召唤服务器 (🚨 重点避坑区域)**

登录 Vultr 后台，点击 **Deploy New Server** (部署新服务器)。请严格按照以下“极客黄金配置”进行选择，避免产生高昂费用：

1. **Choose Type (极其关键)**：  
   * ❌ **千万不要选** Dedicated CPU (极其昂贵)  
   * ✅ **必须选择** Shared CPU \-\> Cloud Compute (或 Regular Performance)。  
2. **Location**：选择离你物理位置或目标用户最近的节点（如 Silicon Valley 或 Tokyo）。  
3. **OS Image**：坚定地选择 **Ubuntu 26.04 LTS x64**（长期支持版，最稳健的底座）。  
4. **Server Size**：在 Shared CPU 下寻找最便宜的套餐（通常是 $5.00/mo，配置为 1 vCPU, 1024MB RAM, 25GB SSD）。  
5. **Automatic Backups (强烈建议)**：保持开启（约 $1.00/mo）。因为我们的数据库是单文件 SQLite，开启每天整机快照是性价比最高的数据灾备方案。  
6. **Add SSH Keys (防爆破防线)**：  
   * 点击 Add New。  
   * 把刚才复制的公钥粘贴进去，起个名字（比如 MacBook\_Key 或 brian\_verihash\_admin），然后**务必勾选它**！  
7. **Server Hostname**：填入 verihash-node。

点击右下角的 **Deploy Now**！等待大约 1-2 分钟，机器状态变成绿色的 Running 后，你会获得一个 **公网 IP 地址**（假设为 104.238.180.86）。

## **阶段三：编译与“带数据”跨海发射 (本地电脑操作)**

回到你本地写代码的 VerihashOrg 目录。

### **1\. 交叉编译为 Linux 二进制文件**

* **Windows (PowerShell):**  
  $env:GOOS="linux"; $env:GOARCH="amd64"; go build \-o verihash-node main.go crypto.go

* **Mac/Linux:**  
  GOOS=linux GOARCH=amd64 go build \-o verihash-node main.go crypto.go

### **2\. 使用 SCP 上传程序与数据库 (🚨 Windows 避坑)**

*在 Windows PowerShell 中，scp 有时无法自动找到私钥，导致提示输入密码或报错。我们需要使用 \-i 参数强行指定私钥路径。*

把编译好的程序和包含 verihash.db 的 data 目录一起传上去（**记得把 IP 换成你自己的**）：

\# 上传二进制核心程序  
scp \-i \~/.ssh/id\_ed25519 verihash-node root@104.238.180.86:\~

\# 上传包含 SQLite 数据库的 data 文件夹 (注意必须带 \-r 递归参数)  
scp \-r \-i \~/.ssh/id\_ed25519 data root@104.238.180.86:\~

## **阶段四：服务器内部组装与守护进程 (远程服务器操作)**

带上私钥，正式通过 SSH 登入你的 Vultr 服务器：

ssh \-i \~/.ssh/id\_ed25519 root@104.238.180.86

当看到 root@verihash-node:\~\# 提示符时，说明已成功潜入。**一口气复制并执行以下代码块**，完成目录组装和 Systemd 后台守护配置：

\# 1\. 创建规范的运行目录并移动文件  
mkdir \-p /opt/verihash  
mv \~/verihash-node /opt/verihash/  
mv \~/data /opt/verihash/

\# 2\. 赋予二进制程序执行权限  
chmod \+x /opt/verihash/verihash-node

\# 3\. 自动创建 Systemd 后台守护进程文件  
cat \<\< 'EOF' \> /etc/systemd/system/verihash.service  
\[Unit\]  
Description=VeriHash Official Node  
After=network.target

\[Service\]  
Type=simple  
User=root  
WorkingDirectory=/opt/verihash  
ExecStart=/opt/verihash/verihash-node  
Restart=on-failure  
RestartSec=5

\[Install\]  
WantedBy=multi-user.target  
EOF

\# 4\. 重新加载系统配置，并启动 VeriHash  
systemctl daemon-reload  
systemctl enable verihash  
systemctl start verihash

\# 5\. 查看运行状态  
systemctl status verihash

**🚨 极客生存指南：**

当你看到绿色的 Active: active (running) 时，代表启动成功！此时界面会卡住，**必须按下键盘上的英文字母 q 键**，才能退出日志并回到命令行输入状态。

## **阶段五：域名 DNS 解析与自动化 HTTPS (Caddy)**

### **1\. 铺设 DNS 高速公路 (在你的域名服务商处操作)**

在安装 Caddy 之前，**必须先配置域名解析**，否则 Caddy 申请证书会失败。

登录域名后台（如 Cloudflare, GoDaddy），添加一条 **A 记录**：

* **Name / Host:** @ (代表主域名，例如 verihash.org)  
* **Value / IP:** 104.238.180.86 (你的 Vultr IP)

### **2\. 暴力轰开防火墙 (预防性操作)**

回到 Vultr 服务器终端，确保 Web 端口畅通无阻：

ufw allow 80/tcp  
ufw allow 443/tcp  
ufw reload

### **3\. 安装 Caddy 并配置自动 HTTPS**

一口气复制并执行以下脚本，自动安装 Caddy 并配置反向代理：

\# 1\. 安装 Caddy 官方依赖和源  
sudo apt install \-y debian-keyring debian-archive-keyring apt-transport-https curl  
curl \-1sLf '\[https://dl.cloudsmith.io/public/caddy/stable/gpg.key\](https://dl.cloudsmith.io/public/caddy/stable/gpg.key)' | sudo gpg \--dearmor \-o /usr/share/keyrings/caddy-stable-archive-keyring.gpg  
curl \-1sLf '\[https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt\](https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt)' | sudo tee /etc/apt/sources.list.d/caddy-stable.list  
sudo apt update  
sudo apt install \-y caddy

\# 2\. 写入 Caddyfile 配置 (把 verihash.org 换成你的真实域名)  
cat \<\< 'EOF' \> /etc/caddy/Caddyfile  
verihash.org {  
    reverse\_proxy localhost:8080  
}  
EOF

\# 3\. 重启 Caddy，触发全自动 HTTPS 证书申请  
systemctl restart caddy

\# 4\. 查看 Caddy 是否成功拿到证书  
systemctl status caddy

同样，看到日志后，**按下 q 键退出**。

## **阶段六：公网验证与 AI 友好度测试 (🚨 HTTP 避坑)**

### **1\. 人类视角测试**

打开浏览器，访问 https://verihash.org。你应该能看到黑底绿字的极客主页，以及地址栏旁边的**安全小绿锁**！

### **2\. 机器视角测试 (llms.txt)**

想在终端测试你的 AI 机器可读文档是否生效？

* ❌ **错误测试法:** curl \-I https://verihash.org/llms.txt  
  *(注意：大写 \-I 代表 HEAD 请求。Gin 框架默认只处理 GET 请求，遇到 HEAD 会无情返回 404 Not Found。这曾是一个经典的排障大坑！)*  
* ✅ **正确测试法:** curl https://verihash.org/llms.txt  
  *(使用标准 GET 请求，你将看到结构优雅的 Markdown 文本倾泻在屏幕上！)*

### **3\. 客户端接轨**

最后，别忘了修改你的 Wails 桌面端代码，将 API 发送地址从 http://localhost:8080 替换为 https://verihash.org。重新编译桌面端，发布你的第一条真实公网凭证！🎉