# **🚀 VeriHash.org - Vultr 公网部署与更新上线实战指南 (2026 最新版)**

本指南是针对 VeriHash.org 节点的**全栈公网实战手册**。它不仅包含了首次登录 Vultr 时的完整初始化安装、系统配置、自动化 HTTPS 证书申请（Caddy）等步骤，还全新融入了**后续版本迭代、二进制增量更新、SQLite 数据库无序自愈、Favicon 静态资源嵌入编译及移动端适配验证**等内容。

---

# **第一部分：首次部署与上线指南**

## **阶段一：建立“零密码”安全防线 (本地电脑操作)**

传统的账号密码登录极其容易被公网的扫描机器人暴力破解。我们将使用 SSH 密钥对（公钥+私钥）来打造绝对安全的免密登录。

### **1. 生成 SSH 密钥对**

打开你本地电脑的 **终端 (Terminal)** 或 **PowerShell**，输入以下命令：

```bash
ssh-keygen -t ed25519 -C "brian_verihash_admin"
```

一路按回车（Enter）即可，不需要设置额外的 passphrase（密码短语）。

### **2. 获取公钥**

生成完毕后，输入以下命令**查看你的公钥**：

* **Mac/Linux:** `cat ~/.ssh/id_ed25519.pub`
* **Windows:** `type %USERPROFILE%\.ssh\id_ed25519.pub`

把屏幕上打印出来的那一长串以 `ssh-ed25519` 开头的文本**复制到剪贴板**备用。

---

## **阶段二：在 Vultr 召唤服务器 (🚨 重点避坑区域)**

登录 Vultr 后台，点击 **Deploy New Server** (部署新服务器)。请严格按照以下“极客黄金配置”进行选择，避免产生高昂费用：

1. **Choose Type (极其关键)**：
   * ❌ **千万不要选** Dedicated CPU (极其昂贵)
   * ✅ **必须选择** Shared CPU -> Cloud Compute (或 Regular Performance)。
2. **Location**：选择离你物理位置或目标用户最近的节点（如 Silicon Valley 或 Tokyo）。
3. **OS Image**：坚定地选择 **Ubuntu 26.04 LTS x64**（长期支持版，最稳健的底座）。
4. **Server Size**：在 Shared CPU 下寻找最便宜的套餐（通常是 $5.00/mo，配置为 1 vCPU, 1024MB RAM, 25GB SSD）。
5. **Automatic Backups (强烈建议)**：保持开启（约 $1.00/mo）。因为我们的数据库是单文件 SQLite，开启每天整机快照是性价比最高的数据灾备方案。
6. **Add SSH Keys (防爆破防线)**：
   * 点击 Add New。
   * 把刚才复制的公钥粘贴进去，起个名字（比如 MacBook_Key 或 brian_verihash_admin），然后**务必勾选它**！
7. **Server Hostname**：填入 `verihash-node`。

点击右下角的 **Deploy Now**！等待大约 1-2 分钟，机器状态变成绿色的 Running 后，你会获得一个 **公网 IP 地址**（例如 `104.238.180.86`）。

---

## **阶段三：首次编译与“带数据”跨海发射 (本地电脑操作)**

回到你本地写代码的 `VerihashOrg` 目录。

### **1. 交叉编译为 Linux 二进制文件**

在最新版本中，我们在 Go 后端使用 `//go:embed` 机制直接嵌入了高分辨率的 `favicon.png` 图标。编译前，请确保 `VerihashOrg` 目录下已存在 `favicon.png`。

在本地终端的 `VerihashOrg` 目录下执行编译命令：

* **Windows (PowerShell):**
  ```powershell
  $env:GOOS="linux"; $env:GOARCH="amd64"; go build -o verihash-node
  ```
* **Mac/Linux:**
  ```bash
  GOOS=linux GOARCH=amd64 go build -o verihash-node
  ```

> 💡 **极客提示**：不需要像旧版那样手动指定 `main.go crypto.go` 等多个文件，直接运行 `go build -o verihash-node` 会自动将当前目录下所有的 Go 源码（包括 `main.go`、`crypto.go`、`query_db.go` 等）进行一体化打包，既方便又不易漏掉文件。

### **2. 使用 SCP 上传程序与数据库 (🚨 Windows 避坑)**

*在 Windows PowerShell 中，scp 有时无法自动找到私钥，导致提示输入密码或报错。我们需要使用 `-i` 参数强行指定私钥路径。*

把编译好的程序和包含 `verihash.db` 的 `data` 目录一同传上去（**记得把 IP 换成你自己的**）：

```bash
# 上传二进制核心程序
scp -i ~/.ssh/id_ed25519 verihash-node root@104.238.180.86:~

# 上传包含 SQLite 数据库的 data 文件夹 (注意必须带 -r 递归参数)
scp -r -i ~/.ssh/id_ed25519 data root@104.238.180.86:~
```

---

## **阶段四：服务器内部组装与守护进程 (远程服务器操作)**

带上私钥，正式通过 SSH 登入你的 Vultr 服务器：

```bash
ssh -i ~/.ssh/id_ed25519 root@104.238.180.86
```

当看到 `root@verihash-node:~#` 提示符时，说明已成功进入。**一口气复制并执行以下代码块**，完成目录组装和 Systemd 后台守护配置：

```bash
# 1. 创建规范的运行目录并移动文件
mkdir -p /opt/verihash
mv ~/verihash-node /opt/verihash/
mv ~/data /opt/verihash/

# 2. 赋予二进制程序执行权限
chmod +x /opt/verihash/verihash-node

# 3. 自动创建 Systemd 后台守护进程文件
cat << 'EOF' > /etc/systemd/system/verihash.service
[Unit]
Description=VeriHash Official Node
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/verihash
ExecStart=/opt/verihash/verihash-node
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# 4. 重新加载系统配置，并启动 VeriHash
systemctl daemon-reload
systemctl enable verihash
systemctl start verihash

# 5. 查看运行状态
systemctl status verihash
```

**🚨 极客生存指南：**

当你看到绿色的 `Active: active (running)` 时，代表启动成功！此时界面会卡住，**必须按下键盘上的英文字母 q 键**，才能退出日志并回到命令行输入状态。

---

## **阶段五：域名 DNS 解析与自动化 HTTPS (Caddy)**

### **1. 铺设 DNS 高速公路 (在你的域名服务商处操作)**

在安装 Caddy 之前，**必须先配置域名解析**，否则 Caddy 申请证书会失败。

登录域名后台（如 Cloudflare, GoDaddy），添加一条 **A 记录**：

* **Name / Host:** `@` (代表主域名，例如 `verihash.org`)
* **Value / IP:** `104.238.180.86` (你的 Vultr IP)

### **2. 暴力轰开防火墙 (预防性操作)**

回到 Vultr 服务器终端，确保 Web 端口畅通无阻：

```bash
ufw allow 80/tcp
ufw allow 443/tcp
ufw reload
```

### **3. 安装 Caddy 并配置自动 HTTPS**

一口气复制并执行以下脚本，自动安装 Caddy 并配置反向代理：

```bash
# 1. 安装 Caddy 官方依赖和源
sudo apt install -y debian-keyring debian-archive-keyring apt-transport-https curl
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | sudo tee /etc/apt/sources.list.d/caddy-stable.list
sudo apt update
sudo apt install -y caddy

# 2. 写入 Caddyfile 配置 (把 verihash.org 换成你的真实域名)
cat << 'EOF' > /etc/caddy/Caddyfile
verihash.org {
    reverse_proxy localhost:8080
}
EOF

# 3. 重启 Caddy，触发全自动 HTTPS 证书申请
systemctl restart caddy

# 4. 查看 Caddy 是否成功拿到证书
systemctl status caddy
```

同样，看到日志后，**按下 q 键退出**。

---

## **阶段六：首次公网验证**

### **1. 访问验证**
在浏览器中打开 `https://verihash.org`，确认站点能正常打开且已成功加上 HTTPS 小绿锁。

### **2. 机器视角测试 (llms.txt)**
* ❌ **错误测试法:** `curl -I https://verihash.org/llms.txt`（ Gin 框架默认只处理 GET 请求，HEAD 请求会返回 404，这也是一个容易踩的误区）。
* ✅ **正确测试法:** `curl https://verihash.org/llms.txt`（标准的 GET 请求，即可瞬间抓取到规范的 Markdown 纯文本）。

---

# **第二部分：日常迭代与后续更新部署指南**

当节点程序在本地更新（例如：加入了新路由、优化了 Favicon、修复了移动端排版样式等）后，我们不需要重复执行上述复杂的系统级配置，只需进行**平滑更新**即可。

## **阶段七：日常代码更新与增量部署流程**

我们采用**增量覆盖**的方式更新已上线的服务。无需重新上传数据库，这能百分之百保证公网历史数据的完整与安全。

### **1. 本地交叉编译最新二进制文件**
在本地 `VerihashOrg` 目录下执行交叉编译（此时包含已嵌入的最新 `favicon.png`）：

* **Windows (PowerShell):**
  ```powershell
  $env:GOOS="linux"; $env:GOARCH="amd64"; go build -o verihash-node
  ```
* **Mac/Linux:**
  ```bash
  GOOS=linux GOARCH=amd64 go build -o verihash-node
  ```

### **2. 上传新的二进制程序至服务器 (无需上传 data 目录)**
通过 SCP 仅将编译出的 `verihash-node` 上传到服务器的 `root` 家目录下。
*(注意：请不要在此步骤中上传 data 文件夹，避免用本地的测试库覆盖了生产环境宝贵的历史真实凭证库！)*

```bash
scp -i ~/.ssh/id_ed25519 verihash-node root@104.238.180.86:~
```

### **3. 登录服务器，平滑热替换并重启**
使用 SSH 登录你的 Vultr 服务器：

```bash
ssh -i ~/.ssh/id_ed25519 root@104.238.180.86
```

然后在服务器终端执行以下指令，安全替换运行文件：

```bash
# 1. 优雅停止当前正在运行的 verihash 节点服务
sudo systemctl stop verihash

# 2. 将旧的二进制文件备份（防翻车备用）
mv /opt/verihash/verihash-node /opt/verihash/verihash-node.bak

# 3. 将新上传的 verihash-node 移动到正式工作目录中
mv ~/verihash-node /opt/verihash/

# 4. 重新赋予新程序可执行权限
chmod +x /opt/verihash/verihash-node

# 5. 启动服务，让新节点开始执勤
sudo systemctl start verihash

# 6. 查看新版本服务状态
sudo systemctl status verihash
```

看到绿色的 `active (running)` 后，**按下 q 键**退出日志监视。
确认一切运行良好后，可以安全删除备份的旧文件以保持干净的目录结构：
```bash
rm /opt/verihash/verihash-node.bak
```

---

## **阶段八：数据库自愈与数据自动无缝迁移**

有些开发者在经历了大版本更新后（例如为了搜索引擎爬取而调整了 DID 路由格式，或者将历史凭证的旧本地域名 `http://localhost:8080` 改为公网主域名 `https://verihash.org`），会非常担心需要进行毁灭性的 "nuke" 数据库清理或者繁琐的批量重新广播签名。

**💡 VeriHash 优雅升级秘诀：**

1. **自动修复**：本次大版本升级中，我们在 Go 后端的 `database_wrapper.go` 内部内置了 SQLite 自愈清洗函数。
2. **零手动干预**：当你在**阶段七**中替换了二进制文件并重启了 `verihash` 服务，程序在引导初始化阶段便会自动扫描数据库内所有的历史凭证。
3. **数据升级**：它能自动且安全地将所有老凭证中遗留的 `http://localhost:8080/` 统一平滑替换为 `https://verihash.org/`，并全自动转为无冒号的全新 DID/llms.txt 路由结构。
4. **无需 nuke**：无须清空数据库，无须再次拉起桌面端重新上传！历史数据完美融合，对 AI 爬虫和搜索引擎的秒级友好度直接拉满。

---

## **阶段九：更新功能验收清单**

更新上线后，你可以对照以下三项快速验收本次更新的重要改进点：

### **1. 浏览器 Favicon 图标验证**
* 打开浏览器访问你的公网网址 `https://verihash.org`。
* 检查浏览器标签页（Tabs）中是否已经成功显示出了 VeriHash 桌面客户端的同款极客高分辨率图标（同时兼容 `/favicon.ico` 与 `/favicon.png` 请求）。

### **2. 移动端折行完美适配（解决 ID 不换行大坑）**
* 使用手机访问你的 DID 个人凭证页面（如 `https://verihash.org/u/z6Mku1zjBSMtEfatigDcALGhBvTQQHR1SgNhBF7Yryxq1kUo`）。
* 或者在 PC 端按下 `F12` 键打开开发者工具，切换到移动端小屏预览模式。
* 确认页面中的长 UUID 以及 Base58 编码的 DID 字符串能随屏幕边缘完美自动折行（这得益于我们全新写入的 `word-break: break-all;` 样式），彻底告别大面积溢出或突兀的横向滚动条。

### **3. 无冒号路由兼容性校验**
* 任意挑选一条历史凭证，在浏览器访问无冒号 DID 格式的地址：
  `https://verihash.org/<你的DID>` 
* 校验其是否能完美渲染出你的个人主页及所有绑定的 Credential，并确保在 `/llms.txt` 及 `/sitemap.xml` 中生成的链接也都采用无冒号优雅链接。
* 自此，彻底清除 AI 爬虫抓取多冒号地址时产生的转义与无法解析故障！

🎉 恭喜你，你的 VeriHash.org 公网节点已经成功完成 2026 版无感平滑升级！极客之光再次闪耀！
