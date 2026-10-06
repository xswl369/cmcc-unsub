# 中国移动退订业务

在低配 ARM 设备（460MB 内存）上运行的中国移动网上营业厅退订工具。**纯 HTTP 实现，不依赖任何浏览器。**

## 为什么不用浏览器

最初用 Playwright/CDP 驱动 Chromium 完成登录。实践中发现致命问题：

- Chromium 常驻 4 个进程，占用 **360MB**，而设备总内存只有 460MB
- 登录页的 FingerprintJS 设备指纹在软渲 ARM 上要算 60 秒以上，期间渲染进程被压死
- 提交登录瞬间必然 OOM，渲染进程崩溃 → 登录态丢失
- 表现为 `HTTP 524`（超过 Cloudflare 100s 上限）/ `HTTP 502`（watchdog 误判重启）

**结论：在这类设备上，浏览器方案不可行。** 本项目把整条链路逆向后用纯 HTTP 复刻，内存占用从 360MB 降到 28MB。

## 架构

```
访问者 ── HTTPS ──> Cloudflare ── Tunnel ──> 本机 nginx:5701
                                                  │
                                                  ▼
                                        gunicorn (1 worker / 48 threads)
                                                  │
                              ┌───────────────────┼───────────────────┐
                              ▼                   ▼                   ▼
                        session A            session B           session C
                    (PureLogin+出口A)    (PureLogin+出口B)   (PureLogin+出口C)
                              │                   │                   │
                              └───────────────────┴───────────────────┘
                                                  │
                                          中国移动 HTTP API
```

**多会话隔离**：每个访客一个 `sid`（HttpOnly cookie），各自独立的 cookie 容器、图形码、登录态。100 人同时使用互不干扰（实测 100 并发 p95 = 273ms）。

**出口 IP 池**：解决"同一 IP 批量登录"风控。

- B 方案：IPv6 源地址轮换。若设备有公网 IPv6 `/64`，可在段内生成多个源地址，绑定后出网 IP 各不相同（实测 4 个会话 → 4 个不同公网 IP）
- C 方案：代理池。在 `data/ip_pool.json` 里填 SOCKS5/HTTP 代理，优先级高于 IPv6

## 账号池与批量登录（联通方案移植）

移动侧与联通侧的共性：**短信验证码与手机号绑定，风控关注的是“同一出口 IP 的
批量登录频次”，而不是账号数量**。因此把联通方案里真正管用的三件事搬了过来。

**1. 一个手机号一份独立会话**

每个号码拥有自己的图形码、cookie 容器、风控 token 与短信码，互不覆盖。同一
浏览器里可以同时推进 20 个号码的登录（`POST /api/batch/start`）。

**2. 登录成功即入池，切号不再收码**

登录成功后 cookie 以手机号为键写入 `data/accounts_pool.json`。之后点「账号池 →
使用」直接恢复登录态（`POST /api/accounts/use`），不发短信、不填验证码。

> **账号池是按访客隔离的。** 每个浏览器首次访问会拿到一个 HttpOnly 的
> `cmcc_uid`（180 天），账号池里的每条记录都带 `owner`。列表 / 使用 / 删除
> 三个接口都会校验 `owner`：别人的号码在你这里等同于不存在（列表为空，
> 使用和删除返回失败）。同一台设备的同一浏览器才能看到自己的账号；
> 换浏览器 / 无痕窗口 / 清 cookie 后看不到原账号（需要重新登录一次）。

**3. 按号码节流 + 多出口**

- 短信冷却按手机号跨会话共享（同一号码 55 秒内只发一次）
- 每个访客会话分配独立出口（IPv6 源地址轮换 / SOCKS5·HTTP 代理）
- 每 IP 每分钟上限 120 次发码，真实访客 IP 取 `CF-Connecting-IP`

### 批量登录接口

| 方法与路径 | 作用 |
|---|---|
| `POST /api/batch/start` | 粘贴多个手机号，逐个建独立会话并取图形码（最多 20） |
| `POST /api/batch/refresh` | 单号码重拿图形码，不影响其它号码 |
| `POST /api/batch/send` | 单号码发短信（图形码 + 风控 token 在它自己的会话里） |
| `POST /api/batch/submit` | 提交短信码，成功即写入账号池 |
| `GET  /api/accounts` | 账号池列表（只返回本人的） |
| `POST /api/accounts/use` | 直接切到池中账号（免收码） |
| `POST /api/accounts/delete` | 从池中移除账号 |

### 出口池健康检查

```
GET /api/ip/status
{"ok":true,"pool":{"total":4,"ipv6":4,"proxy":0,"sample":["v6-p0","v6-p1"]},
 "mine":"<Egress v6-p2 2409:8a6c:272b:b991:...>"}
```

`ip_pool.py` 会过滤文档段（`2001:db8::/32`）、ULA、链路本地地址；网卡上已有
的公网 IPv6 直接复用，需要新增时先直接调 `ip`，被 SELinux 拒绝再用 `su` 重试，
完全没有 `ip` 命令时降级为“无出口池”而不是报错。

## 直登通道：发码在用户侧，本站只做登录（推荐）

移动的风控盯的是「**同一个 IP 替很多号码发短信**」。既然发短信这步最容易被拦，
就把它交还给用户自己的设备与网络：

```
用户手机（他的 IP）                      本站服务器（出口 IP 池）
  中国移动 App / 10086.cn
  输入本机号码 → 获取验证码  ──短信──▶  手机收到 6 位码
                                        │
                          填「手机号 + 验证码」
                                        ▼
                                  POST /api/login/direct
                                  建会话 → login.htm → 落 SSO cookie
```

**关键实测结论（2026-10-06 逐项验证）**

| 结论 | 证据 |
|---|---|
| `login.htm` **不校验图形码** | 全新会话、不带任何图形码 token、直接提交 → 返回 `6001 短信随机码不正确`（说明已越过图形码校验，卡在短信码上） |
| 图形码只挡「发短信」那一步 | `sendRandomCodeAction.action` 需要 `et(图形码) + Xa-before token` |
| 图形码答案绑在 cookie 上、可跨会话 | 把 `CaptchaCode` cookie 塞进另一个会话 + 提交对应答案 → `resultCode 0` |
| 短信码按号码校验 | 换会话提交，真号的假码一律 `6001`，与发码会话无关 |

因为登录这步既不要图形码、也不要本站发码，**整条链路再没有任何"本站代发短信"的动作**，
风控针对的行为从根上消失了。

### 出口池（为什么还要它）

登录这步仍从本站出去，所以按访客 + 号码分散出口：

- 手机上加了一批公网 IPv6 源地址（`/data/adb/service.d/cmcc_v6.sh` 开机补齐，目标 48 个）
- 实测 **52 个可用出口**，随机抽查 6 个全部能 TLS 到 `login.10086.cn`
- 单号登录用会话出口；批量登录按 `uid|手机号` 做一致性哈希，实测 10 个号码分到 9 个不同出口
- `GET /api/ip/status` 可随时查看

### 接口

| 方法与路径 | 作用 |
|---|---|
| `POST /api/login/direct` | `{phone, code}`：用户自带验证码直接登录，不发短信、不要图形码 |
| `POST /api/batch/direct` | `{lines}`：每行 `手机号 验证码`，最多 20 条，并发登录并按号码分散出口 |
| `POST /api/login/start` `/send` `/submit` | 备用通道：本站代发短信（需要图形码，有 IP 风控风险） |
| `GET  /api/ip/status` | 出口池状态 |

## 逆向要点

登录链路的加密与流程（`pure_login.py`）：

| 环节 | 实现 |
|---|---|
| 密码/手机号加密 | RSA PKCS#1 v1.5，公钥内嵌在 `login_qr_fun.js` 的 `et()` 函数里 |
| 图形码获取 | `GET /captchazh.htm?type=12` |
| 图形码校验 | `GET /verifyCaptcha.htm?inputCode=xxx`（必须是 **GET**，页面用 `$.getJSON`） |
| 风控 token | `POST /loadToken.action` |
| 发送短信 | `POST /sendRandomCodeAction.action`，带 `Xa-before: token` 头 |
| 提交登录 | `POST /login.htm`，成功后跟随 `assertAcceptURL` 落 SSO cookie |

业务接口（`core.py`）：AES-128-CBC（key = iv = 从页面源码取的常量字面量），双层 base64；`msgId` 需要 `sessionStorage.aqjg_cmcc_month`，在纯 HTTP 下改为调 `GET /v1/auth/loginfo` 取 `data.msgId`。

## 部署

### 1. 依赖

```bash
apt-get install -y python3 python3-pip nginx
pip3 install flask gunicorn pycryptodome
```

### 2. 配置

编辑 `config.ini`：

```ini
[cmcc]
phone = 13800138000          ; 默认手机号
port = 8686                  ; 内部端口
access_token =               ; 留空=不启用访问口令
```

### 3. 启动

```bash
mkdir -p /opt/cmcc-unsub
cp -r . /opt/cmcc-unsub/
cd /opt/cmcc-unsub

# 直接跑（调试）
python3 -m gunicorn -c gunicorn.conf.py wsgi:app
```

### 4. systemd（生产）

```bash
cp cmcc.service /etc/systemd/system/cmcc-unsub.service
systemctl enable --now cmcc-unsub
```

### 5. nginx

参考 `nginx.conf`，把 `server_name` 换成自己的域名，反代到 `127.0.0.1:8686`。

### 6. Cloudflare Tunnel（可选）

```bash
cp cloudflared-config.yml /etc/cloudflared/config.yml
# 编辑 tunnel ID 与 credentials-file
systemctl enable --now cloudflared
```

## 出口 IP 池配置

`data/ip_pool.json`（不存在则用默认值）：

```json
{
  "ipv6": {
    "enabled": true,
    "iface": "wlan0",
    "prefix": "2001:db8:1234:5678::/64",
    "count": 24,
    "ttl": 1800
  },
  "proxies": [
    "socks5://user:pass@1.2.3.4:1080",
    "http://user:pass@5.6.7.8:8080"
  ],
  "strategy": "sid"
}
```

- `strategy: sid` — 同一访客始终走同一出口（一致性哈希，会话更稳）
- `strategy: round` — 轮询
- 有 `proxies` 时**代理优先**，IPv6 作为兜底

查看池状态：`GET /api/ip/status`

## API

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/` | 网页界面 |
| GET | `/api/state` | 当前会话登录态 + 业务数 |
| GET | `/api/busi` | 业务列表 |
| GET | `/api/ip/status` | 出口池状态 |
| POST | `/api/sms` | 发退订短信码 |
| POST | `/api/unsub` | 提交退订 |
| POST | `/api/login/start` | 取图形码（换账号） |
| POST | `/api/login/send` | 图形码 + 发短信 |
| POST | `/api/login/submit` | 短信码登录 |
| POST | `/api/login/logout` | 退出 |

## 已知限制

**移动侧的限制，代码无法绕过：**

1. **短信冷却按手机号计算** — 每个号码约 1 分钟才能发一次，密集操作会返回业务码 `1`（"请一分钟以后再试"），累计过量会较长时间锁定
2. **同 IP 批量登录风控** — 同出口 IP 高频登录返回 `3007`。本项目用出口 IP 池 + 节流缓解，但根本解决需要多个真实出口
3. **图形码有效期短** — 实测 2-3 分钟失效，需及时使用

**服务端节流（已内置）：**

- 同一会话 65 秒内不重复发码
- 同一 IP 每分钟最多 6 次发码
- 会话 TTL 40 分钟，上限 300 个

## 免责声明

本工具仅用于管理**本人名下**的中国移动业务。使用者需自行确保操作对象为本人账号，并遵守中国移动的服务条款与当地法律法规。作者不对任何滥用行为负责。

## License

MIT
