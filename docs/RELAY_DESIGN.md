# 自托管中继：把 tailnet 搬到 HTTPS 上（设计草案）

**状态：第 1 阶段已实现（预览）**：中继服务端、设备登记与信任、帧封装，`/health`、`/info`、`/msg` 与 wake
（`relay.py`、`tests/test_relay.py`）。第 2–4 阶段尚未实现；在那之前，tracked request 和附件走中继时会被明确拒绝。
本文描述一种新的传输方式：设备只需出站 HTTPS，经过所有者自己托管的中继
（relay）交换现有的 tailmsg protocol v1 流量。目标场景是同一所有者的设备之间通信，其中一部分设备不能安装
Tailscale（例如公司电脑）。Tailscale 传输保持不变，仍是默认。

## 1. 目标与非目标

目标：

- 不能装 Tailscale 的设备，只需出站 HTTPS（443），就能像 tailnet 节点一样收发消息、request、附件，并按原有
  规则唤醒 agent（包括 Codex bridge 和 dispatcher）。
- **协议层不变。** `/msg`、`/info`、`/health`、`/f/<token>/<name>`、`/requests/...` 的语义、状态码、
  幂等规则、request 生命周期全部沿用 SPEC。只替换"连得上"和"对方是谁"这两件事。
- 中继**读不到、改不了、伪造不了**内容：端到端加密，发送方身份由设备密钥证明，而不是由中继声明。
- 中继不保存消息：和 Tailscale 一样，对方离线就是不可达，不做存储转发。

非目标：

- 不对他人开放。这不是 Friends，没有关注、好友、消息请求，也不给陌生人注册。
- 不复用 Friends 网关进程。Friends 网关"绝不把内容转进 tailmsg 收件箱、唤醒适配器或 Codex bridge"
  这一边界保持不变；中继是另一个进程（可以部署在同一台服务器上）。
- 不隐藏元数据：中继能看到哪台设备和哪台设备、何时、多大。
- 不绕过设备所在网络的管理规定。在公司电脑上运行之前，需由使用者确认这符合其单位的政策。

## 2. Tailscale 当前提供了什么，中继怎么替代

| Tailscale 提供 | 代码里的位置 | 中继的替代 |
|---|---|---|
| 可达性 | 接收端在 Tailscale IP 上监听 7766；`http_json()`、`upload_request_file()`、`cmd_fetch()` 直接用 `HTTPConnection(ip, port)` | 接收端对中继长轮询取帧；发送方把帧交给中继，由中继同步转给对方 |
| 机器身份 | `Ctx.whois_uncached()` 用 LocalAPI 得到 `node`、`stable_id`、`tags`、`user`；`sender_matches()` 校验信封 `from` | 设备静态 X25519 密钥；身份 = 本机**显式信任**的密钥指纹，不信中继目录 |
| 网络边界 | `identify()` 先查 `is_tailnet_ip()` | 帧必须能用已信任的发送方密钥打开，否则 403 |
| 传输加密 | WireGuard | 每帧用 `public_bots/bot_e2e.py` 的 `seal()`/`open_sealed()`（X25519 + HKDF-SHA256 + ChaCha20-Poly1305，纯标准库） |
| 名称解析 | `Ctx.resolve()` 读 `tailscale status` | 本机 `relay/peers.json` 里的已信任设备 |
| 接收端身份固定 | `ReceiverIdentity` 固定 LocalAPI 身份 | 固定本机设备密钥；密钥变化同样锁定并返回 503 |

访问策略、wake 策略、静默时间、频率限制、request 账本、附件校验都不改：它们只依赖 `ident` 字典，
中继只需构造一个等价的 `ident`。

## 3. 组成

```text
公司 Mac（只出站 HTTPS）        东京服务器（自己的）             家里 Mac mini / Grok bot 的电脑
yobiru serve --relay  ──HTTPS──> yobiru relay serve  <──HTTPS── yobiru serve（同时保留 Tailscale 监听）
  长轮询取帧、交回应答            127.0.0.1:7790，前面放          send / request / fetch 选中 *.relay 对端时走中继
  inbox / wake / Codex bridge     自己的 HTTPS 反向代理
```

- **中继** `yobiru relay serve`：单个进程，只认已登记设备的 bearer 凭证，只做路由和限流，不解密、
  不落盘消息。持久数据只有设备登记表（名称、公钥、凭证哈希、吊销状态）和管理员凭证。
- **设备端**：`serve` 增加中继轮询线程，与现有 Tailscale 监听共用同一个 home、inbox、request 账本。
  只用中继的设备（公司 Mac）不启动 TCP 监听。
- **管理**：没有网络管理接口。邀请、列出、吊销设备都在中继服务器本机执行，直接操作它的 data home
  （`relay.sqlite3`）；中继服务器上不运行任何 agent。

## 4. 设备登记与信任

```sh
# 中继服务器（东京）
sh Y relay server init  --relay-home /srv/yobiru-relay --port 7790
sh Y relay server serve --relay-home /srv/yobiru-relay           # 127.0.0.1:7790，前面放 HTTPS 反向代理
sh Y relay server invite --relay-home /srv/yobiru-relay work-mini # 一次性邀请码，绑定这个名字，一小时有效
sh Y relay server devices --relay-home /srv/yobiru-relay
sh Y relay server revoke  --relay-home /srv/yobiru-relay work-mini
# 新设备（公司 Mac）
sh Y relay join https://relay.example.com --name work-mini --invite CODE
sh Y relay whoami                                                  # 显示本机指纹
# 每台要和它通信的设备上，核对指纹后显式信任
sh Y relay trust work-mini --fingerprint FP
sh Y relay directory                                               # trusted / untrusted / key_changed
sh Y relay ping work-mini                                          # 经中继请求对方的 /health
```

接收端在 `config.json` 里设置 `"relay": "on"`（同时保留 Tailscale 监听）或 `"only"`（不需要 Tailscale），
再照常运行 `serve`。只 `join` 而不改配置，不会打开任何新的入站通道。

- `join` 在本机生成 X25519 密钥（`relay/device.json`，0600），只把公钥交给中继。
- 中继目录只是"建议"：设备只和本机 `relay trust` 过的指纹通信。没有首次使用即信任（TOFU）：
  这是能触发执行的通道，指纹必须由所有者在两台设备上当面核对。
- 指纹变化（重装、换钥、中继被替换）→ 一律拒绝并报告 `key_changed`，需要重新 `trust`。
- `relay server revoke NAME` 立即让中继拒绝该设备；各设备的本地信任也应一并撤销（`relay untrust`）。
  中继吊销只能阻止转发，不能阻止已泄露的密钥向别的中继冒充，所以本地撤销是必需的。

## 5. 身份映射

中继对端的 `ident`：

```json
{"ip": null, "node": "work-mini.relay", "host": "work-mini", "tags": ["tag:relay"],
 "user": "relay:relay.example.com", "stable_id": "<指纹十六进制>", "dns_name": "work-mini.relay",
 "transport": "relay"}
```

- `.relay` 是保留后缀，不会和 `*.ts.net` 或 MagicDNS 短名冲突；`select_peer()` 对 `NAME.relay` 只查本机
  已信任设备，查不到就拒绝，绝不回落到 Tailscale。
- `stable_peer_id()` 给出 `node:<hex>`，所以 pull 请求的稳定身份、`allow`/`deny`、wake 规则都能精确匹配。
- 现有 `tailnet` 访问模式会放行"已认证的对端"。对中继对端，"已认证"等于"本机显式信任的密钥"，
  因此行为与 tailnet 对等；需要更严时用 `allowlist` 或 `deny`，规则语法不变（`tag:relay`、`work-mini.relay`）。

## 6. 帧协议（`relay-v1`）

所有中继请求都带设备 bearer 凭证。帧内容对中继不透明。

**发送方 → 中继：** `POST /v1/exchange`

```json
{"to": "DEVICE_ID", "frame_id": "<随机 128 位>", "timeout_s": 15, "sealed": { ...bot_e2e 信封... }}
```

中继把帧放进接收方的待取队列，**挂起这个 HTTP 请求**，直到接收方交回应答或超时。超时返回
`504 peer_unreachable`；接收方不在线直接返回 `503 peer_offline`。这与 Tailscale 下"连不上"的语义一致：
对 `POST /msg` 来说，超时意味着"投递未知"，沿用 `http_json()` 现有的提示，不自动重发新 ID。

**接收方 → 中继：** `POST /v1/poll`（挂起至多 25 秒，返回 0 到 N 个帧）和 `POST /v1/answer`
`{"frame_id": ..., "sealed": {...}}`。

**帧明文**（封装前）：

```json
{"v": 1, "kind": "request", "frame_id": "...", "from": "FROM_KID", "to": "TO_KID", "ts": "ISO8601",
 "method": "POST", "path": "/msg", "headers": {"Content-Type": "application/json"}, "body_b64": "..."}
```

应答帧为 `kind: "response"`，带同一 `frame_id`、`status`、`headers`、`body_b64`。

- **封装上下文**（`seal()` 的 `context`）：`["yobiru-relay-v1", 中继 URL, from_kid, to_kid, frame_id, kind]`。
  中继把帧换给别的设备、把应答换给别的请求、或把请求和应答对调，都会打开失败。
- **发送方认证**：`seal()` 包含发送方静态密钥的 DH，接收方用本机信任的发送方公钥打开，打开成功即证明发送方。
- **重放**：接收方拒绝 `ts` 偏离本机时间超过 5 分钟的帧，并在 10 分钟内记住已处理的 `frame_id`。
  tailmsg 本身按消息 ID 幂等（重复 `/msg` 返回 200），这一层只是额外防线。
- **大小**：单帧明文上限 8 MiB。超过的内容（附件下载、pull 上传）按第 7 节分块。

## 7. 附件

现有附件流程是"发送方暂存，接收方按 URL 拉取，校验大小和 SHA-256"，`max_fetch_bytes` 默认 1 GiB。
走中继时：

- URL 主机是 `NAME.relay`，`cmd_fetch()` 据此选中继传输。
- 接收端 `/f/<token>/<name>` 增加 `Range: bytes=a-b` 支持（Tailscale 下也能用，向后兼容）；
  中继客户端按 4 MiB 分块拉取，全部到齐后照旧校验 SHA-256。
- pull 上传 `PUT /requests/<id>/uploads/<token>` 增加分块上传（`?offset=`，最后一块提交），
  接收端照旧在全部到齐后校验大小和哈希，再返回 201/200。
- 带宽全部经过中继服务器。中继按设备设每日字节上限，防止失控的 agent 把服务器流量打满。

## 8. 代码改动范围

| 位置 | 改动 |
|---|---|
| 新 `relay.py`（打包到 `plugins/yobiru/scripts/`） | 中继服务端、管理命令、设备端 `join`/`trust`/`whoami`、帧封装与打开 |
| `tailmsg.py` 传输层 | 抽出 `Transport`：`TailscaleTransport` 包装现有 `http_json()`、上传、下载；`RelayTransport` 走帧。约 8 个调用点改为经 `Transport`：响应投递（`deliver_response`）、`cmd_send` 的 `/info` 与 `/msg`、pull 的 prepare/upload/submit、`request status --refresh`、`cmd_fetch`、`cmd_peers` |
| `tailmsg.py` 接收端 | `serve --relay` 启动轮询线程；把解开的帧交给 `make_handler()` 的同一个处理器（内存中的 rfile/wfile），`identify()` 在帧来源时直接返回第 5 节的 `ident`，不调用 whois、不查 `is_tailnet_ip()` |
| `Ctx.resolve()` / `select_peer()` | `NAME.relay` 只解析到本机已信任设备 |
| `ReceiverIdentity` | 中继模式下固定本机设备密钥 |
| `yobiru.py` | `onboard`/`doctor` 报告中继连通性、信任状态、指纹变化；`agents --peer NAME.relay` |
| `SPEC.md` | 新增"中继传输 relay-v1"一节 |
| 测试 | 回环端到端（一个中继进程、三个 home）：消息、wake、push/pull request、分块附件；中继篡改、换帧、重放、未信任密钥、吊销、指纹变化、接收方离线与超时 |
| `tools/build_plugin.py` | 把 `relay.py` 纳入打包清单并 `sync`/`check` |

Codex bridge、dispatcher、wake 适配器**不需要改**：它们只看本地 inbox，不关心消息从哪个传输来。

## 9. 部署（东京服务器）

- `relay serve` 只监听 `127.0.0.1:7790`，前面放 Caddy/nginx 终止 TLS；不要和 7766 接收端、Friends
  网关（7780）共用端口或 data home。
- 长轮询需要反向代理的读超时大于 30 秒。
- 只开放给自己的设备：邀请码一次性、短时有效；登记设备数设上限；管理员凭证不上服务器之外的 agent 设备。
- 公司网络若有 TLS 检查代理，内容仍受端到端加密保护，但代理能看到中继域名和流量规模；部分代理会掐断
  长连接，客户端需能退化为短轮询（`--poll-seconds`）。

## 10. 风险与取舍

- **中继是单点。** 它停了，只走中继的设备就失联；Tailscale 设备之间不受影响。
- **信任根变了。** 原来是"你的 tailnet 账户加 Tailscale 控制面"，现在是"你在各设备上核对过的指纹"。
  只要不跳过指纹核对，中继被攻破也只能断网和看元数据，不能读或伪造。
- **执行权限更敏感。** 一个能被远程唤醒、执行任务的 agent，凭证和密钥一旦泄露，后果比聊天通道严重。
  继续沿用 dispatcher 的授权规则；公司 Mac 上建议用 `allowlist`，只放行自己的 Grok bot 和家里的 Mac mini。
- **同步转发而非存储转发**，换来的是语义与 Tailscale 一致、中继不存消息；代价是发送时对方必须在线。
  需要离线投递时，可在后续版本单独设计，不在 v1 范围内。

## 11. 分阶段

1. 中继服务端、设备登记与信任、帧封装；`/health`、`/info`、`/msg` 与 wake 走通。
2. push 与 pull request、响应投递、`request status --refresh`。
3. 附件分块下载与上传。
4. `onboard`/`doctor`、SPEC、SETUP 文档；在真实设备（东京中继、公司 Mac、家里 Mac mini、Grok bot）上验收，
   验收记录写入 `docs/VERIFICATION.md`。
