# 自托管中继部署手册（预览，第 1–2 阶段）

本手册把[中继](RELAY_DESIGN.md)部署到你自己的设备上：一台有公网域名的服务器运行中继；公司 Mac 只走中继，
不装 Tailscale；Grok bot 的电脑和家里的 Mac mini 同时保留 Tailscale。完成后，Grok bot 可以给公司 Mac 上的
Codex 发消息并唤醒它，也可以派 tracked request（`request send`），收到 `received`、`running` 和最终结果；
Codex 的回复会原路回来。

交给 agent 执行的版本：[Coolify 部署中继](agents/RELAY_COOLIFY.md)、[更新 Grok Bot](agents/RELAY_GROK_UPDATE.md)、
[安装公司 Mac](agents/RELAY_WORK_MAC.md)。容器镜像见 `deploy/relay/Dockerfile`。

**中继还不转发附件。** 消息、wake、tracked request（push 和 pull）都能走中继；带 `--file` 的发送和带附件的
结果会被明确拒绝，要等第 3 阶段。在公司电脑上运行之前，请先确认这符合公司的规定。

## 0. 约定

| 名字 | 指什么 |
|---|---|
| `relay.example.com` | 你的中继域名，换成自己的 |
| `work-mini` | 公司 Mac 的中继设备名 |
| `grok` | Grok bot 电脑的中继设备名 |
| `home-mini` | 家里 Mac mini 的中继设备名（可选） |
| `Y` | 该设备上源码目录里 `plugins/yobiru/scripts/yobiru` 的绝对路径，命令写作 `sh "$Y" ...` |
| `HOME_T` | 该设备的 Yobiru data home（默认 `~/.tailmsg`），命令写作 `sh "$Y" --home "$HOME_T" ...` |

设备名只能是一个 DNS 标签：小写字母、数字和中间的 `-`。中继上的设备在 tailmsg 里叫 `NAME.relay`。

**拓扑与信任关系：**

```text
Grok bot 电脑 (grok, relay=on) ──┐                         ┌── 公司 Mac (work-mini, relay=only)
                                 ├─HTTPS─> 东京中继 <─HTTPS─┤     Codex + wake 适配器
家里 Mac mini (home-mini, on) ───┘                         └── 不装 Tailscale，不开端口
```

| 设备 | 需要信任 |
|---|---|
| work-mini | grok，home-mini（如果用） |
| grok | work-mini |
| home-mini | work-mini |

## 1. 获取代码

中继只在你 fork 的 `main` 上（提交 `fd158d4` 及之后），**不在已发布的 0.7.15 插件包里**。每台设备，包括服务器，
都需要这份源码：

```sh
git clone https://github.com/mario1in/yobiru.git ~/src/yobiru     # 服务器上放到 /opt/yobiru，见第 2 节
git -C ~/src/yobiru log -1 --format=%h                        # 应为 fd158d4 或更新
python3 --version                                             # 3.8 或更高
Y="$HOME/src/yobiru/plugins/yobiru/scripts/yobiru"
sh "$Y" relay --help
```

公司网络不能访问 GitHub 时，从家里把整个源码目录打包，再复制过去。

### 常驻运行时和 relay 文件

接收服务（`service-template` 生成的 launchd/systemd 定义）运行的是 data home 里的那份 `tailmsg.py`。中继模式
还要用到它旁边的 `relay.py` 和 `public_bots/bot_e2e.py`；`install-runtime --apply`（或 `--upgrade --apply`）会把
它们和 `tailmsg.py` 一起写进 data home，运行时已是最新时也会补上缺的文件。`doctor` 会在缺文件时报
`relay-runtime` 错误。

**顺序很重要：** 先 `install-runtime`、先 `relay join`，最后才在 `config.json` 里打开 `"relay"`。打开了却没登记，
或者运行时旁边缺 relay 文件，接收端会拒绝启动；对已有的 Tailscale 接收端（家里 Mac mini、Grok bot）来说，这意味着
原来的 Tailscale 通路也一起停了。打开之前先运行 `doctor`，确认没有 `relay` 和 `relay-runtime` 错误。

## 2. 东京服务器：中继

前提：一个 DNS A/AAAA 记录 `relay.example.com` 指向服务器；防火墙只开放 80 和 443（用于 HTTPS 和证书签发）。
中继自己只监听 `127.0.0.1:7790`，不对外开放。

```sh
sudo useradd --system --home-dir /var/lib/yobiru-relay --shell /usr/sbin/nologin yobiru-relay
sudo install -d -o yobiru-relay -g yobiru-relay -m 700 /var/lib/yobiru-relay
sudo git clone https://github.com/mario1in/yobiru.git /opt/yobiru     # 私有仓库时改用部署密钥或复制
sudo -u yobiru-relay python3 /opt/yobiru/plugins/yobiru/scripts/relay.py \
    server init --relay-home /var/lib/yobiru-relay --port 7790
```

`/etc/systemd/system/yobiru-relay.service`：

```ini
[Unit]
Description=Yobiru relay (relay-v1)
After=network-online.target
Wants=network-online.target

[Service]
User=yobiru-relay
Group=yobiru-relay
ExecStart=/usr/bin/python3 /opt/yobiru/plugins/yobiru/scripts/relay.py server serve --relay-home /var/lib/yobiru-relay
Restart=always
RestartSec=5
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/var/lib/yobiru-relay

[Install]
WantedBy=multi-user.target
```

```sh
sudo systemctl daemon-reload && sudo systemctl enable --now yobiru-relay
journalctl -u yobiru-relay -n 5          # 第一行应为 {"listening": "http://127.0.0.1:7790"}
curl -s http://127.0.0.1:7790/v1/health  # {"ok": true, "relay": "yobiru-relay", ...}
```

HTTPS 反向代理（Caddy，`/etc/caddy/Caddyfile`）。设备的长轮询每次最多挂 25 秒，发消息最多等 60 秒，所以把等待
上游响应头的时间设得比这更长：

```caddyfile
relay.example.com {
	reverse_proxy 127.0.0.1:7790 {
		transport http {
			response_header_timeout 90s
		}
	}
}
```

```sh
sudo systemctl reload caddy
curl -s https://relay.example.com/v1/health      # 在任意一台电脑上
```

用 nginx 时，同样要把 `proxy_read_timeout` 设成 90s 以上。

**发邀请**（在服务器上，每台设备一个；邀请码一次性、绑定名字、一小时内有效，只显示一次）：

```sh
relay_admin() { sudo -u yobiru-relay python3 /opt/yobiru/plugins/yobiru/scripts/relay.py "$@"; }
relay_admin server invite --relay-home /var/lib/yobiru-relay work-mini
relay_admin server invite --relay-home /var/lib/yobiru-relay grok
relay_admin server invite --relay-home /var/lib/yobiru-relay home-mini
relay_admin server devices --relay-home /var/lib/yobiru-relay
```

把邀请码交给对应设备的过程中不要经过公共渠道；它只用一次，用过即失效。

## 3. 公司 Mac：只走中继

```sh
HOME_T="$HOME/.tailmsg"
sh "$Y" --home "$HOME_T" setup --agent codex --self-agent codex --default-agent codex --apply
sh "$Y" --home "$HOME_T" install-runtime --apply                    # 连同 relay 文件
sh "$Y" --home "$HOME_T" relay join https://relay.example.com --name work-mini --invite 邀请码
sh "$Y" --home "$HOME_T" relay whoami        # 记下 fingerprint，第 6 节要用
```

只接受自己的 Grok bot 和家里的 Mac mini，并允许 Grok 立即唤醒 Codex：

```sh
sh "$Y" --home "$HOME_T" policy set --mode allowlist --allow grok.relay --allow home-mini.relay --apply
sh "$Y" --home "$HOME_T" wake-config --peer-max grok.relay=now --apply
```

然后在 `$HOME_T/config.json` 里加一行 `"relay": "only"`。

**Codex 唤醒：** 按家里 Mac mini 现在的方式配置 Codex bridge（见 [CODEX_LOCAL.md](../CODEX_LOCAL.md) 和
`yobiru-wake` skill）。它只读本地 inbox，与消息从哪个传输进来无关；不过还没有在没装 Tailscale 的机器上验证过。
在 bridge 配好之前，消息会留在 `inbox --pending` 里，第 7 节的验收照样可以做。

**常驻服务：**

```sh
sh "$Y" --home "$HOME_T" service-template launchd > ~/Library/LaunchAgents/dev.tailmsg.plist
launchctl load -w ~/Library/LaunchAgents/dev.tailmsg.plist
tail -n 5 "$HOME_T/serve.log"     # 应有 "serving work-mini.relay through the relay only"
```

在「系统设置 → 能源」里打开「防止自动进入睡眠」：Mac 睡眠时收不到消息，发送方会看到 `peer_timeout` 或 `peer_offline`。

检查：`sh "$Y" --home "$HOME_T" doctor`。`"relay": "only"` 时它不检查 Tailscale 和本机端口，改为检查中继登记、
信任、relay 文件和中继服务器；`relay-trust` 在第 6 节完成之前会是 warn。对方能否收到，用第 7 节的 `relay ping` 确认。

## 4. Grok bot 的电脑：Tailscale 加中继

这些步骤在 Grok bot 自己的电脑上执行，可以让 Grok bot 照做。先按 [GROK_BOT.md](GROK_BOT.md) 找到它**现有的**
data home 和启动方式，不要另建。源码放在能保留下来的目录，例如 `/workspace/yobiru-src`。

```sh
git clone https://github.com/mario1in/yobiru.git /workspace/yobiru-src     # 或复制
Y=/workspace/yobiru-src/plugins/yobiru/scripts/yobiru
sh "$Y" --home "$HOME_T" install-runtime --upgrade --apply            # 连同 relay 文件；旧运行时留一份备份
sh "$Y" --home "$HOME_T" relay join https://relay.example.com --name grok --invite 邀请码
sh "$Y" --home "$HOME_T" relay whoami
```

然后在 `config.json` 加 `"relay": "on"`（同时接收 Tailscale 和中继），用它现有的启动方式重启接收端，再确认原来的
Tailscale 通路仍然正常（`sh "$Y" --home "$HOME_T" doctor`）。Grok 发消息时，命令要用新源码里的 `$Y`：已安装的
0.7.15 插件不认识 `NAME.relay` 地址。

## 5. 家里 Mac mini（可选）

和 Grok bot 一样，保留 Tailscale：`install-runtime --upgrade --apply`，`relay join --name
home-mini`，`config.json` 加 `"relay": "on"`，然后重启：

```sh
launchctl kickstart -k "gui/$(id -u)/dev.tailmsg"
```

## 6. 交换指纹并信任

在**每台设备自己**的终端或聊天里运行 `relay whoami`，读出它的 fingerprint（32 位十六进制，分成 8 组）。不要用
中继目录（`relay directory`）里看到的指纹来核对：那正是要防的东西。然后按第 0 节的信任表逐台执行：

```sh
# 公司 Mac
sh "$Y" --home "$HOME_T" relay trust grok --fingerprint "grok 的指纹"
sh "$Y" --home "$HOME_T" relay trust home-mini --fingerprint "home-mini 的指纹"
# Grok bot 电脑、家里 Mac mini
sh "$Y" --home "$HOME_T" relay trust work-mini --fingerprint "work-mini 的指纹"
# 任意设备上查看
sh "$Y" --home "$HOME_T" relay directory     # trust: trusted / untrusted / key_changed
```

指纹不对时，`trust` 会以 `fingerprint_mismatch` 拒绝。这时不要换别的方式强行信任，先查清是谁的密钥。信任立即
生效，接收端不需要重启。

## 7. 验收清单

在 Grok bot 的电脑上依次执行（`$Y` 指新源码）。每一项通过再做下一项。

| # | 命令 | 期望 |
|---|---|---|
| 1 | `curl -s https://relay.example.com/v1/health` | `"ok": true` |
| 2 | `sh "$Y" --home "$HOME_T" relay directory` | 三台设备都在，work-mini 为 `trusted`、`online: true` |
| 3 | `sh "$Y" --home "$HOME_T" relay ping work-mini` | `"status": 200`，`node` 为 `work-mini.relay` |
| 4 | `sh "$Y" --home "$HOME_T" relay info work-mini` | `"status": 200`，`capabilities` 含 `request-lifecycle-v1` 和 `request-pull-v1`，列出 `codex` |
| 5 | `sh "$Y" --home "$HOME_T" send work-mini.relay/codex "验收：请回复 ok" --wake now` | `"status": 202` |
| 6 | 公司 Mac：`sh "$Y" --home "$HOME_T" inbox` | 有这条消息，来自 `grok.relay`；bridge 配好时 Codex 被唤醒 |
| 7 | 公司 Mac：`sh "$Y" --home "$HOME_T" reply 消息ID "ok"` | `"status": 202` |
| 8 | Grok 电脑：`sh "$Y" --home "$HOME_T" inbox` | 有回复，来自 `work-mini.relay` |
| 9 | 公司 Mac 上 `launchctl kickstart -k "gui/$(id -u)/dev.tailmsg"`，等 30 秒后重做第 3 项 | 仍为 200 |
| 10 | 公司 Mac 断网再恢复，等一分钟后重做第 3 项 | 仍为 200（轮询失败会以 1 秒到 60 秒的间隔重试） |
| 11 | 公司 Mac 睡眠时重做第 5 项 | 失败且没有 `Delivery is unknown`：刚睡眠的约一分钟内报 `peer_timeout`，之后报 `peer_offline` |
| 12 | Grok 电脑：`sh "$Y" --home "$HOME_T" request send work-mini.relay/codex "验收：请回复 ok" --wake now` | `"status": 202`、`"submission": "accepted"`；记下 `id` |
| 13 | Grok 电脑：`sh "$Y" --home "$HOME_T" request status 请求ID` | 几秒内变为 `state=received`；Codex 回复后变为 `completed`，下面一行是回复内容 |
| 14 | Grok 电脑：`sh "$Y" --home "$HOME_T" request send work-mini.relay/codex "x" --transport pull`，公司 Mac 回复后再 `request status 请求ID --refresh` | 回复前状态不变（pull 不推送）；`--refresh` 之后为 `completed` |

第 10、11 项最能暴露公司网络代理的问题；如果长轮询总是被掐断，记下 `serve.log` 里的报错，这会影响后续阶段的设计。

## 8. 运维

**吊销一台设备**（丢失、重装、怀疑泄露）：

```sh
relay_admin server revoke --relay-home /var/lib/yobiru-relay work-mini      # 服务器：中继立即拒绝它
sh "$Y" --home "$HOME_T" relay untrust work-mini                  # 每台信任过它的设备上
```

中继吊销只能阻止转发；已泄露的密钥仍可能被拿去别处冒充，所以每台设备上的 `untrust` 必须做。

**重新登记**（重装后）：吊销旧的，发新邀请，在新设备上 `join`，再按第 6 节重新核对指纹并 `trust`。旧的
`relay/device.json` 不会被覆盖：`join` 发现已有登记会拒绝。

**升级：** `git pull` 后运行 `install-runtime --upgrade --apply`（relay 文件会一起更新），然后重启接收端。服务器上
`git pull` 后执行 `sudo systemctl restart yobiru-relay`；重启会断开正在进行的交换，发送方会看到一次失败。

**备份：** 服务器只需备份 `/var/lib/yobiru-relay`（设备登记表）。设备上的 `HOME_T/relay/` 存有私钥和凭证
（0600），属于该设备的 data home，随 data home 一起备份，不要复制到别的机器。

**常见错误：**

| 报错 | 原因与处理 |
|---|---|
| `not_joined` | 这个 data home 还没 `relay join`；接收端打开了 `"relay"` 却没登记也会这样 |
| `No such file or directory: .../relay.py` | 常驻运行时旁边缺 relay 文件：`install-runtime --apply`，再重启 |
| `not_trusted` | 本机还没信任对方，见第 6 节 |
| `peer_refused: sender_not_trusted` | 对方没信任你，或已 `untrust` |
| `peer_refused: clock_skew` | 两台设备的时钟差超过 5 分钟；打开系统自动校时 |
| `peer_refused: frame_unopened` | 密钥对不上：对方重装过却没重新核对指纹，或中继出了问题。不要绕过，先查 |
| `peer_offline` | 对方约一分钟没有轮询：没运行、睡眠或断网。消息确定没有送到 |
| `peer_timeout` | 对方没及时应答。帧没被取走时（刚睡眠、刚断网）消息确定没送到；已被取走时，`send` 会提示 `Delivery is unknown`，先查对方 inbox 再决定是否重发 |
| `unauthorized` | 这台设备已被中继吊销 |
| `relay_unreachable` | 连不上中继：DNS、证书、公司代理或中继没运行 |
| `receiver_identity_changed` | 接收端运行期间 `relay/device.json` 被换过；重启接收端 |

## 9. 已知限制

- 不转发附件：`send --file`、`request send --file` 和带 `--file` 的回复会被拒绝（第 3 阶段）。
- push request 的 `received`、`running` 和结果由公司 Mac 经中继推回 Grok，所以 Grok 的接收端要打开 `"relay": "on"`
  并在运行；Grok 不在线时公司 Mac 会按 2 到 60 秒的间隔重试，结果不会丢。不想依赖这一点时用 `--transport pull`，
  再用 `request status --refresh` 取结果。
- `doctor` 只检查本机的中继登记、信任、relay 文件和中继服务器；对方能否收到，要用 `relay ping` 确认。
- 接收端重启后的 5 分钟内，中继可以把重启前的帧重放一次；`/msg` 按消息 ID 去重，所以不会产生重复消息。
- 中继能看到哪台设备在何时和哪台设备通信、数据多大，看不到内容。
- 中继是单点：它停了，只走中继的公司 Mac 就失联；Tailscale 设备之间不受影响。
