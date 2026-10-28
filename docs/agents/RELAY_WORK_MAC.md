# 给公司 Mac 上的 Codex：安装支持中继的 Yobiru

你在用户公司的 Mac 上工作。这台 Mac 不能装 Tailscale，所以 Yobiru 只走用户自己托管的中继：只需要出站 HTTPS，
不开任何端口。目标：让用户的 Grok Bot（中继名 `grok`）能给这台 Mac 上的 Codex 发消息、唤醒它，并收到回复。
这台 Mac 的中继名是 `work-mini`。消息、wake、tracked request（`request send`）和附件都能走中继。

## 需要用户提供

| 项 | 说明 |
|---|---|
| `RELAY_DOMAIN` | 中继域名，例如 `relay.example.com` |
| 邀请码 | 中继给 `work-mini` 这个名字发的一次性邀请码，一小时内有效 |
| `grok` 的指纹 | Grok Bot 运行 `relay whoami` 后报告的 fingerprint；用家里 Mac mini 时，还要它的指纹 |
| Codex 会话 | 用来接收消息的那个**已有** Codex 会话的 thread id（UUID） |
| 是否允许 Codex 自动回复 | 只有用户明确说允许，才在安装 bridge 时加 `--allow-replies` |

## 不能做的事

- 不要安装 Tailscale、VPN 或任何网络扩展，不要开监听端口，不要修改系统安全设置或绕过公司的设备管理。
  公司的管理策略阻止某一步（例如不允许常驻进程或出站连接）时，停下来告诉用户，不要找变通办法。
- `~/.tailmsg` 已经存在时，不要覆盖或重建它：停下来告诉用户里面有什么。
- 不要打印或转发 `~/.tailmsg/relay/device.json` 里的凭证和私钥。
- 不要用中继目录（`relay directory`）里看到的指纹去信任设备；只用用户给的指纹。
- 不要替用户选 Codex 会话，也不要在用户没明确同意时打开自动回复。

## 0. 预检

```sh
sw_vers -productVersion
python3 --version          # 3.8 或更高
git --version
test -e ~/.tailmsg && echo "EXISTS: stop and ask the user" || echo "no existing data home"
curl -s "https://RELAY_DOMAIN/v1/health"    # {"ok": true, "relay": "yobiru-relay", ...}；连不上就停下来汇报
```

## 1. 获取代码

```sh
git clone https://github.com/mario1in/yobiru.git ~/src/yobiru
git -C ~/src/yobiru merge-base --is-ancestor 42123d4 HEAD && echo "has relay fixes"
Y="$HOME/src/yobiru/plugins/yobiru/scripts/yobiru"
HOME_T="$HOME/.tailmsg"
sh "$Y" relay --help
```

公司网络不能访问 GitHub 时，请用户把源码目录打包传过来，解压到 `~/src/yobiru`，再做上面的检查。

## 2. 配置和运行时

```sh
sh "$Y" --home "$HOME_T" setup --agent codex --self-agent codex --default-agent codex           # 先看计划
sh "$Y" --home "$HOME_T" setup --agent codex --self-agent codex --default-agent codex --apply
sh "$Y" --home "$HOME_T" install-runtime --apply           # 写入 tailmsg.py，以及旁边的 relay 文件
```

只接受用户自己的设备，并允许 Grok 立即唤醒 Codex（不用家里 Mac mini 时去掉第二个 `--allow`）：

```sh
sh "$Y" --home "$HOME_T" policy set --mode allowlist --allow grok.relay --allow home-mini.relay --apply
sh "$Y" --home "$HOME_T" wake-config --peer-max grok.relay=now --apply
```

## 3. 登记到中继并互信

```sh
sh "$Y" --home "$HOME_T" relay join "https://RELAY_DOMAIN" --name work-mini --invite 邀请码
sh "$Y" --home "$HOME_T" relay whoami
```

把 `whoami` 输出的 fingerprint 原样告诉用户：Grok Bot 要用它来信任这台 Mac。然后用用户给的指纹信任对方：

```sh
sh "$Y" --home "$HOME_T" relay trust grok --fingerprint "用户给的 grok 指纹"
sh "$Y" --home "$HOME_T" relay trust home-mini --fingerprint "用户给的 home-mini 指纹"     # 可选
```

报 `fingerprint_mismatch` 时停下来告诉用户。

## 4. 只走中继

在 `$HOME_T/config.json` 里加一个字段 `"relay": "only"`，其他内容不动。然后：

```sh
sh "$Y" --home "$HOME_T" doctor
```

期望：`tailscale` 为 info（`not used`），`relay` ok（`work-mini.relay ... config relay: only`），`relay-trust` ok，
`relay-server` ok，没有 `relay-runtime` 错误。`wake @codex` 在下一步之前显示 none 是正常的。

## 5. Codex 唤醒（Codex bridge）

用户给出 thread id 后，先预演，再安装：

```sh
sh "$Y" --home "$HOME_T" codex-bridge install --thread-id 用户给的UUID --dry-run
sh "$Y" --home "$HOME_T" codex-bridge install --thread-id 用户给的UUID              # 用户明确同意时才加 --allow-replies
sh "$Y" --home "$HOME_T" codex-bridge status
```

bridge 只读本地 inbox，与消息从哪个传输进来无关，但还没有在没装 Tailscale 的机器上验证过。如果它的检查因为
Tailscale 失败，停下来把完整报错告诉用户，不要改代码或配置去绕过。bridge 没装好之前，消息会留在 `inbox --pending`
里，第 7 步的验收仍然可以做。

## 6. 常驻服务

```sh
test -e ~/Library/LaunchAgents/dev.tailmsg.plist && echo "EXISTS: stop and ask the user"
sh "$Y" --home "$HOME_T" service-template launchd > ~/Library/LaunchAgents/dev.tailmsg.plist
plutil -lint ~/Library/LaunchAgents/dev.tailmsg.plist
launchctl load -w ~/Library/LaunchAgents/dev.tailmsg.plist
sleep 5; tail -n 5 "$HOME_T/serve.log"      # 应有 "serving work-mini.relay through the relay only"
```

请用户在「系统设置 → 能源」里打开「防止自动进入睡眠」：Mac 睡眠时收不到消息。这是系统设置，由用户自己改。

## 7. 验证（Grok Bot 完成更新之后）

```sh
sh "$Y" --home "$HOME_T" relay directory        # grok: trusted, online: true
sh "$Y" --home "$HOME_T" relay ping grok        # "status": 200
sh "$Y" --home "$HOME_T" inbox                  # Grok 发来的测试消息，来自 grok.relay
sh "$Y" --home "$HOME_T" reply 消息ID "ok"       # "status": 202
sh "$Y" --home "$HOME_T" request status 请求ID --direction incoming   # Grok 发来的 request：peer 为 grok.relay
sh "$Y" --home "$HOME_T" reply 请求ID "ok"       # tracked request 的回复：{"queued": true}，结果经中继推回 Grok
launchctl kickstart -k "gui/$(id -u)/dev.tailmsg"; sleep 30; sh "$Y" --home "$HOME_T" relay ping grok   # 重启后仍为 200
```

## 以后怎么用

- 回复 Grok：`sh "$Y" --home "$HOME_T" reply 消息ID "内容"`；主动发：`sh "$Y" --home "$HOME_T" send grok.relay "内容"`。
- 更新：`git -C ~/src/yobiru pull --ff-only`，`sh "$Y" --home "$HOME_T" install-runtime --upgrade --apply`，再
  `launchctl kickstart -k "gui/$(id -u)/dev.tailmsg"`。
- 停用：`launchctl unload -w ~/Library/LaunchAgents/dev.tailmsg.plist`。中继侧的吊销由用户在服务器上做。

## 向用户汇报

- 每一步的结果，尤其是 `doctor` 的 error 和 warn
- 这台 Mac 的 fingerprint
- Codex bridge 的状态（装好、预演失败的原因，或在等用户给 thread id）
- `serve.log` 的最后几行、`relay ping grok` 的结果
- 被公司策略挡住或没有完成的步骤
