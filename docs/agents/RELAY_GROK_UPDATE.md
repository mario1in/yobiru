# 给 Grok Bot：把 Yobiru 更新到支持中继的版本

你在 Grok Bot 这个对话的电脑上工作，这里已经装了 Yobiru 0.7.15，并通过 Tailscale 和用户家里的 Mac mini 通信。
目标：更新到用户 fork 的 `main`（支持自托管中继），在保留现有 Tailscale 通路的同时，经中继和用户公司的 Mac
（中继名 `work-mini`，不装 Tailscale）互通。中继只转发消息：第 1 阶段不支持 tracked request（`request send`）和附件。

先读 `yobiru-grok-bot` skill：其中关于 data home、持久目录、启动定义和备份的规则在这里全部适用。

## 需要用户提供

| 项 | 说明 |
|---|---|
| `RELAY_DOMAIN` | 中继域名，例如 `relay.example.com` |
| 邀请码 | 中继给 `grok` 这个名字发的一次性邀请码，一小时内有效 |
| `work-mini` 的指纹 | 用户在公司 Mac 上运行 `relay whoami` 读到的 fingerprint |

## 不能做的事

- 不要新建 data home，不要启动第二个接收端，不要改 Tailscale 登录、ACL/grants 或 shields-up。
- 保留现有的 agents、wake 适配器、routine webhook、会话绑定和访问策略。
- 不要打印或转发 `relay/device.json` 里的凭证和私钥，也不要把它们复制到别的机器。
- 不要用中继目录（`relay directory`）里看到的指纹去信任设备；只用用户给的指纹。指纹对不上就停下来。
- 在 `doctor` 没有 `relay` 和 `relay-runtime` 错误之前，不要在 `config.json` 里打开 `"relay"`：打开了而缺文件或
  没登记，接收端会拒绝启动，现有的 Tailscale 通路也会一起停掉。

## 0. 找到现有安装

```sh
OLD_Y=已安装插件里 scripts/yobiru 的绝对路径
sh "$OLD_Y" paths
sh "$OLD_Y" --home "$HOME_T" doctor
```

记下 `HOME_T`（现有 data home）、接收端的启动定义（它运行的是哪个 `tailmsg.py`、怎么重启），以及 `doctor` 的结果。
后面每一步都用同一个 `HOME_T`。

## 1. 备份

按 `yobiru-grok-bot` skill 的规则，把整个 data home 备份到一个可见的私有目录，例如：

```sh
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
install -d -m 700 /workspace/tailmsg-backup
tar -C "$(dirname "$HOME_T")" -czf "/workspace/tailmsg-backup/home-$STAMP.tgz" "$(basename "$HOME_T")"
chmod 600 "/workspace/tailmsg-backup/home-$STAMP.tgz"
```

## 2. 获取新版本

```sh
git clone https://github.com/mario1in/yobiru.git /workspace/yobiru-src     # 已存在时：git -C /workspace/yobiru-src pull --ff-only
git -C /workspace/yobiru-src merge-base --is-ancestor 42123d4 HEAD && echo "has relay fixes"
Y=/workspace/yobiru-src/plugins/yobiru/scripts/yobiru
sh "$Y" version
sh "$Y" relay --help
```

## 3. 更新运行时，先不打开中继

```sh
sh "$Y" --home "$HOME_T" install-runtime --upgrade          # 先看计划
sh "$Y" --home "$HOME_T" install-runtime --upgrade --apply  # 旧运行时留一份 tailmsg.py.bak-*；relay 文件一起写入
```

用现有的启动定义重启**这一个**接收端，然后确认 Tailscale 通路和以前一样：

```sh
sh "$Y" --home "$HOME_T" doctor     # tailscale、receiver、maintenance 应与第 0 步一致
```

不一致就停下来，按文末的回滚步骤恢复，再报告给用户。

## 4. 登记到中继

```sh
sh "$Y" --home "$HOME_T" relay join "https://RELAY_DOMAIN" --name grok --invite 邀请码
sh "$Y" --home "$HOME_T" relay whoami
```

把 `whoami` 输出的 fingerprint 原样告诉用户：公司 Mac 要用它来信任你。然后用用户给的指纹信任公司 Mac：

```sh
sh "$Y" --home "$HOME_T" relay trust work-mini --fingerprint "用户给的 work-mini 指纹"
```

报 `fingerprint_mismatch` 时停下来告诉用户，不要换别的办法信任。

## 5. 打开中继

```sh
sh "$Y" --home "$HOME_T" doctor     # 不能有 relay 或 relay-runtime 错误
```

备份 `config.json`，再只加一个字段 `"relay": "on"`（同时接收 Tailscale 和中继），其他内容不动。用现有的启动定义重启
接收端，然后：

```sh
sh "$Y" --home "$HOME_T" doctor     # relay ok（config relay: on），relay-server ok，tailscale 和 receiver 仍然 ok
```

接收端日志里应有一行 `relay: receiving as grok.relay through https://RELAY_DOMAIN`。

公司 Mac 的回复默认最多以 batch 唤醒你。如果用户希望回复立即唤醒你的 routine，经用户同意后再运行：

```sh
sh "$Y" --home "$HOME_T" wake-config --peer-max work-mini.relay=now --apply
```

## 6. 验证（公司 Mac 就绪之后）

```sh
sh "$Y" --home "$HOME_T" relay directory          # work-mini: trusted, online: true
sh "$Y" --home "$HOME_T" relay ping work-mini     # "status": 200
sh "$Y" --home "$HOME_T" relay info work-mini     # capabilities: [], agents 里有 codex
sh "$Y" --home "$HOME_T" send work-mini.relay/codex "验收：请回复 ok" --wake now   # "status": 202
sh "$Y" --home "$HOME_T" inbox                    # 稍后应有来自 work-mini.relay 的回复
```

`peer_offline` 表示公司 Mac 没在运行或在睡眠；`peer_refused: sender_not_trusted` 表示公司 Mac 还没信任你。

## 以后怎么用

- 发给中继设备（`NAME.relay`）时，一律用新源码里的 `$Y`。已安装的 0.7.15 插件和它的 skill 调用的是旧 CLI，不认识
  `NAME.relay` 地址。发给 Tailscale 上的设备照旧。
- 中继上还不能用 `request send`，也不能带附件；会被明确拒绝。
- 更新：`git -C /workspace/yobiru-src pull --ff-only`，再 `install-runtime --upgrade --apply`，然后重启接收端。

## 回滚

1. 把 `config.json` 里的 `"relay"` 改回 `"off"`（或恢复第 5 步的备份）。
2. 需要退回旧运行时时，把 `HOME_T/tailmsg.py.bak-*` 中最新的一份恢复为 `HOME_T/tailmsg.py`。
3. 用现有的启动定义重启接收端，运行 `doctor` 确认 Tailscale 通路恢复。
4. 第 1 步的完整备份只在 data home 损坏时使用。

## 向用户汇报

- `HOME_T`、接收端的启动方式、更新前后的运行时版本
- 第 3 步和第 5 步 `doctor` 的结论（error 和 warn 列出来）
- 你的 fingerprint
- `relay ping work-mini` 和测试消息的结果
- 没有完成或不确定的步骤
