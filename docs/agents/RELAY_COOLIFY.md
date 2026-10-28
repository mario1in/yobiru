# 给 Codex：在 Coolify 上部署 Yobiru 中继，并在 Cloudflare 添加域名解析

你在用户的东京服务器上工作。目标：把 Yobiru 中继（`relay.py`，见 `docs/RELAY_DESIGN.md`）作为一个 Coolify
应用跑起来，用 HTTPS 域名对外提供服务，并在 Cloudflare 上添加这个域名的 DNS 记录。中继只为用户自己的设备转发
加密帧，不保存消息。

## 需要用户提供

| 项 | 说明 |
|---|---|
| `RELAY_DOMAIN` | 中继域名，例如 `relay.example.com` |
| `ZONE` | 它所在的 Cloudflare zone，例如 `example.com` |
| `CLOUDFLARE_API_TOKEN` | 只给这个 zone 的 `Zone:DNS:Edit` 权限；由用户放进环境变量，不要出现在聊天里 |
| Coolify 访问方式 | Coolify 网页，或 API（`COOLIFY_URL` 和 `COOLIFY_API_TOKEN` 环境变量） |
| Coolify 的项目、环境和服务器 | 应用部署到哪里，由用户指定 |
| 服务器公网 IPv4（以及要不要 IPv6） | 从服务器自己的网络配置或 Coolify 的服务器设置里读，再跟用户确认 |

缺任何一项就先问用户，不要猜。

## 不能做的事

- 不要在输出、日志、提交或文件里打印任何 token。
- 不要把容器的 7790 端口映射到宿主机（Coolify 里的 Ports Mappings 留空）。中继只能经 Coolify 的 HTTPS 代理访问。
- 不要修改别的 Coolify 应用、Coolify 自己的代理配置或服务器防火墙；确实需要改时，先说明原因并征得用户同意。
- 不要覆盖或删除已有的 DNS 记录。`RELAY_DOMAIN` 已有记录时停下来，告诉用户它现在指向哪里。
- 记录默认设为 **DNS only**（不经 Cloudflare 代理）。只有用户明确要求时才打开代理。
- 邀请码只在用户要求时生成，生成后只交给用户本人。

## 1. Cloudflare DNS

```sh
: "${CLOUDFLARE_API_TOKEN:?set it in the environment first}"
CF=https://api.cloudflare.com/client/v4
H="Authorization: Bearer $CLOUDFLARE_API_TOKEN"
ZONE_ID=$(curl -s -H "$H" "$CF/zones?name=$ZONE" | python3 -c 'import json,sys; r=json.load(sys.stdin)["result"]; print(r[0]["id"] if len(r)==1 else "")')
test -n "$ZONE_ID" || echo "zone not found or ambiguous; stop and tell the user"
curl -s -H "$H" "$CF/zones/$ZONE_ID/dns_records?name=$RELAY_DOMAIN" | python3 -m json.tool   # 必须为空
```

结果里已有记录（任何类型）时停下来汇报。为空时创建 A 记录（需要 IPv6 时再加一条 `AAAA`）：

```sh
curl -s -X POST -H "$H" -H "Content-Type: application/json" "$CF/zones/$ZONE_ID/dns_records" \
  --data "{\"type\":\"A\",\"name\":\"$RELAY_DOMAIN\",\"content\":\"$SERVER_IPV4\",\"ttl\":1,\"proxied\":false}" \
  | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["success"], d["result"]["id"] if d["success"] else d["errors"])'
dig +short "$RELAY_DOMAIN" @1.1.1.1      # 等到返回 $SERVER_IPV4
```

先完成 DNS，再在 Coolify 里配置域名：Coolify 签发证书需要域名已经解析到这台服务器。

## 2. Coolify 应用

仓库是公开的，Coolify 直接从 GitHub 构建。在用户指定的项目、环境和服务器下新建应用（网页或 API 都可以；用 API
时按这台 Coolify 版本自带的 API 文档填写字段名，不要猜）：

| 设置 | 值 |
|---|---|
| 来源 | 公开仓库 `https://github.com/mario1in/yobiru`，分支 `main` |
| Build Pack | Dockerfile |
| Base Directory | `/` |
| Dockerfile Location | `/deploy/relay/Dockerfile` |
| Ports Exposes | `7790` |
| Ports Mappings | 留空 |
| Domains | `https://RELAY_DOMAIN` |
| 持久存储 | 一个**卷**（volume，不要用 bind mount），挂载到 `/data`，名字如 `yobiru-relay-data` |
| 健康检查 | 用 Dockerfile 自带的 `HEALTHCHECK`；在 Coolify 里配置时用路径 `/v1/health`、端口 `7790` |
| 环境变量 | 不需要 |

`/data` 必须是卷：镜像以 uid 10001 运行，Docker 会让新卷沿用镜像里 `/data` 的属主；bind mount 的目录属于 root，
中继会写不进去。

部署。容器第一次启动时会在 `/data` 里初始化中继（`relay.json`、`relay.sqlite3`），以后重新部署都沿用卷里的数据，
已登记的设备不会丢。日志前两行应为：

```text
{"initialized": "/data", "bind": "0.0.0.0", "port": 7790}
{"listening": "http://0.0.0.0:7790"}
```

（第二次及以后的启动只有第二行。）

## 3. 验证

```sh
curl -s "https://$RELAY_DOMAIN/v1/health"          # {"ok": true, "relay": "yobiru-relay", "v": 1, "relay_id": "..."}
curl -sv "https://$RELAY_DOMAIN/v1/health" 2>&1 | grep -E "subject:|issuer:|expire date"   # 证书有效
curl -s -m 5 "http://$SERVER_IPV4:7790/v1/health" || echo "7790 is not published: good"
```

**长轮询经过代理的测试。** 设备会对中继发起最长 25 秒的请求，确认 Coolify 的代理不会提前断开。下面的命令在中继
容器里执行（Coolify 应用的 Terminal，或在服务器上找到这个容器后用 `docker exec -it 容器 sh`）。它会登记一台叫
`probe` 的临时设备，经公网域名轮询一次，然后把它吊销：

```sh
CODE=$(python3 /app/relay.py server invite --relay-home /data probe | python3 -c 'import json,sys; print(json.load(sys.stdin)["invite"])')
python3 /app/relay.py --home /tmp/probe join "https://RELAY_DOMAIN" --name probe --invite "$CODE"
python3 - <<'EOF'
import importlib.util, time
spec = importlib.util.spec_from_file_location("relay", "/app/relay.py")
relay = importlib.util.module_from_spec(spec); spec.loader.exec_module(relay)
started = time.time()
print("frames:", relay.Device("/tmp/probe").poll(25), "after %.1f s" % (time.time() - started))
EOF
python3 /app/relay.py server revoke --relay-home /data probe
rm -rf /tmp/probe
```

期望：`frames: [] after 25.x s`，没有报错。提前报错或返回 502/504，说明代理的超时比 25 秒短；把现象报告给用户，
不要自己改 Coolify 的全局代理配置。

## 4. 生成邀请码（用户要求时）

在中继容器里，每台设备一个；邀请码一次性、绑定名字、一小时内有效：

```sh
python3 /app/relay.py server invite --relay-home /data work-mini
python3 /app/relay.py server invite --relay-home /data grok
python3 /app/relay.py server devices --relay-home /data
python3 /app/relay.py server revoke --relay-home /data NAME      # 吊销
```

每台设备每个 UTC 日最多经中继转发 8 GiB 密文，超出后报 `quota_exceeded`。用户要求改上限时，在容器里改
`/data/relay.json` 的 `daily_bytes`（字节数，其他字段不动），再在 Coolify 里重启这个应用：

```sh
python3 -c 'import json; p = "/data/relay.json"; c = json.load(open(p)); c["daily_bytes"] = 16 << 30; json.dump(c, open(p, "w"))'
```

## 5. 向用户汇报

- `RELAY_DOMAIN`，DNS 记录的类型、内容、记录 id，以及是否经 Cloudflare 代理
- Coolify 应用的名字和 uuid、卷的名字、部署的提交（应包含 `deploy/relay/Dockerfile`）
- `/v1/health` 的输出和证书有效期
- 7790 端口没有对外开放的确认
- 长轮询测试的结果和耗时
- 遇到但没有处理的问题

以后的升级：在 Coolify 里重新部署这个应用即可（会拉取 `main` 的最新提交）。需要备份的只有 `/data` 这个卷。
附件分块（第 3 阶段）改了中继服务端：在这之前部署的中继要重新部署一次，设备才能经它传附件。
