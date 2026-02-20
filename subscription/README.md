# 订阅 MVP：License Key（本地存储 + 可选离线验签）

本工具当前的订阅能力定位为「个人开发者优先」：
- 默认只在本机本地存储 License（`docs/pm-config.json`）。
- 可选启用离线验签（不依赖云端服务），避免“随便填个 key 就算激活”。

## 1. 当前实现（2026-02-13）
- UI：看板 `设置` Tab 内可粘贴/清除 License Key，并展示状态。
- 后端：`POST /api/config`（`action=set_subscription`）会尝试离线验签：
  - 公钥存在：验签并解析 payload，计算 `active/expired/invalid`
  - 公钥缺失：返回 `unverified`

## 2. License Key 格式

```
base64url(payload_json) + "." + base64url(signature_bytes)
```

- `payload_json` 建议字段：
  - `sub`：主体（邮箱/用户标识）
  - `tier`：`free|pro|team`
  - `iat`：签发时间（ISO8601 或 epoch 秒）
  - `exp`：到期时间（ISO8601 或 epoch 秒，可选；不填视为不过期）

验签算法：
- `RSA-SHA256`（对 `payload_json` 的原始 bytes 做签名）
- 使用 `docs/subscription/public_key.pem` 进行验签

## 3. 生成公私钥（仅本机）

私钥不要放进仓库。建议放到 `~/.codex/pm-subscription/`：

```bash
mkdir -p ~/.codex/pm-subscription
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out ~/.codex/pm-subscription/private_key.pem
openssl rsa -pubout -in ~/.codex/pm-subscription/private_key.pem -out ./coach-feishu-suite/docs/subscription/public_key.pem
```

## 4. 生成一个 License Key（示例）

1) 准备 payload：

```bash
cat > /tmp/pm_license_payload.json <<'JSON'
{
  "sub": "you@example.com",
  "tier": "pro",
  "iat": "2026-02-13T00:00:00+08:00",
  "exp": "2026-03-13T00:00:00+08:00"
}
JSON
```

2) 生成签名：

```bash
openssl dgst -sha256 -sign ~/.codex/pm-subscription/private_key.pem -out /tmp/pm_license_sig.bin /tmp/pm_license_payload.json
```

3) 组装 key（macOS 自带 `base64` 默认会换行，这里用 `tr -d` 去掉换行）：

```bash
payload=$(base64 -i /tmp/pm_license_payload.json | tr -d '\n' | tr '+/' '-_' | tr -d '=')
sig=$(base64 -i /tmp/pm_license_sig.bin | tr -d '\n' | tr '+/' '-_' | tr -d '=')
echo "${payload}.${sig}"
```

把输出粘贴到看板 `设置 -> 订阅（MVP）` 里保存即可。

## 5. 后续规划（不在 MVP 内）
- Stripe/国内支付接入
- 云端 License 服务（可吊销/设备绑定/并发限制）
- 团队版：云同步、权限、审计

## 6. 云端激活（本地 mock，可跑）

目标：在“离线验签”之外补齐商业化必须能力：
- 吊销（revocation）
- 设备绑定（device binding）
- 并发/设备数限制（concurrency）

本仓库提供一个 stdlib-only 的本地 mock 服务：`docs/subscription/license_service.py`。

启动：

```bash
export PM_LICENSE_ADMIN_TOKEN="dev-admin-token"
export PM_LICENSE_PRIVATE_KEY="$HOME/.codex/pm-subscription/private_key.pem"
python3 ./coach-feishu-suite/docs/subscription/license_service.py
```

默认监听 `http://127.0.0.1:8789`，数据落盘到：
- `~/.codex/pm-license-service/store.json`

健康检查：

```bash
curl -sS http://127.0.0.1:8789/healthz
```

### 6.1 管理端：签发 License（HTTP）

> 仅用于本地 mock / 开发联调。生产环境建议把签发能力放在云端服务内，并做好审计与权限。

```bash
curl -sS -X POST http://127.0.0.1:8789/v1/issue \
  -H "Authorization: Bearer dev-admin-token" \
  -H "Content-Type: application/json" \
  -d '{"sub":"you@example.com","tier":"pro","exp":"2026-03-13T00:00:00+08:00","maxDevices":2}'
```

返回：
- `licenseKey`：可直接粘贴到看板 `设置 -> 订阅（MVP）`
- `licenseId`：可用于 revoke / 查询

## 7. 在看板 UI 里启用云端激活

1) 打开 `设置 -> 云端激活`：
- 模式选 `云端`
- 激活服务地址填 `http://127.0.0.1:8789`
- 点“保存设置”

2) 粘贴 License Key 后，点击“执行云端激活”。

说明：
- 云端激活不会替代离线验签结果；它提供额外约束（吊销/设备数）。
- 真正云端部署时，只需要把 `license_service.py` 的存储替换为 DB（SQLite/Postgres）并做鉴权/审计即可。

## 8. 管理端：签发 License（脚本）

你可以用脚本更快签发 License Key（依旧使用 `openssl`）：

```bash
python3 ./coach-feishu-suite/docs/subscription/issue_license.py --sub you@example.com --tier pro --exp 2026-03-13T00:00:00+08:00 --max-devices 2
```

私钥默认读取：
- `~/.codex/pm-subscription/private_key.pem`

注意：私钥不要入库。

## 9. 支付与云端激活闭环（Stripe Webhook 骨架）

`license_service.py` 内置一个不依赖第三方库的 Stripe Webhook 验签骨架：
- `POST /v1/webhook/stripe`（需要 `STRIPE_WEBHOOK_SECRET`）
- 处理 `checkout.session.completed` 时（并配置了 `PM_LICENSE_PRIVATE_KEY`）会自动签发 License 并落库

> 该骨架用于把“支付成功 -> 发 License -> 可云端激活”串起来，生产环境仍需要补齐：邮件交付/成功页交付、退款吊销、风控/审计、购买记录查询等。
