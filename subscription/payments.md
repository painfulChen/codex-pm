# 支付与云端激活闭环（设计草案）

目标：把 `订阅（本地验签）` 升级为 `订阅（支付闭环 + 可吊销 + 设备绑定/并发）`，且保持“本地优先、云能力可选”。

## 1. 最小闭环（个人开发者版）

1) 用户购买（Stripe Checkout / Gumroad 等）
2) 支付成功触发 Webhook -> License Service 生成签名 License Key
3) 交付 License（成功页展示 + 邮件备份）
4) 客户端粘贴 License：
   - 本地离线验签：防止随便填 key
   - 云端激活（可选）：吊销/设备数限制/并发限制

## 2. 推荐技术方案（Stripe 优先）

### 2.1 Stripe Checkout
- 产品：单一订阅（Pro 月付/年付）起步
- 流程：前端点击“购买” -> 创建 Checkout Session -> Stripe Hosted Checkout -> 回到 success_url

### 2.2 Webhook（支付成功 -> 发码）

> `docs/subscription/license_service.py` 已提供 `POST /v1/webhook/stripe` 的验签骨架（stdlib-only）。

- 事件：`checkout.session.completed`
- 从 event 里取：
  - 邮箱：`data.object.customer_details.email`
  - metadata：`tier / exp / maxDevices / lid`
- 签发：
  - 使用 `PM_LICENSE_PRIVATE_KEY`（私钥不入库）
  - 输出 `licenseKey = base64url(payload).base64url(sig)`
- 落库：
  - 购买记录（eventId/type/receivedAt）
  - License 元数据（tier/maxDevices/expiresAt/issuedAt）

### 2.3 交付（success page）

MVP 选择其一即可：
- 方式 A（最快）：success page 引导用户去邮箱收取 License
- 方式 B（更顺滑）：success page 调用 License Service 获取 licenseKey（需要一次性 token 或 sessionId 绑定，避免被人刷）

## 3. 吊销与退款

- 退款触发：`charge.refunded` / `customer.subscription.deleted` 等
- 动作：对 `licenseId` 执行 `revoke`
- 客户端侧：
  - 既可下次“云端 validate”时发现 revoked
  - 也可在下次“云端 activate”时被拒绝

## 4. 国内支付（后续）

建议路线：
1) 先 Stripe 跑通海外闭环（最快验证订阅价值）
2) 国内再用聚合收款（例如爱发电/小鹅通/第三方聚合）跑通“收款+发码”
3) 最后再考虑自建微信/支付宝直连（复杂、合规成本高）

## 5. 需要补齐的工程项（落到看板）

- 购买页与支付按钮（pricing -> checkout）
- Webhook 部署与密钥管理
- 成功页交付 License（一次性 token）
- 退款吊销链路
- License 服务鉴权/审计/速率限制

