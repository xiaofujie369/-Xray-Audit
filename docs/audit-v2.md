# V2：大陆屏蔽事件调查

版本 `2.1.0-dev`。本次按维护者要求直接开发交付，不执行本地测试、构建或部署验证。新增回归测试和 CI 配置随代码交付，运行结果需在部署环境确认。

## 已有中央服务器升级

先升级中央，再升级 Probe。以下命令保留现有 `.env`、数据库凭据、账户及数据卷，并在迁移前备份数据库。

```bash
cd /opt/xray-audit-src
git pull --ff-only origin main
bash audit-server/update-central.sh /root/audit-v2-backup-$(date -u +%Y%m%d-%H%M%S) --retention-seven-days --https
```

使用自有 Nginx 等 HTTPS 反向代理时省略 `--https`。脚本构建镜像后暂停中央数据库写入服务，执行迁移，再启动服务；不会触碰各 VPS 的 Xray、XBoard 同步或上报。升级期间 Agent/Probe 通过本地 SQLite spool 重试。

`--retention-seven-days` 显式将普通访问明细、用户流量改为 7 天；事件证据、关联记录和小时基线改为 90 天。它写入数据库设置，优先于旧 `.env` 中的保留期。省略此参数会保留已有设置。尚未恢复的事件及手动事件不自动清除；恢复事件在恢复后保留 90 天。7 天不是 IP 必然恢复的期限。

迁移会标记旧事件重新生成调查快照，并对已有访问明细分批回填小时基线。后台“系统状态”的 `baseline_backfill` 显示游标与边界；两者相等表示回填完成。回填及待处理调查完成前暂缓访问明细清理，磁盘使用可能暂时高于 7 天目标。基线摘要保留按小时、按对象的 HMAC 标识与计数，不保存原始访问组合；请保留原 `APP_SECRET`，更换它会切断新旧标识的连续性。

## Probe 更新与判定条件

在每台已安装的大陆和境外 Probe 上：

```bash
cd /opt/xray-audit-src
git pull --ff-only origin main
bash probe/update-probe.sh
```

更新保留 `/opt/xray-probe/config.json` 和 SQLite spool，无需重新注册。原代码备份路径会显示在终端。新 Probe 必须连接已升级中央；旧 Probe 上传仍被接受，但缺少对照配置版本的结果不能满足 V2 确认条件。

需要至少两组独立大陆网络、至少一组境外网络。在后台“Agent / Probe”中正确设置大陆标记和独立网络组；同一网络的多个凭据使用同一组，未填写组不能作为多个独立网络。境外组必须与大陆组不同。添加境外 Probe 的方式与大陆相同，只是不勾选“大陆探测点”。

设置可靠且实际可达的 `control_targets`（管理员选择的公网 IP/端口），并为 VPS 添加真实服务端口的探测目标。默认每 300 秒探测一次；可调整 `probe_interval_seconds`。每分钟调查调度不等于每分钟探测，也不保证每分钟出一份 AI 报告。

V2 `CONFIRMED` 在界面显示为“符合屏蔽特征”，需要同时满足：

- 至少两组独立大陆网络达到连续失败阈值，且对照目标正常、配置版本一致。
- 至少一组独立境外网络达到连续成功阈值，对照配置版本一致；同组矛盾结果不计为支持证据。
- 已配置对照目标，VPS 最近 180 秒有 Agent 心跳且报告 Xray 正在运行。

证据不足保持 `SUSPECTED`，并显示缺失项。恢复需要大陆成功共识；疑似后恢复仍保留事件，不声称已经证明误报。历史已确认事件保留当时状态，但详情显示当时依据和新版条件是否满足，不能把 V1 判定当作 V2 对照确认。没有近期探测证据不等于正常。TCP 拒绝、TLS/HTTP 错误等不会直接归为屏蔽。

这些条件只支持区域不可达/屏蔽特征调查，不能证明过滤机制或某个访问对象引发屏蔽。不同协议/端口可能表现不同。

## 调查页面

进入“被墙事件 → 查看”：

- 查看最后正常至首次异常的时间区间。
- 切换事件前 15、30、60 分钟窗口；对象连接统计每类最多 50 项。
- 查看正常时期基线校正后的关联度及评分解释。此评分使用该事件配置的调查窗口，上方窗口切换不会改变评分。
- 点击用户、来源 IP、域名或目标 IP，查看跨事件、跨 VPS 关联记录。详情最多显示 100 条，完整翻页在“关联度”页面。
- 查看保存的探测共识和版本化调查快照。旧明细过期后，已保存证据仍可阅读；不存在的历史明细不会被补造。

每分钟调度新事件/发生变化的调查；上传补传数据会触发相关事件重算。相同快照内容按哈希去重，跨事件评分变化也会刷新相关快照。小时基线优先采用前 7 天同小时，样本不足时采用前 24 小时且排除事件窗口；它是小时级统计，不声称具有完整逐连接精度。明细缺失不代表没有活动，热门对象也不能因为访问量大而被认定为原因。

## 可选 AI

AI 默认关闭。编辑中央 `audit-server/.env`，加入：

```dotenv
AI_API_URL=https://YOUR-PROVIDER/v1/chat/completions
AI_API_KEY=YOUR-PRIVATE-KEY
AI_MODEL=YOUR-PROVIDER-MODEL-ID
```

使用供应商支持 JSON 输出的 Chat Completions 完整 HTTPS 地址和实际模型 ID；不要把示例占位符直接投入使用。实现使用 `messages`、`response_format: json_object`、`max_tokens`，例如 [DeepSeek Chat Completions 文档](https://api-docs.deepseek.com/api/create-chat-completion/) 描述的协议。不同服务的参数兼容性需部署验证；不支持的响应会记录失败状态。

保存后重新创建中央容器以载入环境变量：

```bash
cd /opt/xray-audit-src/audit-server
chmod 600 .env
docker compose up -d --force-recreate audit-api audit-worker audit-ai-worker audit-scheduler
```

然后进入“AI 调查”，确认发送范围并启用。每日默认最多 100 次请求，同一事件默认间隔 300 秒，每次默认最多输出 2000 token。失败请求也计入额度，额度按 UTC 日期重置；这是请求次数上限，不是金额保证。单独 AI worker 每分钟处理最多一个报告，积压时会延迟。没有新证据不会重复调用模型。

仅发送对象 HMAC 别名、统计计数、时间及探测结果。不发送真实用户 ID、IP、域名、备注、原始日志或代理凭据。服务器保存的本地证据仍含调查所需标识，仅受已登录账户/RBAC 保护；备份包含敏感数据。

报告只读，不具备修改代理、封禁用户、改路由或重启服务的工具。外部 HTTP 请求在独立进程执行，不持有数据库事务；30 秒网络超时、独立任务超时、租约和最多三次重试限制失败影响。网络中断存在供应商已计费但本地未收到响应的可能，重试仍受每日额度约束。

在事件详情选择报告即可切换到它引用的证据版本；点击 `E0`、`W15/W30/W60`、`C…`、`P…` 定位对应证据。报告是辅助分析，应人工核查，不能当作屏蔽原因的证明。

## 部署后观察与回滚

```bash
cd /opt/xray-audit-src/audit-server
docker compose ps
docker compose logs --tail=100 audit-api audit-worker audit-ai-worker audit-scheduler
```

先确认登录和探测入库，再观察共识、补传后的快照、正常基线以及可选 AI 报告。“系统状态”提供任务数、AI 失败数、基线回填进度和 AI worker 最后活动时间。

恢复数据：`bash audit-server/restore.sh /root/你的备份目录`，输入 `RESTORE` 后在事务中替换中央 schema，再执行当前代码迁移。恢复 V1 数据也可由 V2 迁移读取；恢复旧代码时先停止中央服务，切回对应 Git 提交，再按该版本恢复流程处理。不要只降级代码而让旧程序继续写入新 schema。备份中的 `.env` 应妥善保存，恢复脚本不会自动覆盖现有凭据。
