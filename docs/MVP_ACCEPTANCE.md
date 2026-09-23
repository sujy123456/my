# MVP 验收记录

## 验收结论

LunaSieve 已完成最小可行产品闭环：用户提交一段文本后，程序能够检测敏感信息、按默认安全策略脱敏，并输出人类可读或 JSON 报告。整个流程可以在本地离线运行，不依赖外部服务。

## 核心流程

```text
文本输入 -> 多检测器扫描 -> 重叠结果消解 -> 脱敏策略 -> 安全报告
```

## 一分钟复现

安装 MoonBit 后，在仓库根目录执行：

```bash
moon run cmd/main -- --text "contact=alice@example.com password=demo-secret"
```

预期结果应包含：

```text
findings: 2
redacted: contact=al************com password=[SECRET]
email
generic-password
```

机器可读输出：

```bash
moon run cmd/main -- --text "contact=alice@example.com" --json
```

## MVP 验收清单

| 能力 | 验收方式 | 状态 |
| --- | --- | --- |
| 敏感信息输入 | `--text` 接收用户文本 | 已完成 |
| 结构化与令牌检测 | 邮箱、手机号、证件、令牌、配置键等检测器 | 已完成 |
| 自动脱敏 | 默认掩码和固定替换策略 | 已完成 |
| 人类可读报告 | 显示统计、风险等级、位置和脱敏文本 | 已完成 |
| JSON 报告 | `--json` 输出完整扫描结果 | 已完成 |
| 隐私保护 | Finding 与报告不保存原始 Secret | 已完成 |
| 自动化验证 | 231 项测试与 GitHub Actions CI | 已完成 |
| 发布准备 | `moon package` 可生成 Mooncakes 包 | 已完成 |

## 验证命令

```bash
moon fmt --check
moon check
moon test
moon build --release
moon package
```

## MVP 边界

当前版本定位为可嵌入 MoonBit 应用的检测与脱敏引擎，并提供最小 CLI 演示。目录递归扫描、操作系统文件权限管理和 Web 控制台不属于本次 MVP；这些能力不会影响核心扫描 API 的使用。

