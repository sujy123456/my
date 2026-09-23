# LunaSieve

LunaSieve 是一个使用 MoonBit 实现的流式敏感信息检测与脱敏引擎。它可以在日志、配置、HTTP 报文和数据导出内容中发现访问令牌、密码、连接串、个人信息与高熵 Secret，并在不泄露原文的前提下生成净化文本和审计报告。

[![CI](https://github.com/sujy123456/my/actions/workflows/ci.yml/badge.svg)](https://github.com/sujy123456/my/actions/workflows/ci.yml)

## MVP 已完成

当前仓库已经具备可直接运行的最小产品闭环：输入文本、检测敏感信息、生成脱敏文本并输出审计报告。无需编写代码即可体验：

```bash
moon run cmd/main -- --text "contact=alice@example.com password=demo-secret"
```

输出 JSON：

```bash
moon run cmd/main -- --text "contact=alice@example.com" --json
```

执行 `moon run cmd/main -- --help` 可查看全部参数。详细验收证据见 [`docs/MVP_ACCEPTANCE.md`](docs/MVP_ACCEPTANCE.md)。示例使用的邮箱和密码均为虚构测试数据，请勿在命令历史中输入真实凭据。

## 特性

- 31 类常见令牌前缀和 113 条敏感配置键规则。
- 邮箱、中国大陆手机号、身份证号、银行卡号、IPv4、JWT、PEM 和连接串检测。
- 高熵令牌发现，并通过语义优先级避免覆盖更明确的检测结果。
- 分块流式扫描，能够发现跨 chunk 的敏感信息。
- 可配置的掩码、替换、删除和稳定哈希脱敏策略。
- 自定义字面量规则、边界模式、大小写模式和显式白名单。
- 多文档扫描、稳定指纹、基线过滤、文本报告和 SARIF 2.1.0 输出。
- 默认不在 Finding 或报告中保存原始 Secret。
- 231 项自动化测试；CI 执行格式、检查、测试、MVP 冒烟验证、Release 构建和打包。

## 安装

```bash
moon add sujy123456/lunasieve
```

在 `moon.pkg` 中导入：

```moonbit nocheck
///|
import {
  "sujy123456/lunasieve",
}
```

## 快速开始

```moonbit nocheck
///|
fn main {
  let input = "user=alice@example.com token=" + "ghp_" +
    "abcdefghijklmnopqrstuvwxyz0123456789"
  let result = @lunasieve.scan(input)
  println("findings: \{result.findings.length()}")
  println(result.redacted)
}
```

运行仓库示例：

```bash
moon run cmd/main
```

## 自定义策略

```moonbit nocheck
///|
let policy = @lunasieve.Policy::new([
  @lunasieve.Rule::new("email", Mask(fill='*', keep_start=2, keep_end=3)),
  @lunasieve.Rule::new("github-pat", Replace("[GITHUB_TOKEN]")),
  @lunasieve.Rule::new("cn-identity", Drop),
])

///|
let result = @lunasieve.Scanner::new(policy~).scan(input)
```

## 流式扫描

`StreamScanner` 保留有限的重叠窗口，因此令牌跨越两个输入块时仍能被识别：

```moonbit nocheck
///|
let stream = @lunasieve.StreamScanner::new(overlap=128)

///|
let first = stream.push("contact alice@")

///|
let second = stream.push("example.com next")

///|
let remaining = stream.finish()
```

## 自定义规则与白名单

```moonbit nocheck
///|
let scanner = @lunasieve.LiteralScanner::new([
  @lunasieve.LiteralRule::new(
    "internal-key",
    "ACME-SECRET",
    boundary=Word,
    case_sensitive=false,
  ),
])

///|
let allowlist = [
  @lunasieve.AllowRule::new(
    detector_id="email",
    exact_value="example@example.com",
    reason="documentation fixture",
  ),
]
```

建议白名单只记录公开测试值，不要把真实 Secret 写入仓库。

## 批量扫描与 SARIF

```moonbit nocheck
let result = @lunasieve.scan_documents([
  @lunasieve.Document::new("service.env", env_text),
  @lunasieve.Document::new("application.log", log_text),
])
println(@lunasieve.batch_to_text(result))
let sarif = @lunasieve.batch_to_sarif(result)
```

每条结果都包含稳定指纹，`filter_new_findings` 可用来过滤历史基线，适合在 CI 中只阻止新增问题。

## 安全边界

- LunaSieve 是检测与脱敏组件，不是凭据保险库。
- Finding 默认只保存位置、类型、置信度及隐藏预览。
- 高熵检测属于启发式规则，应结合语义规则与白名单使用。
- Hash 动作用于稳定关联，不提供密码学不可逆性。
- 核心库处理内存文本；文件遍历、权限和符号链接策略由调用方负责。

## 开发

```bash
moon fmt --check
moon check
moon test
moon build --release
moon package
```

重新生成规则目录测试：

```powershell
./tools/generate_catalog_tests.ps1
```

## 项目结构

- `prefix_detector.mbt`：供应商令牌前缀。
- `contextual_detector.mbt`：配置键、PEM 与连接串。
- `structured_detectors.mbt`：邮箱、手机号、证件、银行卡、IP 和 JWT。
- `entropy_detector.mbt`：高熵令牌。
- `policy.mbt`：重叠消解和脱敏策略。
- `streaming.mbt`：分块流式扫描。
- `custom_rules.mbt`：自定义规则、白名单和位置。
- `batch.mbt`：多文档、基线、文本和 SARIF 报告。
- `docs/ARCHITECTURE.md`：设计与边界。

## 许可证

Apache-2.0。项目为原创实现；使用 Luhn、FNV-1a 等公开算法思想，不复制第三方项目源代码。
