///|
fn assert_has_detector(text : String, detector : String) -> Unit raise {
  let result = @lunasieve.scan(text)
  assert_true(
    result.findings.any(fn(finding) { finding.detector_id == detector }),
  )
}

///|
fn assert_no_detector(text : String, detector : String) -> Unit raise {
  let result = @lunasieve.scan(text)
  assert_false(
    result.findings.any(fn(finding) { finding.detector_id == detector }),
  )
}

///|
test "complete JSON report contains redacted output and summary" {
  let input = "contact=alice@example.com"
  let report = @lunasieve.scan_result_to_json(@lunasieve.scan(input))
  assert_true(report.contains("\"redacted\":\"contact=al************com\""))
  assert_true(report.contains("\"total\":1"))
  assert_true(report.contains("\"detector\":\"email\""))
  assert_false(report.contains("alice@example.com"))
}

///|
test "JSON report escapes all control characters" {
  let input = "line\u0001\b\f\n\r\tend"
  let report = @lunasieve.scan_result_to_json(@lunasieve.scan(input))
  assert_true(report.contains("line\\u0001\\b\\f\\n\\r\\tend"))
  assert_false(report.contains("\u0001"))
}

///|
test "text report demonstrates the scan-to-redaction workflow" {
  let report = @lunasieve.scan_result_to_text(
    @lunasieve.scan("phone=13800138000"),
  )
  assert_true(report.contains("LunaSieve scan completed"))
  assert_true(report.contains("findings: 1"))
  assert_true(report.contains("cn-phone"))
  assert_false(report.contains("13800138000"))
}

///|
test "github personal access token" {
  assert_has_detector(
    "token=" + "ghp_" + "abcdefghijklmnopqrstuvwxyz0123456789",
    "github-pat",
  )
}

///|
test "github oauth token" {
  assert_has_detector(
    "token=" + "gho_" + "abcdefghijklmnopqrstuvwxyz0123456789",
    "github-oauth",
  )
}

///|
test "gitlab personal access token" {
  assert_has_detector(
    "GLPAT=" + "glpat-" + "abcdefghijklmnopqrstuv",
    "gitlab-pat",
  )
}

///|
test "openai project key" {
  assert_has_detector(
    "OPENAI_API_KEY=" + "sk-proj-" + "abcdefghijklmnopqrstuvwxyz012345",
    "openai-project-key",
  )
}

///|
test "anthropic key" {
  assert_has_detector(
    "ANTHROPIC_API_KEY=" + "sk-ant-" + "abcdefghijklmnopqrstuvwxyz012345",
    "anthropic-key",
  )
}

///|
test "slack bot token" {
  assert_has_detector(
    "xoxb-" + "123456789012-abcdefghijklmnopqrstuv",
    "slack-bot",
  )
}

///|
test "slack app token" {
  assert_has_detector(
    "xapp-" + "1-ABCDEFGHIJKLMNOPQRSTUV-abcdefghijklmnop",
    "slack-app",
  )
}

///|
test "stripe live secret" {
  assert_has_detector(
    "sk_live_" + "abcdefghijklmnopqrstuvwxyz012345",
    "stripe-live-secret",
  )
}

///|
test "stripe test secret" {
  assert_has_detector(
    "sk_test_" + "abcdefghijklmnopqrstuvwxyz012345",
    "stripe-test-secret",
  )
}

///|
test "npm token" {
  assert_has_detector("npm_" + "abcdefghijklmnopqrstuvwxyz012345", "npm-token")
}

///|
test "pypi token" {
  assert_has_detector(
    "pypi-" + "abcdefghijklmnopqrstuvwxyz0123456789",
    "pypi-token",
  )
}

///|
test "sendgrid key" {
  assert_has_detector(
    "SG." + "abcdefghijklmnopqrstuv.wxzy0123456789ABCDEFGHIJKLMNOP",
    "sendgrid-key",
  )
}

///|
test "huggingface token" {
  assert_has_detector(
    "hf_" + "abcdefghijklmnopqrstuvwxyz012345",
    "huggingface-token",
  )
}

///|
test "digitalocean token" {
  assert_has_detector(
    "dop_v1_" + "abcdefghijklmnopqrstuvwxyz012345",
    "digitalocean-token",
  )
}

///|
test "linear key" {
  assert_has_detector(
    "lin_api_" + "abcdefghijklmnopqrstuvwxyz012345",
    "linear-key",
  )
}

///|
test "vault service token" {
  assert_has_detector(
    "hvs." + "abcdefghijklmnopqrstuvwxyz012345",
    "vault-service-token",
  )
}

///|
test "email address" {
  assert_has_detector("contact alice@example.com for help", "email")
}

///|
test "email requires domain dot" {
  assert_no_detector("contact alice@localhost for help", "email")
}

///|
test "mainland phone" {
  assert_has_detector("call 13800138000 tomorrow", "cn-phone")
}

///|
test "short phone ignored" {
  assert_no_detector("call 1380013800 tomorrow", "cn-phone")
}

///|
test "payment card luhn" {
  assert_has_detector("card=4111111111111111", "bank-card")
}

///|
test "payment card invalid checksum" {
  assert_no_detector("card=4111111111111112", "bank-card")
}

///|
test "ipv4 address" {
  assert_has_detector("peer 192.168.10.24 connected", "ipv4")
}

///|
test "invalid ipv4 octet" {
  assert_no_detector("peer 999.168.10.24 rejected", "ipv4")
}

///|
test "jwt three segments" {
  assert_has_detector(
    "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijklmnop", "jwt",
  )
}

///|
test "password assignment" {
  assert_has_detector(
    "password = correct-horse-battery-staple", "generic-password",
  )
}

///|
test "quoted password assignment" {
  assert_has_detector(
    "password: \"correct-horse-battery-staple\"", "generic-password",
  )
}

///|
test "password word without assignment" {
  assert_no_detector("password policy documentation", "generic-password")
}

///|
test "aws secret assignment" {
  assert_has_detector(
    "AWS_SECRET_ACCESS_KEY=abcdefghijklmnopqrstuvwxyz012345", "aws-secret-key",
  )
}

///|
test "openai environment assignment" {
  assert_has_detector(
    "OPENAI_API_KEY=abcdefghijklmnopqrstuvwxyz012345", "openai-key",
  )
}

///|
test "database URL assignment" {
  assert_has_detector(
    "DATABASE_URL=postgres://alice:secret@db.local/app", "database-url",
  )
}

///|
test "credential URL" {
  assert_has_detector(
    "connect postgres://alice:secret@db.local/app now", "credential-url",
  )
}

///|
test "URL without password ignored by credential detector" {
  assert_no_detector("connect postgres://db.local/app now", "credential-url")
}

///|
test "private key PEM" {
  assert_has_detector(
    "-----BEGIN PRIVATE KEY-----\nQUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=\n-----END PRIVATE KEY-----",
    "pem-block",
  )
}

///|
test "certificate PEM" {
  assert_has_detector(
    "-----BEGIN CERTIFICATE-----\nQUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=\n-----END CERTIFICATE-----",
    "pem-block",
  )
}

///|
test "high entropy token" {
  assert_has_detector("value=A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6", "high-entropy")
}

///|
test "natural prose is not high entropy" {
  assert_no_detector(
    "thisisalongnaturalenglishwordwithmanyvowels", "high-entropy",
  )
}

///|
test "default output hides preview" {
  let findings = @lunasieve.find("alice@example.com")
  assert_eq(findings[0].preview, "[hidden]")
}

///|
test "preview can be enabled" {
  let options = @lunasieve.ScanOptions::{
    ..@lunasieve.ScanOptions::default(),
    include_preview: true,
  }
  let findings = @lunasieve.Scanner::new(options~).find("alice@example.com")
  assert_true(findings[0].preview != "[hidden]")
}

///|
test "redacts email" {
  let output = @lunasieve.redact_text("mail alice@example.com now")
  assert_eq(output, "mail al************com now")
}

///|
test "redacts phone" {
  let output = @lunasieve.redact_text("call 13800138000 now")
  assert_eq(output, "call 138****8000 now")
}

///|
test "redacts card" {
  let output = @lunasieve.redact_text("card 4111111111111111")
  assert_eq(output, "card 4111********1111")
}

///|
test "hash action stable" {
  let finding = @lunasieve.Finding::new(
    "custom",
    Custom,
    High,
    0,
    6,
    100,
    "[hidden]",
    "custom",
  )
  let policy = @lunasieve.Policy::new([@lunasieve.Rule::new("custom", Hash)])
  let first = @lunasieve.redact("secret", [finding], policy~)
  let second = @lunasieve.redact("secret", [finding], policy~)
  assert_eq(first, second)
}

///|
test "drop action" {
  let finding = @lunasieve.Finding::new(
    "custom",
    Custom,
    High,
    1,
    4,
    100,
    "[hidden]",
    "custom",
  )
  let policy = @lunasieve.Policy::new([@lunasieve.Rule::new("custom", Drop)])
  assert_eq(@lunasieve.redact("abcde", [finding], policy~), "ae")
}

///|
test "replacement action" {
  let finding = @lunasieve.Finding::new(
    "custom",
    Custom,
    High,
    1,
    4,
    100,
    "[hidden]",
    "custom",
  )
  let policy = @lunasieve.Policy::new([
    @lunasieve.Rule::new("custom", Replace("X")),
  ])
  assert_eq(@lunasieve.redact("abcde", [finding], policy~), "aXe")
}

///|
test "severity ranks" {
  assert_true(@lunasieve.Critical.rank() > @lunasieve.High.rank())
  assert_true(@lunasieve.High.rank() > @lunasieve.Medium.rank())
  assert_true(@lunasieve.Medium.rank() > @lunasieve.Low.rank())
  assert_true(@lunasieve.Low.rank() > @lunasieve.Info.rank())
}

///|
test "span length" {
  let span = @lunasieve.Span::new(4, 12) catch {
    _ => abort("unexpected span error")
  }
  assert_eq(span.length(), 8)
}

///|
test "span overlap" {
  let a = @lunasieve.Span::new(4, 12) catch {
    _ => abort("unexpected span error")
  }
  let b = @lunasieve.Span::new(10, 20) catch {
    _ => abort("unexpected span error")
  }
  let c = @lunasieve.Span::new(12, 20) catch {
    _ => abort("unexpected span error")
  }
  assert_true(a.overlaps(b))
  assert_false(a.overlaps(c))
}

///|
test "summary counts severity" {
  let findings = [
    @lunasieve.Finding::new("a", Custom, Critical, 0, 1, 100, "", ""),
    @lunasieve.Finding::new("b", Custom, High, 2, 3, 100, "", ""),
    @lunasieve.Finding::new("c", Custom, High, 4, 5, 100, "", ""),
  ]
  let summary = @lunasieve.summarize(findings)
  assert_eq(summary.total, 3)
  assert_eq(summary.critical, 1)
  assert_eq(summary.high, 2)
}

///|
test "json report contains no raw secret" {
  let result = @lunasieve.scan("email=alice@example.com")
  let report = @lunasieve.findings_to_json(result.findings)
  assert_true(report.contains("email"))
  assert_false(report.contains("alice@example.com"))
}

///|
test "findings sorted by position" {
  let findings = @lunasieve.find("mail alice@example.com card 4111111111111111")
  for i = 1; i < findings.length(); i = i + 1 {
    assert_true(findings[i - 1].span.start <= findings[i].span.start)
  }
}

///|
test "overlapping entropy result removed" {
  let findings = @lunasieve.find(
    "ghp_" + "abcdefghijklmnopqrstuvwxyz0123456789",
  )
  assert_eq(findings.length(), 1)
  assert_eq(findings[0].detector_id, "github-pat")
}

///|
test "empty input" {
  let result = @lunasieve.scan("")
  assert_eq(result.input_length, 0)
  assert_eq(result.findings.length(), 0)
  assert_eq(result.redacted, "")
}

///|
test "benign configuration" {
  let result = @lunasieve.scan("host=localhost\nport=8080\ndebug=true")
  assert_eq(result.findings.length(), 0)
}

///|
test "multiple findings" {
  let result = @lunasieve.scan(
    "email=alice@example.com\nphone=13800138000\ncard=4111111111111111",
  )
  assert_true(result.findings.length() >= 3)
  assert_false(result.redacted.contains("alice@example.com"))
  assert_false(result.redacted.contains("13800138000"))
  assert_false(result.redacted.contains("4111111111111111"))
}

///|
test "stream buffers short chunks" {
  let stream = @lunasieve.StreamScanner::new(overlap=64)
  let first = stream.push("contact alice@") catch {
    _ => abort("unexpected stream error")
  }
  assert_eq(first.length(), 0)
  let second = stream.push("example.com now") catch {
    _ => abort("unexpected stream error")
  }
  assert_eq(second.length(), 0)
  let final_findings = stream.finish() catch {
    _ => abort("unexpected stream error")
  }
  assert_true(
    final_findings.any(fn(finding) { finding.detector_id == "email" }),
  )
}

///|
test "stream absolute offsets" {
  let stream = @lunasieve.StreamScanner::new(overlap=32)
  let prefix = "abcdefghijklmnopqrstuvwxyz0123456789"
  ignore(stream.push(prefix) catch { _ => abort("unexpected stream error") })
  ignore(
    stream.push(" mail alice@example.com") catch {
      _ => abort("unexpected stream error")
    },
  )
  let final_findings = stream.finish() catch {
    _ => abort("unexpected stream error")
  }
  assert_true(
    final_findings.any(fn(finding) { finding.detector_id == "email" }),
  )
}

///|
test "stream cannot finish twice" {
  let stream = @lunasieve.StreamScanner::new()
  ignore(stream.finish() catch { _ => abort("first finish failed") })
  let mut failed = false
  ignore(stream.finish()) catch {
    _ => failed = true
  }
  assert_true(failed)
}
