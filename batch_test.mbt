///|
test "batch scans multiple documents" {
  let result = @lunasieve.scan_documents([
    @lunasieve.Document::new("a.env", "email=alice@example.com"),
    @lunasieve.Document::new("b.env", "phone=13800138000"),
  ])
  assert_eq(result.summary.documents, 2)
  assert_true(result.summary.findings >= 2)
  assert_true(result.findings.any(fn(item) { item.path == "a.env" }))
  assert_true(result.findings.any(fn(item) { item.path == "b.env" }))
}

///|
test "batch redaction keeps document paths and isolates contents" {
  let redacted = @lunasieve.redact_documents([
    @lunasieve.Document::new("first.env", "password=first-secret"),
    @lunasieve.Document::new("second.txt", "ordinary text"),
  ])
  assert_eq(redacted.length(), 2)
  assert_eq(redacted[0].path, "first.env")
  assert_eq(redacted[0].content, "password=[SECRET]")
  assert_eq(redacted[1].path, "second.txt")
  assert_eq(redacted[1].content, "ordinary text")
}

///|
test "batch summary severities" {
  let result = @lunasieve.scan_documents([
    @lunasieve.Document::new(
      "config.env", "password=correct-horse-battery-staple",
    ),
  ])
  assert_true(result.summary.critical >= 1)
}

///|
test "batch detector counts" {
  let result = @lunasieve.scan_documents([
    @lunasieve.Document::new(
      "contacts.txt", "alice@example.com bob@example.com",
    ),
  ])
  let email_count = result.summary.by_detector.filter(fn(item) {
    item.detector_id == "email"
  })
  assert_eq(email_count.length(), 1)
  assert_eq(email_count[0].count, 2)
}

///|
test "batch fingerprints stable" {
  let documents = [
    @lunasieve.Document::new("config.env", "email=alice@example.com"),
  ]
  let first = @lunasieve.scan_documents(documents)
  let second = @lunasieve.scan_documents(documents)
  assert_eq(first.findings[0].fingerprint, second.findings[0].fingerprint)
}

///|
test "batch fingerprints depend on path" {
  let first = @lunasieve.scan_documents([
    @lunasieve.Document::new("a.env", "email=alice@example.com"),
  ])
  let second = @lunasieve.scan_documents([
    @lunasieve.Document::new("b.env", "email=alice@example.com"),
  ])
  assert_true(first.findings[0].fingerprint != second.findings[0].fingerprint)
}

///|
test "filter known findings" {
  let result = @lunasieve.scan_documents([
    @lunasieve.Document::new("a.env", "email=alice@example.com"),
  ])
  let known = [result.findings[0].fingerprint]
  assert_eq(@lunasieve.filter_new_findings(result.findings, known).length(), 0)
}

///|
test "SARIF envelope" {
  let result = @lunasieve.scan_documents([
    @lunasieve.Document::new("a.env", "email=alice@example.com"),
  ])
  let sarif = @lunasieve.batch_to_sarif(result)
  assert_true(sarif.contains("\"version\":\"2.1.0\""))
  assert_true(sarif.contains("LUNASIEVE/email"))
  assert_true(sarif.contains("a.env"))
  assert_false(sarif.contains("alice@example.com"))
}

///|
test "text report" {
  let result = @lunasieve.scan_documents([
    @lunasieve.Document::new("a.env", "email=alice@example.com"),
  ])
  let text = @lunasieve.batch_to_text(result)
  assert_true(text.contains("a.env:1:7"))
  assert_true(text.contains("found 1 issue"))
}

///|
test "batch allowlist" {
  let result = @lunasieve.scan_documents(
    [@lunasieve.Document::new("fixture.txt", "email=example@example.com")],
    allowlist=[
      @lunasieve.AllowRule::new(
        detector_id="email",
        exact_value="example@example.com",
      ),
    ],
  )
  assert_eq(result.summary.findings, 0)
}

///|
test "batch empty input" {
  let result = @lunasieve.scan_documents([])
  assert_eq(result.summary.documents, 0)
  assert_eq(result.summary.bytes, 0)
  assert_eq(result.summary.findings, 0)
  assert_eq(result.findings.length(), 0)
}
