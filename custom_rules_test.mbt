///|
test "literal scanner case sensitive" {
  let scanner = @lunasieve.LiteralScanner::new([
    @lunasieve.LiteralRule::new("tenant-secret", "ACME-SECRET", boundary=Word),
  ])
  assert_eq(scanner.find("use ACME-SECRET here").length(), 1)
  assert_eq(scanner.find("use acme-secret here").length(), 0)
}

///|
test "literal scanner case insensitive" {
  let scanner = @lunasieve.LiteralScanner::new([
    @lunasieve.LiteralRule::new(
      "tenant-secret",
      "ACME-SECRET",
      case_sensitive=false,
      boundary=Word,
    ),
  ])
  assert_eq(scanner.find("use acme-secret here").length(), 1)
}

///|
test "literal word boundary" {
  let scanner = @lunasieve.LiteralScanner::new([
    @lunasieve.LiteralRule::new("word", "secret", boundary=Word),
  ])
  assert_eq(scanner.find("secret").length(), 1)
  assert_eq(scanner.find("secretive").length(), 0)
}

///|
test "literal line boundary" {
  let scanner = @lunasieve.LiteralScanner::new([
    @lunasieve.LiteralRule::new("line", "SECRET", boundary=Line),
  ])
  assert_eq(scanner.find("SECRET\nnext").length(), 1)
  assert_eq(scanner.find("prefix SECRET\n").length(), 0)
}

///|
test "literal replacement" {
  let scanner = @lunasieve.LiteralScanner::new([
    @lunasieve.LiteralRule::new("tenant-secret", "ACME-SECRET"),
  ])
  assert_eq(scanner.redact("value=ACME-SECRET"), "value=[SECRET]")
}

///|
test "allowlist exact value" {
  let text = "mail example@example.com and alice@example.com"
  let findings = @lunasieve.find(text)
  let filtered = @lunasieve.apply_allowlist(text, findings, [
    @lunasieve.AllowRule::new(
      detector_id="email",
      exact_value="example@example.com",
    ),
  ])
  assert_eq(
    filtered.filter(fn(finding) { finding.detector_id == "email" }).length(),
    1,
  )
}

///|
test "allowlist line marker" {
  let text = "email=example@example.com # allow-test\nemail=alice@example.com"
  let findings = @lunasieve.find(text)
  let filtered = @lunasieve.apply_allowlist(text, findings, [
    @lunasieve.AllowRule::new(detector_id="email", line_contains="# allow-test"),
  ])
  assert_eq(
    filtered.filter(fn(finding) { finding.detector_id == "email" }).length(),
    1,
  )
}

///|
test "source location first line" {
  let location = @lunasieve.locate("alpha\nbeta", 3)
  assert_eq(location.line, 1)
  assert_eq(location.column, 4)
}

///|
test "source location second line" {
  let location = @lunasieve.locate("alpha\nbeta", 8)
  assert_eq(location.line, 2)
  assert_eq(location.column, 3)
}

///|
test "located findings text" {
  let text = "header\nmail alice@example.com"
  let report = @lunasieve.located_findings_to_text(
    @lunasieve.locate_findings(text, @lunasieve.find(text)),
  )
  assert_true(report.contains("email at 2:6"))
}
