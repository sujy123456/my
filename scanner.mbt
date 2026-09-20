///|
pub(all) struct Scanner {
  options : ScanOptions
  policy : Policy
}

///|
pub fn Scanner::new(
  options? : ScanOptions = ScanOptions::default(),
  policy? : Policy = Policy::secure_default(),
) -> Scanner {
  { options, policy }
}

///|
pub fn Scanner::find(self : Scanner, text : String) -> Array[Finding] {
  let chars = text.to_array()
  let findings : Array[Finding] = []
  for finding in scan_all_prefixes(chars, self.options.include_preview) {
    findings.push(finding)
  }
  for finding in scan_structured(chars, self.options.include_preview) {
    findings.push(finding)
  }
  for
    finding in scan_contextual_assignments(chars, self.options.include_preview) {
    findings.push(finding)
  }
  for finding in scan_pem_blocks(chars, self.options.include_preview) {
    findings.push(finding)
  }
  for finding in scan_connection_strings(chars, self.options.include_preview) {
    findings.push(finding)
  }
  if self.options.detect_entropy {
    for finding in scan_entropy(chars, self.options) {
      findings.push(finding)
    }
  }
  if self.options.merge_overlaps {
    remove_overlaps(findings)
  } else {
    sort_findings(findings)
  }
}

///|
pub fn Scanner::scan(self : Scanner, text : String) -> ScanResult {
  let findings = self.find(text)
  {
    input_length: text.to_array().length(),
    findings,
    redacted: redact(text, findings, policy=self.policy),
  }
}

///|
pub fn scan(text : String) -> ScanResult {
  Scanner::new().scan(text)
}

///|
pub fn find(text : String) -> Array[Finding] {
  Scanner::new().find(text)
}

///|
pub fn redact_text(text : String) -> String {
  Scanner::new().scan(text).redacted
}
