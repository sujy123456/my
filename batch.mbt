///|
pub(all) struct Document {
  path : String
  content : String
} derive(Eq, Debug)

///|
pub fn Document::new(path : String, content : String) -> Document {
  { path, content, }
}

///|
pub(all) struct DocumentFinding {
  path : String
  finding : Finding
  start : SourceLocation
  end : SourceLocation
  fingerprint : String
} derive(Eq, Debug)

///|
pub(all) struct DetectorCount {
  detector_id : String
  count : Int
} derive(Eq, Debug)

///|
pub(all) struct BatchSummary {
  documents : Int
  bytes : Int
  findings : Int
  critical : Int
  high : Int
  medium : Int
  low : Int
  info : Int
  by_detector : Array[DetectorCount]
} derive(Eq, Debug)

///|
pub(all) struct BatchResult {
  findings : Array[DocumentFinding]
  summary : BatchSummary
} derive(Eq, Debug)

///|
fn fingerprint_for(path : String, finding : Finding) -> String {
  let identity = path +
    "\u0000" +
    finding.detector_id +
    "\u0000" +
    finding.span.start.to_string() +
    "\u0000" +
    finding.span.end.to_string()
  fnv1a(identity).to_string(radix=16)
}

///|
fn to_document_finding(
  document : Document,
  finding : Finding,
) -> DocumentFinding {
  {
    path: document.path,
    finding,
    start: locate(document.content, finding.span.start),
    end: locate(document.content, finding.span.end),
    fingerprint: fingerprint_for(document.path, finding),
  }
}

///|
fn compare_document_findings(
  left : DocumentFinding,
  right : DocumentFinding,
) -> Int {
  let path_order = left.path.compare(right.path)
  if path_order != 0 {
    path_order
  } else if left.finding.span.start != right.finding.span.start {
    left.finding.span.start.compare(right.finding.span.start)
  } else {
    left.finding.detector_id.compare(right.finding.detector_id)
  }
}

///|
fn detector_counts(findings : Array[DocumentFinding]) -> Array[DetectorCount] {
  let counts : Map[String, Int] = Map([])
  for item in findings {
    let current = match counts.get(item.finding.detector_id) {
      Some(value) => value
      None => 0
    }
    counts[item.finding.detector_id] = current + 1
  }
  let out : Array[DetectorCount] = []
  counts.each(fn(key, value) { out.push({ detector_id: key, count: value, }) })
  out.sort_by(fn(left, right) {
    if left.count != right.count {
      right.count.compare(left.count)
    } else {
      left.detector_id.compare(right.detector_id)
    }
  })
  out
}

///|
fn batch_summary(
  documents : Array[Document],
  findings : Array[DocumentFinding],
) -> BatchSummary {
  let mut bytes = 0
  for document in documents {
    bytes = bytes + document.content.to_array().length()
  }
  let plain_findings = findings.map(fn(item) { item.finding })
  let severity = summarize(plain_findings)
  {
    documents: documents.length(),
    bytes,
    findings: findings.length(),
    critical: severity.critical,
    high: severity.high,
    medium: severity.medium,
    low: severity.low,
    info: severity.info,
    by_detector: detector_counts(findings),
  }
}

///|
pub fn scan_documents(
  documents : Array[Document],
  scanner? : Scanner = Scanner::new(),
  allowlist? : Array[AllowRule] = [],
) -> BatchResult {
  let findings : Array[DocumentFinding] = []
  for document in documents {
    let raw = scanner.find(document.content)
    let allowed = apply_allowlist(document.content, raw, allowlist)
    for finding in allowed {
      findings.push(to_document_finding(document, finding))
    }
  }
  findings.sort_by(compare_document_findings)
  { findings, summary: batch_summary(documents, findings), }
}

///|
/// Return redacted copies while preserving each document's path and order.
pub fn redact_documents(
  documents : Array[Document],
  scanner? : Scanner = Scanner::new(),
) -> Array[Document] {
  documents.map(fn(document) {
    Document::new(document.path, scanner.scan(document.content).redacted)
  })
}

///|
pub fn filter_new_findings(
  findings : Array[DocumentFinding],
  known_fingerprints : Array[String],
) -> Array[DocumentFinding] {
  findings.filter(fn(item) {
    !known_fingerprints.any(fn(known) { known == item.fingerprint })
  })
}

///|
fn sarif_level(severity : Severity) -> String {
  match severity {
    Critical | High => "error"
    Medium => "warning"
    Low | Info => "note"
  }
}

///|
fn sarif_rule_id(detector_id : String) -> String {
  "LUNASIEVE/" + detector_id
}

///|
fn write_sarif_result(out : StringBuilder, item : DocumentFinding) -> Unit {
  out.write_string("{\"ruleId\":\"")
  out.write_string(json_escape(sarif_rule_id(item.finding.detector_id)))
  out.write_string("\",\"level\":\"")
  out.write_string(sarif_level(item.finding.severity))
  out.write_string("\",\"message\":{\"text\":\"")
  out.write_string(json_escape(item.finding.message))
  out.write_string(
    "\"},\"partialFingerprints\":{\"primaryLocationLineHash\":\"",
  )
  out.write_string(item.fingerprint)
  out.write_string(
    "\"},\"locations\":[{\"physicalLocation\":{\"artifactLocation\":{\"uri\":\"",
  )
  out.write_string(json_escape(item.path))
  out.write_string("\"},\"region\":{\"startLine\":")
  out.write_string(item.start.line.to_string())
  out.write_string(",\"startColumn\":")
  out.write_string(item.start.column.to_string())
  out.write_string(",\"endLine\":")
  out.write_string(item.end.line.to_string())
  out.write_string(",\"endColumn\":")
  out.write_string(item.end.column.to_string())
  out.write_string("}}}]}")
}

///|
pub fn batch_to_sarif(result : BatchResult) -> String {
  let out = StringBuilder::new()
  out.write_string(
    "{\"version\":\"2.1.0\",\"$schema\":\"https://json.schemastore.org/sarif-2.1.0.json\",\"runs\":[{",
  )
  out.write_string(
    "\"tool\":{\"driver\":{\"name\":\"LunaSieve\",\"informationUri\":\"https://github.com/sujy123456/my\"}},",
  )
  out.write_string("\"results\":[")
  for i = 0; i < result.findings.length(); i = i + 1 {
    if i > 0 {
      out.write_char(',')
    }
    write_sarif_result(out, result.findings[i])
  }
  out.write_string("]}]}")
  out.to_string()
}

///|
pub fn batch_to_text(result : BatchResult) -> String {
  let out = StringBuilder::new()
  for item in result.findings {
    out.write_string(item.path)
    out.write_char(':')
    out.write_string(item.start.line.to_string())
    out.write_char(':')
    out.write_string(item.start.column.to_string())
    out.write_string(" [")
    out.write_string(item.finding.severity.name())
    out.write_string("] ")
    out.write_string(item.finding.detector_id)
    out.write_string(" - ")
    out.write_string(item.finding.message)
    out.write_char('\n')
  }
  out.write_string("scanned ")
  out.write_string(result.summary.documents.to_string())
  out.write_string(" document(s), found ")
  out.write_string(result.summary.findings.to_string())
  out.write_string(" issue(s)\n")
  out.to_string()
}
