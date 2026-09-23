///|
pub(all) struct FindingSummary {
  total : Int
  critical : Int
  high : Int
  medium : Int
  low : Int
  info : Int
} derive(Eq, Debug)

///|
pub fn summarize(findings : Array[Finding]) -> FindingSummary {
  let mut critical = 0
  let mut high = 0
  let mut medium = 0
  let mut low = 0
  let mut info = 0
  for finding in findings {
    match finding.severity {
      Critical => critical = critical + 1
      High => high = high + 1
      Medium => medium = medium + 1
      Low => low = low + 1
      Info => info = info + 1
    }
  }
  { total: findings.length(), critical, high, medium, low, info, }
}

///|
fn json_escape(text : String) -> String {
  let out = StringBuilder::new()
  for c in text {
    match c {
      '"' => out.write_string("\\\"")
      '\\' => out.write_string("\\\\")
      '\b' => out.write_string("\\b")
      '\f' => out.write_string("\\f")
      '\n' => out.write_string("\\n")
      '\r' => out.write_string("\\r")
      '\t' => out.write_string("\\t")
      _ =>
        if c.to_int() < 0x20 {
          let code = c.to_int().to_string(radix=16)
          out.write_string("\\u00")
          if code.length() == 1 {
            out.write_char('0')
          }
          out.write_string(code)
        } else {
          out.write_char(c)
        }
    }
  }
  out.to_string()
}

///|
pub fn findings_to_json(findings : Array[Finding]) -> String {
  let out = StringBuilder::new()
  out.write_string("{\"findings\":[")
  for i = 0; i < findings.length(); i = i + 1 {
    if i > 0 {
      out.write_char(',')
    }
    let finding = findings[i]
    out.write_string("{\"detector\":\"")
    out.write_string(json_escape(finding.detector_id))
    out.write_string("\",\"kind\":\"")
    out.write_string(finding.kind.name())
    out.write_string("\",\"severity\":\"")
    out.write_string(finding.severity.name())
    out.write_string("\",\"start\":")
    out.write_string(finding.span.start.to_string())
    out.write_string(",\"end\":")
    out.write_string(finding.span.end.to_string())
    out.write_string(",\"confidence\":")
    out.write_string(finding.confidence.to_string())
    out.write_string(",\"preview\":\"")
    out.write_string(json_escape(finding.preview))
    out.write_string("\",\"message\":\"")
    out.write_string(json_escape(finding.message))
    out.write_string("\"}")
  }
  out.write_string("]}")
  out.to_string()
}

///|
/// Serialize the complete scan result without exposing the original input.
/// The output contains the redacted text, aggregate counts, and findings.
pub fn scan_result_to_json(result : ScanResult) -> String {
  let summary = summarize(result.findings)
  let out = StringBuilder::new()
  out.write_string("{\"inputLength\":")
  out.write_string(result.input_length.to_string())
  out.write_string(",\"redacted\":\"")
  out.write_string(json_escape(result.redacted))
  out.write_string("\",\"summary\":{\"total\":")
  out.write_string(summary.total.to_string())
  out.write_string(",\"critical\":")
  out.write_string(summary.critical.to_string())
  out.write_string(",\"high\":")
  out.write_string(summary.high.to_string())
  out.write_string(",\"medium\":")
  out.write_string(summary.medium.to_string())
  out.write_string(",\"low\":")
  out.write_string(summary.low.to_string())
  out.write_string(",\"info\":")
  out.write_string(summary.info.to_string())
  out.write_string("},\"result\":")
  out.write_string(findings_to_json(result.findings))
  out.write_char('}')
  out.to_string()
}

///|
/// Render a concise human-readable report for interactive demonstrations.
pub fn scan_result_to_text(result : ScanResult) -> String {
  let summary = summarize(result.findings)
  let out = StringBuilder::new()
  out.write_string("LunaSieve scan completed\n")
  out.write_string("input length: ")
  out.write_string(result.input_length.to_string())
  out.write_string("\nfindings: ")
  out.write_string(summary.total.to_string())
  out.write_string(" (critical=")
  out.write_string(summary.critical.to_string())
  out.write_string(", high=")
  out.write_string(summary.high.to_string())
  out.write_string(", medium=")
  out.write_string(summary.medium.to_string())
  out.write_string(", low=")
  out.write_string(summary.low.to_string())
  out.write_string(", info=")
  out.write_string(summary.info.to_string())
  out.write_string(")\nredacted: ")
  out.write_string(result.redacted)
  out.write_char('\n')
  for finding in result.findings {
    out.write_string("- [")
    out.write_string(finding.severity.name())
    out.write_string("] ")
    out.write_string(finding.detector_id)
    out.write_string(" @ ")
    out.write_string(finding.span.start.to_string())
    out.write_char(':')
    out.write_string(finding.span.end.to_string())
    out.write_string(" - ")
    out.write_string(finding.message)
    out.write_char('\n')
  }
  out.to_string()
}
