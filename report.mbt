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
      '\n' => out.write_string("\\n")
      '\r' => out.write_string("\\r")
      '\t' => out.write_string("\\t")
      _ => out.write_char(c)
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
