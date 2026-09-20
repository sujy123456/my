///|
pub(all) enum BoundaryMode {
  Anywhere
  Word
  Line
} derive(Eq, Debug)

///|
pub(all) struct LiteralRule {
  id : String
  literal : String
  case_sensitive : Bool
  boundary : BoundaryMode
  severity : Severity
  message : String
} derive(Eq, Debug)

///|
pub fn LiteralRule::new(
  id : String,
  literal : String,
  severity? : Severity = High,
  case_sensitive? : Bool = true,
  boundary? : BoundaryMode = Anywhere,
  message? : String = "Custom sensitive literal",
) -> LiteralRule {
  { id, literal, case_sensitive, boundary, severity, message }
}

///|
fn char_equal(left : Char, right : Char, case_sensitive : Bool) -> Bool {
  if case_sensitive {
    left == right
  } else {
    let normalized_left = if left >= 'A' && left <= 'Z' {
      (left.to_int() + 32).unsafe_to_char()
    } else {
      left
    }
    let normalized_right = if right >= 'A' && right <= 'Z' {
      (right.to_int() + 32).unsafe_to_char()
    } else {
      right
    }
    normalized_left == normalized_right
  }
}

///|
fn literal_at(
  chars : Array[Char],
  needle : Array[Char],
  position : Int,
  case_sensitive : Bool,
) -> Bool {
  if position < 0 || position + needle.length() > chars.length() {
    return false
  }
  for i = 0; i < needle.length(); i = i + 1 {
    if !char_equal(chars[position + i], needle[i], case_sensitive) {
      return false
    }
  }
  true
}

///|
fn word_boundary_at(chars : Array[Char], position : Int) -> Bool {
  position <= 0 ||
  position >= chars.length() ||
  is_word_boundary(chars[position])
}

///|
fn line_boundary_at(chars : Array[Char], position : Int) -> Bool {
  position <= 0 ||
  position >= chars.length() ||
  chars[position] == '\n' ||
  chars[position] == '\r'
}

///|
fn boundaries_match(
  chars : Array[Char],
  start : Int,
  end : Int,
  mode : BoundaryMode,
) -> Bool {
  match mode {
    Anywhere => true
    Word => word_boundary_at(chars, start - 1) && word_boundary_at(chars, end)
    Line => line_boundary_at(chars, start - 1) && line_boundary_at(chars, end)
  }
}

///|
pub(all) struct LiteralScanner {
  rules : Array[LiteralRule]
  include_preview : Bool
} derive(Eq, Debug)

///|
pub fn LiteralScanner::new(
  rules : Array[LiteralRule],
  include_preview? : Bool = false,
) -> LiteralScanner {
  { rules, include_preview }
}

///|
fn scan_literal_rule(
  chars : Array[Char],
  rule : LiteralRule,
  include_preview : Bool,
) -> Array[Finding] {
  let out : Array[Finding] = []
  let needle = rule.literal.to_array()
  if needle.length() == 0 {
    return out
  }
  let mut position = 0
  while position + needle.length() <= chars.length() {
    if literal_at(chars, needle, position, rule.case_sensitive) {
      let end = position + needle.length()
      if boundaries_match(chars, position, end, rule.boundary) {
        out.push(
          Finding::new(
            rule.id,
            Custom,
            rule.severity,
            position,
            end,
            100,
            safe_preview(chars, position, end, include_preview),
            rule.message,
          ),
        )
      }
      position = end
    } else {
      position = position + 1
    }
  }
  out
}

///|
pub fn LiteralScanner::find(
  self : LiteralScanner,
  text : String,
) -> Array[Finding] {
  let chars = text.to_array()
  let out : Array[Finding] = []
  for rule in self.rules {
    for finding in scan_literal_rule(chars, rule, self.include_preview) {
      out.push(finding)
    }
  }
  sort_findings(out)
}

///|
pub fn LiteralScanner::redact(
  self : LiteralScanner,
  text : String,
  policy? : Policy = Policy::secure_default(),
) -> String {
  redact(text, self.find(text), policy~)
}

///|
pub(all) struct AllowRule {
  detector_id : String?
  exact_value : String?
  line_contains : String?
  reason : String
} derive(Eq, Debug)

///|
pub fn AllowRule::new(
  detector_id? : String,
  exact_value? : String,
  line_contains? : String,
  reason? : String = "Explicitly allowed",
) -> AllowRule {
  { detector_id, exact_value, line_contains, reason }
}

///|
fn line_span_at(chars : Array[Char], position : Int) -> Span {
  let mut start = if position < 0 { 0 } else { position }
  let mut end = start
  while start > 0 && chars[start - 1] != '\n' && chars[start - 1] != '\r' {
    start = start - 1
  }
  while end < chars.length() && chars[end] != '\n' && chars[end] != '\r' {
    end = end + 1
  }
  { start, end }
}

///|
fn option_matches(expected : String?, actual : String) -> Bool {
  match expected {
    None => true
    Some(value) => value == actual
  }
}

///|
fn allow_rule_matches(
  chars : Array[Char],
  finding : Finding,
  rule : AllowRule,
) -> Bool {
  if !option_matches(rule.detector_id, finding.detector_id) {
    return false
  }
  match rule.exact_value {
    Some(value) =>
      if slice_chars(chars, finding.span.start, finding.span.end) != value {
        return false
      }
    None => ()
  }
  match rule.line_contains {
    Some(fragment) => {
      let line = line_span_at(chars, finding.span.start)
      if !slice_chars(chars, line.start, line.end).contains(fragment) {
        return false
      }
    }
    None => ()
  }
  true
}

///|
pub fn apply_allowlist(
  text : String,
  findings : Array[Finding],
  rules : Array[AllowRule],
) -> Array[Finding] {
  let chars = text.to_array()
  findings.filter(fn(finding) {
    !rules.any(fn(rule) { allow_rule_matches(chars, finding, rule) })
  })
}

///|
pub(all) struct SourceLocation {
  offset : Int
  line : Int
  column : Int
} derive(Eq, Debug)

///|
pub fn locate(text : String, offset : Int) -> SourceLocation {
  let chars = text.to_array()
  let target = if offset < 0 {
    0
  } else if offset > chars.length() {
    chars.length()
  } else {
    offset
  }
  let mut line = 1
  let mut column = 1
  for i = 0; i < target; i = i + 1 {
    if chars[i] == '\n' {
      line = line + 1
      column = 1
    } else {
      column = column + 1
    }
  }
  { offset: target, line, column }
}

///|
pub(all) struct LocatedFinding {
  finding : Finding
  start : SourceLocation
  end : SourceLocation
} derive(Eq, Debug)

///|
pub fn locate_findings(
  text : String,
  findings : Array[Finding],
) -> Array[LocatedFinding] {
  findings.map(fn(finding) {
    {
      finding,
      start: locate(text, finding.span.start),
      end: locate(text, finding.span.end),
    }
  })
}

///|
pub fn located_findings_to_text(items : Array[LocatedFinding]) -> String {
  let out = StringBuilder::new()
  for item in items {
    out.write_string(item.finding.severity.name())
    out.write_string(" ")
    out.write_string(item.finding.detector_id)
    out.write_string(" at ")
    out.write_string(item.start.line.to_string())
    out.write_char(':')
    out.write_string(item.start.column.to_string())
    out.write_string("-")
    out.write_string(item.end.line.to_string())
    out.write_char(':')
    out.write_string(item.end.column.to_string())
    out.write_string(" ")
    out.write_string(item.finding.message)
    out.write_char('\n')
  }
  out.to_string()
}
