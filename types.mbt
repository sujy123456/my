///|
pub(all) enum Severity {
  Info
  Low
  Medium
  High
  Critical
} derive(Eq, Debug)

///|
pub fn Severity::rank(self : Severity) -> Int {
  match self {
    Info => 0
    Low => 1
    Medium => 2
    High => 3
    Critical => 4
  }
}

///|
pub fn Severity::name(self : Severity) -> String {
  match self {
    Info => "info"
    Low => "low"
    Medium => "medium"
    High => "high"
    Critical => "critical"
  }
}

///|
pub(all) enum DetectorKind {
  Prefix
  Email
  Phone
  Identity
  BankCard
  IPv4
  Jwt
  HighEntropy
  Custom
} derive(Eq, Debug)

///|
pub fn DetectorKind::name(self : DetectorKind) -> String {
  match self {
    Prefix => "prefix"
    Email => "email"
    Phone => "phone"
    Identity => "identity"
    BankCard => "bank-card"
    IPv4 => "ipv4"
    Jwt => "jwt"
    HighEntropy => "high-entropy"
    Custom => "custom"
  }
}

///|
pub(all) struct Span {
  start : Int
  end : Int
} derive(Eq, Debug)

///|
pub fn Span::new(start : Int, end : Int) -> Span raise {
  if start < 0 || end < start {
    fail("invalid span")
  }
  { start, end }
}

///|
pub fn Span::length(self : Span) -> Int {
  self.end - self.start
}

///|
pub fn Span::overlaps(self : Span, other : Span) -> Bool {
  self.start < other.end && other.start < self.end
}

///|
pub(all) struct Finding {
  detector_id : String
  kind : DetectorKind
  severity : Severity
  span : Span
  confidence : Int
  preview : String
  message : String
} derive(Eq, Debug)

///|
pub fn Finding::new(
  detector_id : String,
  kind : DetectorKind,
  severity : Severity,
  start : Int,
  end : Int,
  confidence : Int,
  preview : String,
  message : String,
) -> Finding {
  let bounded = if confidence < 0 {
    0
  } else if confidence > 100 {
    100
  } else {
    confidence
  }
  let safe_start = if start < 0 { 0 } else { start }
  let safe_end = if end < safe_start { safe_start } else { end }
  {
    detector_id,
    kind,
    severity,
    span: { start: safe_start, end: safe_end },
    confidence: bounded,
    preview,
    message,
  }
}

///|
pub(all) enum RedactionAction {
  Mask(fill~ : Char, keep_start~ : Int, keep_end~ : Int)
  Replace(String)
  Drop
  Hash
} derive(Eq, Debug)

///|
pub(all) struct Rule {
  detector_id : String
  minimum_severity : Severity
  action : RedactionAction
  enabled : Bool
} derive(Eq, Debug)

///|
pub fn Rule::new(
  detector_id : String,
  action : RedactionAction,
  minimum_severity? : Severity = Info,
  enabled? : Bool = true,
) -> Rule {
  { detector_id, minimum_severity, action, enabled }
}

///|
pub(all) struct ScanOptions {
  detect_entropy : Bool
  minimum_entropy_length : Int
  entropy_threshold_milli : Int
  include_preview : Bool
  merge_overlaps : Bool
} derive(Eq, Debug)

///|
pub fn ScanOptions::default() -> ScanOptions {
  {
    detect_entropy: true,
    minimum_entropy_length: 20,
    entropy_threshold_milli: 3650,
    include_preview: false,
    merge_overlaps: true,
  }
}

///|
pub(all) struct ScanResult {
  input_length : Int
  findings : Array[Finding]
  redacted : String
} derive(Eq, Debug)
