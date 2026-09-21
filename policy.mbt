///|
pub(all) struct Policy {
  rules : Array[Rule]
  fallback : RedactionAction
} derive(Eq, Debug)

///|
pub fn Policy::new(
  rules : Array[Rule],
  fallback? : RedactionAction = Replace("[REDACTED]"),
) -> Policy {
  { rules, fallback, }
}

///|
pub fn Policy::secure_default() -> Policy {
  Policy::new(
    [
      Rule::new("email", Mask(fill='*', keep_start=2, keep_end=3)),
      Rule::new("cn-phone", Mask(fill='*', keep_start=3, keep_end=4)),
      Rule::new("cn-identity", Mask(fill='*', keep_start=4, keep_end=4)),
      Rule::new("bank-card", Mask(fill='*', keep_start=4, keep_end=4)),
      Rule::new("ipv4", Replace("[IP]")),
      Rule::new("high-entropy", Replace("[SECRET]"), minimum_severity=High),
    ],
    fallback=Replace("[SECRET]"),
  )
}

///|
fn action_for(policy : Policy, finding : Finding) -> RedactionAction {
  for rule in policy.rules {
    if rule.enabled &&
      rule.detector_id == finding.detector_id &&
      finding.severity.rank() >= rule.minimum_severity.rank() {
      return rule.action
    }
  }
  policy.fallback
}

///|
fn render_hash(original : String) -> String {
  "[HASH:" + fnv1a(original).to_string(radix=16) + "]"
}

///|
fn apply_action(original : String, action : RedactionAction) -> String {
  match action {
    Replace(value) => value
    Drop => ""
    Hash => render_hash(original)
    Mask(fill~, keep_start~, keep_end~) => {
      let chars = original.to_array()
      let left = if keep_start < 0 {
        0
      } else if keep_start > chars.length() {
        chars.length()
      } else {
        keep_start
      }
      let available = chars.length() - left
      let right = if keep_end < 0 {
        0
      } else if keep_end > available {
        available
      } else {
        keep_end
      }
      slice_chars(chars, 0, left) +
      repeat_char(fill, chars.length() - left - right) +
      slice_chars(chars, chars.length() - right, chars.length())
    }
  }
}

///|
fn finding_priority(finding : Finding) -> Int {
  match finding.kind {
    Prefix => 50
    Jwt => 45
    Identity | BankCard => 40
    Email | Phone => 35
    Custom => 30
    IPv4 => 20
    HighEntropy => 10
  }
}

///|
fn sort_findings(findings : Array[Finding]) -> Array[Finding] {
  let sorted = findings.copy()
  sorted.sort_by(fn(a, b) {
    if a.span.start != b.span.start {
      a.span.start.compare(b.span.start)
    } else if a.span.end != b.span.end {
      b.span.end.compare(a.span.end)
    } else {
      let kind_order = finding_priority(b).compare(finding_priority(a))
      if kind_order != 0 {
        kind_order
      } else {
        let severity_order = b.severity.rank().compare(a.severity.rank())
        if severity_order != 0 {
          severity_order
        } else {
          b.confidence.compare(a.confidence)
        }
      }
    }
  })
  sorted
}

///|
fn remove_overlaps(findings : Array[Finding]) -> Array[Finding] {
  let sorted = sort_findings(findings)
  let out : Array[Finding] = []
  let mut covered_until = -1
  for finding in sorted {
    if finding.span.start >= covered_until {
      out.push(finding)
      covered_until = finding.span.end
    }
  }
  out
}

///|
pub fn redact(
  text : String,
  findings : Array[Finding],
  policy? : Policy = Policy::secure_default(),
) -> String {
  let chars = text.to_array()
  let usable = remove_overlaps(findings)
  let out = StringBuilder::new()
  let mut cursor = 0
  for finding in usable {
    if finding.span.start < cursor || finding.span.end > chars.length() {
      continue
    }
    out.write_string(slice_chars(chars, cursor, finding.span.start))
    let original = slice_chars(chars, finding.span.start, finding.span.end)
    out.write_string(apply_action(original, action_for(policy, finding)))
    cursor = finding.span.end
  }
  out.write_string(slice_chars(chars, cursor, chars.length()))
  out.to_string()
}
