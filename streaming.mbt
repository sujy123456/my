///|
pub(all) struct StreamScanner {
  scanner : Scanner
  overlap : Int
  mut pending : String
  mut absolute_offset : Int
  mut finished : Bool
}

///|
pub fn StreamScanner::new(
  scanner? : Scanner = Scanner::new(),
  overlap? : Int = 256,
) -> StreamScanner {
  {
    scanner,
    overlap: if overlap < 32 {
      32
    } else {
      overlap
    },
    pending: "",
    absolute_offset: 0,
    finished: false,
  }
}

///|
fn offset_finding(finding : Finding, offset : Int) -> Finding {
  Finding::new(
    finding.detector_id,
    finding.kind,
    finding.severity,
    finding.span.start + offset,
    finding.span.end + offset,
    finding.confidence,
    finding.preview,
    finding.message,
  )
}

///|
pub fn StreamScanner::push(
  self : StreamScanner,
  chunk : String,
) -> Array[Finding] raise {
  if self.finished {
    fail("stream already finished")
  }
  let combined = self.pending + chunk
  let chars = combined.to_array()
  let stable_end = if chars.length() > self.overlap {
    chars.length() - self.overlap
  } else {
    0
  }
  let emitted : Array[Finding] = []
  for finding in self.scanner.find(combined) {
    if finding.span.end <= stable_end {
      emitted.push(offset_finding(finding, self.absolute_offset))
    }
  }
  self.absolute_offset = self.absolute_offset + stable_end
  self.pending = slice_chars(chars, stable_end, chars.length())
  emitted
}

///|
pub fn StreamScanner::finish(self : StreamScanner) -> Array[Finding] raise {
  if self.finished {
    fail("stream already finished")
  }
  self.finished = true
  let out : Array[Finding] = []
  for finding in self.scanner.find(self.pending) {
    out.push(offset_finding(finding, self.absolute_offset))
  }
  self.pending = ""
  out
}

///|
pub fn StreamScanner::buffered_bytes(self : StreamScanner) -> Int {
  self.pending.to_array().length()
}
