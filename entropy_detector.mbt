///|
fn alphabet_class_count(chars : Array[Char], start : Int, end : Int) -> Int {
  let mut lower = false
  let mut upper = false
  let mut digit = false
  let mut symbol = false
  for i = start; i < end; i = i + 1 {
    let c = chars[i]
    if c >= 'a' && c <= 'z' {
      lower = true
    } else if c >= 'A' && c <= 'Z' {
      upper = true
    } else if is_ascii_digit(c) {
      digit = true
    } else {
      symbol = true
    }
  }
  let mut count = 0
  if lower {
    count = count + 1
  }
  if upper {
    count = count + 1
  }
  if digit {
    count = count + 1
  }
  if symbol {
    count = count + 1
  }
  count
}

///|
fn unique_ascii_count(chars : Array[Char], start : Int, end : Int) -> Int {
  let seen = Array::make(128, false)
  let mut count = 0
  for i = start; i < end; i = i + 1 {
    let code = chars[i].to_int()
    if code >= 0 && code < 128 && !seen[code] {
      seen[code] = true
      count = count + 1
    }
  }
  count
}

///|
fn entropy_score_milli(chars : Array[Char], start : Int, end : Int) -> Int {
  let length = end - start
  if length <= 0 {
    return 0
  }
  let unique = unique_ascii_count(chars, start, end)
  let classes = alphabet_class_count(chars, start, end)
  let uniqueness = unique * 1000 / length
  let length_bonus = if length >= 48 {
    850
  } else if length >= 32 {
    650
  } else if length >= 24 {
    450
  } else {
    200
  }
  uniqueness * 3 + classes * 240 + length_bonus
}

///|
fn entropy_token_char(c : Char) -> Bool {
  is_ascii_alnum(c) ||
  c == '+' ||
  c == '/' ||
  c == '_' ||
  c == '-' ||
  c == '.' ||
  c == '~'
}

///|
fn obvious_natural_word(chars : Array[Char], start : Int, end : Int) -> Bool {
  let mut only_letters = true
  let mut vowels = 0
  for i = start; i < end; i = i + 1 {
    let c = chars[i]
    if !is_ascii_letter(c) {
      only_letters = false
    }
    if c == 'a' ||
      c == 'e' ||
      c == 'i' ||
      c == 'o' ||
      c == 'u' ||
      c == 'A' ||
      c == 'E' ||
      c == 'I' ||
      c == 'O' ||
      c == 'U' {
      vowels = vowels + 1
    }
  }
  only_letters && vowels * 5 >= end - start
}

///|
fn scan_entropy(chars : Array[Char], options : ScanOptions) -> Array[Finding] {
  let out : Array[Finding] = []
  let mut i = 0
  while i < chars.length() {
    if !entropy_token_char(chars[i]) {
      i = i + 1
      continue
    }
    let start = i
    while i < chars.length() && entropy_token_char(chars[i]) {
      i = i + 1
    }
    let length = i - start
    if length >= options.minimum_entropy_length &&
      !obvious_natural_word(chars, start, i) {
      let score = entropy_score_milli(chars, start, i)
      if score >= options.entropy_threshold_milli {
        let confidence = if score >= 5000 {
          95
        } else if score >= 4400 {
          86
        } else {
          75
        }
        out.push(
          Finding::new(
            "high-entropy",
            HighEntropy,
            High,
            start,
            i,
            confidence,
            safe_preview(chars, start, i, options.include_preview),
            "High-entropy token candidate",
          ),
        )
      }
    }
  }
  out
}
