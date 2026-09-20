///|
fn scan_emails(chars : Array[Char], preview : Bool) -> Array[Finding] {
  let out : Array[Finding] = []
  for at = 1; at + 3 < chars.length(); at = at + 1 {
    if chars[at] != '@' {
      continue
    }
    let mut start = at - 1
    while start > 0 &&
          (
            is_ascii_alnum(chars[start - 1]) ||
            chars[start - 1] == '.' ||
            chars[start - 1] == '_' ||
            chars[start - 1] == '+' ||
            chars[start - 1] == '-'
          ) {
      start = start - 1
    }
    let mut end = at + 1
    let mut dot = false
    while end < chars.length() &&
          (is_ascii_alnum(chars[end]) || chars[end] == '.' || chars[end] == '-') {
      if chars[end] == '.' {
        dot = true
      }
      end = end + 1
    }
    if dot &&
      at - start >= 1 &&
      end - at >= 4 &&
      is_ascii_letter(chars[end - 1]) {
      out.push(
        Finding::new(
          "email",
          Email,
          Medium,
          start,
          end,
          92,
          safe_preview(chars, start, end, preview),
          "Email address",
        ),
      )
    }
  }
  out
}

///|
fn scan_phone_numbers(chars : Array[Char], preview : Bool) -> Array[Finding] {
  let out : Array[Finding] = []
  let mut i = 0
  while i < chars.length() {
    if !is_ascii_digit(chars[i]) {
      i = i + 1
      continue
    }
    let start = i
    while i < chars.length() && is_ascii_digit(chars[i]) {
      i = i + 1
    }
    let length = i - start
    if length == 11 &&
      chars[start] == '1' &&
      chars[start + 1] >= '3' &&
      chars[start + 1] <= '9' {
      out.push(
        Finding::new(
          "cn-phone",
          Phone,
          High,
          start,
          i,
          96,
          safe_preview(chars, start, i, preview),
          "Mainland China mobile number",
        ),
      )
    }
  }
  out
}

///|
fn identity_checksum(chars : Array[Char], start : Int) -> Bool {
  let weights = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2]
  let check = ['1', '0', 'X', '9', '8', '7', '6', '5', '4', '3', '2']
  let mut sum = 0
  for i = 0; i < 17; i = i + 1 {
    if !is_ascii_digit(chars[start + i]) {
      return false
    }
    sum = sum + (chars[start + i].to_int() - '0'.to_int()) * weights[i]
  }
  let actual = chars[start + 17]
  actual == check[sum % 11] || (actual == 'x' && check[sum % 11] == 'X')
}

///|
fn scan_identities(chars : Array[Char], preview : Bool) -> Array[Finding] {
  let out : Array[Finding] = []
  for start = 0; start + 18 <= chars.length(); start = start + 1 {
    if start > 0 && is_ascii_alnum(chars[start - 1]) {
      continue
    }
    if start + 18 < chars.length() && is_ascii_alnum(chars[start + 18]) {
      continue
    }
    if identity_checksum(chars, start) {
      out.push(
        Finding::new(
          "cn-identity",
          Identity,
          Critical,
          start,
          start + 18,
          99,
          safe_preview(chars, start, start + 18, preview),
          "Mainland China identity number",
        ),
      )
    }
  }
  out
}

///|
fn luhn_valid(chars : Array[Char], start : Int, end : Int) -> Bool {
  let mut sum = 0
  let mut alternate = false
  let mut i = end - 1
  while i >= start {
    if !is_ascii_digit(chars[i]) {
      return false
    }
    let mut digit = chars[i].to_int() - '0'.to_int()
    if alternate {
      digit = digit * 2
      if digit > 9 {
        digit = digit - 9
      }
    }
    sum = sum + digit
    alternate = !alternate
    i = i - 1
  }
  sum % 10 == 0
}

///|
fn scan_bank_cards(chars : Array[Char], preview : Bool) -> Array[Finding] {
  let out : Array[Finding] = []
  let mut i = 0
  while i < chars.length() {
    if !is_ascii_digit(chars[i]) {
      i = i + 1
      continue
    }
    let start = i
    while i < chars.length() && is_ascii_digit(chars[i]) {
      i = i + 1
    }
    let length = i - start
    if length >= 13 && length <= 19 && luhn_valid(chars, start, i) {
      out.push(
        Finding::new(
          "bank-card",
          BankCard,
          Critical,
          start,
          i,
          94,
          safe_preview(chars, start, i, preview),
          "Payment card number passing Luhn checksum",
        ),
      )
    }
  }
  out
}

///|
fn parse_octet(chars : Array[Char], start : Int, end : Int) -> Int {
  if end <= start || end - start > 3 {
    return -1
  }
  let mut value = 0
  for i = start; i < end; i = i + 1 {
    if !is_ascii_digit(chars[i]) {
      return -1
    }
    value = value * 10 + chars[i].to_int() - '0'.to_int()
  }
  if value > 255 {
    -1
  } else {
    value
  }
}

///|
fn scan_ipv4(chars : Array[Char], preview : Bool) -> Array[Finding] {
  let out : Array[Finding] = []
  let mut i = 0
  while i < chars.length() {
    if !is_ascii_digit(chars[i]) {
      i = i + 1
      continue
    }
    let start = i
    if start > 0 &&
      (is_ascii_digit(chars[start - 1]) || chars[start - 1] == '.') {
      i = i + 1
      continue
    }
    let mut parts = 0
    let mut valid = true
    while parts < 4 && valid {
      let part_start = i
      while i < chars.length() && is_ascii_digit(chars[i]) {
        i = i + 1
      }
      if parse_octet(chars, part_start, i) < 0 {
        valid = false
      }
      parts = parts + 1
      if parts < 4 {
        if i >= chars.length() || chars[i] != '.' {
          valid = false
        } else {
          i = i + 1
        }
      }
    }
    if valid && parts == 4 && (i == chars.length() || !is_ascii_digit(chars[i])) {
      out.push(
        Finding::new(
          "ipv4",
          IPv4,
          Low,
          start,
          i,
          90,
          safe_preview(chars, start, i, preview),
          "IPv4 address",
        ),
      )
    } else {
      i = start + 1
    }
  }
  out
}

///|
fn scan_jwts(chars : Array[Char], preview : Bool) -> Array[Finding] {
  let out : Array[Finding] = []
  let header = "eyJ".to_array()
  let mut from = 0
  while from < chars.length() {
    let start = index_of_from(chars, header, from)
    if start < 0 {
      break
    }
    let mut end = start
    let mut dots = 0
    while end < chars.length() &&
          (is_base64ish(chars[end]) || chars[end] == '.') {
      if chars[end] == '.' {
        dots = dots + 1
      }
      end = end + 1
    }
    if dots == 2 && end - start >= 30 {
      out.push(
        Finding::new(
          "jwt",
          Jwt,
          Critical,
          start,
          end,
          97,
          safe_preview(chars, start, end, preview),
          "JSON Web Token",
        ),
      )
    }
    from = start + 3
  }
  out
}

///|
fn scan_structured(chars : Array[Char], preview : Bool) -> Array[Finding] {
  let out : Array[Finding] = []
  for finding in scan_emails(chars, preview) {
    out.push(finding)
  }
  for finding in scan_phone_numbers(chars, preview) {
    out.push(finding)
  }
  for finding in scan_identities(chars, preview) {
    out.push(finding)
  }
  for finding in scan_bank_cards(chars, preview) {
    out.push(finding)
  }
  for finding in scan_ipv4(chars, preview) {
    out.push(finding)
  }
  for finding in scan_jwts(chars, preview) {
    out.push(finding)
  }
  out
}
