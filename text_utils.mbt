///|
fn is_ascii_letter(c : Char) -> Bool {
  (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

///|
fn is_ascii_digit(c : Char) -> Bool {
  c >= '0' && c <= '9'
}

///|
fn is_ascii_alnum(c : Char) -> Bool {
  is_ascii_letter(c) || is_ascii_digit(c)
}

///|
fn is_hex(c : Char) -> Bool {
  is_ascii_digit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

///|
fn is_base64ish(c : Char) -> Bool {
  is_ascii_alnum(c) || c == '+' || c == '/' || c == '_' || c == '-' || c == '='
}

///|
fn is_word_boundary(c : Char) -> Bool {
  !(is_ascii_alnum(c) || c == '_' || c == '-')
}

///|
fn slice_chars(chars : Array[Char], start : Int, end : Int) -> String {
  let out = StringBuilder::new()
  let safe_start = if start < 0 { 0 } else { start }
  let safe_end = if end > chars.length() { chars.length() } else { end }
  for i = safe_start; i < safe_end; i = i + 1 {
    out.write_char(chars[i])
  }
  out.to_string()
}

///|
fn index_of_from(chars : Array[Char], needle : Array[Char], from : Int) -> Int {
  if needle.length() == 0 || chars.length() < needle.length() {
    return -1
  }
  let mut i = if from < 0 { 0 } else { from }
  while i + needle.length() <= chars.length() {
    let mut ok = true
    let mut j = 0
    while j < needle.length() && ok {
      if chars[i + j] != needle[j] {
        ok = false
      }
      j = j + 1
    }
    if ok {
      return i
    }
    i = i + 1
  }
  -1
}

///|
fn safe_preview(
  chars : Array[Char],
  start : Int,
  end : Int,
  enabled : Bool,
) -> String {
  if !enabled {
    return "[hidden]"
  }
  let length = end - start
  if length <= 4 {
    return "****"
  }
  let out = StringBuilder::new()
  out.write_char(chars[start])
  out.write_char(chars[start + 1])
  let masks = if length > 10 { 6 } else { length - 4 }
  for i = 0; i < masks; i = i + 1 {
    out.write_char('*')
  }
  out.write_char(chars[end - 2])
  out.write_char(chars[end - 1])
  out.to_string()
}

///|
fn repeat_char(fill : Char, count : Int) -> String {
  let out = StringBuilder::new()
  for i = 0; i < count; i = i + 1 {
    out.write_char(fill)
  }
  out.to_string()
}

///|
fn fnv1a(text : String) -> UInt64 {
  let mut value = 14695981039346656037UL
  for c in text {
    value = (value ^ c.to_int().to_uint64()) * 1099511628211UL
  }
  value
}
