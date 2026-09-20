///|
test "ascii helpers" {
  assert_true(is_ascii_letter('a'))
  assert_true(is_ascii_letter('Z'))
  assert_false(is_ascii_letter('4'))
  assert_true(is_ascii_digit('4'))
  assert_true(is_ascii_alnum('4'))
  assert_true(is_hex('f'))
  assert_true(is_hex('A'))
  assert_false(is_hex('x'))
}

///|
test "substring search" {
  let chars = "alpha beta gamma".to_array()
  assert_eq(index_of_from(chars, "beta".to_array(), 0), 6)
  assert_eq(index_of_from(chars, "alpha".to_array(), 1), -1)
  assert_eq(index_of_from(chars, "delta".to_array(), 0), -1)
}

///|
test "luhn implementation" {
  let valid = "4111111111111111".to_array()
  let invalid = "4111111111111112".to_array()
  assert_true(luhn_valid(valid, 0, valid.length()))
  assert_false(luhn_valid(invalid, 0, invalid.length()))
}

///|
test "ipv4 octet parser" {
  let text = "255".to_array()
  assert_eq(parse_octet(text, 0, 3), 255)
  let invalid = "256".to_array()
  assert_eq(parse_octet(invalid, 0, 3), -1)
}

///|
test "entropy unique count" {
  let low = "aaaaaaaa".to_array()
  let high = "aB3$xY7!".to_array()
  assert_eq(unique_ascii_count(low, 0, low.length()), 1)
  assert_true(unique_ascii_count(high, 0, high.length()) > 6)
  assert_true(
    entropy_score_milli(high, 0, high.length()) >
    entropy_score_milli(low, 0, low.length()),
  )
}

///|
test "preview never returns full input" {
  let chars = "abcdefghijklmnop".to_array()
  let preview = safe_preview(chars, 0, chars.length(), true)
  assert_false(preview.contains("abcdefghijklmnop"))
  assert_true(preview.contains("******"))
}

///|
test "fnv hash deterministic" {
  assert_eq(fnv1a("secret"), fnv1a("secret"))
  assert_true(fnv1a("secret") != fnv1a("Secret"))
}
