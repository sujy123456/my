///|
const DEMO_INPUT : String = "user=alice@example.com password=demo-password"

///|
fn has_arg(args : Array[String], expected : String) -> Bool {
  args.any(fn(arg) { arg == expected })
}

///|
fn value_after(args : Array[String], option : String) -> String? {
  for i = 0; i + 1 < args.length(); i = i + 1 {
    if args[i] == option {
      return Some(args[i + 1])
    }
  }
  None
}

///|
fn print_help() -> Unit {
  println(
    (
      #|LunaSieve MVP - detect and redact sensitive text
      #|
      #|Usage:
      #|  moon run cmd/main
      #|  moon run cmd/main -- --text "email=alice@example.com"
      #|  moon run cmd/main -- --text "password=demo-secret" --json
      #|  moon run cmd/main -- --text "password=demo-secret" --redacted-only
      #|
      #|Options:
      #|  --text <value>  Text to scan. Without it, a safe demo is used.
      #|  --json          Emit a machine-readable JSON report.
      #|  --redacted-only Emit only sanitized text for downstream tools.
      #|  --help, -h      Show this help message.
    ),
  )
}

///|
fn main {
  let args = @env.args()
  if has_arg(args, "--help") || has_arg(args, "-h") {
    print_help()
    return
  }
  let input = match value_after(args, "--text") {
    Some(value) => value
    None => DEMO_INPUT
  }
  let result = @lunasieve.scan(input)
  if has_arg(args, "--redacted-only") {
    println(result.redacted)
  } else if has_arg(args, "--json") {
    println(@lunasieve.scan_result_to_json(result))
  } else {
    println(@lunasieve.scan_result_to_text(result))
  }
}
