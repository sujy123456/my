///|
/// Entry point for the CLI or runnable program in this template.
/// Keep main focused; move logic into the library package.
/// Run with `moon run cmd/main` from the project root.
fn main {
  let sample = "user=alice@example.com token=" +
    "ghp_" +
    "abcdefghijklmnopqrstuvwxyz0123456789"
  let result = @lunasieve.scan(sample)
  println("LunaSieve demo")
  println("findings: \{result.findings.length()}")
  println("redacted: \{result.redacted}")
  println(@lunasieve.findings_to_json(result.findings))
}
