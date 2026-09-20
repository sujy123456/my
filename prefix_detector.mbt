///|
pub(all) struct PrefixPattern {
  id : String
  prefix : String
  minimum_tail : Int
  maximum_tail : Int
  severity : Severity
  message : String
} derive(Eq, Debug)

///|
pub fn PrefixPattern::new(
  id : String,
  prefix : String,
  minimum_tail : Int,
  maximum_tail : Int,
  severity : Severity,
  message : String,
) -> PrefixPattern {
  { id, prefix, minimum_tail, maximum_tail, severity, message }
}

///|
pub fn builtin_prefix_patterns() -> Array[PrefixPattern] {
  [
    PrefixPattern::new(
      "github-pat",
      "ghp_",
      30,
      64,
      Critical,
      "GitHub personal access token",
    ),
    PrefixPattern::new(
      "github-oauth",
      "gho_",
      30,
      64,
      Critical,
      "GitHub OAuth token",
    ),
    PrefixPattern::new(
      "github-user-token",
      "ghu_",
      30,
      64,
      Critical,
      "GitHub user token",
    ),
    PrefixPattern::new(
      "github-server-token",
      "ghs_",
      30,
      64,
      Critical,
      "GitHub server token",
    ),
    PrefixPattern::new(
      "github-refresh-token",
      "ghr_",
      30,
      128,
      Critical,
      "GitHub refresh token",
    ),
    PrefixPattern::new(
      "gitlab-pat",
      "glpat-",
      16,
      64,
      Critical,
      "GitLab personal access token",
    ),
    PrefixPattern::new(
      "openai-project-key",
      "sk-proj-",
      20,
      180,
      Critical,
      "OpenAI project API key",
    ),
    PrefixPattern::new("openai-key", "sk-", 20, 180, Critical, "API secret key"),
    PrefixPattern::new(
      "anthropic-key",
      "sk-ant-",
      20,
      180,
      Critical,
      "Anthropic API key",
    ),
    PrefixPattern::new(
      "slack-bot",
      "xoxb-",
      20,
      120,
      Critical,
      "Slack bot token",
    ),
    PrefixPattern::new(
      "slack-user",
      "xoxp-",
      20,
      120,
      Critical,
      "Slack user token",
    ),
    PrefixPattern::new(
      "slack-app",
      "xapp-",
      20,
      160,
      Critical,
      "Slack application token",
    ),
    PrefixPattern::new(
      "stripe-live-secret",
      "sk_live_",
      20,
      120,
      Critical,
      "Stripe live secret key",
    ),
    PrefixPattern::new(
      "stripe-test-secret",
      "sk_test_",
      20,
      120,
      High,
      "Stripe test secret key",
    ),
    PrefixPattern::new(
      "stripe-restricted",
      "rk_live_",
      20,
      120,
      Critical,
      "Stripe restricted key",
    ),
    PrefixPattern::new(
      "npm-token",
      "npm_",
      20,
      120,
      Critical,
      "npm access token",
    ),
    PrefixPattern::new(
      "pypi-token",
      "pypi-",
      30,
      160,
      Critical,
      "PyPI upload token",
    ),
    PrefixPattern::new(
      "sendgrid-key",
      "SG.",
      20,
      160,
      Critical,
      "SendGrid API key",
    ),
    PrefixPattern::new(
      "datadog-key",
      "ddapi_",
      20,
      96,
      Critical,
      "Datadog API key",
    ),
    PrefixPattern::new(
      "grafana-token",
      "glc_",
      20,
      128,
      Critical,
      "Grafana service token",
    ),
    PrefixPattern::new(
      "huggingface-token",
      "hf_",
      20,
      100,
      Critical,
      "Hugging Face token",
    ),
    PrefixPattern::new(
      "digitalocean-token",
      "dop_v1_",
      20,
      100,
      Critical,
      "DigitalOcean token",
    ),
    PrefixPattern::new(
      "linear-key",
      "lin_api_",
      20,
      100,
      Critical,
      "Linear API key",
    ),
    PrefixPattern::new(
      "sentry-token",
      "sntrys_",
      20,
      160,
      Critical,
      "Sentry authentication token",
    ),
    PrefixPattern::new(
      "cloudflare-token",
      "v1.0-",
      24,
      160,
      High,
      "Cloudflare token candidate",
    ),
    PrefixPattern::new(
      "discord-token",
      "mfa.",
      20,
      120,
      Critical,
      "Discord multi-factor token",
    ),
    PrefixPattern::new(
      "shopify-token",
      "shpat_",
      20,
      100,
      Critical,
      "Shopify private app token",
    ),
    PrefixPattern::new(
      "shopify-shared-secret",
      "shpss_",
      20,
      100,
      Critical,
      "Shopify shared secret",
    ),
    PrefixPattern::new(
      "shopify-custom-app",
      "shpca_",
      20,
      100,
      Critical,
      "Shopify custom app token",
    ),
    PrefixPattern::new(
      "vault-service-token",
      "hvs.",
      20,
      180,
      Critical,
      "HashiCorp Vault service token",
    ),
    PrefixPattern::new(
      "vault-batch-token",
      "hvb.",
      20,
      180,
      Critical,
      "HashiCorp Vault batch token",
    ),
  ]
}

///|
fn valid_secret_tail(c : Char) -> Bool {
  is_hex(c) || is_base64ish(c) || c == '.' || c == '~'
}

///|
fn scan_prefix_pattern(
  chars : Array[Char],
  pattern : PrefixPattern,
  include_preview : Bool,
) -> Array[Finding] {
  let findings : Array[Finding] = []
  let needle = pattern.prefix.to_array()
  let mut from = 0
  while from < chars.length() {
    let position = index_of_from(chars, needle, from)
    if position < 0 {
      break
    }
    let tail_start = position + needle.length()
    let mut end = tail_start
    while end < chars.length() &&
          end - tail_start < pattern.maximum_tail &&
          valid_secret_tail(chars[end]) {
      end = end + 1
    }
    if end - tail_start >= pattern.minimum_tail {
      let prefix_bonus = if needle.length() > 10 { 10 } else { needle.length() }
      findings.push(
        Finding::new(
          pattern.id,
          Prefix,
          pattern.severity,
          position,
          end,
          90 + prefix_bonus,
          safe_preview(chars, position, end, include_preview),
          pattern.message,
        ),
      )
    }
    from = position + needle.length()
  }
  findings
}

///|
fn scan_all_prefixes(
  chars : Array[Char],
  include_preview : Bool,
) -> Array[Finding] {
  let findings : Array[Finding] = []
  for pattern in builtin_prefix_patterns() {
    for finding in scan_prefix_pattern(chars, pattern, include_preview) {
      findings.push(finding)
    }
  }
  findings
}
