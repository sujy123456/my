///|
pub(all) struct KeyPattern {
  id : String
  key : String
  severity : Severity
  minimum_length : Int
  message : String
} derive(Eq, Debug)

///|
pub fn KeyPattern::new(
  id : String,
  key : String,
  severity : Severity,
  minimum_length? : Int = 6,
  message? : String = "Sensitive configuration value",
) -> KeyPattern {
  { id, key, severity, minimum_length, message, }
}

///|
pub fn builtin_key_patterns() -> Array[KeyPattern] {
  [
    KeyPattern::new("generic-password", "password", Critical),
    KeyPattern::new("generic-password", "passwd", Critical),
    KeyPattern::new("generic-password", "pwd", High),
    KeyPattern::new("generic-secret", "secret", Critical),
    KeyPattern::new("generic-secret", "client_secret", Critical),
    KeyPattern::new("generic-secret", "client-secret", Critical),
    KeyPattern::new("generic-token", "token", Critical),
    KeyPattern::new("generic-token", "access_token", Critical),
    KeyPattern::new("generic-token", "access-token", Critical),
    KeyPattern::new("generic-token", "refresh_token", Critical),
    KeyPattern::new("generic-token", "refresh-token", Critical),
    KeyPattern::new("generic-api-key", "api_key", Critical),
    KeyPattern::new("generic-api-key", "api-key", Critical),
    KeyPattern::new("generic-api-key", "apikey", Critical),
    KeyPattern::new("generic-private-key", "private_key", Critical),
    KeyPattern::new("generic-private-key", "private-key", Critical),
    KeyPattern::new("generic-signing-key", "signing_key", Critical),
    KeyPattern::new("generic-signing-key", "signing-key", Critical),
    KeyPattern::new("generic-encryption-key", "encryption_key", Critical),
    KeyPattern::new("generic-encryption-key", "encryption-key", Critical),
    KeyPattern::new("generic-auth", "authorization", Critical),
    KeyPattern::new("generic-auth", "auth_token", Critical),
    KeyPattern::new("generic-auth", "auth-token", Critical),
    KeyPattern::new("generic-auth", "bearer", Critical),
    KeyPattern::new("database-password", "db_password", Critical),
    KeyPattern::new("database-password", "database_password", Critical),
    KeyPattern::new("database-url", "database_url", Critical, minimum_length=12),
    KeyPattern::new("database-url", "db_url", Critical, minimum_length=12),
    KeyPattern::new("redis-url", "redis_url", Critical, minimum_length=12),
    KeyPattern::new("redis-password", "redis_password", Critical),
    KeyPattern::new("mongodb-uri", "mongodb_uri", Critical, minimum_length=12),
    KeyPattern::new("postgres-url", "postgres_url", Critical, minimum_length=12),
    KeyPattern::new("mysql-url", "mysql_url", Critical, minimum_length=12),
    KeyPattern::new("jdbc-url", "jdbc_url", Critical, minimum_length=12),
    KeyPattern::new("aws-access-key", "aws_access_key_id", Critical),
    KeyPattern::new("aws-secret-key", "aws_secret_access_key", Critical),
    KeyPattern::new("aws-session-token", "aws_session_token", Critical),
    KeyPattern::new("aws-account", "aws_account_id", Medium),
    KeyPattern::new("azure-client-secret", "azure_client_secret", Critical),
    KeyPattern::new("azure-tenant", "azure_tenant_id", Medium),
    KeyPattern::new("azure-storage-key", "azure_storage_key", Critical),
    KeyPattern::new(
      "gcp-credential",
      "google_application_credentials",
      Critical,
    ),
    KeyPattern::new("gcp-private-key", "google_private_key", Critical),
    KeyPattern::new("gcp-api-key", "google_api_key", Critical),
    KeyPattern::new("github-token", "github_token", Critical),
    KeyPattern::new("github-token", "gh_token", Critical),
    KeyPattern::new("gitlab-token", "gitlab_token", Critical),
    KeyPattern::new("bitbucket-token", "bitbucket_token", Critical),
    KeyPattern::new("npm-token", "npm_token", Critical),
    KeyPattern::new("pypi-token", "pypi_token", Critical),
    KeyPattern::new("cargo-token", "cargo_registry_token", Critical),
    KeyPattern::new("docker-password", "docker_password", Critical),
    KeyPattern::new("docker-token", "docker_token", Critical),
    KeyPattern::new("registry-password", "registry_password", Critical),
    KeyPattern::new("kubernetes-token", "kubernetes_token", Critical),
    KeyPattern::new("kubernetes-token", "k8s_token", Critical),
    KeyPattern::new("helm-password", "helm_password", Critical),
    KeyPattern::new("terraform-token", "terraform_token", Critical),
    KeyPattern::new("vault-token", "vault_token", Critical),
    KeyPattern::new("consul-token", "consul_http_token", Critical),
    KeyPattern::new("nomad-token", "nomad_token", Critical),
    KeyPattern::new("cloudflare-token", "cloudflare_api_token", Critical),
    KeyPattern::new("cloudflare-key", "cloudflare_api_key", Critical),
    KeyPattern::new("digitalocean-token", "digitalocean_access_token", Critical),
    KeyPattern::new("heroku-key", "heroku_api_key", Critical),
    KeyPattern::new("vercel-token", "vercel_token", Critical),
    KeyPattern::new("netlify-token", "netlify_auth_token", Critical),
    KeyPattern::new("fly-token", "fly_api_token", Critical),
    KeyPattern::new("openai-key", "openai_api_key", Critical),
    KeyPattern::new("anthropic-key", "anthropic_api_key", Critical),
    KeyPattern::new("gemini-key", "gemini_api_key", Critical),
    KeyPattern::new("deepseek-key", "deepseek_api_key", Critical),
    KeyPattern::new("cohere-key", "cohere_api_key", Critical),
    KeyPattern::new("huggingface-token", "huggingface_token", Critical),
    KeyPattern::new("replicate-token", "replicate_api_token", Critical),
    KeyPattern::new("groq-key", "groq_api_key", Critical),
    KeyPattern::new("mistral-key", "mistral_api_key", Critical),
    KeyPattern::new("slack-token", "slack_token", Critical),
    KeyPattern::new("slack-secret", "slack_signing_secret", Critical),
    KeyPattern::new("discord-token", "discord_token", Critical),
    KeyPattern::new("telegram-token", "telegram_bot_token", Critical),
    KeyPattern::new("teams-secret", "teams_client_secret", Critical),
    KeyPattern::new("twilio-token", "twilio_auth_token", Critical),
    KeyPattern::new("sendgrid-key", "sendgrid_api_key", Critical),
    KeyPattern::new("mailgun-key", "mailgun_api_key", Critical),
    KeyPattern::new("postmark-token", "postmark_server_token", Critical),
    KeyPattern::new("stripe-secret", "stripe_secret_key", Critical),
    KeyPattern::new("stripe-webhook", "stripe_webhook_secret", Critical),
    KeyPattern::new("paypal-secret", "paypal_client_secret", Critical),
    KeyPattern::new("shopify-token", "shopify_access_token", Critical),
    KeyPattern::new("square-token", "square_access_token", Critical),
    KeyPattern::new("adyen-key", "adyen_api_key", Critical),
    KeyPattern::new("sentry-token", "sentry_auth_token", Critical),
    KeyPattern::new("datadog-key", "datadog_api_key", Critical),
    KeyPattern::new("newrelic-key", "new_relic_license_key", Critical),
    KeyPattern::new("grafana-token", "grafana_service_account_token", Critical),
    KeyPattern::new("honeycomb-key", "honeycomb_api_key", Critical),
    KeyPattern::new("splunk-token", "splunk_hec_token", Critical),
    KeyPattern::new("elastic-password", "elastic_password", Critical),
    KeyPattern::new("oauth-secret", "oauth_client_secret", Critical),
    KeyPattern::new("oidc-secret", "oidc_client_secret", Critical),
    KeyPattern::new("jwt-secret", "jwt_secret", Critical),
    KeyPattern::new("session-secret", "session_secret", Critical),
    KeyPattern::new("cookie-secret", "cookie_secret", Critical),
    KeyPattern::new("csrf-secret", "csrf_secret", Critical),
    KeyPattern::new("webhook-secret", "webhook_secret", Critical),
    KeyPattern::new("basic-password", "basic_auth_password", Critical),
    KeyPattern::new("ldap-password", "ldap_bind_password", Critical),
    KeyPattern::new("smtp-password", "smtp_password", Critical),
    KeyPattern::new("ssh-passphrase", "ssh_passphrase", Critical),
    KeyPattern::new("keystore-password", "keystore_password", Critical),
    KeyPattern::new("truststore-password", "truststore_password", Critical),
    KeyPattern::new("certificate-password", "certificate_password", Critical),
  ]
}

///|
fn ascii_lower_string(text : String) -> String {
  let out = StringBuilder::new()
  for c in text {
    out.write_char(
      if c >= 'A' && c <= 'Z' {
        (c.to_int() + 32).unsafe_to_char()
      } else {
        c
      },
    )
  }
  out.to_string()
}

///|
fn skip_horizontal_space(chars : Array[Char], position : Int) -> Int {
  let mut i = position
  while i < chars.length() && (chars[i] == ' ' || chars[i] == '\t') {
    i = i + 1
  }
  i
}

///|
fn find_assignment_separator(chars : Array[Char], position : Int) -> Int {
  let i = skip_horizontal_space(chars, position)
  if i < chars.length() && (chars[i] == '=' || chars[i] == ':') {
    i
  } else {
    -1
  }
}

///|
fn parse_assignment_value(chars : Array[Char], position : Int) -> Span {
  let mut start = skip_horizontal_space(chars, position)
  if start >= chars.length() {
    return { start, end: start, }
  }
  let quote = if chars[start] == '"' || chars[start] == '\'' {
    chars[start]
  } else {
    '\u0000'
  }
  if quote != '\u0000' {
    start = start + 1
  }
  let mut end = start
  if quote != '\u0000' {
    while end < chars.length() &&
          chars[end] != quote &&
          chars[end] != '\n' &&
          chars[end] != '\r' {
      end = end + 1
    }
  } else {
    while end < chars.length() &&
          chars[end] != '\n' &&
          chars[end] != '\r' &&
          chars[end] != ',' &&
          chars[end] != '}' {
      end = end + 1
    }
    while end > start && (chars[end - 1] == ' ' || chars[end - 1] == '\t') {
      end = end - 1
    }
  }
  { start, end, }
}

///|
fn scan_key_pattern(
  chars : Array[Char],
  lower : Array[Char],
  pattern : KeyPattern,
  preview : Bool,
) -> Array[Finding] {
  let out : Array[Finding] = []
  let needle = pattern.key.to_array()
  let mut from = 0
  while from < lower.length() {
    let position = index_of_from(lower, needle, from)
    if position < 0 {
      break
    }
    let before_ok = position == 0 || is_word_boundary(lower[position - 1])
    let after_position = position + needle.length()
    let after_ok = after_position >= lower.length() ||
      is_word_boundary(lower[after_position])
    if before_ok && after_ok {
      let separator = find_assignment_separator(chars, after_position)
      if separator >= 0 {
        let value = parse_assignment_value(chars, separator + 1)
        if value.length() >= pattern.minimum_length {
          let confidence = match pattern.id {
            "generic-password"
            | "generic-secret"
            | "generic-token"
            | "generic-api-key"
            | "generic-private-key"
            | "generic-signing-key"
            | "generic-encryption-key"
            | "generic-auth" => 88
            _ => 99
          }
          out.push(
            Finding::new(
              pattern.id,
              Custom,
              pattern.severity,
              value.start,
              value.end,
              confidence,
              safe_preview(chars, value.start, value.end, preview),
              pattern.message,
            ),
          )
        }
      }
    }
    from = position + needle.length()
  }
  out
}

///|
fn scan_contextual_assignments(
  chars : Array[Char],
  preview : Bool,
) -> Array[Finding] {
  let lower = ascii_lower_string(slice_chars(chars, 0, chars.length())).to_array()
  let out : Array[Finding] = []
  for pattern in builtin_key_patterns() {
    for finding in scan_key_pattern(chars, lower, pattern, preview) {
      out.push(finding)
    }
  }
  out
}

///|
fn scan_pem_blocks(chars : Array[Char], preview : Bool) -> Array[Finding] {
  let out : Array[Finding] = []
  let begin = "-----BEGIN ".to_array()
  let end_marker = "-----END ".to_array()
  let mut from = 0
  while from < chars.length() {
    let start = index_of_from(chars, begin, from)
    if start < 0 {
      break
    }
    let end_start = index_of_from(chars, end_marker, start + begin.length())
    if end_start < 0 {
      break
    }
    let mut end = end_start
    while end < chars.length() && chars[end] != '\n' && chars[end] != '\r' {
      end = end + 1
    }
    let header_end = index_of_from(
      chars,
      "-----".to_array(),
      start + begin.length(),
    )
    let label = if header_end > start {
      slice_chars(chars, start + begin.length(), header_end)
    } else {
      "PEM"
    }
    let severity = if label.contains("PRIVATE KEY") { Critical } else { Medium }
    out.push(
      Finding::new(
        "pem-block",
        Custom,
        severity,
        start,
        end,
        99,
        safe_preview(chars, start, end, preview),
        "PEM encoded " + label,
      ),
    )
    from = end
  }
  out
}

///|
fn scan_connection_strings(
  chars : Array[Char],
  preview : Bool,
) -> Array[Finding] {
  let schemes = [
    "postgres://", "postgresql://", "mysql://", "mongodb://", "mongodb+srv://", "redis://",
    "rediss://", "amqp://", "amqps://",
  ]
  let out : Array[Finding] = []
  for scheme in schemes {
    let needle = scheme.to_array()
    let mut from = 0
    while from < chars.length() {
      let start = index_of_from(chars, needle, from)
      if start < 0 {
        break
      }
      let mut end = start + needle.length()
      let mut at = -1
      while end < chars.length() &&
            chars[end] != ' ' &&
            chars[end] != '\t' &&
            chars[end] != '\n' &&
            chars[end] != '\r' &&
            chars[end] != '"' &&
            chars[end] != '\'' {
        if chars[end] == '@' {
          at = end
        }
        end = end + 1
      }
      if at > start &&
        index_of_from(chars, ":".to_array(), start + needle.length()) < at {
        out.push(
          Finding::new(
            "credential-url",
            Custom,
            Critical,
            start,
            end,
            97,
            safe_preview(chars, start, end, preview),
            "Connection URL containing credentials",
          ),
        )
      }
      from = start + needle.length()
    }
  }
  out
}
