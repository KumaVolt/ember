//! The two HTML pages Ember serves itself.
//!
//! Authentication is Rust's job — it holds the PAM stack and the signing key —
//! so the setup and login screens are rendered here rather than by the panel.
//! Everything past the session cookie belongs to Symfony.

/// Escape text destined for HTML body or attribute context.
pub fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(ch),
        }
    }
    out
}

const STYLE: &str = r#"
:root { color-scheme: dark; }
* { box-sizing: border-box; }
body { margin:0; min-height:100vh; display:flex; align-items:center; justify-content:center;
  background:#0e0f12; color:#e6e8ee; padding:2rem 1.25rem;
  font:15px/1.6 ui-sans-serif, system-ui, -apple-system, sans-serif; }
main { width:100%; max-width:26rem; }
.brand { font-size:1.5rem; font-weight:650; letter-spacing:-.02em; margin:0 0 .2rem; }
.brand span { color:#ff7a45; }
.tag { color:#8b90a0; margin:0 0 1.75rem; font-size:.9rem; }
form { border:1px solid #23252c; background:#14161a; border-radius:12px; padding:1.5rem; }
h2 { font-size:.75rem; text-transform:uppercase; letter-spacing:.08em; color:#8b90a0;
  margin:0 0 1.15rem; font-weight:600; }
label { display:block; font-size:.82rem; color:#b6bac6; margin:0 0 .35rem; }
label .opt { color:#6b7080; font-weight:400; }
input { width:100%; padding:.6rem .7rem; margin:0 0 1rem; border-radius:8px;
  border:1px solid #2b2e37; background:#0e0f12; color:#e6e8ee; font-size:.95rem;
  font-family:inherit; }
input:focus { outline:none; border-color:#ff7a45; box-shadow:0 0 0 3px rgba(255,122,69,.15); }
button { width:100%; padding:.65rem; border:0; border-radius:8px; background:#ff7a45;
  color:#1a0d06; font-weight:650; font-size:.95rem; cursor:pointer; font-family:inherit; }
button:hover { background:#ff8d5f; }
.err { border:1px solid #7f2d2d; background:#2a1414; color:#ffb4b4; padding:.7rem .85rem;
  border-radius:8px; margin:0 0 1.15rem; font-size:.88rem; }
.note { color:#8b90a0; font-size:.82rem; margin:1.15rem 0 0; }
.note code { color:#c9cdd8; }
.hint { color:#6b7080; font-size:.78rem; margin:-.7rem 0 1rem; }
"#;

fn shell(title: &str, tagline: &str, body: &str) -> String {
    format!(
        "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">\n\
         <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n\
         <title>{title}</title><style>{STYLE}</style></head><body><main>\n\
         <h1 class=\"brand\">Ember<span>.</span></h1>\n\
         <p class=\"tag\">{tagline}</p>\n{body}\n</main></body></html>"
    )
}

fn error_block(error: Option<&str>) -> String {
    match error {
        Some(message) => format!("<div class=\"err\">{}</div>", escape(message)),
        None => String::new(),
    }
}

/// First-run setup. Shown until an administrator exists.
pub fn setup(
    error: Option<&str>,
    username: &str,
    email: &str,
    can_create_system_user: bool,
) -> String {
    // Be explicit about which kind of account this will create — the difference
    // decides where the password lives and how it is checked later.
    let account_note = if can_create_system_user {
        "This creates a <strong>system account</strong> on this machine. Its password \
         is stored by the operating system and checked through PAM."
    } else {
        "Ember is in <strong>isolated mode</strong>, so it will not create a system \
         account. This administrator is stored by Ember alone — enough to set up and \
         recover the panel, and it does not touch this machine's users."
    };

    let body = format!(
        "{errors}\
         <form method=\"post\" action=\"/setup\">\n\
         <h2>Set up your administrator</h2>\n\
         <label for=\"username\">Username</label>\n\
         <input id=\"username\" name=\"username\" value=\"{username}\" autocapitalize=\"none\" \
         autocorrect=\"off\" spellcheck=\"false\" required>\n\
         <label for=\"email\">Email <span class=\"opt\">— optional</span></label>\n\
         <input id=\"email\" name=\"email\" type=\"email\" value=\"{email}\" \
         autocapitalize=\"none\" spellcheck=\"false\">\n\
         <label for=\"password\">Password</label>\n\
         <input id=\"password\" name=\"password\" type=\"password\" \
         autocomplete=\"new-password\" required>\n\
         <p class=\"hint\">At least 12 characters.</p>\n\
         <label for=\"confirm\">Confirm password</label>\n\
         <input id=\"confirm\" name=\"confirm\" type=\"password\" \
         autocomplete=\"new-password\" required>\n\
         <button type=\"submit\">Create administrator</button>\n\
         <p class=\"note\">{account_note}</p>\n\
         </form>",
        errors = error_block(error),
        username = escape(username),
        email = escape(email),
    );

    shell(
        "Ember — Setup",
        "Welcome. Let's create your administrator.",
        &body,
    )
}

/// The login page.
pub fn login(error: Option<&str>, username: &str, notice: Option<&str>) -> String {
    let notice_block = match notice {
        Some(text) => format!("<p class=\"note\">{}</p>", escape(text)),
        None => String::new(),
    };

    let body = format!(
        "{errors}\
         <form method=\"post\" action=\"/login\">\n\
         <h2>Sign in</h2>\n\
         <label for=\"username\">Username</label>\n\
         <input id=\"username\" name=\"username\" value=\"{username}\" autocapitalize=\"none\" \
         autocorrect=\"off\" spellcheck=\"false\" autocomplete=\"username\" required autofocus>\n\
         <label for=\"password\">Password</label>\n\
         <input id=\"password\" name=\"password\" type=\"password\" \
         autocomplete=\"current-password\" required>\n\
         <button type=\"submit\">Sign in</button>\n\
         <p class=\"note\">Locked out? Run <code>ember recover</code> on this server.</p>\n\
         {notice_block}\
         </form>",
        errors = error_block(error),
        username = escape(username),
    );

    shell("Ember — Sign in", "Server control panel", &body)
}
