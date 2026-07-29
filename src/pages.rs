//! The pages Ember serves itself: sign-in and first-run setup.
//!
//! Authentication is Rust's job — it holds the PAM stack and the signing key —
//! so these screens are rendered here rather than by the panel. Everything past
//! the session cookie is Symfony's.
//!
//! Colours come from design tokens rather than literals, and the accent and
//! product name come from [`Branding`], so a white-label rebrand touches config
//! and not this file.

use crate::config::Branding;

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

/// The shared token set. Every colour in the product resolves through these, so
/// a theme is a matter of overriding the block rather than hunting literals.
pub fn tokens(branding: &Branding) -> String {
    format!(
        ":root {{\n\
         \x20 --accent: {accent};\n\
         \x20 --accent-contrast: #ffffff;\n\
         \x20 --bg: #f1f5f9;\n\
         \x20 --surface: #ffffff;\n\
         \x20 --surface-sunken: #f8fafc;\n\
         \x20 --border: #e2e8f0;\n\
         \x20 --border-strong: #cbd5e1;\n\
         \x20 --text: #0f172a;\n\
         \x20 --text-muted: #64748b;\n\
         \x20 --danger: #b91c1c;\n\
         \x20 --danger-bg: #fef2f2;\n\
         \x20 --danger-border: #fecaca;\n\
         \x20 --success: #15803d;\n\
         \x20 --success-bg: #f0fdf4;\n\
         \x20 --radius: 8px;\n\
         \x20 --radius-lg: 12px;\n\
         \x20 --shadow: 0 1px 2px rgba(15,23,42,.06), 0 8px 24px rgba(15,23,42,.06);\n\
         \x20 --font: ui-sans-serif, system-ui, -apple-system, \"Segoe UI\", sans-serif;\n\
         \x20 --mono: ui-monospace, SFMono-Regular, Menlo, monospace;\n\
         }}\n",
        accent = branding.safe_accent()
    )
}

fn style(branding: &Branding) -> String {
    format!(
        "{tokens}\n\
         * {{ box-sizing: border-box; }}\n\
         body {{ margin:0; min-height:100vh; display:flex; align-items:center;\n\
         \x20 justify-content:center; background:var(--bg); color:var(--text);\n\
         \x20 padding:2rem 1.25rem; font:15px/1.6 var(--font); }}\n\
         main {{ width:100%; max-width:25rem; }}\n\
         .brand {{ display:flex; align-items:center; gap:.6rem; margin:0 0 .2rem; }}\n\
         .brand img {{ height:28px; width:auto; }}\n\
         .brand h1 {{ font-size:1.4rem; font-weight:650; letter-spacing:-.02em; margin:0; }}\n\
         .tag {{ color:var(--text-muted); margin:0 0 1.5rem; font-size:.9rem; }}\n\
         form {{ background:var(--surface); border:1px solid var(--border);\n\
         \x20 border-radius:var(--radius-lg); padding:1.5rem; box-shadow:var(--shadow); }}\n\
         h2 {{ font-size:1rem; font-weight:600; margin:0 0 1.15rem; }}\n\
         label {{ display:block; font-size:.85rem; font-weight:500; margin:0 0 .35rem; }}\n\
         label .opt {{ color:var(--text-muted); font-weight:400; }}\n\
         input {{ width:100%; padding:.55rem .7rem; margin:0 0 1rem; border-radius:var(--radius);\n\
         \x20 border:1px solid var(--border-strong); background:var(--surface);\n\
         \x20 color:var(--text); font-size:.95rem; font-family:inherit; }}\n\
         input:focus {{ outline:none; border-color:var(--accent);\n\
         \x20 box-shadow:0 0 0 3px color-mix(in srgb, var(--accent) 18%, transparent); }}\n\
         button {{ width:100%; padding:.6rem; border:0; border-radius:var(--radius);\n\
         \x20 background:var(--accent); color:var(--accent-contrast); font-weight:600;\n\
         \x20 font-size:.95rem; cursor:pointer; font-family:inherit; }}\n\
         button:hover {{ filter:brightness(1.08); }}\n\
         .err {{ border:1px solid var(--danger-border); background:var(--danger-bg);\n\
         \x20 color:var(--danger); padding:.65rem .8rem; border-radius:var(--radius);\n\
         \x20 margin:0 0 1.15rem; font-size:.88rem; }}\n\
         .note {{ color:var(--text-muted); font-size:.82rem; margin:1.1rem 0 0; }}\n\
         .note code {{ font-family:var(--mono); color:var(--text); }}\n\
         .hint {{ color:var(--text-muted); font-size:.78rem; margin:-.75rem 0 1rem; }}\n",
        tokens = tokens(branding)
    )
}

fn wordmark(branding: &Branding) -> String {
    match &branding.logo_url {
        Some(url) if !url.trim().is_empty() => format!(
            "<img src=\"{}\" alt=\"{}\">",
            escape(url),
            escape(&branding.name)
        ),
        _ => String::new(),
    }
}

fn shell(branding: &Branding, title: &str, tagline: &str, body: &str) -> String {
    format!(
        "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">\n\
         <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n\
         <title>{title}</title><style>{style}</style></head><body><main>\n\
         <div class=\"brand\">{logo}<h1>{name}</h1></div>\n\
         <p class=\"tag\">{tagline}</p>\n{body}\n</main></body></html>",
        style = style(branding),
        logo = wordmark(branding),
        name = escape(&branding.name),
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
    let branding = Branding::resolve();

    // Be explicit about which kind of account this creates — the difference
    // decides where the password lives and how it is checked later.
    let account_note = if can_create_system_user {
        "This creates a <strong>system account</strong> on this machine. Its password \
         is stored by the operating system and checked through PAM."
    } else {
        "Running in <strong>isolated mode</strong>, so no system account will be \
         created. This administrator is stored by the panel alone — enough to set up \
         and recover it, and it does not touch this machine's users."
    };

    let body = format!(
        "{errors}\
         <form method=\"post\" action=\"/setup\">\n\
         <h2>Create your administrator</h2>\n\
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
        &branding,
        &format!("{} — Setup", branding.name),
        "Welcome. Let's create your administrator.",
        &body,
    )
}

/// The sign-in page.
pub fn login(error: Option<&str>, username: &str, notice: Option<&str>) -> String {
    let branding = Branding::resolve();

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

    shell(
        &branding,
        &format!("{} — Sign in", branding.name),
        &branding.tagline,
        &body,
    )
}
