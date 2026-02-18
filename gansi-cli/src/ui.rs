use std::io::{self, Write};

use chrono::Local;
use console::{Style, Term, style};

pub fn banner() {
    let cyan = Style::new().cyan().bold();
    let dim = Style::new().dim();
    let magenta = Style::new().magenta().bold();

    println!();
    println!(
        "  {}  {}",
        cyan.apply_to("▄▆█  G A N S I"),
        magenta.apply_to(format!("v{}", env!("CARGO_PKG_VERSION")))
    );
    println!(
        "  {}",
        dim.apply_to("Gain · AMSI provider · Defender control · local telemetry")
    );
    println!(
        "  {}",
        dim.apply_to("────────────────────────────────────────────")
    );
    println!();
}

pub fn info(msg: impl AsRef<str>) {
    println!(
        "  {} {}",
        style("·").cyan().bold(),
        style(msg.as_ref()).white()
    );
}

pub fn ok(msg: impl AsRef<str>) {
    println!(
        "  {} {}",
        style("✓").green().bold(),
        style(msg.as_ref()).green()
    );
}

pub fn warn(msg: impl AsRef<str>) {
    println!(
        "  {} {}",
        style("!").yellow().bold(),
        style(msg.as_ref()).yellow()
    );
}

pub fn err(msg: impl AsRef<str>) {
    eprintln!(
        "  {} {}",
        style("✗").red().bold(),
        style(msg.as_ref()).red().bold()
    );
}

pub fn kv(key: &str, value: impl AsRef<str>) {
    println!(
        "    {}  {}",
        style(format!("{key:<12}")).dim(),
        style(value.as_ref()).white().bold()
    );
}

pub fn section(title: &str) {
    println!();
    println!(
        "  {} {}",
        style("▸").magenta().bold(),
        style(title).magenta().bold()
    );
}

pub fn listening(pipe: &str) {
    section("listening");
    kv("pipe", pipe);
    kv("stop", "Ctrl+C");
    println!();
    println!(
        "  {}",
        style("waiting for AMSI events…").dim().italic()
    );
    println!();
    let _ = io::stdout().flush();
}

pub fn event_line(seq: u64, message: &str) {
    let ts = Local::now().format("%H:%M:%S%.3f");
    let term = Term::stdout();
    let width = term.size_checked().map(|(_, w)| w as usize).unwrap_or(100);
    let prefix = format!("  {}  {:04}  ", style(ts).dim(), style(seq).cyan().bold());
    // approximate visible prefix length without ANSI: "  HH:MM:SS.mmm  NNNN  "
    let visible_prefix = 2 + 12 + 2 + 4 + 2;
    let body_width = width.saturating_sub(visible_prefix).max(24);

    let body = wrap_dim(message, body_width);
    println!("{prefix}{}", style(&body).white());
    let _ = io::stdout().flush();
}

fn wrap_dim(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let mut out = String::new();
    for (i, ch) in s.chars().enumerate() {
        if i >= max.saturating_sub(1) {
            out.push('…');
            break;
        }
        out.push(ch);
    }
    out
}

pub fn goodbye(events: u64) {
    println!();
    ok(format!("session closed · {events} event(s)"));
    println!();
}

pub fn done_register(dll: &str, pipe: &str) {
    section("registered");
    kv("dll", dll);
    kv("pipe", pipe);
    ok("COM + AMSI provider installed (admin required)");
    println!();
}

pub fn done_unregister(dll: &str) {
    section("unregistered");
    kv("dll", dll);
    ok("COM + AMSI provider removed");
    println!();
}
