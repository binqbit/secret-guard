//! Human-readable terminal output and the plain formats used by scripts.
use std::fmt::Display;
use std::io::{self, IsTerminal, Write};

use clap::builder::styling::{AnsiColor, Styles};
use colored::{ColoredString, Colorize};

pub enum Tone {
    Open,
    Locked,
    Warning,
    Heading,
    Action,
    Error,
}

pub struct Palette {
    terminal: bool,
    color: bool,
}

fn color_disabled() -> bool {
    std::env::var_os("NO_COLOR").is_some_and(|value| !value.is_empty())
        || std::env::var_os("TERM").is_some_and(|value| value == "dumb")
}

impl Palette {
    pub fn for_stream(stream: &impl IsTerminal) -> Self {
        let terminal = stream.is_terminal();
        Self {
            terminal,
            color: terminal && !color_disabled(),
        }
    }

    pub fn is_terminal(&self) -> bool {
        self.terminal
    }

    pub fn paint(&self, tone: Tone, value: impl Display) -> ColoredString {
        let text = ColoredString::from(value.to_string());
        if !self.color {
            return text;
        }
        match tone {
            Tone::Open => text.green(),
            Tone::Locked => text.red(),
            Tone::Warning => text.yellow(),
            Tone::Heading => text.cyan().bold(),
            Tone::Action => text.bold(),
            Tone::Error => text.red().bold(),
        }
    }
}

pub fn cli_styles() -> Styles {
    let heading = AnsiColor::Cyan.on_default().bold();
    Styles::styled().header(heading).usage(heading)
}

pub fn print_cli_message(error: &clap::Error) {
    // Help uses stdout and argument errors use stderr. Decide using that exact
    // descriptor, including when a caller redirects only one of them.
    fn print(out: &mut (impl Write + IsTerminal), error: &clap::Error) -> io::Result<()> {
        let rendered = error.render();
        if Palette::for_stream(out).color {
            write!(out, "{}", rendered.ansi())
        } else {
            write!(out, "{rendered}")
        }
    }
    // Match clap's exit behavior when a reader closes a help or error pipe.
    if error.use_stderr() {
        let _ = print(&mut io::stderr().lock(), error);
    } else {
        let _ = print(&mut io::stdout().lock(), error);
    }
}

// Leave rule syntax and real line breaks readable. Escape nonprinting characters
// from configuration or diagnostics before they reach a terminal.
pub fn terminal_text(contents: &str) -> String {
    let mut text = String::with_capacity(contents.len());
    for ch in contents.chars() {
        match ch {
            '\n' | '\'' | '"' | '\\' => text.push(ch),
            _ => text.extend(ch.escape_debug()),
        }
    }
    text
}

pub fn report_error(error: &anyhow::Error) {
    let _ = write_error(&mut io::stderr().lock(), error);
}

fn write_error(out: &mut (impl Write + IsTerminal), error: &anyhow::Error) -> io::Result<()> {
    let palette = Palette::for_stream(out);
    if palette.is_terminal() {
        writeln!(
            out,
            "{}  {}",
            palette.paint(Tone::Error, "Error"),
            terminal_text(&error.to_string())
        )?;
        for cause in error.chain().skip(1) {
            writeln!(out, "       {}", terminal_text(&cause.to_string()))?;
        }
    } else {
        writeln!(out, "secret-guard: {error:#}")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::terminal_text;

    #[test]
    fn terminal_rules_preserve_patterns_and_escape_control_sequences() {
        assert_eq!(
            terminal_text("# Alice's café\n./dir\\[0\\]\n\x1b[2J\r\u{202e}"),
            "# Alice's café\n./dir\\[0\\]\n\\u{1b}[2J\\r\\u{202e}"
        );
    }
}
