//! `parabellum` — command-line client of parabellumd.

use clap::Parser;
use std::io::IsTerminal;
use std::process::ExitCode;

fn main() -> ExitCode {
    let cli = pb_cli::Cli::parse();
    let stdout = std::io::stdout();
    let stderr = std::io::stderr();
    let progress = stderr.is_terminal();
    let (mut out, mut err) = (stdout.lock(), stderr.lock());
    let code = pb_cli::run(
        &cli,
        &mut pb_cli::Output {
            out: &mut out,
            err: &mut err,
            progress,
            // SAFETY: geteuid has no preconditions.
            is_root: unsafe { libc::geteuid() } == 0,
        },
    );
    ExitCode::from(code.clamp(0, 255) as u8)
}
