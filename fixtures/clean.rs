// clean.rs — negative regression fixture for Rust rules.
//
// Adapted from Clippy allow-by-default patterns (MIT / Apache-2.0).
//
// Expected: NO rust:* or smells:unwrap-usage issues on this file.

use std::fs;
use std::io;

fn read_config(path: &str) -> io::Result<String> {
    fs::read_to_string(path)
}

fn divide(a: i64, b: i64) -> Option<i64> {
    if b == 0 {
        return None;
    }
    Some(a / b)
}

struct Widget {
    name: String,
}

impl From<Widget> for String {
    fn from(widget: Widget) -> Self {
        widget.name
    }
}

fn process(items: &[i32]) -> i32 {
    items.iter().copied().sum()
}

fn main() -> io::Result<()> {
    let config = read_config("config.toml")?;
    let total = process(&[1, 2, 3]);
    let _ = divide(total, 1);
    println!("{total} {config}");
    Ok(())
}
