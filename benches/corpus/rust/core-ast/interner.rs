//! Process-wide string interner for grammar node-kind labels
//! ([`NodeKind::Other`](crate::NodeKind::Other)). Every tree-sitter grammar
//! has a fixed, small vocabulary of node-kind names (`"if_statement"`,
//! `"binary_expression"`, ...), but each occurs on a huge number of AST
//! nodes within one file — before this, every unmapped node paid a fresh
//! heap allocation (`str::to_string`) for the same handful of short
//! strings repeated thousands of times. [`intern`] hands back a shared
//! `Arc<str>` for a given string, allocating once per distinct string for
//! the life of the process and cloning (an atomic refcount bump, no copy)
//! on every repeat.

use std::collections::HashSet;
use std::sync::{Arc, Mutex, OnceLock};

fn table() -> &'static Mutex<HashSet<Arc<str>>> {
    static TABLE: OnceLock<Mutex<HashSet<Arc<str>>>> = OnceLock::new();
    TABLE.get_or_init(|| Mutex::new(HashSet::new()))
}

/// Returns the shared `Arc<str>` for `text`, interning it on first sight.
pub fn intern(text: &str) -> Arc<str> {
    let mut table = table().lock().expect("interner lock poisoned");
    if let Some(existing) = table.get(text) {
        return Arc::clone(existing);
    }
    let interned: Arc<str> = Arc::from(text);
    table.insert(Arc::clone(&interned));
    interned
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repeated_interning_returns_the_same_allocation() {
        let a = intern("if_statement");
        let b = intern("if_statement");
        assert!(Arc::ptr_eq(&a, &b));
    }

    #[test]
    fn distinct_strings_intern_to_distinct_allocations_with_equal_content() {
        let a = intern("if_statement");
        let b = intern("for_statement");
        assert!(!Arc::ptr_eq(&a, &b));
        assert_eq!(&*a, "if_statement");
        assert_eq!(&*b, "for_statement");
    }
}
