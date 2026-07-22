//! Criterion benchmark suite for yunq static analysis performance verification.

use criterion::{criterion_group, criterion_main, Criterion};
use yunq_ast::{LanguageIdentifier, SourceFile};
use yunq_parser_rust::RustParser;
use yunq_rules_engine::AstParser;

fn bench_rust_parser(c: &mut Criterion) {
    let code = r#"
fn calculate_sum(numbers: &[i32]) -> i32 {
    let mut total = 0;
    for &num in numbers {
        if num % 2 == 0 {
            total += num;
        } else {
            total -= num;
        }
    }
    total
}
"#;
    let file = SourceFile::new("bench.rs", code, LanguageIdentifier::rust()).unwrap();
    let parser = RustParser::new();

    c.bench_function("parse_rust_ast", |b| {
        b.iter(|| {
            parser.parse(&file).unwrap();
        })
    });
}

criterion_group!(benches, bench_rust_parser);
criterion_main!(benches);
