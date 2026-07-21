// FIXME: this whole module needs proper error handling
fn main() {
    let home = std::env::var("HOME").unwrap();
    let config = std::fs::read_to_string(&home).expect("config");
    println!("{config}");
}

fn very_long_function() -> i64 {
    let mut total: i64 = 0;
    total += 1;
    total += 2;
    total += 3;
    total += 4;
    total += 5;
    total += 6;
    total += 7;
    total += 8;
    total += 9;
    total += 10;
    total += 11;
    total += 12;
    total += 13;
    total += 14;
    total += 15;
    total += 16;
    total += 17;
    total += 18;
    total += 19;
    total += 20;
    total += 21;
    total += 22;
    total += 23;
    total += 24;
    total += 25;
    total += 26;
    total += 27;
    total += 28;
    total += 29;
    total += 30;
    total += 31;
    total += 32;
    total += 33;
    total += 34;
    total += 35;
    total += 36;
    total += 37;
    total += 38;
    total += 39;
    total += 40;
    total += 41;
    total += 42;
    total += 43;
    total += 44;
    total += 45;
    total += 46;
    total += 47;
    total += 48;
    total += 49;
    total += 50;
    total += 51;
    total += 52;
    total
}
