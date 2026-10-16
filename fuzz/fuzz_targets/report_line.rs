//! NDJSON report lines as `fsblame` reads them back: any text. Parsing never panics, and a
//! line that parses serializes to JSON that parses again into the same line. The first
//! serialization may normalize the input (a time with a UTC offset or nanoseconds is written
//! in UTC with microseconds, unknown fields are dropped), so the round trip is checked from
//! there: serializing the re-parsed line yields the same JSON.
#![no_main]

use fsblame::report::Line;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|text: &str| {
    let Ok(line) = Line::parse(text) else {
        return;
    };
    let json = serde_json::to_string(&line).expect("a parsed line serializes");
    let again = Line::parse(&json).unwrap_or_else(|err| panic!("{json} does not parse: {err}"));
    assert_eq!(
        serde_json::to_string(&again).expect("a parsed line serializes"),
        json,
        "the line changed in a second round trip"
    );
});
