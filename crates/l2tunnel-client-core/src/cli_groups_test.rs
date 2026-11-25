//! `test` commands of the grouped CLI: speed and ping tests through the
//! tunnel (docs/modules/tunnel-tests.md TT-03).
use super::{Usage, usage};
use crate::local::tunnel_test::{
    DURATION_MS, Direction, MAX_PINGS, MAX_STREAMS, PING_INTERVAL_MS, TestPhase, TestRequest,
    TestState, test_text,
};
use std::collections::BTreeMap;

/// What a `test` verb asks for.
#[derive(Debug, Eq, PartialEq)]
pub(super) enum Query {
    /// Start a test; follow it to the end unless detached.
    Start { test: TestRequest, follow: bool },
    /// The latest test or test `id`.
    Status(Option<u64>),
    /// Cancel test `id`.
    Cancel(u64),
}

/// Value options and flags a `test` verb accepts (besides the shared ones).
pub(super) fn accepted(verb: &str) -> Option<(&'static [&'static str], &'static [&'static str])> {
    Some(match verb {
        "speed" => (&["--streams", "--seconds"], &["--download", "--detach"]),
        "ping" => (&["--count", "--interval-ms"], &["--detach"]),
        "status" | "cancel" => (&[], &[]),
        _ => return None,
    })
}

fn bounded<T: std::str::FromStr + PartialOrd + Copy>(
    options: &BTreeMap<String, String>,
    key: &str,
    default: T,
    range: std::ops::RangeInclusive<T>,
    reason: &str,
) -> Result<T, Usage> {
    let value = match options.get(key) {
        Some(text) => text
            .parse()
            .map_err(|_| usage(format!("{key} must be a number")))?,
        None => default,
    };
    if !range.contains(&value) {
        return Err(usage(format!("{key} {reason}")));
    }
    Ok(value)
}

/// Parse a `test` verb.
pub(super) fn parse(
    verb: &str,
    positional: &[String],
    options: &BTreeMap<String, String>,
    flag: impl Fn(&str) -> bool,
) -> Result<Query, Usage> {
    let id = || -> Result<u64, Usage> {
        match positional {
            [id] => id
                .parse()
                .ok()
                .filter(|id| *id != 0)
                .ok_or_else(|| usage("ID must be a positive test number")),
            _ => Err(usage("expected one test ID")),
        }
    };
    let start = |test: TestRequest| -> Result<Query, Usage> {
        if let Some(extra) = positional.first() {
            return Err(usage(format!("unexpected argument {extra}")));
        }
        test.validate().map_err(usage)?;
        Ok(Query::Start {
            test,
            follow: !flag("--detach"),
        })
    };
    match verb {
        "speed" => start(TestRequest::Speed {
            direction: if flag("--download") {
                Direction::Download
            } else {
                Direction::Upload
            },
            streams: bounded(options, "--streams", 1, 1..=MAX_STREAMS, "must be 1..8")?,
            duration_ms: bounded(
                options,
                "--seconds",
                10,
                DURATION_MS.start() / 1000..=DURATION_MS.end() / 1000,
                "must be 1..30",
            )? * 1000,
        }),
        "ping" => start(TestRequest::Ping {
            count: bounded(options, "--count", 10, 1..=MAX_PINGS, "must be 1..100")?,
            interval_ms: bounded(
                options,
                "--interval-ms",
                200,
                PING_INTERVAL_MS,
                "must be 100..1000",
            )?,
        }),
        "status" => match positional {
            [] => Ok(Query::Status(None)),
            _ => id().map(|id| Query::Status(Some(id))),
        },
        _ => id().map(Query::Cancel),
    }
}

/// Whether a test reached its end.
pub(super) fn finished(state: &TestState) -> bool {
    state.state != TestPhase::Running
}

/// One progress or result line.
pub(super) fn line(state: &TestState) -> String {
    test_text(state)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn options(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect()
    }

    #[test]
    fn test_verbs_parse_with_defaults_and_bounds() {
        let none = |_: &str| false;
        assert_eq!(
            parse("speed", &[], &options(&[]), none).ok(),
            Some(Query::Start {
                test: TestRequest::Speed {
                    direction: Direction::Upload,
                    streams: 1,
                    duration_ms: 10_000
                },
                follow: true
            })
        );
        assert_eq!(
            parse(
                "speed",
                &[],
                &options(&[("--streams", "4"), ("--seconds", "5")]),
                |flag| flag == "--download" || flag == "--detach"
            )
            .ok(),
            Some(Query::Start {
                test: TestRequest::Speed {
                    direction: Direction::Download,
                    streams: 4,
                    duration_ms: 5_000
                },
                follow: false
            })
        );
        assert_eq!(
            parse("ping", &[], &options(&[("--count", "3")]), none).ok(),
            Some(Query::Start {
                test: TestRequest::Ping {
                    count: 3,
                    interval_ms: 200
                },
                follow: true
            })
        );
        assert_eq!(
            parse("status", &[], &options(&[]), none).ok(),
            Some(Query::Status(None))
        );
        assert_eq!(
            parse("cancel", &["7".into()], &options(&[]), none).ok(),
            Some(Query::Cancel(7))
        );
        for (verb, pairs) in [
            ("speed", vec![("--streams", "9")]),
            ("speed", vec![("--seconds", "0")]),
            ("speed", vec![("--seconds", "31")]),
            ("ping", vec![("--count", "101")]),
            ("ping", vec![("--interval-ms", "50")]),
            ("ping", vec![("--count", "x")]),
        ] {
            assert!(
                parse(verb, &[], &options(&pairs), none).is_err(),
                "{pairs:?}"
            );
        }
        assert!(parse("cancel", &[], &options(&[]), none).is_err());
        assert!(parse("cancel", &["0".into()], &options(&[]), none).is_err());
    }
}
