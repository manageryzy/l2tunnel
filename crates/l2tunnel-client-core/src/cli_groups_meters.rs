//! `meters read|catalog|watch`: the meter CSR over the local API
//! (`docs/modules/meter-csr.md`, MCSR-11).
use super::{Exit, Output, Usage, exchange, note, refused, unavailable as failed, usage};
use crate::local::{METER_PAGE_LIMIT, MeterEntry, MeterPage, MeterSide, OperationAction};
use l2tunnel_meters::catalog::{self, Kind};
use std::collections::BTreeMap;
use std::io::Write;
use std::path::PathBuf;
use std::time::Duration;

/// Most pages one command follows, so a bad cursor can never loop forever.
const PAGE_BOUND: usize = 4096;

/// What a `meters` verb asks for.
#[derive(Debug, Eq, PartialEq)]
pub(super) enum Query {
    /// One page, or every page with `all`.
    Read {
        side: MeterSide,
        prefix: String,
        limit: u16,
        all: bool,
    },
    /// Catalog patterns.
    Catalog {
        prefix: String,
        limit: u16,
        all: bool,
    },
    /// Every register under `prefix`, repeatedly, as rates and percentiles.
    Watch {
        side: MeterSide,
        prefix: String,
        interval: u64,
        count: Option<u64>,
    },
}

/// Value options and flags a `meters` verb accepts (besides the shared ones).
pub(super) fn accepted(verb: &str) -> Option<(&'static [&'static str], &'static [&'static str])> {
    Some(match verb {
        "read" => (&["--limit"], &["--remote", "--all"]),
        "catalog" => (&["--limit"], &["--all"]),
        "watch" => (&["--interval", "--count"], &["--remote"]),
        _ => return None,
    })
}

fn number(options: &BTreeMap<String, String>, key: &str) -> Result<Option<u64>, Usage> {
    options
        .get(key)
        .map(|text| {
            text.parse()
                .map_err(|_| usage(format!("{key} must be a number")))
        })
        .transpose()
}

/// Parse a `meters` verb.
pub(super) fn parse(
    verb: &str,
    positional: &[String],
    options: &BTreeMap<String, String>,
    flag: impl Fn(&str) -> bool,
) -> Result<Query, Usage> {
    let prefix = match positional {
        [] => String::new(),
        [prefix] => prefix.clone(),
        [_, extra, ..] => return Err(usage(format!("unexpected argument {extra}"))),
    };
    if l2tunnel_meters::path::validate_prefix(&prefix).is_err() {
        return Err(usage(format!(
            "invalid meter prefix {prefix:?}: dot-separated [a-z0-9_] segments, at most {} bytes",
            l2tunnel_meters::path::MAX_PREFIX_BYTES
        )));
    }
    let side = if flag("--remote") {
        MeterSide::Remote
    } else {
        MeterSide::Local
    };
    let limit = match number(options, "--limit")? {
        None => METER_PAGE_LIMIT,
        Some(value) => u16::try_from(value)
            .ok()
            .filter(|value| (1..=METER_PAGE_LIMIT).contains(value))
            .ok_or_else(|| usage(format!("--limit must be 1..{METER_PAGE_LIMIT}")))?,
    };
    Ok(match verb {
        "read" => Query::Read {
            side,
            prefix,
            limit,
            all: flag("--all"),
        },
        "catalog" => Query::Catalog {
            prefix,
            limit,
            all: flag("--all"),
        },
        _ => {
            let interval = number(options, "--interval")?.unwrap_or(1);
            if !(1..=60).contains(&interval) {
                return Err(usage("--interval must be 1..60"));
            }
            let count = number(options, "--count")?;
            if count == Some(0) {
                return Err(usage("--count must be nonzero"));
            }
            Query::Watch {
                side,
                prefix,
                interval,
                count,
            }
        }
    })
}

fn side_name(side: MeterSide) -> &'static str {
    match side {
        MeterSide::Local => "local",
        MeterSide::Remote => "remote",
    }
}

fn header(out: &mut dyn Write, page: &MeterPage) -> std::io::Result<()> {
    writeln!(
        out,
        "{} · generation {} · sampled at {} ms{}",
        side_name(page.side),
        page.generation,
        page.sampled_ms,
        page.age_ms
            .map(|age| format!(" · table age {age} ms"))
            .unwrap_or_default()
    )
}

/// Every page under `prefix`; `Err` is the exit already reported.
async fn read_all(
    socket: &PathBuf,
    output: &Output,
    side: MeterSide,
    prefix: &str,
    limit: u16,
    all: bool,
    print: bool,
) -> Result<(u64, Vec<MeterEntry>), Exit> {
    let mut cursor: Option<String> = None;
    let mut entries = Vec::new();
    let mut generation = None;
    for _ in 0..PAGE_BOUND {
        let action = OperationAction::MetersRead {
            side,
            prefix: prefix.to_owned(),
            cursor: cursor.clone(),
            limit,
        };
        let reply = match Box::pin(exchange(socket, action)).await {
            Ok(reply) if reply.ok => reply,
            Ok(reply) => return Err(refused(output, &reply)),
            Err((exit, error)) => return Err(failed(exit, error)),
        };
        let Some(page) = reply.meters.as_deref() else {
            note("service replied without meters");
            return Err(Exit::Failed);
        };
        if generation.is_some_and(|value| value != page.generation) {
            note("the session generation changed while paging; read again");
            return Err(Exit::Failed);
        }
        let first = generation.is_none();
        generation = Some(page.generation);
        if print {
            output.reply(&reply, |out| {
                if first {
                    header(out, page)?;
                }
                for entry in &page.entries {
                    writeln!(out, "{} = {}", entry.path, entry.value)?;
                }
                Ok(())
            });
        }
        // A cursor must move forward; anything else is a service fault.
        if page.next.is_some() && page.next <= cursor {
            note("service returned a non-advancing cursor");
            return Err(Exit::Failed);
        }
        entries.extend(page.entries.iter().cloned());
        match (&page.next, all) {
            (Some(next), true) => cursor = Some(next.clone()),
            (Some(next), false) => {
                if print {
                    note(format!("more registers follow {next}; add --all"));
                }
                return Ok((page.generation, entries));
            }
            (None, _) => return Ok((page.generation, entries)),
        }
    }
    note("page bound reached");
    Err(Exit::Failed)
}

async fn catalog(socket: &PathBuf, output: &Output, prefix: String, limit: u16, all: bool) -> Exit {
    let mut cursor = None;
    for _ in 0..PAGE_BOUND {
        let action = OperationAction::MetersCatalog {
            prefix: prefix.clone(),
            cursor,
            limit,
        };
        let reply = match Box::pin(exchange(socket, action)).await {
            Ok(reply) if reply.ok => reply,
            Ok(reply) => return refused(output, &reply),
            Err((exit, error)) => return failed(exit, error),
        };
        let Some(page) = reply.meter_catalog.as_deref() else {
            note("service replied without a catalog");
            return Exit::Failed;
        };
        output.reply(&reply, |out| {
            for entry in &page.entries {
                write!(
                    out,
                    "{}  {} {} · {} · {}",
                    entry.pattern, entry.kind, entry.unit, entry.family, entry.row
                )?;
                match &entry.reason {
                    Some(reason) => writeln!(out, " · unavailable: {reason}")?,
                    None => writeln!(out)?,
                }
            }
            Ok(())
        });
        match (page.next, all) {
            (Some(next), true) if cursor.is_none_or(|previous| next > previous) => {
                cursor = Some(next);
            }
            (Some(_), true) => {
                note("service returned a non-advancing cursor");
                return Exit::Failed;
            }
            (Some(next), false) => {
                note(format!("more patterns follow (cursor {next}); add --all"));
                return Exit::Completed;
            }
            (None, _) => return Exit::Completed,
        }
    }
    note("page bound reached");
    Exit::Failed
}

/// One watch line per register or wait block. Counters and durations show
/// per-second rates against the previous read of the same generation;
/// histograms show p50/p99 of the waits completed in the interval.
pub(super) fn watch_lines(
    previous: Option<&BTreeMap<String, u64>>,
    current: &BTreeMap<String, u64>,
    seconds: f64,
) -> Vec<String> {
    let mut lines = Vec::new();
    let mut histograms: BTreeMap<&str, [u64; l2tunnel_meters::wait::BUCKETS]> = BTreeMap::new();
    for (path, value) in current {
        if let Some((base, bucket)) = path.rsplit_once(".hist.b")
            && let Ok(index) = bucket.parse::<usize>()
            && index < l2tunnel_meters::wait::BUCKETS
        {
            let before = previous.and_then(|map| map.get(path)).copied().unwrap_or(0);
            histograms.entry(base).or_default()[index] = value.saturating_sub(before);
            continue;
        }
        let kind = catalog::lookup(path).map(|descriptor| descriptor.kind);
        match (kind, previous.and_then(|map| map.get(path))) {
            (Some(Kind::Counter | Kind::Duration), Some(before)) if seconds > 0.0 => {
                let rate = value.saturating_sub(*before) as f64 / seconds;
                lines.push(format!("{path} = {value} ({rate:.1}/s)"));
            }
            _ => lines.push(format!("{path} = {value}")),
        }
    }
    for (base, counts) in histograms {
        let histogram = l2tunnel_meters::Histogram::from_counts(counts);
        match (histogram.quantile(0.5), histogram.quantile(0.99)) {
            (Some(p50), Some(p99)) => {
                lines.push(format!("{base} waits: p50 ≤ {p50} µs, p99 ≤ {p99} µs"));
            }
            _ => lines.push(format!("{base} waits: none completed")),
        }
    }
    lines
}

/// The query as a heap future: keeps the large shared command dispatcher's
/// frame unchanged in debug builds.
#[inline(never)]
pub(super) fn boxed<'a>(
    socket: &'a PathBuf,
    output: &'a Output,
    query: Query,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Exit> + Send + 'a>> {
    Box::pin(run(socket, output, query))
}

/// Run one parsed `meters` query.
async fn run(socket: &PathBuf, output: &Output, query: Query) -> Exit {
    match query {
        Query::Read {
            side,
            prefix,
            limit,
            all,
        } => match Box::pin(read_all(socket, output, side, &prefix, limit, all, true)).await {
            Ok(_) => Exit::Completed,
            Err(exit) => exit,
        },
        Query::Catalog { prefix, limit, all } => {
            Box::pin(catalog(socket, output, prefix, limit, all)).await
        }
        Query::Watch {
            side,
            prefix,
            interval,
            count,
        } => {
            let mut previous: Option<(u64, BTreeMap<String, u64>)> = None;
            let mut taken = 0_u64;
            loop {
                // Boxed: these futures nest the exchange future.
                let (generation, entries) = match Box::pin(read_all(
                    socket,
                    output,
                    side,
                    &prefix,
                    METER_PAGE_LIMIT,
                    true,
                    output.json,
                ))
                .await
                {
                    Ok(value) => value,
                    Err(exit) => return exit,
                };
                let current: BTreeMap<String, u64> = entries
                    .into_iter()
                    .map(|entry| (entry.path, entry.value))
                    .collect();
                if !output.json {
                    let before = previous
                        .as_ref()
                        .filter(|(value, _)| *value == generation)
                        .map(|(_, map)| map);
                    let mut out = std::io::stdout().lock();
                    let _written = writeln!(out, "— {} generation {generation}", side_name(side));
                    for line in watch_lines(before, &current, interval as f64) {
                        let _written = writeln!(out, "{line}");
                    }
                }
                previous = Some((generation, current));
                taken += 1;
                if count.is_some_and(|count| taken >= count) {
                    return Exit::Completed;
                }
                tokio::time::sleep(Duration::from_secs(interval)).await;
            }
        }
    }
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
    fn parses_verbs_and_limits() {
        let none = |_: &str| false;
        assert_eq!(
            parse("read", &["mux".into()], &options(&[]), |name: &str| name
                == "--remote")
            .ok(),
            Some(Query::Read {
                side: MeterSide::Remote,
                prefix: "mux".into(),
                limit: METER_PAGE_LIMIT,
                all: false
            })
        );
        assert!(parse("read", &["Bad".into()], &options(&[]), none).is_err());
        assert!(parse("read", &[], &options(&[("--limit", "0")]), none).is_err());
        assert!(parse("read", &[], &options(&[("--limit", "257")]), none).is_err());
        assert!(parse("watch", &[], &options(&[("--interval", "61")]), none).is_err());
        assert!(parse("watch", &[], &options(&[("--count", "0")]), none).is_err());
        assert_eq!(
            parse(
                "catalog",
                &[],
                &options(&[("--limit", "5")]),
                |name: &str| name == "--all"
            )
            .ok(),
            Some(Query::Catalog {
                prefix: String::new(),
                limit: 5,
                all: true
            })
        );
    }

    #[test]
    fn watch_shows_rates_gauges_and_interval_percentiles() {
        let base = "runtime.native_ingress.lane0.user";
        let mut before = BTreeMap::new();
        before.insert(format!("{base}.refusals"), 10);
        before.insert(format!("{base}.occupancy_bytes"), 100);
        before.insert(format!("{base}.wait.queue_full.hist.b03"), 5);
        let mut now = before.clone();
        now.insert(format!("{base}.refusals"), 30);
        now.insert(format!("{base}.occupancy_bytes"), 50);
        now.insert(format!("{base}.wait.queue_full.hist.b03"), 6);
        now.insert(format!("{base}.wait.queue_full.hist.b10"), 1);
        let lines = watch_lines(Some(&before), &now, 2.0);
        assert!(lines.contains(&format!("{base}.refusals = 30 (10.0/s)")));
        assert!(lines.contains(&format!("{base}.occupancy_bytes = 50")));
        assert!(lines.contains(&format!(
            "{base}.wait.queue_full waits: p50 ≤ 15 µs, p99 ≤ 2047 µs"
        )));
        let first = watch_lines(None, &now, 2.0);
        assert!(first.contains(&format!("{base}.refusals = 30")));
    }
}
