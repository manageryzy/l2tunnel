//! Time a single byte-verified repair on the public Rust Rolling decoder.
//! Build the optimized workspace fec crate, then compile this study against its rlib.
use l2tunnel_fec::rolling::{
    Begin, Config, DecodeStep, Decoder, Encoder, MAX_STEP_WORK, Repair, Scope, SourceId, Tick,
    WorkBudget,
};
use std::time::Instant;

const SCOPE: Scope = Scope {
    session: [31; 16],
    epoch: 1,
    stream: 0,
    direction: 0,
};
const NOW: Tick = Tick(1);
const BUDGET: WorkBudget = WorkBudget {
    field: MAX_STEP_WORK,
    copies: MAX_STEP_WORK,
    metadata: MAX_STEP_WORK,
};

fn input(source: usize, width: usize) -> Vec<u8> {
    // Dense, deterministic, full-length payload including every byte value.
    (0..width)
        .map(|col| ((source * 71 + col * 133 + (source >> 4) + (col >> 5)) % 256) as u8)
        .collect()
}

fn finish(decoder: &mut Decoder) -> (WorkBudget, usize) {
    let mut total = WorkBudget::default();
    let mut calls = 0;
    loop {
        calls += 1;
        let step = decoder.step(NOW, BUDGET).unwrap();
        let (work, done) = match step {
            DecodeStep::Pending(work) => (work, false),
            DecodeStep::Accepted { work, .. } => (work, true),
            _ => panic!("unexpected step {step:?}"),
        };
        total.field += work.field;
        total.copies += work.copies;
        total.metadata += work.metadata;
        if done {
            return (total, calls);
        }
    }
}

fn main() {
    let config = Config {
        window: 8192,
        local_window: 128,
        global_every: 16,
        max_payload: 1458,
        max_rows: 2048,
        repair_history: 64,
        handoff_sources: 8192,
        job_ticks: 100,
        debt_ticks: 1000,
        handoff_ticks: 500,
        memory_bytes: 256 * 1024 * 1024,
    };
    println!(
        "support,sample,source_batch_ns,source_count,repair_ns,field,copies,metadata,step_calls,packet_verified"
    );
    for support in [128, 8192] {
        let originals: Vec<_> = (0..support).map(|i| input(i, config.max_payload)).collect();
        let mut encoder = Encoder::new(config, SCOPE, NOW).unwrap();
        for src in &originals {
            encoder.admit_source(src, NOW).unwrap();
        }
        encoder.begin_repair(support == 8192, NOW).unwrap();
        while encoder.pending_repair().is_none() {
            encoder.step(NOW, BUDGET).unwrap();
        }
        let repair: Repair<'_> = encoder.pending_repair().unwrap();
        assert_eq!(repair.support.end - repair.support.start, support as u32);
        assert_eq!(repair.bytes.len(), 1460);
        assert!(repair.bytes.iter().any(|x| *x != 0));
        assert_ne!(
            l2tunnel_fec::field::compact_coefficient(repair.support.seed, 0),
            0
        );
        for sample in 0..12 {
            // Fresh state for every trial. Allocation and encoder work are excluded.
            let mut decoder = Decoder::new(config, SCOPE, NOW).unwrap();
            let sources_started = Instant::now();
            for (i, src) in originals.iter().enumerate().skip(1) {
                assert_eq!(
                    decoder
                        .begin_source(SCOPE, SourceId(i as u32), src, NOW)
                        .unwrap(),
                    Begin::Staged
                );
                finish(&mut decoder);
            }
            let sources_ns = sources_started.elapsed().as_nanos();
            let started = Instant::now();
            assert_eq!(decoder.begin_repair(repair, NOW).unwrap(), Begin::Staged);
            let (work, steps) = finish(&mut decoder);
            let repair_ns = started.elapsed().as_nanos();
            assert_eq!(
                decoder.pending_source(),
                Some((SourceId(0), originals[0].as_slice()))
            );
            assert_eq!(decoder.status().decoded_prefix, support as u32);
            if sample >= 3 {
                println!(
                    "{support},{sample},{sources_ns},{},{repair_ns},{},{},{},{steps},true",
                    support - 1,
                    work.field,
                    work.copies,
                    work.metadata,
                );
            }
        }
    }
}
