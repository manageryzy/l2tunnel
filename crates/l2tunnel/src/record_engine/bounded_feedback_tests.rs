//! Actual retained Swift owner feedback under a smaller caller wire allowance.
//! Trusted pure ingress/commit calls do not claim crypto or physical-device proof.
use super::tests::{Family, context, fixture, geometry, packet};
use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;
fn reserved(value: configuration::Configuration, role: Role) -> Result<Engine, storage::Error> {
    let plan = storage::Plan::for_engine(
        value,
        context(role),
        geometry(),
        NativeLimits {
            stall_micros: 50_000,
        },
    )?;
    Engine::new_reserved(
        plan,
        storage::Limits {
            capacity_bytes: plan.capacity_bytes(),
        },
    )
}
#[test]
fn drained_old_swift_duplicate_gets_exact_small_feedback_without_data_or_native_redelivery()
-> TestResult {
    let initial = fixture(Family::Swift, false)?;
    let descriptor = initial.descriptor();
    let configuration::Profile::Swift {
        mut forward,
        mut reverse,
    } = *descriptor.profile()
    else {
        return Err("Swift fixture required".into());
    };
    forward.codec.repair_numerator = 0;
    reverse.codec.repair_numerator = 0;
    forward.codec.flush_micros = 0;
    reverse.codec.flush_micros = 0;
    let value = configuration::Configuration::new(
        initial.envelope(),
        configuration::Descriptor::new(
            descriptor.path_mtu(),
            descriptor.duplex(),
            *descriptor.direction(Role::Client).common(),
            *descriptor.direction(Role::Server).common(),
            configuration::Profile::Swift { forward, reverse },
        )?,
    )?;
    let mut sender = reserved(value, Role::Client)?;
    let mut receiver = reserved(value, Role::Server)?;
    let native = packet(false, 1001, 100, 0x43);
    sender.enqueue_borrowed(Tick(0), &native)?;
    sender
        .admit_borrowed(Tick(0))?
        .ok_or("actual native admission")?;
    let mut output = vec![0; 1024];
    let mut witnesses = [];
    let first_number = (1u64 << 48) + 7;
    let mut budget = OutboundBudget {
        packets: 1,
        wire_bytes: 4096,
    };
    let source = sender
        .poll(
            Tick(1000),
            first_number,
            true,
            &mut output,
            &mut budget,
            &mut witnesses,
        )?
        .ok_or("actual source")?;
    assert_eq!(source.kind, EmissionKind::Source(SourceForm::Swift));
    let original = output[..source.bytes].to_vec();
    receiver.accept_authenticated(
        Tick(1000),
        first_number,
        source.kind,
        &mut output[..source.bytes],
    )?;
    let mut native_output = vec![0; 1024];
    let mut commits = 0;
    for at in 1001..1009 {
        match receiver.prepare_native(Tick(at), 4, Tick(40_000), &mut native_output)? {
            NativePreparation::Ready(prepared) => {
                assert_eq!(&native_output[..prepared.bytes()], native);
                receiver.commit_native(Tick(at), prepared.token())?;
                commits += 1;
            }
            NativePreparation::Idle | NativePreparation::Progress => {}
            NativePreparation::AlreadyPending(_) => {
                return Err("test did not commit its actual token".into());
            }
        }
    }
    assert_eq!(commits, 1);
    let mut feedback_budget = OutboundBudget {
        packets: 1,
        wire_bytes: 4096,
    };
    let feedback = receiver
        .poll(
            Tick(2000),
            first_number + 1,
            false,
            &mut output,
            &mut feedback_budget,
            &mut witnesses,
        )?
        .ok_or("actual confirmation")?;
    assert_eq!(feedback.kind, EmissionKind::Feedback);
    sender.accept_authenticated(
        Tick(2000),
        first_number + 1,
        feedback.kind,
        &mut output[..feedback.bytes],
    )?;
    assert!(sender.drained()? && receiver.drained()?);
    let counts = receiver.native_counts()?;
    let before = (counts.prepared.to_vec(), counts.committed.to_vec());
    let native_stats = receiver.statistics();
    let actual_usage = receiver.storage_usage();
    // A distinct externally replay-checked security number carries the exact
    // old source bytes. It is a genuine codec duplicate, not another native ID.
    let mut delayed = original;
    receiver.accept_authenticated(Tick(2020), first_number + 2, source.kind, &mut delayed)?;
    for at in 2021..2029 {
        assert!(matches!(
            receiver.prepare_native(Tick(at), 4, Tick(40_000), &mut native_output)?,
            NativePreparation::Idle | NativePreparation::Progress
        ));
    }
    assert!(receiver.drained()?);
    let (at, body) = receiver
        .feedback_opportunity()?
        .ok_or("old receiver feedback debt")?;
    assert_eq!(body, swift::FEEDBACK_HEADER);
    let full = body + geometry().reverse_overhead_bytes;
    assert!(full < reverse.codec.datagram_bytes + geometry().reverse_overhead_bytes);
    let mut insufficient = OutboundBudget {
        packets: 1,
        wire_bytes: full - 1,
    };
    let original_budget = insufficient;
    output.fill(0xa5);
    let output_before = output.clone();
    let statistics = receiver.statistics();
    assert!(
        receiver
            .poll(
                at,
                first_number + 3,
                false,
                &mut output,
                &mut insufficient,
                &mut witnesses
            )?
            .is_none()
    );
    assert_eq!(insufficient, original_budget);
    assert_eq!(output, output_before);
    assert_eq!(receiver.statistics(), statistics);
    assert_eq!(receiver.feedback_opportunity()?, Some((at, body)));
    let mut exact = OutboundBudget {
        packets: 1,
        wire_bytes: full,
    };
    let feedback = receiver
        .poll(
            at,
            first_number + 3,
            false,
            &mut output,
            &mut exact,
            &mut witnesses,
        )?
        .ok_or("small exact old-generation feedback")?;
    assert_eq!(feedback.kind, EmissionKind::Feedback);
    assert_eq!(feedback.bytes, body);
    assert_eq!(feedback.wire_bytes, full);
    assert_eq!(feedback.security_number, first_number + 3);
    assert_eq!(exact, OutboundBudget::default());
    sender.accept_authenticated(
        at,
        first_number + 3,
        feedback.kind,
        &mut output[..feedback.bytes],
    )?;
    assert!(sender.drained()? && receiver.drained()?);
    let counts = receiver.native_counts()?;
    assert_eq!(
        (counts.prepared, counts.committed),
        (before.0.as_slice(), before.1.as_slice())
    );
    assert_eq!(receiver.statistics().prepared, native_stats.prepared);
    assert_eq!(receiver.statistics().committed, native_stats.committed);
    assert_eq!(receiver.storage_usage(), actual_usage);
    Ok(())
}
