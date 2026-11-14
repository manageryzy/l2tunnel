//! Real endpoint constructions use the existing directional/loss fixtures.
use super::*;
use crate::storage;
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

fn reserved(send: Config, receive: Config, role: EndpointRole) -> Result<Endpoint> {
    let plan = storage::Plan::for_duplex(send, receive)?;
    Ok(Endpoint::new_duplex_reserved(
        send,
        receive,
        context(role),
        storage::Limits {
            capacity_bytes: plan.capacity_bytes(),
        },
    )?)
}
fn reserved_packed(
    send: packed::Config,
    receive: packed::Config,
    role: EndpointRole,
) -> Result<packed::Endpoint> {
    let plan = storage::Plan::for_packed_duplex(send, receive)?;
    Ok(packed::Endpoint::new_duplex_reserved(
        send,
        receive,
        context(role),
        storage::Limits {
            capacity_bytes: plan.capacity_bytes(),
        },
    )?)
}

#[test]
fn complete_reserved_aligned_owners_deliver_real_asymmetric_frames_after_loss() -> Result {
    let (a, b) = policies();
    let left = reserved(a, b, EndpointRole::Initiator)?;
    let right = reserved(b, a, EndpointRole::Responder)?;
    assert_eq!(
        left.storage_usage()
            .ok_or("no reserved usage")?
            .capacity_bytes,
        storage::Plan::for_duplex(a, b)?.capacity_bytes()
    );
    assert_eq!(
        right
            .storage_usage()
            .ok_or("no reserved usage")?
            .capacity_bytes,
        storage::Plan::for_duplex(b, a)?.capacity_bytes()
    );
    exercise(left, right)
}

#[test]
fn complete_reserved_packed_owners_deliver_real_independent_hold_work_unit_policies() -> Result {
    let (a, b) = policies();
    let a = packed_policy(a, 2, 200, 1)?;
    let b = packed_policy(b, 4, 900, 3)?;
    let left = reserved_packed(a, b, EndpointRole::Initiator)?;
    let right = reserved_packed(b, a, EndpointRole::Responder)?;
    assert_eq!(
        left.storage_usage()
            .ok_or("no reserved usage")?
            .capacity_bytes,
        storage::Plan::for_packed_duplex(a, b)?.capacity_bytes()
    );
    assert_eq!(
        right
            .storage_usage()
            .ok_or("no reserved usage")?
            .capacity_bytes,
        storage::Plan::for_packed_duplex(b, a)?.capacity_bytes()
    );
    exercise(left, right)
}

#[test]
fn legacy_and_complete_reserved_sender_traces_keep_exact_bytes_ids_budgets_and_retries() -> Result {
    let (a, _) = policies();
    compare_equal(
        Endpoint::new(a, context(EndpointRole::Initiator))?,
        reserved(a, a, EndpointRole::Initiator)?,
    )?;
    let p = packed_policy(a, 4, 500, 4)?;
    compare_equal(
        packed::Endpoint::new(p, context(EndpointRole::Initiator))?,
        reserved_packed(p, p, EndpointRole::Initiator)?,
    )?;
    Ok(())
}

#[test]
fn exact_full_plan_has_no_arq_only_subtotal_or_zero_budget_fallback() -> Result {
    let (a, b) = policies();
    let plan = storage::Plan::for_duplex(a, b)?;
    assert_eq!(plan.send_config(), a);
    assert_eq!(plan.receive_config(), b);
    assert_eq!(plan.send_packed(), None);
    assert_eq!(plan.receive_packed(), None);
    assert_eq!(plan.reliable_plan().send_config(), a.recovery);
    assert_eq!(plan.reliable_plan().receive_config(), b.recovery);
    assert!(plan.capacity_bytes() > plan.reliable_plan().capacity_bytes());
    assert!(
        matches!(Endpoint::new_duplex_reserved(a, b, context(EndpointRole::Initiator), storage::Limits {capacity_bytes: plan.capacity_bytes() - 1}),
        Err(storage::Error::Limit {required, limit}) if required == plan.capacity_bytes() && limit + 1 == required)
    );
    let mut bad = b;
    bad.receiver.channels = 0;
    let mut wrong_context = context(EndpointRole::Initiator);
    wrong_context.session = 0;
    assert!(matches!(
        Endpoint::new_duplex_reserved(a, bad, wrong_context, storage::Limits { capacity_bytes: 0 }),
        Err(storage::Error::Endpoint(Error::Receiver(
            receiver::Error::Configuration
        )))
    ));
    assert!(matches!(
        Endpoint::new_duplex_reserved(a, b, wrong_context, storage::Limits { capacity_bytes: 0 }),
        Err(storage::Error::Endpoint(Error::Configuration))
    ));
    assert_eq!(
        Endpoint::new_duplex(a, b, context(EndpointRole::Initiator))?.storage_usage(),
        None
    );
    let p = packed_policy(a, 4, 500, 4)?;
    let q = packed_policy(b, 2, 900, 2)?;
    let packed = storage::Plan::for_packed_duplex(p, q)?;
    assert_eq!(packed.send_packed(), Some(p));
    assert_eq!(packed.receive_packed(), Some(q));
    assert!(matches!(
        packed::Endpoint::new_duplex_reserved(
            p,
            q,
            context(EndpointRole::Initiator),
            storage::Limits { capacity_bytes: 0 }
        ),
        Err(storage::Error::Limit { .. })
    ));
    Ok(())
}

#[test]
fn actual_nested_owners_drop_on_later_wrapper_failure_and_transfer_once_on_success() -> Result {
    use std::{cell::RefCell, rc::Rc};
    let (a, b) = policies();
    let p = packed_policy(a, 4, 500, 4)?;
    let q = packed_policy(b, 2, 900, 2)?;
    for plan in [
        storage::Plan::for_duplex(a, b)?,
        storage::Plan::for_packed_duplex(p, q)?,
    ] {
        let limits = storage::Limits {
            capacity_bytes: plan.capacity_bytes(),
        };
        let trace = Rc::new(RefCell::new(Vec::new()));
        let mut allocation = storage::Allocation::new(&plan, limits)?;
        allocation.trace = Some(trace.clone());
        let owner = Endpoint::assemble_reserved(
            plan,
            context(EndpointRole::Initiator),
            limits,
            &mut allocation,
        )?;
        let count = allocation.actual().1;
        assert_eq!(
            trace.borrow().as_slice(),
            [storage::ConstructionEvent::Transferred {
                capacity_bytes: plan.capacity_bytes()
            }]
        );
        assert_eq!(
            owner
                .storage_usage()
                .ok_or("published usage missing")?
                .capacity_bytes,
            plan.capacity_bytes()
        );
        drop(owner);
        // No temporary construction hook or guard survives in the actual owner.
        assert_eq!(trace.borrow().len(), 1);
        for fail_at in 1..=count {
            let trace = Rc::new(RefCell::new(Vec::new()));
            let mut allocation = storage::Allocation::new(&plan, limits)?;
            allocation.fail_at = Some(fail_at);
            allocation.trace = Some(trace.clone());
            assert!(
                matches!(
                    Endpoint::assemble_reserved(
                        plan,
                        context(EndpointRole::Initiator),
                        limits,
                        &mut allocation
                    ),
                    Err(storage::Error::Allocation)
                ),
                "wrapper reservation {fail_at}"
            );
            let observed = trace.borrow();
            if fail_at == 1 {
                assert!(observed.is_empty());
            } else {
                assert!(
                    matches!(observed.as_slice(), [storage::ConstructionEvent::BeforeDrop {capacity_bytes: Some(n)}, storage::ConstructionEvent::AfterDrop] if *n > 0 && *n < plan.capacity_bytes())
                );
                if fail_at == count {
                    // Both real nested owners were retained before the last
                    // source-buffer allocation failed, then actual drop returned.
                    assert!(
                        matches!(observed[0], storage::ConstructionEvent::BeforeDrop {capacity_bytes: Some(n)} if n > plan.reliable_plan().capacity_bytes() + plan.receiver.capacity_bytes())
                    );
                }
            }
        }
    }
    Ok(())
}
