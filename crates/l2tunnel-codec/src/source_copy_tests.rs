use super::*;

#[test]
fn exact_unit_threshold_and_context_scope_match_reference_without_padding_or_clamping()
-> Result<(), Error> {
    let policy = Policy {
        max_unit_bytes: 72,
        copies: 3,
        scope: Scope::ContextAndIndependent,
    };
    let mut context = vec![0, 0xff, 0xff, 0, 0, 66];
    context.extend_from_slice(&[0; 66]);
    let mut raw = vec![1, 0, 0, 2, 0, 66];
    raw.extend_from_slice(&[0x51; 66]);
    assert_eq!(policy.copies_for_unit(&context, 128)?, 3);
    assert_eq!(policy.copies_for_unit(&raw, 128)?, 3);
    assert_eq!(
        Policy {
            max_unit_bytes: 71,
            ..policy
        }
        .copies_for_unit(&context, 128)?,
        1
    );
    assert_eq!(Policy::default().copies_for_unit(&raw, 128)?, 1);

    // A valid explicit timestamp body and a valid fragment are generic short
    // units, but neither is a complete independent/context record.
    let mut timestamp = vec![0, 0, 0, 1, 0, 0];
    timestamp.extend_from_slice(&[0; 23]);
    let fragment = [0, 0, 0, 4, 0, 3, 0, 0, 2, 0, 0];
    for unit in [timestamp.as_slice(), &fragment] {
        assert_eq!(policy.copies_for_unit(unit, 128)?, 1);
        assert_eq!(
            Policy {
                scope: Scope::AllShort,
                ..policy
            }
            .copies_for_unit(unit, 128)?,
            3
        );
    }
    let mut trailing = raw.clone();
    trailing.push(0);
    assert!(matches!(
        policy.copies_for_unit(&trailing, 128),
        Err(Error::Unit(_))
    ));
    assert!(matches!(
        policy.copies_for_unit(&[0, 0, 0], 128),
        Err(Error::Unit(_))
    ));
    for copies in [0, 5, u8::MAX] {
        assert_eq!(
            Policy { copies, ..policy }.validate(128),
            Err(Error::Configuration)
        );
    }
    assert_eq!(
        Policy {
            max_unit_bytes: 129,
            ..policy
        }
        .validate(128),
        Err(Error::Configuration)
    );
    assert_eq!(policy.validate(8), Err(Error::Configuration));
    Ok(())
}
