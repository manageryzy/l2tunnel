//! Local exact-capacity and every-allocation failure tests; no allocator/RSS claim.

use super::*;

type Result = io::Result<()>;
const SIZES: [usize; 7] = [11, 17, 17, 23, 29, 31, 43];

fn allocations(fail_at: Option<usize>) -> Allocation {
    Allocation {
        fail_at,
        ..Allocation::new()
    }
}
fn capacities(buffers: &Buffers) -> [usize; 7] {
    [
        buffers.wire.capacity(),
        buffers.seal.capacity(),
        buffers.open.capacity(),
        buffers.plain.capacity(),
        buffers.control_wire.capacity(),
        buffers.control_input.capacity(),
        buffers.frame.capacity(),
    ]
}
fn lengths(buffers: &Buffers) -> [usize; 7] {
    [
        buffers.wire.len(),
        buffers.seal.len(),
        buffers.open.len(),
        buffers.plain.len(),
        buffers.control_wire.len(),
        buffers.control_input.len(),
        buffers.frame.len(),
    ]
}

#[test]
fn seven_real_workspaces_have_exact_layouts_initialized_lengths_and_empty_reserved_frame() -> Result
{
    let mut allocation = allocations(None);
    let buffers = Buffers::build(SIZES, &mut allocation)?;
    assert_eq!(allocation.attempts, 7);
    assert_eq!(allocation.layouts, SIZES);
    assert_eq!(capacities(&buffers), SIZES);
    assert_eq!(lengths(&buffers), [11, 17, 17, 23, 29, 31, 0]);
    assert_eq!(buffers.capacity_bytes(), SIZES.iter().sum::<usize>());
    for bytes in [
        &buffers.wire,
        &buffers.seal,
        &buffers.open,
        &buffers.plain,
        &buffers.control_wire,
        &buffers.control_input,
    ] {
        assert!(bytes.iter().all(|byte| *byte == 0));
    }
    assert!(buffers.frame.is_empty());
    assert_eq!(buffers.frame.capacity(), 43);
    let public = Buffers::new(11, 17, 23, 29, 31, 43)?;
    assert_eq!(capacities(&public), SIZES);
    assert_eq!(public.capacity_bytes(), buffers.capacity_bytes());
    Ok(())
}

#[test]
fn each_of_seven_actual_workspace_allocation_failures_publishes_no_owner_and_is_local() -> Result {
    for failed in 1..=7 {
        let mut allocation = allocations(Some(failed));
        let result = Buffers::build(SIZES, &mut allocation);
        assert!(matches!(result,Err(error) if error.kind()==io::ErrorKind::OutOfMemory));
        assert_eq!(allocation.attempts, failed);
        assert_eq!(&allocation.layouts[..failed], &SIZES[..failed]);
        assert!(allocation.layouts[failed..].iter().all(|bytes| *bytes == 0));
        // Injection is constructor-local; a subsequent ordinary constructor succeeds.
        let real = Buffers::new(11, 17, 23, 29, 31, 43)?;
        assert_eq!(real.capacity_bytes(), SIZES.iter().sum::<usize>());
    }
    Ok(())
}

#[test]
fn each_workspace_zero_or_invalid_layout_is_refused_before_any_allocation() -> Result {
    for index in 0..7 {
        for size in [0, usize::MAX, (isize::MAX as usize) + 1] {
            let mut sizes = SIZES;
            sizes[index] = size;
            let mut allocation = allocations(Some(1));
            assert!(
                matches!(Buffers::build(sizes,&mut allocation),Err(error) if error.kind()==io::ErrorKind::InvalidInput)
            );
            assert_eq!(allocation.attempts, 0);
            assert_eq!(allocation.layouts, [0; 7]);
        }
    }
    for sizes in [
        [0, 1, 1, 1, 1, 1],
        [1, 0, 1, 1, 1, 1],
        [1, 1, 0, 1, 1, 1],
        [1, 1, 1, 0, 1, 1],
        [1, 1, 1, 1, 0, 1],
        [1, 1, 1, 1, 1, 0],
    ] {
        assert_eq!(
            Buffers::new(sizes[0], sizes[1], sizes[2], sizes[3], sizes[4], sizes[5])
                .err()
                .map(|e| e.kind()),
            Some(io::ErrorKind::InvalidInput)
        );
    }
    Ok(())
}

#[test]
fn individually_valid_layouts_with_overflowing_total_are_rejected_before_allocation() -> Result {
    let max = isize::MAX as usize;
    assert!(Layout::array::<u8>(max).is_ok());
    let mut allocation = allocations(Some(1));
    let sizes = [max, max, 1, 1, 1, 1, 1];
    assert!(
        matches!(Buffers::build(sizes,&mut allocation),Err(error) if error.kind()==io::ErrorKind::InvalidInput)
    );
    assert_eq!(allocation.attempts, 0);
    assert_eq!(allocation.layouts, [0; 7]);
    // Two individually legal input arrays cannot overflow usize; no huge allocation is attempted here.
    assert_eq!(layout_bytes(&[max, max])?, usize::MAX - 1);
    Ok(())
}

#[test]
fn both_actual_input_allocations_are_exact_zeroed_and_fail_independently() -> Result {
    for failed in 1..=2 {
        let mut allocation = allocations(Some(failed));
        assert!(
            matches!(Inputs::build([47,53],&mut allocation),Err(error) if error.kind()==io::ErrorKind::OutOfMemory)
        );
        assert_eq!(allocation.attempts, failed);
        assert_eq!(&allocation.layouts[..failed], &[47, 53][..failed]);
        assert!(allocation.layouts[failed..].iter().all(|bytes| *bytes == 0));
    }
    let mut allocation = allocations(None);
    let inputs = Inputs::build([47, 53], &mut allocation)?;
    assert_eq!(allocation.attempts, 2);
    assert_eq!(allocation.layouts, [47, 53, 0, 0, 0, 0, 0]);
    assert_eq!(inputs.native.len(), 47);
    assert_eq!(inputs.native.capacity(), 47);
    assert_eq!(inputs.datagram.len(), 53);
    assert_eq!(inputs.datagram.capacity(), 53);
    assert!(
        inputs
            .native
            .iter()
            .chain(&inputs.datagram)
            .all(|byte| *byte == 0)
    );
    assert_eq!(inputs.capacity_bytes(), 100);
    let public = Inputs::new(47, 53)?;
    assert_eq!(public.capacity_bytes(), inputs.capacity_bytes());
    Ok(())
}

#[test]
fn all_input_bounds_are_preflighted_before_allocating_the_first_input() -> Result {
    for index in 0..2 {
        for size in [0, usize::MAX, (isize::MAX as usize) + 1] {
            let mut sizes = [47, 53];
            sizes[index] = size;
            let mut allocation = allocations(Some(1));
            assert!(
                matches!(Inputs::build(sizes,&mut allocation),Err(error) if error.kind()==io::ErrorKind::InvalidInput)
            );
            assert_eq!(allocation.attempts, 0);
            assert_eq!(allocation.layouts, [0; 7]);
        }
    }
    assert!(Inputs::new(0, 1).is_err());
    assert!(Inputs::new(1, 0).is_err());
    Ok(())
}

#[test]
fn logical_clear_and_frame_use_do_not_remove_retained_backing_charges() -> Result {
    let mut buffers = Buffers::new(11, 17, 23, 29, 31, 43)?;
    let charge = buffers.capacity_bytes();
    buffers.frame.extend_from_slice(&[0x61; 43]);
    assert_eq!(buffers.frame.len(), 43);
    assert_eq!(buffers.frame.capacity(), 43);
    assert_eq!(buffers.capacity_bytes(), charge);
    buffers.frame.clear();
    buffers.wire.clear();
    buffers.seal.clear();
    buffers.open.clear();
    buffers.plain.clear();
    buffers.control_wire.clear();
    buffers.control_input.clear();
    assert_eq!(buffers.capacity_bytes(), charge);
    assert_eq!(capacities(&buffers), SIZES);
    let mut inputs = Inputs::new(47, 53)?;
    inputs.native.clear();
    inputs.datagram.clear();
    assert_eq!(inputs.capacity_bytes(), 100);
    Ok(())
}

#[test]
fn minimum_buffers_still_charge_both_security_copies_and_are_send() -> Result {
    fn is_send<T: Send>() {}
    is_send::<Buffers>();
    is_send::<Inputs>();
    let buffers = Buffers::new(1, 1, 1, 1, 1, 1)?;
    assert_eq!(buffers.capacity_bytes(), 7);
    assert_eq!(lengths(&buffers), [1, 1, 1, 1, 1, 1, 0]);
    let inputs = Inputs::new(1, 1)?;
    assert_eq!(inputs.capacity_bytes(), 2);
    Ok(())
}
