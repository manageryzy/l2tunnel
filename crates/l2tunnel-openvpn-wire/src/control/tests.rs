use super::*;
type TestResult = Result<(), Box<dyn std::error::Error>>;

fn config(local: u8) -> Config {
    Config {
        local: SessionId([local; 8]),
        max_datagram_bytes: 256,
        arq: ArqConfig {
            max_source_bytes: 4,
            send_bytes: 16,
            receive_bytes: 16,
            send_records: 4,
            receive_records: 4,
            initial_rto: Duration::from_millis(10),
            maximum_rto: Duration::from_millis(40),
            ack_delay: Duration::from_millis(1),
            max_retries: 4,
        },
        lifetime: Duration::from_secs(1),
    }
}
fn pair() -> Result<(Transport, Transport), Error> {
    let mut a = Transport::new(config(1), Role::Client, Duration::ZERO)?;
    let mut b = Transport::new(config(2), Role::Server, Duration::ZERO)?;
    let mut packet = [0; 256];
    let length = a.poll(Duration::ZERO, &mut packet)?.ok_or(Error::State)?;
    assert_eq!(length, 14);
    b.receive(&packet[..length], Duration::ZERO)?;
    let length = b.poll(Duration::ZERO, &mut packet)?.ok_or(Error::State)?;
    assert_eq!(length, 26);
    a.receive(&packet[..length], Duration::ZERO)?;
    let length = a.poll(Duration::ZERO, &mut packet)?.ok_or(Error::State)?;
    assert_eq!(length, 22);
    b.receive(&packet[..length], Duration::ZERO)?;
    Ok((a, b))
}

#[test]
fn real_tls_fragment_stream_survives_loss_reorder_and_duplicate_control() -> TestResult {
    let (mut a, mut b) = pair()?;
    let tls = b"\x16\x03\x03\0\x07\x01\x80\xff\0\0x";
    let mut offset = 0;
    while offset < tls.len() {
        offset += a.write_tls(&tls[offset..], Duration::ZERO)?;
    }
    let mut scratch = [0; 256];
    let mut wires = Vec::new();
    for expected in 1..=3 {
        let length = a.poll(Duration::ZERO, &mut scratch)?.ok_or(Error::State)?;
        let Packet::Control(parsed) = decode(&scratch[..length])? else {
            return Err(Error::State.into());
        };
        assert_eq!(parsed.opcode, Opcode::Control);
        assert_eq!(parsed.packet_id, Some(expected));
        assert!(parsed.acks.is_empty());
        assert!(!scratch[..length].windows(4).any(|value| value == b"L2AR"));
        wires.push(scratch[..length].to_vec());
    }
    // The first source is lost. Later sources and duplicates cannot skip its gap.
    b.receive(&wires[2], Duration::ZERO)?;
    b.receive(&wires[1], Duration::ZERO)?;
    b.receive(&wires[2], Duration::ZERO)?;
    assert_eq!(b.read_tls(&mut scratch, Duration::ZERO)?, 0);
    let length = b.poll(Duration::ZERO, &mut scratch)?.ok_or(Error::State)?;
    let Packet::Control(ack) = decode(&scratch[..length])? else {
        return Err(Error::State.into());
    };
    assert_eq!(ack.opcode, Opcode::Ack);
    assert_eq!(ack.acks.iter().collect::<Vec<_>>(), [3, 2]);
    assert_eq!(ack.remote, Some(config(1).local));
    assert_eq!(ack.packet_id, None);
    a.receive(&scratch[..length], Duration::ZERO)?;
    let retry = Duration::from_millis(10);
    let length = a.poll(retry, &mut scratch)?.ok_or(Error::State)?;
    assert_eq!(&scratch[..length], wires[0]);
    b.receive(&scratch[..length], retry)?;
    let mut actual = Vec::new();
    let mut tiny = [0xa5; 2];
    loop {
        let length = b.read_tls(&mut tiny, retry)?;
        if length == 0 {
            break;
        }
        actual.extend_from_slice(&tiny[..length]);
    }
    assert_eq!(actual, tls);
    // Reverse TLS bytes share the control-session pair and independent IDs.
    assert_eq!(b.write_tls(b"\x17\0\x80\0", retry)?, 4);
    let ack = b.poll(retry, &mut scratch)?.ok_or(Error::State)?;
    a.receive(&scratch[..ack], retry)?;
    let length = b.poll(retry, &mut scratch)?.ok_or(Error::State)?;
    a.receive(&scratch[..length], retry)?;
    let count = a.read_tls(&mut scratch, retry)?;
    assert_eq!(&scratch[..count], b"\x17\0\x80\0");
    Ok(())
}

#[test]
fn unknown_sessions_unsent_ack_and_short_output_preserve_original_owner() -> TestResult {
    let (mut a, mut b) = pair()?;
    let mut packet = [0; 256];
    let length = encode_control(
        Opcode::Ack,
        0,
        config(2).local,
        &[1],
        Some(config(1).local),
        None,
        &[],
        &mut packet,
    )?;
    assert_eq!(
        a.receive(&packet[..length], Duration::ZERO),
        Err(Error::Recovery(
            recovery::RecoveryError::UnsentAcknowledgement
        ))
    );
    let length = encode_control(
        Opcode::Control,
        0,
        SessionId([3; 8]),
        &[],
        None,
        Some(1),
        b"abcd",
        &mut packet,
    )?;
    assert_eq!(
        b.receive(&packet[..length], Duration::ZERO),
        Err(Error::Peer)
    );
    assert_eq!(a.write_tls(b"abcd", Duration::ZERO)?, 4);
    let mut short = [0xa5; 255];
    assert_eq!(a.poll(Duration::ZERO, &mut short), Err(Error::Output));
    assert_eq!(short, [0xa5; 255]);
    let length = a.poll(Duration::ZERO, &mut packet)?.ok_or(Error::State)?;
    let Packet::Control(data) = decode(&packet[..length])? else {
        return Err(Error::State.into());
    };
    assert_eq!(data.packet_id, Some(1));
    b.receive(&packet[..length], Duration::ZERO)?;
    assert_eq!(b.read_tls(&mut packet, Duration::ZERO)?, 4);
    let original = a.expires();
    let length = encode_control(
        Opcode::HardResetServerV2,
        0,
        config(2).local,
        &[0],
        Some(config(1).local),
        Some(0),
        &[],
        &mut packet,
    )?;
    a.receive(&packet[..length], Duration::from_millis(900))?;
    assert_eq!(a.expires(), original);
    assert_eq!(a.poll(original, &mut packet), Err(Error::Expired));
    Ok(())
}

#[test]
fn lost_reset_and_ack_retry_same_original_ids_and_copy_cap() -> TestResult {
    let mut cfg = config(1);
    cfg.arq.max_retries = 1;
    let mut a = Transport::new(cfg, Role::Client, Duration::ZERO)?;
    let mut b = Transport::new(config(2), Role::Server, Duration::ZERO)?;
    let mut packet = [0; 256];
    let first = a.poll(Duration::ZERO, &mut packet)?.ok_or(Error::State)?;
    let original = packet[..first].to_vec();
    assert_eq!(a.poll(Duration::from_millis(9), &mut packet)?, None);
    let length = a
        .poll(Duration::from_millis(10), &mut packet)?
        .ok_or(Error::State)?;
    assert_eq!(&packet[..length], original);
    b.receive(&packet[..length], Duration::from_millis(10))?;
    let length = b
        .poll(Duration::from_millis(10), &mut packet)?
        .ok_or(Error::State)?;
    let reset = packet[..length].to_vec();
    a.receive(&reset, Duration::from_millis(10))?;
    // Drop the client's first ACK. A duplicate reset only generates a second ACK.
    let _ = a.poll(Duration::from_millis(10), &mut packet)?;
    let length = b
        .poll(Duration::from_millis(20), &mut packet)?
        .ok_or(Error::State)?;
    assert_eq!(&packet[..length], reset);
    a.receive(&packet[..length], Duration::from_millis(20))?;
    let length = a
        .poll(Duration::from_millis(20), &mut packet)?
        .ok_or(Error::State)?;
    b.receive(&packet[..length], Duration::from_millis(20))?;
    assert!(b.reset_confirmed);
    let mut exhausted = Transport::new(cfg, Role::Client, Duration::ZERO)?;
    let _ = exhausted.poll(Duration::ZERO, &mut packet)?;
    let _ = exhausted.poll(Duration::from_millis(10), &mut packet)?;
    assert_eq!(
        exhausted.poll(Duration::from_millis(20), &mut packet),
        Err(Error::Expired)
    );
    Ok(())
}
