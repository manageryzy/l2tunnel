use super::*;

#[tokio::test]
async fn old_v1_credit_wire_bytes_and_legacy_event_remain_exact() -> io::Result<()> {
    const OLD: &[u8; 16] = b"L2UC\x01\x03\x00\x08\x00\x00\x00\x00\x00\x00\x00\x07";
    let (mut writer, mut reader) = tokio::io::duplex(32);
    write_control_frame_bound(&mut writer, 3, &7_u64.to_be_bytes(), *b"L2UC").await?;
    let mut bytes = [0; 16];
    reader.read_exact(&mut bytes).await?;
    assert_eq!(&bytes, OLD);
    let (sender, mut events) = mpsc::channel(1);
    let result = read_control_bound(
        std::io::Cursor::new(OLD),
        5,
        sender,
        Duration::from_secs(1),
        64,
        *b"L2UC",
    )
    .await;
    assert_eq!(
        result.err().map(|e| e.kind()),
        Some(io::ErrorKind::UnexpectedEof)
    );
    assert!(matches!(
        events.try_recv(),
        Ok((5, ControlEvent::Credit(7)))
    ));
    Ok(())
}

#[tokio::test]
async fn common_parser_keeps_profile_magic_version_and_feedback_length_strict() {
    for header in [
        *b"L2UC\x02\x02\x00\x40",
        *b"L2UC\x01\x02\x00\x08",
        *b"L2RC\x01\x02\x00\x40",
        *b"L2UC\x01\x03\x00\x09",
    ] {
        let (sender, mut events) = mpsc::channel(1);
        let result = read_control_bound_timed(
            std::io::Cursor::new(header),
            0,
            sender,
            Duration::from_secs(1),
            64,
            *b"L2UC",
        )
        .await;
        assert_eq!(
            result.err().map(|e| e.kind()),
            Some(io::ErrorKind::InvalidData)
        );
        assert!(events.try_recv().is_err());
    }
}

#[tokio::test]
async fn native_receipt_uses_the_same_envelope_with_explicit_nine_byte_grammar() -> io::Result<()> {
    const FRAME: &[u8; 17] = b"L2AC\x01\x03\x00\x09\x02\x00\x00\x00\x00\x00\x00\x00\x07";
    let (sender, mut events) = mpsc::channel(1);
    let result = read_native_control_bound_timed(
        std::io::Cursor::new(FRAME),
        3,
        sender,
        Duration::from_secs(1),
        64,
        *b"L2AC",
    )
    .await;
    assert_eq!(
        result.err().map(|e| e.kind()),
        Some(io::ErrorKind::UnexpectedEof)
    );
    assert!(matches!(
        events.try_recv(),
        Ok((
            3,
            NativeControlEvent::Delivered {
                channel: 2,
                record: 7
            },
            _
        ))
    ));
    Ok(())
}
