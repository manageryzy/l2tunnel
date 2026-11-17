//! Actual actor custody and original packet caps; no synthetic session owner.
use super::*;
use std::{
    future::Future,
    pin::Pin,
    sync::{Arc, atomic::Ordering},
    task::Poll,
};

async fn pair() -> Result<(Carrier, Carrier), TestError> {
    let cert = rcgen::generate_simple_self_signed(vec!["openvpn-custody.test".to_owned()])?;
    let roots = vec![cert.cert.der().to_vec()];
    let client_tls = ClientTls::from_der_roots(&roots)?;
    let server_tls = ServerTls::from_der(&roots, &cert.signing_key.serialize_der())?;
    let member = MemberKey::from_pkcs8(&MemberKey::generate_pkcs8()?)?;
    let members = MemberAllowlist::new(&[member.public_key()])?;
    let (a, b) = sockets().await?;
    let cap = Instant::now() + Duration::from_secs(3);
    let (a, b) = timeout(Duration::from_secs(4), async {
        tokio::join!(
            client_connect_until(
                a,
                config(),
                ClientCredentials {
                    tls: &client_tls,
                    server_name: "openvpn-custody.test",
                    member: &member
                },
                cap
            ),
            server_accept_until(
                b,
                config(),
                ServerCredentials {
                    tls: &server_tls,
                    members: &members
                },
                cap
            )
        )
    })
    .await?;
    Ok((a?, b?))
}

#[tokio::test]
async fn real_actor_retains_user_wouldblock_while_common_control_and_tls_complete() -> TestResult {
    let (mut a, mut b) = pair().await?;
    let addresses = a.addresses();
    a.shared.user_gate.store(true, Ordering::Relaxed);
    let cap = Instant::now() + Duration::from_secs(1);
    let slots = a.shared.user.available_permits();
    let mut user = a.try_send_until(Class::User, b"held-user", cap)?;
    assert_eq!(user.deadline(), cap);
    assert_eq!(a.shared.user.available_permits(), slots - 1);
    std::future::poll_fn(|cx| {
        assert!(Pin::new(&mut user).poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    timeout(Duration::from_secs(1), async {
        loop {
            if a.physical_status()?.user_would_block > 0 {
                return Ok::<_, Error>(());
            }
            tokio::task::yield_now().await;
        }
    })
    .await??;
    let before = a.physical_status()?;
    assert_eq!(before.user_datagrams, 0);
    let control = a.try_send_until(Class::Control, b"real-common-control", cap)?;
    let receipt = timeout(Duration::from_secs(1), control).await??;
    assert_eq!(
        (receipt.record_bytes, receipt.udp_bytes, receipt.ip_bytes),
        (19, 20, 48)
    );
    assert_eq!(
        timeout(Duration::from_secs(1), b.recv()).await??,
        b"real-common-control"
    );
    let mut tls = [0; 3];
    let (write, read) = timeout(Duration::from_secs(1), async {
        tokio::join!(
            a.control().write_all(b"tls"),
            b.control().read_exact(&mut tls)
        )
    })
    .await?;
    write?;
    read?;
    assert_eq!(&tls, b"tls");
    let blocked = a.physical_status()?;
    assert_eq!(blocked.user_datagrams, 0);
    assert_eq!(
        blocked.common_control_datagrams,
        before.common_control_datagrams + 1
    );
    assert!(blocked.tls_control_datagrams > before.tls_control_datagrams);
    a.shared.user_gate.store(false, Ordering::Relaxed);
    let receipt = timeout(Duration::from_secs(1), user).await??;
    assert_eq!(receipt.record_bytes, 9);
    assert!(receipt.accepted_at < cap);
    assert_eq!(
        timeout(Duration::from_secs(1), b.recv()).await??,
        b"held-user"
    );
    assert_eq!(a.shared.user.available_permits(), slots);
    assert_eq!(a.physical_status()?.user_datagrams, 1);
    assert_eq!(a.addresses(), addresses);
    Ok(())
}

#[tokio::test]
async fn real_actor_original_packet_expiry_refuses_held_user_without_blocking_control() -> TestResult
{
    let (a, mut b) = pair().await?;
    a.shared.user_gate.store(true, Ordering::Relaxed);
    let cap = Instant::now() + Duration::from_millis(20);
    let pending = a.try_send_until(Class::User, b"must-expire", cap)?;
    assert!(matches!(
        timeout(Duration::from_secs(1), pending).await?,
        Err(SendFailure::Expired { accepted: None })
    ));
    assert_eq!(a.physical_status()?.user_datagrams, 0);
    assert_eq!(a.physical_status()?.expired_before_write, 1);
    let pending = a.try_send_until(
        Class::Control,
        b"still-live",
        Instant::now() + Duration::from_secs(1),
    )?;
    timeout(Duration::from_secs(1), pending).await??;
    assert_eq!(
        timeout(Duration::from_secs(1), b.recv()).await??,
        b"still-live"
    );
    assert!(matches!(
        a.try_send_until(Class::User, b"old-cap", cap),
        Err(Error::Timeout)
    ));
    Ok(())
}

#[tokio::test]
async fn actual_whole_write_crossing_original_cap_retains_late_fact_and_single_debit() -> TestResult
{
    let cfg = config();
    let budget = crate::budget::Budget::new(cfg.wire_budget, Instant::now());
    let ledger = send::Ledger::new();
    let mut data = Data::Opaque;
    let record = b"late-original";
    let mut output = [0; 1280];
    let length = actor::poll_data(
        &mut data,
        record,
        false,
        &budget,
        cfg.actor(),
        &mut [],
        &mut output,
    )?
    .ok_or("no raw output")?;
    let debit = budget.status()?;
    let cap = Instant::now() + Duration::from_secs(1);
    let semaphore = Arc::new(tokio::sync::Semaphore::new(1));
    let (response, receiver) = oneshot::channel();
    let (completion, _) = oneshot::channel();
    let mut pending = Some(actor::PendingData {
        length,
        completion,
        custody: Some(send::Custody {
            deadline: cap,
            class: Class::User,
            record_bytes: record.len(),
            response,
            _permit: semaphore.clone().try_acquire_owned()?,
        }),
    });
    let ticket = PendingSend {
        response: Some(receiver),
        deadline: cap,
        class: Class::User,
        record_bytes: record.len(),
    };
    for _ in 0..2 {
        assert!(!actor::flush_data_with(
            &mut pending,
            &output,
            28,
            Some(&ledger),
            || cap - Duration::from_micros(1),
            |_| Err(std::io::ErrorKind::WouldBlock.into())
        )?);
        assert_eq!(semaphore.available_permits(), 0);
        assert_eq!(budget.status()?, debit);
    }
    let (a, b) = sockets().await?;
    a.writable().await?;
    let mut sample = 0;
    assert!(actor::flush_data_with(
        &mut pending,
        &output,
        28,
        Some(&ledger),
        || {
            sample += 1;
            if sample == 1 {
                cap - Duration::from_micros(1)
            } else {
                cap
            }
        },
        |bytes| a.try_send(bytes)
    )?);
    let Err(SendFailure::Expired {
        accepted: Some(actual),
    }) = ticket.await
    else {
        return Err("late whole write was erased or reported successful".into());
    };
    assert_eq!(
        (actual.record_bytes, actual.udp_bytes, actual.ip_bytes),
        (record.len(), length, length + 28)
    );
    assert_eq!(actual.accepted_at, cap);
    assert_eq!(actual.deadline, cap);
    assert_eq!(budget.status()?, debit);
    assert_eq!(semaphore.available_permits(), 1);
    assert_eq!(ledger.status()?.accepted_datagrams, 1);
    assert_eq!(ledger.status()?.accepted_after_deadline, 1);
    let mut wire = [0; 1280];
    let bytes = timeout(Duration::from_secs(1), b.recv(&mut wire)).await??;
    assert_eq!(&wire[..bytes], &output[..length]);
    Ok(())
}

#[tokio::test]
async fn selected_compact_openvpn_actor_preserves_final_bytes_custody_and_bounded_setup_tails()
-> TestResult {
    let (mut a, mut b) = pair().await?;
    let addresses = a.addresses();
    let setup_cap = Instant::now() + Duration::from_millis(250);
    a.select_final_records(setup_cap)?;
    b.select_final_records(setup_cap)?;
    assert!(a.select_final_records(setup_cap).is_err());
    for opcode in [3u8, 4, 5, 6, 7, 8, 9] {
        for key in 0..8 {
            assert!(!actor::final_prefix(&[opcode << 3 | key]));
        }
    }
    for prefix in [0u8, 1, 128, 191, 192, 255] {
        assert!(actor::final_prefix(&[prefix]));
    }
    for slot in 0..64u8 {
        let route = if slot < 22 { slot + 2 } else { slot + 58 };
        assert!(actor::final_prefix(&[route]));
    }
    for reserved in 122..128u8 {
        assert!(!actor::final_prefix(&[reserved]));
    }
    assert!(!actor::final_prefix(b"L2QD"));
    let collision = b"\x80identical-inner-prefix-for-both-paths";
    let tail = a.try_send_bootstrap_until(Class::Control, collision, setup_cap)?;
    let receipt = tail.await?;
    assert_eq!(receipt.udp_bytes, receipt.record_bytes + 1);
    assert_eq!(receipt.ip_bytes, receipt.record_bytes + 29);
    let initial = timeout(Duration::from_secs(1), b.recv_framed()).await??;
    assert_eq!(initial.bytes, collision);
    assert_eq!(initial.framing, ReceiveFraming::DataV1);
    a.try_send_until(Class::Control, collision, setup_cap)?
        .await?;
    let established = timeout(Duration::from_secs(1), b.recv_framed()).await??;
    assert_eq!(established.bytes, collision);
    assert_eq!(established.framing, ReceiveFraming::Final);
    a.shared.user_gate.store(true, Ordering::Relaxed);
    let bytes = b"\x80final-data-without-an-opcode";
    let final_cap = Instant::now() + Duration::from_secs(1);
    let held = a.try_send_until(Class::User, bytes, final_cap)?;
    timeout(Duration::from_secs(1), async {
        while a.physical_status()?.user_would_block == 0 {
            tokio::task::yield_now().await;
        }
        Ok::<_, Error>(())
    })
    .await??;
    let control = b.try_send_until(Class::Control, b"\0final-strong-control", final_cap)?;
    let receipt = control.await?;
    assert_eq!(receipt.udp_bytes, receipt.record_bytes);
    assert_eq!(receipt.ip_bytes, receipt.record_bytes + 28);
    assert_eq!(
        timeout(Duration::from_secs(1), a.recv()).await??,
        b"\0final-strong-control"
    );
    a.shared.user_gate.store(false, Ordering::Relaxed);
    let receipt = held.await?;
    assert_eq!(receipt.udp_bytes, bytes.len());
    assert_eq!(receipt.ip_bytes, bytes.len() + 28);
    assert_eq!(timeout(Duration::from_secs(1), b.recv()).await??, bytes);
    tokio::time::sleep_until(setup_cap).await;
    assert!(matches!(
        a.try_send_bootstrap_until(Class::Control, b"expired-tail", final_cap),
        Err(Error::Timeout)
    ));
    let before = a.physical_status()?.tls_control_datagrams;
    let bytes = b"\xfffinal-feedback-after-setup-cap";
    let receipt = a.try_send_until(Class::Control, bytes, final_cap)?.await?;
    assert_eq!(receipt.ip_bytes, bytes.len() + 28);
    assert_eq!(timeout(Duration::from_secs(1), b.recv()).await??, bytes);
    // Exercise both disjoint strong-data ranges on the original actual UDP
    // owner. These are routing/custody bytes; Common authenticates their body.
    for route in [2, 23, 80, 121] {
        let mut record = [0; 21];
        record[0] = route;
        let receipt = a.try_send_until(Class::User, &record, final_cap)?.await?;
        assert_eq!(receipt.udp_bytes, record.len());
        assert_eq!(receipt.ip_bytes, record.len() + 28);
        let received = timeout(Duration::from_secs(1), b.recv_framed()).await??;
        assert_eq!(received.framing, ReceiveFraming::Final);
        assert_eq!(received.bytes, record);
    }
    assert_eq!(a.physical_status()?.tls_control_datagrams, before);
    assert_eq!(a.addresses(), addresses);
    assert_eq!(b.addresses(), (addresses.1, addresses.0));
    Ok(())
}
