fn udp_startup_addr_in_use(error: &(dyn std::error::Error + 'static)) -> bool {
    let mut cause = Some(error);
    // io::Error::source can skip its boxed error, and the maintained QUIC
    // carrier intentionally exposes no source chain. Inspect these typed
    // wrappers directly; authentication/protocol variants are never retried.
    for _ in 0..16 {
        let Some(current) = cause else { return false };
        if let Some(error) = current.downcast_ref::<io::Error>() {
            if error.kind() == io::ErrorKind::AddrInUse {
                return true;
            }
            cause = error
                .get_ref()
                .map(|inner| inner as &(dyn std::error::Error + 'static));
        } else if let Some(error) = current.downcast_ref::<l2tunnel_quic::Error>() {
            cause = match error {
                l2tunnel_quic::Error::Io(inner) => Some(inner),
                _ => return false,
            };
        } else {
            cause = current.source();
        }
    }
    false
}

// Test-only startup retry: public clients bind their own UDP sockets, so address
// reservations cannot be handed through. Retry only AddrInUse, before forwarding,
// within the original absolute startup deadline. Never retry protocol failures.
macro_rules! retry_udp_startup {
    ($seconds:expr, $body:block) => {{
        let deadline = tokio::time::Instant::now() + Duration::from_secs($seconds);
        tokio::time::timeout_at(deadline, async {
            for attempt in 0..4 {
                let result: Result<_, Box<dyn std::error::Error + Send + Sync>> =
                    async { $body }.await;
                match result {
                    Ok(value) => return Ok(value),
                    Err(error) => {
                        let occupied = udp_startup_addr_in_use(error.as_ref());
                        if !occupied || attempt == 3 {
                            return Err(error);
                        }
                    }
                }
            }
            unreachable!("bounded startup retry always returns")
        })
        .await?
    }};
}
