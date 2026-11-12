fn udp_startup_addr_in_use(error: &(dyn std::error::Error + 'static)) -> bool {
    let mut cause = Some(error);
    while let Some(current) = cause {
        if current.downcast_ref::<io::Error>()
            .is_some_and(|e| e.kind() == io::ErrorKind::AddrInUse) {
            return true;
        }
        cause = current.source();
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
        }).await?
    }};
}
