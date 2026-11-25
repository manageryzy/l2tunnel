//! Short human descriptions shared by the CLI and GUI.
use crate::secure_udp::common_status::CanonicalConfiguration;

/// Variant name of a Debug rendering, in snake case.
fn kind(text: &str) -> String {
    let name = text.split(['(', ' ', '{']).next().unwrap_or_default();
    let mut out = String::with_capacity(name.len() + 4);
    for (index, character) in name.chars().enumerate() {
        if character.is_ascii_uppercase() {
            if index != 0 {
                out.push('_');
            }
            out.push(character.to_ascii_lowercase());
        } else {
            out.push(character);
        }
    }
    out
}

/// One line describing a complete configuration: profile kind, path MTU and
/// duplex. An undecodable value is reported as such, never guessed.
pub fn configuration_summary(configuration: &CanonicalConfiguration) -> String {
    match configuration.configuration() {
        Ok(value) => {
            let descriptor = value.descriptor();
            format!(
                "{} · MTU {} · {}",
                protocol_name(descriptor.profile()),
                descriptor.path_mtu(),
                kind(&format!("{:?}", descriptor.duplex())),
            )
        }
        Err(_) => "undecodable configuration".into(),
    }
}

/// Record protocol and its loss recovery in words, from the forward
/// direction (the plan sets both directions alike for the named rows).
fn protocol_name(profile: &l2tunnel::record_configuration::Profile) -> String {
    use l2tunnel::record_configuration::Profile;
    let reliable = |name: &str, repair: usize| {
        if repair == 0 {
            format!("{name} · ARQ")
        } else {
            format!("{name} · ARQ + FEC ({repair} repair per group)")
        }
    };
    match profile {
        Profile::Swift { forward, .. } => {
            let codec = &forward.codec;
            if codec.repair_numerator == 0 {
                "swift · ARQ".into()
            } else {
                format!(
                    "swift · ARQ + FEC ({}/{} repair)",
                    codec.repair_numerator, codec.repair_denominator
                )
            }
        }
        Profile::Aligned { forward, .. } => reliable("aligned", forward.recovery.repair_symbols),
        Profile::Packed { forward, .. } => reliable("packed", forward.base.recovery.repair_symbols),
        other => kind(&format!("{other:?}")),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn kind_is_snake_case_variant() {
        assert_eq!(super::kind("RollingStriped { a: 1 }"), "rolling_striped");
        assert_eq!(super::kind("Full"), "full");
    }
}
