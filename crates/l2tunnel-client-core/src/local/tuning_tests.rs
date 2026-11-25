use super::*;
use l2tunnel::live_tuning::Repair;

fn setting(repair: Repair, device_mtu: u16, path_mtu: u16) -> Setting {
    Setting {
        repair,
        device_mtu,
        path_mtu,
    }
}

#[test]
fn view_lists_each_control_choice_once_and_every_entry() -> io::Result<()> {
    let quarter = Repair::Rate {
        numerator: 1,
        denominator: 4,
    };
    let settings = [
        setting(quarter, 1400, 1500),
        setting(Repair::Off, 1400, 1500),
        setting(quarter, 1280, 1500),
        setting(Repair::Off, 1280, 1500),
        setting(quarter, 1400, 1500),
    ];
    let view = TuningView::new(true, Some(settings[0]), settings, None);
    assert_eq!(view.repair, ["off", "1/4"]);
    assert_eq!(view.device_mtu, [1280, 1400]);
    assert_eq!(view.path_mtu, [1500]);
    assert_eq!(view.entries.len(), 4);
    assert_eq!(
        view.current.as_ref().map(|c| c.repair.as_str()),
        Some("1/4")
    );
    // The wire form round-trips and refuses unknown fields.
    let text = serde_json::to_string(&view).map_err(io::Error::other)?;
    assert_eq!(
        serde_json::from_str::<TuningView>(&text).map_err(io::Error::other)?,
        view
    );
    assert!(
        serde_json::from_str::<TuningSetting>(
            r#"{"repair":"off","device_mtu":1,"path_mtu":2,"x":3}"#
        )
        .is_err()
    );
    // Settings convert both ways; a malformed repair is refused.
    let back = view.entries[1].setting()?;
    assert_eq!(back, settings[1]);
    let bad = TuningSetting {
        repair: "half".into(),
        device_mtu: 1400,
        path_mtu: 1500,
    };
    assert!(bad.setting().is_err());
    Ok(())
}
