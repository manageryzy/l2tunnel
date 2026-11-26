//! Redirect Rules (CIDR / ASN / GeoIP IP location / Continent / Private LAN)
//! panel rendered on the Desktop GUI Routes page.
use eframe::egui;
use l2tunnel_client_core::local::redirect_policy::{
    IpGeoAsnDatabase, RedirectAction, RedirectPolicy, RedirectRule, RuleMatcher,
};
use std::net::IpAddr;

/// Per-window UI draft state for the Redirect Rules panel.
#[derive(Debug)]
pub struct PolicyForm {
    /// Editable ordered redirect policy.
    pub policy: RedirectPolicy,
    /// Cached built-in offline GeoIP + ASN database.
    pub db: IpGeoAsnDatabase,
    /// New rule shorthand input (`geoip:CN`, `asn:13335`, `continent:EU`, `10.0.0.0/8`, `lan`).
    pub new_matcher: String,
    /// Action for newly added rules.
    pub new_action: RedirectAction,
    /// Inline add error.
    pub add_error: Option<String>,
    /// IP address entered in the live GeoIP/ASN/rule tester.
    pub test_ip: String,
}

impl Default for PolicyForm {
    fn default() -> Self {
        Self {
            policy: RedirectPolicy::preset("bypass-cn-and-lan").unwrap_or_default(),
            db: IpGeoAsnDatabase::builtin(),
            new_matcher: String::new(),
            new_action: RedirectAction::Direct,
            add_error: None,
            test_ip: "114.114.114.114".into(),
        }
    }
}

/// Render the Redirect Rules (ASN / GeoIP / CIDR) editor and live IP tester.
pub fn show(ui: &mut egui::Ui, form: &mut PolicyForm, peer_ip: Option<IpAddr>) {
    ui.add_space(12.0);
    ui.separator();
    ui.add_space(6.0);
    ui.strong("Redirect Rules (GeoIP IP Location / ASN / CIDR)");
    ui.weak(format!(
        "Evaluate and compile ordered redirect rules using the shared offline GeoIP/ASN database ({} prefixes). Use `l2tunnelctl policy` for external CSV/MMDB files.",
        form.db.len()
    ));

    ui.horizontal_wrapped(|ui| {
        ui.label("Presets:");
        for &(name, _) in RedirectPolicy::preset_catalog() {
            if ui.button(name).clicked()
                && let Some(p) = RedirectPolicy::preset(name)
            {
                form.policy = p;
                form.add_error = None;
            }
        }
    });

    ui.horizontal(|ui| {
        ui.label("Default action:");
        for action in [RedirectAction::Tunnel, RedirectAction::Direct] {
            ui.selectable_value(&mut form.policy.default_action, action, action.to_string());
        }
    });

    ui.horizontal(|ui| {
        ui.add(
            egui::TextEdit::singleline(&mut form.new_matcher)
                .desired_width(240.0)
                .hint_text("geoip:CN, asn:13335, continent:EU, 10.0.0.0/8"),
        );
        egui::ComboBox::from_id_salt("policy-new-action")
            .selected_text(form.new_action.to_string())
            .show_ui(ui, |ui| {
                for act in [
                    RedirectAction::Direct,
                    RedirectAction::Tunnel,
                    RedirectAction::Reject,
                ] {
                    ui.selectable_value(&mut form.new_action, act, act.to_string());
                }
            });
        if ui.button("Add rule").clicked() {
            match RuleMatcher::parse_shorthand(&form.new_matcher) {
                Ok(matcher) => {
                    let id = format!("rule-{}", form.policy.rules.len() + 1);
                    form.policy.rules.push(RedirectRule {
                        id,
                        enabled: true,
                        matcher,
                        action: form.new_action,
                        comment: None,
                    });
                    form.new_matcher.clear();
                    form.add_error = None;
                }
                Err(msg) => form.add_error = Some(msg),
            }
        }
    });
    if let Some(err) = &form.add_error {
        ui.colored_label(egui::Color32::from_rgb(220, 80, 80), err);
    }

    let mut remove_idx: Option<usize> = None;
    egui::Grid::new("redirect-rules-grid")
        .striped(true)
        .num_columns(4)
        .spacing([12.0, 4.0])
        .show(ui, |ui| {
            ui.strong("#");
            ui.strong("Matcher");
            ui.strong("Action");
            ui.strong("");
            ui.end_row();
            for (idx, rule) in form.policy.rules.iter_mut().enumerate() {
                ui.checkbox(&mut rule.enabled, format!("{}", idx + 1));
                ui.monospace(rule.matcher.label());
                ui.label(rule.action.to_string());
                if ui.small_button("Remove").clicked() {
                    remove_idx = Some(idx);
                }
                ui.end_row();
            }
        });
    if let Some(idx) = remove_idx {
        form.policy.rules.remove(idx);
    }

    ui.add_space(6.0);
    ui.horizontal(|ui| {
        ui.label("Test IP:");
        ui.add(egui::TextEdit::singleline(&mut form.test_ip).desired_width(150.0));
        for sample in ["114.114.114.114", "1.1.1.1", "8.8.8.8", "192.168.1.1"] {
            if ui.small_button(sample).clicked() {
                form.test_ip = sample.into();
            }
        }
    });
    if let Ok(ip) = form.test_ip.trim().parse::<IpAddr>() {
        let decision = form.policy.evaluate(ip, &form.db);
        let geo_str = decision.geo.as_ref().map_or_else(
            || "No GeoIP/ASN entry".to_owned(),
            |g| {
                format!(
                    "{}{} ({}) · AS{} {}",
                    g.country,
                    g.region
                        .as_deref()
                        .map_or_else(String::new, |r| format!("-{r}")),
                    g.continent,
                    g.asn,
                    g.org
                )
            },
        );
        ui.monospace(format!(
            "Decision: {} via {} ({}) | {}",
            decision.action, decision.matched_by, decision.matched_rule_id, geo_str
        ));
    }
    let compiled = form.policy.compile_tun_routes(&form.db, peer_ip);
    ui.weak(format!(
        "Compiled TUN routes: {} include IPv4 CIDRs, {} bypass IPv4 CIDRs ({} prefixes expanded)",
        compiled.include_v4.len(),
        compiled.exclude_v4.len(),
        compiled.expanded_prefixes
    ));
}
