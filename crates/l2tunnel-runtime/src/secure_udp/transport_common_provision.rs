//! Exact selected Control plans for the shared Common constructor.
use super::*;
use mg::messages::{self, storage};

// These are constructor-only immutable plans, never duplicate message owners.
#[allow(clippy::large_enum_variant)]
pub(super) enum ControlPlan {
    Legacy(control_owner::Settings, [storage::Plan; 3]),
    Managed(control_owner::SettingsV2, [storage::Plan; 4]),
}
impl ControlPlan {
    pub(super) fn new(
        contract: &CommonTransactionContract,
        binding: delivery::Binding,
    ) -> io::Result<Self> {
        let config = contract.resources();
        match contract.managed_streams() {
            Some(selected) => Ok(Self::Managed(
                selected,
                selected.message_storage_plans(binding, Duration::ZERO, config.lifetime.lease)?,
            )),
            None => {
                let selected = config
                    .streams
                    .ok_or_else(|| invalid("common streams absent"))?;
                Ok(Self::Legacy(
                    selected,
                    selected.message_storage_plans(
                        binding,
                        Duration::ZERO,
                        config.lifetime.lease,
                    )?,
                ))
            }
        }
    }
    pub(super) fn capacity_bytes(&self) -> io::Result<usize> {
        let plans: &[storage::Plan] = match self {
            Self::Legacy(_, plans) => plans,
            Self::Managed(_, plans) => plans,
        };
        plans.iter().try_fold(0usize, |total, plan| {
            total
                .checked_add(plan.capacity_bytes())
                .ok_or_else(exhausted)
        })
    }
    pub(super) fn maximum_message_bytes(&self) -> io::Result<usize> {
        let settings: &[messages::Settings] = match self {
            Self::Legacy(value, _) => &value.streams,
            Self::Managed(value, _) => &value.streams,
        };
        settings
            .iter()
            .map(|value| value.max_message_bytes)
            .max()
            .ok_or_else(exhausted)
    }
    pub(super) fn maximum_packet_bytes(&self, base: delivery::Settings) -> io::Result<usize> {
        match self {
            Self::Legacy(value, _) => value.max_packet_bytes(base),
            Self::Managed(value, _) => value.max_packet_bytes(base),
        }
    }
    pub(super) fn wrapper(
        &self,
        base: delivery::Settings,
    ) -> io::Result<control_owner::wrapper_storage::Plan> {
        match self {
            Self::Legacy(selected, _) => control_owner::wrapper_storage::Plan::new(*selected, base),
            Self::Managed(selected, _) => {
                control_owner::wrapper_storage::Plan::new_v2(*selected, base)
            }
        }
    }
    pub(super) fn construct(
        self,
        config: Config,
        binding: delivery::Binding,
        control_scope: Scope,
        data_scope: Scope,
        wrapper: control_owner::wrapper_storage::Plan,
    ) -> io::Result<control_owner::Owner> {
        let limit = control_owner::wrapper_storage::Limits {
            capacity_bytes: wrapper.capacity_bytes(),
        };
        let control = match self {
            Self::Legacy(selected, plans) => {
                let owner = control_owner::Owner::new_leased_reserved_messages_with_wrapper_plan(
                    config.control,
                    selected,
                    binding,
                    envelope_scope(control_scope),
                    envelope_scope(data_scope),
                    Duration::ZERO,
                    config.lifetime.lease,
                    plans.map(|plan| storage::Limits {
                        capacity_bytes: plan.capacity_bytes(),
                    }),
                    wrapper,
                    limit,
                )?;
                verify(
                    owner
                        .message_storage_usage()
                        .ok_or_else(|| protocol("common Control reservation absent"))?,
                    plans,
                )?;
                owner
            }
            Self::Managed(selected, plans) => {
                let owner =
                    control_owner::Owner::new_leased_reserved_messages_v2_with_wrapper_plan(
                        config.control,
                        selected,
                        binding,
                        envelope_scope(control_scope),
                        envelope_scope(data_scope),
                        Duration::ZERO,
                        config.lifetime.lease,
                        plans.map(|plan| storage::Limits {
                            capacity_bytes: plan.capacity_bytes(),
                        }),
                        wrapper,
                        limit,
                    )?;
                verify(
                    owner
                        .message_storage_usage_v2()
                        .ok_or_else(|| protocol("managed common Control reservation absent"))?,
                    plans,
                )?;
                owner
            }
        };
        Ok(control)
    }
}
fn verify<const N: usize>(
    actual: [storage::Usage; N],
    plans: [storage::Plan; N],
) -> io::Result<()> {
    if actual.iter().zip(plans).any(|(actual, plan)| {
        actual.capacity_bytes != plan.capacity_bytes()
            || actual.arq.capacity_bytes != plan.arq_plan().capacity_bytes()
            || actual.reassembly.capacity_bytes != plan.reassembly_plan().capacity_bytes()
    }) {
        return Err(protocol(
            "common Control reservation differs from actual plan",
        ));
    }
    Ok(())
}
