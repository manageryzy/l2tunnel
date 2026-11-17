//! Exact selected Control plans for the shared Common constructor.
use super::*;
use mg::messages::storage;

// These are constructor-only immutable plans, never duplicate message owners.
pub(super) struct ControlPlan {
    settings: control_owner::Settings,
    plans: [storage::Plan; 3],
}
impl ControlPlan {
    pub(super) fn new(
        contract: &CommonTransactionContract,
        binding: delivery::Binding,
    ) -> io::Result<Self> {
        let config = contract.resources();
        let settings = config
            .streams
            .ok_or_else(|| invalid("common streams absent"))?;
        Ok(Self {
            settings,
            plans: settings.message_storage_plans(
                binding,
                Duration::ZERO,
                config.lifetime.lease,
            )?,
        })
    }
    pub(super) fn capacity_bytes(&self) -> io::Result<usize> {
        self.plans.iter().try_fold(0usize, |total, plan| {
            total
                .checked_add(plan.capacity_bytes())
                .ok_or_else(exhausted)
        })
    }
    pub(super) fn maximum_message_bytes(&self) -> io::Result<usize> {
        self.settings
            .streams
            .iter()
            .map(|value| value.max_message_bytes)
            .max()
            .ok_or_else(exhausted)
    }
    pub(super) fn maximum_packet_bytes(&self, base: delivery::Settings) -> io::Result<usize> {
        self.settings.max_packet_bytes(base)
    }
    pub(super) fn wrapper(
        &self,
        base: delivery::Settings,
    ) -> io::Result<control_owner::wrapper_storage::Plan> {
        control_owner::wrapper_storage::Plan::new(self.settings, base)
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
        let control = control_owner::Owner::new_leased_reserved_messages_with_wrapper_plan(
            config.control,
            self.settings,
            binding,
            envelope_scope(control_scope),
            envelope_scope(data_scope),
            Duration::ZERO,
            config.lifetime.lease,
            self.plans.map(|plan| storage::Limits {
                capacity_bytes: plan.capacity_bytes(),
            }),
            wrapper,
            limit,
        )?;
        verify(
            control
                .message_storage_usage()
                .ok_or_else(|| protocol("common Control reservation absent"))?,
            self.plans,
        )?;
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
