//! PS-xx persistence rules (autoruns, tasks, services, WMI, COM, IFEO).

use super::{Ctx, Family, FamilyHit};
use kestrel_common::{Event, RuleMeta};

#[derive(Default)]
pub(crate) struct Persistence {}

impl Family for Persistence {
    fn on_event(&mut self, _ctx: &Ctx, _e: &Event, _out: &mut Vec<FamilyHit>) {}
}

pub(crate) fn catalog() -> Vec<RuleMeta> {
    vec![]
}
