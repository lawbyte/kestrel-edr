//! CD-xx credential dumping rules (LSASS, SAM, NTDS, LSA).

use super::{Ctx, Family, FamilyHit};
use kestrel_common::{Event, RuleMeta};

#[derive(Default)]
pub(crate) struct CredDump {}

impl Family for CredDump {
    fn on_event(&mut self, _ctx: &Ctx, _e: &Event, _out: &mut Vec<FamilyHit>) {}
}

pub(crate) fn catalog() -> Vec<RuleMeta> {
    vec![]
}
