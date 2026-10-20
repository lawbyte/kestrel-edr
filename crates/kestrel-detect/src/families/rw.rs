//! RW-xx ransomware preparation and impact rules.

use super::{Ctx, Family, FamilyHit};
use kestrel_common::{Event, RuleMeta};

#[derive(Default)]
pub(crate) struct Ransomware {}

impl Family for Ransomware {
    fn on_event(&mut self, _ctx: &Ctx, _e: &Event, _out: &mut Vec<FamilyHit>) {}
}

pub(crate) fn catalog() -> Vec<RuleMeta> {
    vec![]
}
