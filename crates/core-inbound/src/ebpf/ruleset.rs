use std::{collections::BTreeSet, sync::Arc};

use core_ruleset::{
    RulesetIndex, RulesetIpPrefixSemantics, RulesetIpPrefixSnapshot, RulesetIpPrefixStatus,
};
use tokio::sync::watch;

use super::{BypassPrefixSnapshot, EbpfRuleSetProvider};

impl EbpfRuleSetProvider for RulesetIndex {
    fn snapshot(&self, names: &[String]) -> Result<BypassPrefixSnapshot, String> {
        merge_snapshot(self.ip_prefix_snapshot(names))
    }

    fn subscribe(&self) -> Option<watch::Receiver<u64>> {
        Some(self.subscribe_ip_prefix_updates())
    }

    fn snapshot_and_subscribe(
        &self,
        names: &[String],
    ) -> Result<(BypassPrefixSnapshot, watch::Receiver<u64>), String> {
        let (snapshot, updates) = self.ip_prefix_snapshot_and_subscribe(names);
        Ok((merge_snapshot(snapshot)?, updates))
    }
}

fn merge_snapshot(snapshot: RulesetIpPrefixSnapshot) -> Result<BypassPrefixSnapshot, String> {
    let mut ipv4 = BTreeSet::new();
    let mut ipv6 = BTreeSet::new();
    for set in snapshot.sets.iter() {
        match &set.status {
            RulesetIpPrefixStatus::Ready {
                semantics: RulesetIpPrefixSemantics::Exact | RulesetIpPrefixSemantics::Extracted,
            } => {
                ipv4.extend(set.ipv4.iter().copied());
                ipv6.extend(set.ipv6.iter().copied());
            }
            RulesetIpPrefixStatus::Ready {
                semantics: RulesetIpPrefixSemantics::NotIpSet,
            } => {
                return Err(format!(
                    "bypass rule-set `{}` contains no destination IP prefixes",
                    set.name
                ));
            }
            RulesetIpPrefixStatus::Pending => {
                return Err(format!("bypass rule-set `{}` is still pending", set.name));
            }
            RulesetIpPrefixStatus::Unavailable => {
                return Err(format!("bypass rule-set `{}` is unavailable", set.name));
            }
            RulesetIpPrefixStatus::Missing => {
                return Err(format!("bypass rule-set `{}` does not exist", set.name));
            }
            RulesetIpPrefixStatus::TooManyPrefixes { limit } => {
                return Err(format!(
                    "bypass rule-set `{}` exceeds the prefix limit of {limit}",
                    set.name
                ));
            }
            RulesetIpPrefixStatus::AllocationFailed => {
                return Err(format!(
                    "bypass rule-set `{}` prefix allocation failed",
                    set.name
                ));
            }
            RulesetIpPrefixStatus::InvalidRange { family } => {
                return Err(format!(
                    "bypass rule-set `{}` contains an invalid {family} range",
                    set.name
                ));
            }
        }
    }
    Ok(BypassPrefixSnapshot {
        revision: snapshot.revision,
        ipv4: Arc::new(ipv4.into_iter().collect()),
        ipv6: Arc::new(ipv6.into_iter().collect()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use core_ruleset::RulesetMatcher;

    #[test]
    fn index_is_a_race_free_ebpf_provider() {
        let index = RulesetIndex::new();
        index.insert(Arc::new(RulesetMatcher::compile_ipcidr(
            "cnip",
            ["1.0.1.0/24".to_owned()],
        )));
        let names = vec!["cnip".to_owned()];
        let (snapshot, updates) =
            EbpfRuleSetProvider::snapshot_and_subscribe(index.as_ref(), &names).unwrap();
        assert_eq!(snapshot.ipv4.as_slice(), &["1.0.1.0/24".parse().unwrap()]);
        assert_eq!(*updates.borrow(), index.ip_prefix_revision());
    }
}
