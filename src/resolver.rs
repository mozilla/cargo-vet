//! The Resolver is the heart of cargo-vet, and does all the work to validate the audits
//! for your current packages and to suggest fixes. This is done in 3 phases:
//!
//! 1. Validating the audits against your policies
//! 2. Blaming packages for failed policies
//! 3. Suggesting audits that would make your project pass validation
//!
//! # High-level Usage
//!
//! * [`resolve`] is the main entry point, Validating and Blaming and producing a [`ResolveReport`]
//! * [`ResolveReport::compute_suggest`] does Suggesting and produces a [`Suggest`]
//! * various methods on [`ResolveReport`] and [`Suggest`] handle printing
//!
//! # Low-level Design
//!
//!
//! ## Resolve
//!
//! * construct the [`DepGraph`] and [`CriteriaMapper`]
//!     * the DepGraph contains computed facts like whether a node is a third-party or dev-only
//!       and includes a special topological sorting of the packages that prioritizes the normal
//!       build over the dev build (it's complicated...)
//!
//! * resolve_third_party: for each third-party package, resolve what criteria it's audited for
//!     * compute the [`AuditGraph`] and check for violations
//!     * for each criteria, search_for_path (check if it has a connected path in the audit graph)
//!         * if it does, then we have validated that it has that criteria
//!         * if it doesn't, but only because dependency_criteria, blame those dependencies
//!         * otherwise, blame ourselves and note the reachable nodes from root and target
//!
//! * resolve_first_party: inherit third-party criteria from normal/build deps, check policies
//!     * first-parties "inherit" the intersection of all their dependencies' validated criteria
//!         * as with third-parties, this is done per-criteria so we can granularly blame deps
//!     * if there is a policy.dependency_criteria, then that dep isn't inherited normally
//!       and is instead effectively no_criteria or all_criteria based on whether it passes or not
//!     * if there is a policy.criteria (or it's a root), then we check our inherited criteria
//!       against that policy and then set ourselves to all_criteria or no_criteria
//!         * **This is the check that matters!** Anything that fails this check is registered
//!           as a "root (policy) failure" and will be fed into the blame phase.
//!
//! * resolve_first_party_dev: same as above, but check dev-deps and dev-policies
//!     * this must be done as a second pass because dev-deps can introduce cycles. by doing
//!       all other analysis first, we can guarantee all dev-deps are fully resolved, as you
//!       cannot actually depend on the "dev" build of a package.
//!
//!
//!
//! ## Blame
//!
//! * take the "root failures" and descend back down the DepGraph as a tree, following
//!   every package's "blames" until we hit packages that blame themselves. Packages that
//!   blame themselves are "leaf failures" and are will be the basis for `suggest`
//!
//!
//!
//! ## Suggest
//!
//! * take the blame and do a huge pile of diffstats on the reachable versions
//!   (from search_for_path) to figure out which audits to recommend for which criteria

use cargo_metadata::{DependencyKind, Metadata, Node, PackageId, Version};
use core::fmt;
use futures_util::future::join_all;
use miette::IntoDiagnostic;
use serde::Serialize;
use serde_json::json;
use tracing::{error, trace, trace_span, warn};

use crate::errors::SuggestError;
use crate::format::{
    self, AuditKind, CriteriaName, CriteriaStr, Delta, DiffStat, ImportName, PackageName,
    PackageStr, PolicyEntry, UnauditedDependency,
};
use crate::format::{FastMap, FastSet, SortedMap, SortedSet};
use crate::network::Network;
use crate::out::Out;
use crate::{
    AuditEntry, Cache, Config, CriteriaEntry, DumpGraphArgs, GraphFilter, GraphFilterProperty,
    GraphFilterQuery, PackageExt, Store,
};

/// A report of the results of running `resolve`.
#[derive(Debug, Clone)]
pub struct ResolveReport<'a> {
    /// The Cargo dependency graph as parsed and understood by cargo-vet.
    ///
    /// All [`PackageIdx`][] values are indices into this graph's nodes.
    pub graph: DepGraph<'a>,
    /// Mappings between criteria names and CriteriaSets/Indices.
    pub criteria_mapper: CriteriaMapper,

    /// Low-level results for each package's individual criteria resolving analysis,
    /// indexed by [`PackageIdx`][].
    pub results: Vec<ResolveResult<'a>>,

    /// The final conclusion of our analysis.
    pub conclusion: Conclusion,
}

#[derive(Debug, Clone)]
pub enum Conclusion {
    Success(Success),
    FailForViolationConflict(FailForViolationConflict),
    FailForVet(FailForVet),
}

#[derive(Debug, Clone)]
pub struct Success {
    /// Third-party packages that were successfully vetted using only 'unaudited'
    pub vetted_with_unaudited: Vec<PackageIdx>,
    /// Third-party packages that were successfully vetted using both 'audits' and 'unaudited'
    pub vetted_partially: Vec<PackageIdx>,
    /// Third-party packages that were successfully vetted using only 'audits'
    pub vetted_fully: Vec<PackageIdx>,
    /// Third-party packages that have an unaudited entry that can be removed.
    pub useless_unaudited: Vec<PackageIdx>,
}

#[derive(Debug, Clone)]
pub struct FailForViolationConflict {
    pub violations: SortedMap<PackageIdx, Vec<ViolationConflict>>,
}

#[derive(Debug, Clone)]
pub struct FailForVet {
    /// These packages are to blame and need to be fixed
    pub failures: SortedMap<PackageIdx, AuditFailure>,
    pub suggest: Option<Suggest>,
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Serialize)]
pub enum ViolationConflict {
    UnauditedConflict {
        violation_source: AuditSource,
        violation: AuditEntry,
        unaudited: UnauditedDependency,
    },
    AuditConflict {
        violation_source: AuditSource,
        violation: AuditEntry,
        audit_source: AuditSource,
        audit: AuditEntry,
    },
}

#[derive(Debug, Clone, Serialize)]
pub enum AuditSource {
    OwnAudits,
    Foreign(ImportName),
}

#[derive(Debug, Clone, Default)]
pub struct Suggest {
    pub suggestions: Vec<SuggestItem>,
    pub suggestions_by_criteria: SortedMap<CriteriaName, Vec<SuggestItem>>,
    pub total_lines: u64,
}

#[derive(Debug, Clone)]
pub struct SuggestItem {
    pub package: PackageIdx,
    pub suggested_criteria: CriteriaFailureSet,
    pub suggested_diff: DiffRecommendation,
    pub notable_parents: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DiffRecommendation {
    pub from: Version,
    pub to: Version,
    pub diffstat: DiffStat,
}

/// Set of booleans, 64 should be Enough For Anyone (but abstracting in case not).
#[derive(Clone, Default)]
pub struct CriteriaSet(u64);
const MAX_CRITERIA: usize = u64::BITS as usize; // funnier this way

/// Set of criteria which failed for a given package. `confident` contains only
/// criteria which we're confident about, whereas `all` contains all criteria.
#[derive(Debug, Clone, Default)]
pub struct CriteriaFailureSet {
    pub confident: CriteriaSet,
    pub all: CriteriaSet,
}

/// A processed version of config.toml's criteria definitions, for mapping
/// lists of criteria names to CriteriaSets.
#[derive(Debug, Clone)]
pub struct CriteriaMapper {
    /// All the criteria in their raw form
    pub list: Vec<(CriteriaName, CriteriaEntry)>,
    /// name -> index in all lists
    pub index: FastMap<CriteriaName, usize>,
    /// The transitive closure of all criteria implied by each criteria (including self)
    pub implied_criteria: Vec<CriteriaSet>,
}

/// An "interned" cargo PackageId which is used to uniquely identify packages throughout
/// the code. This is simpler and faster than actually using PackageIds (strings) or name+version.
/// In the current implementation it can be used to directly index into the `graph` or `results`.
pub type PackageIdx = usize;

#[derive(Debug, Clone, Serialize)]
pub struct PackageNode<'a> {
    #[serde(skip_serializing_if = "pkgid_unstable")]
    /// The PackageId that cargo uses to uniquely identify this package
    ///
    /// Prefer using a [`DepGraph`] and its memoized [`PackageIdx`]'s.
    pub package_id: &'a PackageId,
    /// The name of the package
    pub name: PackageStr<'a>,
    /// The version of this package
    pub version: &'a Version,
    /// All normal deps (shipped in the project or a proc-macro it uses)
    pub normal_deps: Vec<PackageIdx>,
    /// All build deps (used for build.rs)
    pub build_deps: Vec<PackageIdx>,
    /// All dev deps (used for tests/benches)
    pub dev_deps: Vec<PackageIdx>,
    /// Just the normal and build deps (deduplicated)
    pub normal_and_build_deps: Vec<PackageIdx>,
    /// All deps combined (deduplicated)
    pub all_deps: Vec<PackageIdx>,
    /// All reverse-deps (mostly just used for contextualizing what uses it)
    pub reverse_deps: SortedSet<PackageIdx>,
    /// Whether this package is a workspace member (can have dev-deps)
    pub is_workspace_member: bool,
    /// Whether this package is third-party (from crates.io)
    pub is_third_party: bool,
    /// Whether this package is a root in the "normal" build graph
    pub is_root: bool,
    /// Whether this package only shows up in dev (test/bench) builds
    pub is_dev_only: bool,
}

/// Don't serialize path package ids, not stable across systems
fn pkgid_unstable(pkgid: &PackageId) -> bool {
    pkgid.repr.contains("(path+file:/")
}

/// The dependency graph in a form we can use more easily.
#[derive(Debug, Clone)]
pub struct DepGraph<'a> {
    pub nodes: Vec<PackageNode<'a>>,
    pub interner_by_pkgid: SortedMap<&'a PackageId, PackageIdx>,
    pub interner_by_name_and_ver: SortedMap<PackageStr<'a>, SortedMap<&'a Version, PackageIdx>>,
    pub topo_index: Vec<PackageIdx>,
}

/// Results and notes from running vet on a particular package.
#[derive(Debug, Clone)]
pub struct ResolveResult<'a> {
    /// The set of criteria we validated for this package.
    pub validated_criteria: CriteriaSet,
    /// The set of criteria we validated for this package without 'unaudited' entries.
    pub fully_audited_criteria: CriteriaSet,
    /// Individual search results for each criteria.
    pub search_results: Vec<SearchResult<'a>>,
    /// Whether there was an 'unaudited' entry for this exact version.
    pub directly_unaudited: bool,
    /// Whether we ever needed the not-fully_audited_criteria for our reverse-deps.
    pub needed_unaudited: bool,
}

pub type PolicyFailures = SortedMap<PackageIdx, CriteriaSet>;
/// (FailedPackage, Failures, is_dev)
pub type RootFailures = Vec<(PackageIdx, PolicyFailures, bool)>;

#[derive(Default, Debug, Clone)]
pub struct AuditFailure {
    pub criteria_failures: CriteriaFailureSet,
}

/// The possible results of search for an audit chain for a Criteria
#[derive(Debug, Clone)]
pub enum SearchResult<'a> {
    /// We found a path, criteria validated.
    Connected {
        /// Whether we found a path to a fully_audited entry
        fully_audited: bool,
    },
    /// We failed to find a *proper* path, criteria not valid, but adding in failing
    /// edges caused by our dependencies not meeting criteria created a connection!
    /// If you fix these dependencies then we should validate this criteria!
    PossiblyConnected {
        /// The dependencies that failed on some edges (blame them).
        /// This is currently overbroad in corner cases where there are two possible
        /// paths blocked by two different dependencies and so only fixing one would
        /// actually be sufficient, but, whatever.
        failed_deps: SortedMap<PackageIdx, CriteriaSet>,
    },
    /// We failed to find any path, criteria not valid.
    Disconnected {
        /// Nodes we could reach from "root"
        reachable_from_root: SortedSet<&'a Version>,
        /// Nodes we could reach from the "target"
        ///
        /// We will only ever fill in the other one, but on failure we run the algorithm
        /// in reverse and will merge that result into this value.
        reachable_from_target: SortedSet<&'a Version>,
    },
}

/// A graph of the audits for a package.
///
/// The nodes of the graph are Versions and the edges are audits.
/// An AuditGraph is directed, potentially cyclic, and potentially disconnected.
///
/// There are two important versions in each AuditGraph:
///
/// * The "root" version (0.0.0) which exists as a dummy node for full-audits
/// * The "target" version which is the current version of the package
///
/// The edges are constructed as follows:
///
/// * Delta Audits desugar directly to edges
/// * Full Audits and Unaudited desugar to 0.0.0 -> Version
///
/// If there are multiple versions of a package in-tree, we analyze each individually
/// so there is always one root and one target. All we want to know is if there exists
/// a path between the two where every edge on that path has a given criteria. We do this
/// check for every possible criteria in a loop to keep the analysis simple and composable.
///
/// When resolving the audits for a package, we create a "forward" graph and a "backward" graph.
/// These are the same graphs but with the edges reversed. The backward graph is only used if
/// we can't find the desired path in the forward graph, and is used to compute the
/// reachability set of the target version for that criteria. That reachability is
/// used for `suggest`.
pub type AuditGraph<'a> = SortedMap<&'a Version, Vec<DeltaEdge<'a>>>;

/// A directed edge in the graph of audits. This may be forward or backwards,
/// depending on if we're searching from "roots" (forward) or the target (backward).
/// The source isn't included because that's implicit in the Node.
#[derive(Debug, Clone)]
pub struct DeltaEdge<'a> {
    /// The version this edge goes to.
    version: &'a Version,
    /// The criteria that this edge is valid for.
    criteria: CriteriaSet,
    /// Requirements that dependencies must satisfy for the edge to be valid.
    /// If a dependency isn't mentioned, then it defaults to `criteria`.
    dependency_criteria: FastMap<PackageStr<'a>, CriteriaSet>,
    /// Whether this edge represents an 'unaudited' entry. These will initially
    /// be ignored, and then used only if we can't find a path.
    is_unaudited_entry: bool,
}

fn builtin_criteria() -> SortedMap<CriteriaName, CriteriaEntry> {
    [
        (
            "safe-to-run".to_string(),
            CriteriaEntry {
                description: Some("safe to run locally".to_string()),
                description_url: None,
                implies: vec![],
            },
        ),
        (
            "safe-to-deploy".to_string(),
            CriteriaEntry {
                description: Some("safe to deploy to production".to_string()),
                description_url: None,
                implies: vec!["safe-to-run".to_string()],
            },
        ),
    ]
    .into_iter()
    .collect()
}

impl CriteriaMapper {
    pub fn new(criteria: &SortedMap<CriteriaName, CriteriaEntry>) -> CriteriaMapper {
        let builtins = builtin_criteria();
        let list = criteria
            .iter()
            .chain(builtins.iter())
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect::<Vec<_>>();
        let index: FastMap<CriteriaName, usize> = list
            .iter()
            .enumerate()
            .map(|(idx, v)| (v.0.clone(), idx))
            .collect();

        let mut implied_criteria = Vec::with_capacity(list.len());
        for (idx, (_name, entry)) in list.iter().enumerate() {
            // Precompute implied criteria (doing it later is genuinely a typesystem headache)
            let mut implied = CriteriaSet::none(list.len());
            implied.set_criteria(idx);
            recursive_implies(&mut implied, &entry.implies, &index, &list);

            implied_criteria.push(implied);

            fn recursive_implies(
                result: &mut CriteriaSet,
                implies: &[CriteriaName],
                index: &FastMap<CriteriaName, usize>,
                list: &[(CriteriaName, CriteriaEntry)],
            ) {
                for implied in implies {
                    let idx = index[&**implied];
                    result.set_criteria(idx);

                    // FIXME: we should detect infinite implies loops?
                    let further_implies = &list[idx].1.implies[..];
                    recursive_implies(result, further_implies, index, list);
                }
            }
        }

        Self {
            list,
            index,
            implied_criteria,
        }
    }
    pub fn criteria_from_entry(&self, entry: &AuditEntry) -> CriteriaSet {
        self.criteria_from_list(&entry.criteria)
    }
    pub fn criteria_from_list<'b, S: AsRef<str> + 'b + ?Sized>(
        &self,
        list: impl IntoIterator<Item = &'b S>,
    ) -> CriteriaSet {
        let mut result = self.no_criteria();
        for criteria in list {
            let idx = self.index[criteria.as_ref()];
            result.unioned_with(&self.implied_criteria[idx]);
        }
        result
    }
    pub fn set_criteria(&self, set: &mut CriteriaSet, criteria: CriteriaStr) {
        set.set_criteria(self.index[criteria])
    }
    pub fn clear_criteria(&self, set: &mut CriteriaFailureSet, criteria: CriteriaStr) {
        set.clear_criteria(&self.implied_criteria[self.index[criteria]])
    }
    /// An iterator over every criteria in order, with 'implies' fully applied.
    pub fn all_criteria_iter(&self) -> impl Iterator<Item = &CriteriaSet> {
        self.implied_criteria.iter()
    }
    pub fn len(&self) -> usize {
        self.list.len()
    }
    pub fn is_empty(&self) -> bool {
        self.list.is_empty()
    }
    pub fn no_criteria(&self) -> CriteriaSet {
        CriteriaSet::none(self.len())
    }
    pub fn all_criteria(&self) -> CriteriaSet {
        CriteriaSet::_all(self.len())
    }
    pub fn no_criteria_failures(&self) -> CriteriaFailureSet {
        CriteriaFailureSet::none(self.len())
    }

    /// Yields all the names of the set criteria with implied members filtered out.
    pub fn criteria_names<'a>(
        &'a self,
        criteria: &'a CriteriaSet,
    ) -> impl Iterator<Item = CriteriaStr<'a>> + 'a {
        // Filter out any criteria implied by other criteria
        criteria
            .indices()
            .filter(|&cur_idx| {
                criteria.indices().all(|other_idx| {
                    // Require that we aren't implied by other_idx (and ignore our own index)
                    cur_idx == other_idx || !self.implied_criteria[other_idx].has_criteria(cur_idx)
                })
            })
            .map(|idx| &*self.list[idx].0)
    }

    pub fn all_criteria_names<'a>(
        &'a self,
        criteria: &'a CriteriaFailureSet,
    ) -> impl Iterator<Item = CriteriaStr<'a>> + 'a {
        self.criteria_names(criteria.all())
    }

    pub fn confident_criteria_names<'a>(
        &'a self,
        criteria: &'a CriteriaFailureSet,
    ) -> impl Iterator<Item = CriteriaStr<'a>> + 'a {
        self.criteria_names(criteria.confident())
    }

    pub fn unconfident_criteria_names<'a>(
        &'a self,
        criteria: &'a CriteriaFailureSet,
    ) -> impl Iterator<Item = CriteriaStr<'a>> + 'a {
        // Filter out any criteria implied by other criteria or present in `confident()`
        criteria
            .all()
            .indices()
            .filter(|&cur_idx| {
                !criteria.confident().has_criteria(cur_idx)
                    && criteria.all().indices().all(|other_idx| {
                        // Require that we aren't implied by other_idx (and ignore our own index)
                        cur_idx == other_idx
                            || !self.implied_criteria[other_idx].has_criteria(cur_idx)
                    })
            })
            .map(|idx| &*self.list[idx].0)
    }
}

impl CriteriaSet {
    pub fn none(count: usize) -> Self {
        assert!(
            count <= MAX_CRITERIA,
            "{MAX_CRITERIA} was not Enough For Everyone ({count} criteria)"
        );
        CriteriaSet(0)
    }
    pub fn _all(count: usize) -> Self {
        assert!(
            count <= MAX_CRITERIA,
            "{MAX_CRITERIA} was not Enough For Everyone ({count} criteria)"
        );
        if count == MAX_CRITERIA {
            CriteriaSet(!0)
        } else {
            // Bit Magic to get 'count' 1's
            CriteriaSet((1 << count) - 1)
        }
    }
    pub fn set_criteria(&mut self, idx: usize) {
        self.0 |= 1 << idx;
    }
    pub fn clear_criteria(&mut self, other: &CriteriaSet) {
        self.0 &= !other.0;
    }
    pub fn has_criteria(&self, idx: usize) -> bool {
        (self.0 & (1 << idx)) != 0
    }
    pub fn _intersected_with(&mut self, other: &CriteriaSet) {
        self.0 &= other.0;
    }
    pub fn unioned_with(&mut self, other: &CriteriaSet) {
        self.0 |= other.0;
    }
    pub fn contains(&self, other: &CriteriaSet) -> bool {
        (self.0 & other.0) == other.0
    }
    pub fn is_empty(&self) -> bool {
        self.0 == 0
    }
    pub fn indices(&self) -> impl Iterator<Item = usize> + '_ {
        // Yield all the offsets that are set by repeatedly getting the lowest 1 and clearing it
        let mut raw = self.0;
        std::iter::from_fn(move || {
            if raw == 0 {
                None
            } else {
                let next = raw.trailing_zeros() as usize;
                raw &= !(1 << next);
                Some(next)
            }
        })
    }
}

impl fmt::Debug for CriteriaSet {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt, "{:08b}", self.0)
    }
}

impl CriteriaFailureSet {
    pub fn none(count: usize) -> Self {
        CriteriaFailureSet {
            confident: CriteriaSet::none(count),
            all: CriteriaSet::none(count),
        }
    }
    pub fn from(criteria: &CriteriaSet, confident: bool) -> Self {
        CriteriaFailureSet {
            confident: if confident {
                criteria.clone()
            } else {
                CriteriaSet::default()
            },
            all: criteria.clone(),
        }
    }
    pub fn set_criteria(&mut self, idx: usize, confident: bool) {
        self.all.set_criteria(idx);
        if confident {
            self.confident.set_criteria(idx);
        }
    }
    pub fn clear_criteria(&mut self, other: &CriteriaSet) {
        self.confident.clear_criteria(other);
        self.all.clear_criteria(other);
    }
    pub fn unioned_with(&mut self, other: &CriteriaFailureSet) {
        self.all.unioned_with(&other.all);
        self.confident.unioned_with(&other.confident);
    }
    pub fn contains(&self, other: &CriteriaFailureSet) -> bool {
        self.all.contains(&other.all) && self.confident.contains(&other.confident)
    }
    pub fn is_empty(&self) -> bool {
        self.all.is_empty()
    }
    pub fn is_fully_confident(&self) -> bool {
        self.confident.contains(&self.all)
    }
    pub fn is_fully_unconfident(&self) -> bool {
        self.confident.is_empty()
    }
    pub fn all(&self) -> &CriteriaSet {
        &self.all
    }
    pub fn confident(&self) -> &CriteriaSet {
        &self.confident
    }
}

impl ResolveResult<'_> {
    fn with_no_criteria(empty: CriteriaSet) -> Self {
        Self {
            validated_criteria: empty.clone(),
            fully_audited_criteria: empty,
            search_results: vec![],
            directly_unaudited: false,
            needed_unaudited: false,
        }
    }

    fn contains(&mut self, other: &CriteriaSet) -> bool {
        if self.fully_audited_criteria.contains(other) {
            true
        } else if self.validated_criteria.contains(other) {
            self.needed_unaudited = true;
            true
        } else {
            false
        }
    }

    fn _has_criteria(&mut self, criteria_idx: usize) -> bool {
        if self.fully_audited_criteria.has_criteria(criteria_idx) {
            true
        } else if self.validated_criteria.has_criteria(criteria_idx) {
            self.needed_unaudited = true;
            true
        } else {
            false
        }
    }
}

impl<'a> DepGraph<'a> {
    pub fn new(
        metadata: &'a Metadata,
        filter_graph: Option<&Vec<GraphFilter>>,
        policy: Option<&SortedMap<PackageName, PolicyEntry>>,
    ) -> Self {
        let empty_override = SortedMap::new();
        let policy = policy.unwrap_or(&empty_override);
        let package_list = &*metadata.packages;
        let resolve_list = &*metadata
            .resolve
            .as_ref()
            .expect("cargo metadata did not yield resolve!")
            .nodes;
        let package_index_by_pkgid = package_list
            .iter()
            .enumerate()
            .map(|(idx, pkg)| (&pkg.id, idx))
            .collect::<SortedMap<_, _>>();
        let resolve_index_by_pkgid = resolve_list
            .iter()
            .enumerate()
            .map(|(idx, pkg)| (&pkg.id, idx))
            .collect();

        // Do a first-pass where we populate skeletons of the primary nodes
        // and setup the interners, which will only ever refer to these nodes
        let mut interner_by_pkgid = SortedMap::<&PackageId, PackageIdx>::new();
        let mut interner_by_name_and_ver =
            SortedMap::<PackageStr, SortedMap<&Version, PackageIdx>>::new();
        let mut nodes = vec![];

        // Stub out the initial state of all the nodes
        for resolve_node in resolve_list {
            let package = &package_list[package_index_by_pkgid[&resolve_node.id]];
            nodes.push(PackageNode {
                package_id: &resolve_node.id,
                name: &package.name,
                version: &package.version,
                is_third_party: package.is_third_party(policy),
                // These will get (re)computed later
                normal_deps: vec![],
                build_deps: vec![],
                dev_deps: vec![],
                normal_and_build_deps: vec![],
                all_deps: vec![],
                reverse_deps: SortedSet::new(),
                is_workspace_member: false,
                is_root: false,
                is_dev_only: true,
            });
        }

        // Sort the nodes by package_id to make the graph more stable and to make
        // anything sorted by package_idx to also be approximately sorted by name and version.
        nodes.sort_by_key(|k| k.package_id);

        // Populate the interners based on the new ordering
        for (idx, node) in nodes.iter_mut().enumerate() {
            assert!(interner_by_pkgid.insert(node.package_id, idx).is_none());
            assert!(interner_by_name_and_ver
                .entry(node.name)
                .or_default()
                .insert(node.version, idx)
                .is_none());
        }

        // Do topological sort: just recursively visit all of a node's children, and only add it
        // to the list *after* visiting the children. In this way we have trivially already added
        // all of the dependencies of a node to the list by the time we add itself to the list.
        let mut topo_index = vec![];
        {
            let mut visited = FastMap::new();
            // All of the roots can be found in the workspace_members.
            // First we visit all the workspace members while ignoring dev-deps,
            // this should get us an analysis of the "normal" build graph, which
            // we should compute roots from. Then we will do a second pass on
            // the dev-deps. If we don't do it this way, then dev-dep cycles can
            // confuse us about which nodes are roots or not (potentially resulting
            // in no roots at all!
            for pkgid in &metadata.workspace_members {
                let node_idx = interner_by_pkgid[pkgid];
                nodes[node_idx].is_workspace_member = true;
                visit_node(
                    &mut nodes,
                    &mut topo_index,
                    &mut visited,
                    &interner_by_pkgid,
                    &resolve_index_by_pkgid,
                    resolve_list,
                    node_idx,
                );
            }

            // Anything we visited in the first pass isn't dev-only
            for (&node_idx, ()) in &visited {
                nodes[node_idx].is_dev_only = false;
            }

            // Now that we've visited the normal build graph, mark the nodes that are roots
            for pkgid in &metadata.workspace_members {
                let node = &mut nodes[interner_by_pkgid[pkgid]];
                node.is_root = node.reverse_deps.is_empty();
            }

            // And finally visit workspace-members' dev-deps, safe in the knowledge that
            // we know what all the roots are now.
            for pkgid in &metadata.workspace_members {
                let node_idx = interner_by_pkgid[pkgid];
                let resolve_node = &resolve_list[resolve_index_by_pkgid[pkgid]];
                let dev_deps = deps(
                    resolve_node,
                    &[DependencyKind::Development],
                    &interner_by_pkgid,
                );

                // Now visit all the dev deps
                for &child in &dev_deps {
                    visit_node(
                        &mut nodes,
                        &mut topo_index,
                        &mut visited,
                        &interner_by_pkgid,
                        &resolve_index_by_pkgid,
                        resolve_list,
                        child,
                    );
                    // Note that these edges do not change whether something is a "root"
                    nodes[child].reverse_deps.insert(node_idx);
                }

                let node = &mut nodes[node_idx];
                node.dev_deps = dev_deps;
            }
            fn visit_node<'a>(
                nodes: &mut Vec<PackageNode<'a>>,
                topo_index: &mut Vec<PackageIdx>,
                visited: &mut FastMap<PackageIdx, ()>,
                interner_by_pkgid: &SortedMap<&'a PackageId, PackageIdx>,
                resolve_index_by_pkgid: &SortedMap<&'a PackageId, usize>,
                resolve_list: &'a [cargo_metadata::Node],
                normal_idx: PackageIdx,
            ) {
                // Don't revisit a node we've already seen
                let query = visited.entry(normal_idx);
                if matches!(query, std::collections::hash_map::Entry::Vacant(..)) {
                    query.or_insert(());
                    let resolve_node =
                        &resolve_list[resolve_index_by_pkgid[nodes[normal_idx].package_id]];

                    // Compute the different kinds of dependencies
                    let all_deps = resolve_node
                        .dependencies
                        .iter()
                        .map(|pkgid| interner_by_pkgid[pkgid])
                        .collect::<Vec<_>>();
                    let build_deps =
                        deps(resolve_node, &[DependencyKind::Build], interner_by_pkgid);
                    let normal_deps =
                        deps(resolve_node, &[DependencyKind::Normal], interner_by_pkgid);
                    let normal_and_build_deps = deps(
                        resolve_node,
                        &[DependencyKind::Normal, DependencyKind::Build],
                        interner_by_pkgid,
                    );

                    // Now visit all the normal and build deps
                    for &child in &normal_and_build_deps {
                        visit_node(
                            nodes,
                            topo_index,
                            visited,
                            interner_by_pkgid,
                            resolve_index_by_pkgid,
                            resolve_list,
                            child,
                        );
                        nodes[child].reverse_deps.insert(normal_idx);
                    }

                    // Now visit this node itself
                    topo_index.push(normal_idx);

                    // Now commit all the deps
                    let cur_node = &mut nodes[normal_idx];
                    cur_node.build_deps = build_deps;
                    cur_node.normal_deps = normal_deps;
                    cur_node.normal_and_build_deps = normal_and_build_deps;
                    cur_node.all_deps = all_deps;

                    // dev-deps will be handled in a second pass
                }
            }
            fn deps(
                resolve_node: &Node,
                kinds: &[DependencyKind],
                interner_by_pkgid: &SortedMap<&PackageId, PackageIdx>,
            ) -> Vec<PackageIdx> {
                // Note that dep_kinds has target cfg info. If we want to handle targets
                // we should gather those up with filter/fold instead of just 'any'.
                // TODO: map normal-deps that whose package has a "proc-macro" target to be build-deps
                resolve_node
                    .deps
                    .iter()
                    .filter(|dep| {
                        dep.dep_kinds
                            .iter()
                            .any(|dep_kind| kinds.contains(&dep_kind.kind))
                    })
                    .map(|dep| interner_by_pkgid[&dep.pkg])
                    .collect()
            }
        }

        let result = Self {
            interner_by_pkgid,
            interner_by_name_and_ver,
            nodes,
            topo_index,
        };

        // Now apply filters, if any
        if let Some(filters) = filter_graph {
            result.filter(filters)
        } else {
            result
        }
    }

    pub fn filter(self, filters: &[GraphFilter]) -> Self {
        use GraphFilter::*;
        use GraphFilterProperty::*;
        use GraphFilterQuery::*;

        fn matches_query(package: &PackageNode, query: &GraphFilterQuery) -> bool {
            match query {
                All(queries) => queries.iter().all(|q| matches_query(package, q)),
                Any(queries) => queries.iter().any(|q| matches_query(package, q)),
                Not(query) => !matches_query(package, query),
                Prop(property) => matches_property(package, property),
            }
        }
        fn matches_property(package: &PackageNode, property: &GraphFilterProperty) -> bool {
            match property {
                Name(val) => package.name == val,
                Version(val) => package.version == val,
                IsRoot(val) => &package.is_root == val,
                IsWorkspaceMember(val) => &package.is_workspace_member == val,
                IsThirdParty(val) => &package.is_third_party == val,
                IsDevOnly(val) => &package.is_dev_only == val,
            }
        }

        let mut passed_filters = FastSet::new();
        'nodes: for (idx, package) in self.nodes.iter().enumerate() {
            for filter in filters {
                match filter {
                    Include(query) => {
                        if !matches_query(package, query) {
                            continue 'nodes;
                        }
                    }

                    Exclude(query) => {
                        if matches_query(package, query) {
                            continue 'nodes;
                        }
                    }
                }
            }
            // If we pass all the filters, then we get to be included
            passed_filters.insert(idx);
        }

        let mut reachable = FastMap::new();
        for (idx, package) in self.nodes.iter().enumerate() {
            if package.is_workspace_member {
                visit(&mut reachable, &self, &passed_filters, idx);
            }
            fn visit(
                visited: &mut FastMap<PackageIdx, ()>,
                graph: &DepGraph,
                passed_filters: &FastSet<PackageIdx>,
                node_idx: PackageIdx,
            ) {
                if !passed_filters.contains(&node_idx) {
                    return;
                }
                let query = visited.entry(node_idx);
                if matches!(query, std::collections::hash_map::Entry::Vacant(..)) {
                    query.or_insert(());
                    for &child in &graph.nodes[node_idx].all_deps {
                        visit(visited, graph, passed_filters, child);
                    }
                }
            }
        }

        let mut old_to_new = FastMap::new();
        let mut nodes = Vec::new();
        let mut interner_by_pkgid = SortedMap::new();
        let mut interner_by_name_and_ver = SortedMap::<_, SortedMap<_, _>>::new();
        let mut topo_index = Vec::new();
        for (old_idx, package) in self.nodes.iter().enumerate() {
            if !reachable.contains_key(&old_idx) {
                continue;
            }
            let new_idx = nodes.len();
            old_to_new.insert(old_idx, new_idx);
            nodes.push(PackageNode {
                package_id: package.package_id,
                name: package.name,
                version: package.version,
                normal_deps: vec![],
                build_deps: vec![],
                dev_deps: vec![],
                normal_and_build_deps: vec![],
                all_deps: vec![],
                reverse_deps: SortedSet::new(),
                is_workspace_member: package.is_workspace_member,
                is_third_party: package.is_third_party,
                is_root: package.is_root,
                is_dev_only: package.is_dev_only,
            });
            interner_by_pkgid.insert(package.package_id, new_idx);
            interner_by_name_and_ver
                .entry(package.name)
                .or_default()
                .insert(package.version, new_idx);
        }
        for old_idx in &self.topo_index {
            if let Some(&new_idx) = old_to_new.get(old_idx) {
                topo_index.push(new_idx);
            }
        }
        for (old_idx, old_package) in self.nodes.iter().enumerate() {
            if let Some(&new_idx) = old_to_new.get(&old_idx) {
                let new_package = &mut nodes[new_idx];
                for old_dep in &old_package.normal_deps {
                    if let Some(&new_dep) = old_to_new.get(old_dep) {
                        new_package.normal_deps.push(new_dep);
                    }
                }
                for old_dep in &old_package.build_deps {
                    if let Some(&new_dep) = old_to_new.get(old_dep) {
                        new_package.build_deps.push(new_dep);
                    }
                }
                for old_dep in &old_package.dev_deps {
                    if let Some(&new_dep) = old_to_new.get(old_dep) {
                        new_package.dev_deps.push(new_dep);
                    }
                }
                for old_dep in &old_package.normal_and_build_deps {
                    if let Some(&new_dep) = old_to_new.get(old_dep) {
                        new_package.normal_and_build_deps.push(new_dep);
                    }
                }
                for old_dep in &old_package.all_deps {
                    if let Some(&new_dep) = old_to_new.get(old_dep) {
                        new_package.all_deps.push(new_dep);
                    }
                }
                for old_dep in &old_package.reverse_deps {
                    if let Some(&new_dep) = old_to_new.get(old_dep) {
                        new_package.reverse_deps.insert(new_dep);
                    }
                }
            }
        }

        Self {
            nodes,
            interner_by_pkgid,
            interner_by_name_and_ver,
            topo_index,
        }
    }

    pub fn print_mermaid(
        &self,
        out: &mut dyn Out,
        sub_args: &DumpGraphArgs,
    ) -> Result<(), std::io::Error> {
        use crate::DumpGraphDepth::*;
        let depth = sub_args.depth;

        let mut visible_nodes = SortedSet::new();
        let mut nodes_with_children = SortedSet::new();
        let mut shown = SortedSet::new();

        for (idx, package) in self.nodes.iter().enumerate() {
            if (package.is_root && depth >= Roots)
                || (package.is_workspace_member && depth >= Workspace)
                || (!package.is_third_party && depth >= FirstParty)
                || depth >= Full
            {
                visible_nodes.insert(idx);
                nodes_with_children.insert(idx);

                if depth >= FirstPartyAndDirects {
                    for &dep in &package.all_deps {
                        visible_nodes.insert(dep);
                    }
                }
            }
        }

        writeln!(out, "graph LR")?;

        writeln!(out, "    subgraph roots")?;
        for &idx in &visible_nodes {
            let package = &self.nodes[idx];
            if package.is_root && shown.insert(idx) {
                writeln!(
                    out,
                    "        node{idx}{{{}:{}}}",
                    package.name, package.version
                )?;
            }
        }
        writeln!(out, "    end")?;

        writeln!(out, "    subgraph workspace-members")?;
        for &idx in &visible_nodes {
            let package = &self.nodes[idx];
            if package.is_workspace_member && shown.insert(idx) {
                writeln!(
                    out,
                    "        node{idx}[/{}:{}/]",
                    package.name, package.version
                )?;
            }
        }
        writeln!(out, "    end")?;

        writeln!(out, "    subgraph first-party")?;
        for &idx in &visible_nodes {
            let package = &self.nodes[idx];
            if !package.is_third_party && shown.insert(idx) {
                writeln!(
                    out,
                    "        node{idx}[{}:{}]",
                    package.name, package.version
                )?;
            }
        }
        writeln!(out, "    end")?;

        writeln!(out, "    subgraph third-party")?;
        for &idx in &visible_nodes {
            let package = &self.nodes[idx];
            if shown.insert(idx) {
                writeln!(
                    out,
                    "        node{idx}({}:{})",
                    package.name, package.version
                )?;
            }
        }
        writeln!(out, "    end")?;

        for &idx in &nodes_with_children {
            let package = &self.nodes[idx];
            for &dep_idx in &package.all_deps {
                if visible_nodes.contains(&dep_idx) {
                    writeln!(out, "    node{idx} --> node{dep_idx}")?;
                }
            }
        }

        Ok(())
    }
}

// Dummy values for corner cases
pub static ROOT_VERSION: Version = Version::new(0, 0, 0);
static NO_AUDITS: Vec<AuditEntry> = Vec::new();

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum ResolveDepth {
    Deep,
    Shallow,
}

pub fn resolve<'a>(
    metadata: &'a Metadata,
    filter_graph: Option<&Vec<GraphFilter>>,
    store: &'a Store,
    resolve_depth: ResolveDepth,
) -> ResolveReport<'a> {
    let _resolve_span = trace_span!("validate").entered();
    // A large part of our algorithm is unioning and intersecting criteria, so we map all
    // the criteria into indexed boolean sets (*whispers* an integer with lots of bits).
    let graph = DepGraph::new(metadata, filter_graph, Some(&store.config.policy));
    // trace!("built DepGraph: {:#?}", graph);
    trace!("built DepGraph!");

    let criteria_mapper = CriteriaMapper::new(&store.audits.criteria);
    trace!("built CriteriaMapper!");

    // This uses the same indexing pattern as graph.resolve_index_by_pkgid
    let mut results =
        vec![ResolveResult::with_no_criteria(criteria_mapper.no_criteria()); graph.nodes.len()];
    let mut root_failures = RootFailures::new();
    let mut violations = SortedMap::new();

    // Actually vet the build graph
    for &pkgidx in &graph.topo_index {
        let package = &graph.nodes[pkgidx];

        if package.is_third_party {
            resolve_third_party(
                metadata,
                store,
                &graph,
                &criteria_mapper,
                &mut results,
                &mut violations,
                &mut root_failures,
                pkgidx,
            );
        } else {
            resolve_first_party(
                metadata,
                store,
                &graph,
                &criteria_mapper,
                &mut results,
                &mut violations,
                &mut root_failures,
                pkgidx,
            );
        }
    }

    // Now that we've processed the "normal" graph we need to check the dev (test/bench) builds.
    // This needs to be done as a separate pass because tests can introduce apparent cycles in
    // the Cargo graph, because our X's tests can depend on Y which in turn depend on X again.
    //
    // This is fine for Cargo because the tests are a completely different build from X itself
    // so the cycle completely disappears once the graph is "desugarred" into actual build units,
    // but it's an annoying problem for us because it essentially means we cannot fully analyze
    // X in one shot. However we have a few useful insights we can leverage:
    //
    // * Nothing can "depend" on X's tests, and therefore ignoring the tests on our first pass
    //   shouldn't logically affect any other node's results. i.e. UsesX being safe-to-run
    //   does not depend on X's tests being safe-to-run. If we were to desugar X into two nodes
    //   as Cargo does, the "dev" node would always be a root, so we should treat it as such
    //   during this second pass.
    //
    // * We don't actually *care* if a node *has* tests/benches. All we care about is if
    //   the node has dev-dependencies, because that's the only thing that could change the
    //   results of the previous pass. (TODO: is this actually true? Root nodes get special
    //   default policies, so maybe all nodes that are testable should get rescanned? But
    //   also tests are expected to have weaker requirements... hmm...)
    //
    // * We will only ever test/bench a workspace member, and workspace members are always
    //   first-party packages. This means we can avoid thinking about all the complicated
    //   graph search stuff and just need to do simple one-shot analysis of our deps and
    //   check against root policies.
    for &pkgidx in &graph.topo_index {
        let package = &graph.nodes[pkgidx];
        if package.is_workspace_member {
            resolve_dev(
                metadata,
                store,
                &graph,
                &criteria_mapper,
                &mut results,
                &mut violations,
                &mut root_failures,
                pkgidx,
            );
        } else {
            assert!(
                package.dev_deps.is_empty(),
                "{}:{} isn't a workspace member but has dev-deps!",
                package.name,
                package.version
            );
        }
    }

    // If there were violations, report that
    if !violations.is_empty() {
        return ResolveReport {
            graph,
            criteria_mapper,
            results,
            conclusion: Conclusion::FailForViolationConflict(FailForViolationConflict {
                violations,
            }),
        };
    }
    _resolve_span.exit();
    let _blame_span = trace_span!("blame").entered();

    // There weren't any violations, so now compute the final failures by pushing blame
    // down from the roots to the leaves that caused those failures.
    let mut failures = SortedMap::<PackageIdx, AuditFailure>::new();
    visit_failures(
        &graph,
        &criteria_mapper,
        &results,
        &root_failures,
        resolve_depth,
        |failure, depth, own_failure| {
            if let Some(criteria_failures) = own_failure {
                trace!(
                    " {:width$}blaming: {}:{} for {:?} + {:?}",
                    "",
                    graph.nodes[failure].name,
                    graph.nodes[failure].version,
                    criteria_mapper
                        .confident_criteria_names(criteria_failures)
                        .collect::<Vec<_>>(),
                    criteria_mapper
                        .unconfident_criteria_names(criteria_failures)
                        .collect::<Vec<_>>(),
                    width = depth
                );
                failures
                    .entry(failure)
                    .or_default()
                    .criteria_failures
                    .unioned_with(criteria_failures);
            }
            Ok::<(), ()>(())
        },
    )
    .unwrap();

    // There should always be leaf failures if there were root failures!
    assert_eq!(
        root_failures.is_empty(),
        failures.is_empty(),
        "failure blaming system bugged out"
    );

    // If there are any failures, report that
    if !failures.is_empty() {
        return ResolveReport {
            graph,
            criteria_mapper,
            results,
            conclusion: Conclusion::FailForVet(FailForVet {
                failures,
                suggest: None,
            }),
        };
    }

    // Ok, we've actually completely succeeded! Gather up stats on that success.
    let mut vetted_with_unaudited = vec![];
    let mut vetted_partially = vec![];
    let mut vetted_fully = vec![];
    let mut useless_unaudited = vec![];
    for &pkgidx in &graph.topo_index {
        let package = &graph.nodes[pkgidx];
        if !package.is_third_party {
            // We only want to report on third-parties.
            continue;
        }
        let result = &results[pkgidx];

        if !result.needed_unaudited {
            vetted_fully.push(pkgidx);
        } else if result.directly_unaudited {
            vetted_with_unaudited.push(pkgidx);
        } else {
            vetted_partially.push(pkgidx);
        }

        if result.directly_unaudited && !result.needed_unaudited {
            useless_unaudited.push(pkgidx);
        }
    }

    ResolveReport {
        graph,
        criteria_mapper,
        results,
        conclusion: Conclusion::Success(Success {
            vetted_with_unaudited,
            vetted_partially,
            vetted_fully,
            useless_unaudited,
        }),
    }
}

#[allow(clippy::too_many_arguments, clippy::ptr_arg)]
fn resolve_third_party<'a>(
    _metadata: &'a Metadata,
    store: &'a Store,
    graph: &DepGraph<'a>,
    criteria_mapper: &CriteriaMapper,
    results: &mut [ResolveResult<'a>],
    violations: &mut SortedMap<PackageIdx, Vec<ViolationConflict>>,
    _root_failures: &mut RootFailures,
    pkgidx: PackageIdx,
) {
    let package = &graph.nodes[pkgidx];
    assert!(
        package.dev_deps.is_empty(),
        "third-party packages shouldn't have dev-deps!"
    );
    let unaudited = store.config.unaudited.get(package.name);

    let own_audits = store.audits.audits.get(package.name).unwrap_or(&NO_AUDITS);

    // See AuditGraph's docs for details on the lowering we do here
    let mut forward_audits = AuditGraph::new();
    let mut backward_audits = AuditGraph::new();
    let mut violation_nodes = Vec::new();

    // Collect up all the deltas, their criteria, and dependency_criteria
    for entry in own_audits.iter() {
        // For uniformity, model a Full Audit as `0.0.0 -> x.y.z`
        let (from_ver, to_ver, dependency_criteria) = match &entry.kind {
            AuditKind::Full {
                version,
                dependency_criteria,
            } => (&ROOT_VERSION, version, dependency_criteria),
            AuditKind::Delta {
                delta,
                dependency_criteria,
            } => (&delta.from, &delta.to, dependency_criteria),
            AuditKind::Violation { .. } => {
                violation_nodes.push((AuditSource::OwnAudits, entry));
                continue;
            }
        };

        let criteria = criteria_mapper.criteria_from_entry(entry);
        // Convert all the custom criteria to CriteriaSets
        let dependency_criteria: FastMap<_, _> = dependency_criteria
            .iter()
            .map(|(pkg_name, criteria)| (&**pkg_name, criteria_mapper.criteria_from_list(criteria)))
            .collect();

        forward_audits.entry(from_ver).or_default().push(DeltaEdge {
            version: to_ver,
            criteria: criteria.clone(),
            dependency_criteria: dependency_criteria.clone(),
            is_unaudited_entry: false,
        });
        backward_audits.entry(to_ver).or_default().push(DeltaEdge {
            version: from_ver,
            criteria,
            dependency_criteria,
            is_unaudited_entry: false,
        });
    }

    // Try to map foreign audits into our worldview
    for (foreign_name, foreign_audits) in &store.imports.audits {
        // Prep CriteriaSet machinery for comparing requirements
        let foreign_criteria_mapper = CriteriaMapper::new(&foreign_audits.criteria);
        let criteria_map = &store
            .config
            .imports
            .get(foreign_name)
            .expect("Foreign Import isn't in config file (imports.lock outdated?)")
            .criteria_map;
        let criteria_map: Vec<(CriteriaStr, CriteriaSet)> = criteria_map
            .iter()
            .map(|mapping| {
                let set = foreign_criteria_mapper.criteria_from_list(&mapping.theirs);
                (&*mapping.ours, set)
            })
            .collect();

        for entry in foreign_audits
            .audits
            .get(package.name)
            .unwrap_or(&NO_AUDITS)
        {
            // For uniformity, model a Full Audit as `0.0.0 -> x.y.z`
            let (from_ver, to_ver, dependency_criteria) = match &entry.kind {
                AuditKind::Full {
                    version,
                    dependency_criteria,
                } => (&ROOT_VERSION, version, dependency_criteria),
                AuditKind::Delta {
                    delta,
                    dependency_criteria,
                } => (&delta.from, &delta.to, dependency_criteria),
                AuditKind::Violation { .. } => {
                    violation_nodes.push((AuditSource::Foreign(foreign_name.clone()), entry));
                    continue;
                }
            };
            // TODO: figure out a reasonable way to map foreign dependency_criteria
            if !dependency_criteria.is_empty() {
                // Just discard this entry for now
                warn!("discarding foreign audit with dependency_criteria (TODO)");
                continue;
            }

            // Map this entry's criteria into our worldview
            let mut local_criteria = criteria_mapper.no_criteria();
            let foreign_criteria = foreign_criteria_mapper.criteria_from_entry(entry);
            for (local_implied, foreign_required) in &criteria_map {
                if foreign_criteria.contains(foreign_required) {
                    criteria_mapper.set_criteria(&mut local_criteria, local_implied);
                }
            }

            forward_audits.entry(from_ver).or_default().push(DeltaEdge {
                version: to_ver,
                criteria: local_criteria.clone(),
                dependency_criteria: Default::default(),
                is_unaudited_entry: false,
            });
            backward_audits.entry(to_ver).or_default().push(DeltaEdge {
                version: from_ver,
                criteria: local_criteria,
                dependency_criteria: Default::default(),
                is_unaudited_entry: false,
            });
        }
    }

    // Reject forbidden packages (violations)
    for (violation_source, violation_entry) in &violation_nodes {
        // Ok this is kind of weird. We want to reject any audits which contain any of these criteria.
        // Normally we would slap all the criteria in this entry into a set and do some kind of set
        // comparison, but that's not quite right. Here are the cases we want to work:
        //
        // * violation: safe-to-deploy, audit: safe-to-deploy -- ERROR!
        // * violation: safe-to-deploy, audit: safe-to-run    -- OK!
        // * violation: safe-to-run,    audit: safe-to-deploy -- ERROR!
        // * violation: [a, b],         audit: [a, c]         -- ERROR!
        //
        // The first 3 cases are correctly handled by audit.contains(violation)
        // but the last one isn't. I think the correct solution to this is to
        // *for each individual entry in the violation* do audit.contains(violation).
        // If any of those queries trips, then it's an ERROR.
        //
        // Note that this would also more correctly handle [safe-to-deploy, safe-to-run]
        // as a violation entry because it would effectively become safe-to-run instead
        // of safe-to-deploy, which is the correct and desirable behaviour!
        //
        // So here we make a criteria set for each entry in the violation.
        let violation_criterias = violation_entry
            .criteria
            .iter()
            .map(|c| criteria_mapper.criteria_from_list([&c]))
            .collect::<Vec<_>>();
        let violation_range = if let AuditKind::Violation { violation } = &violation_entry.kind {
            violation
        } else {
            unreachable!("violation_entry wasn't a Violation?");
        };

        // Note if this entry conflicts with any unaudited entries
        if let Some(alloweds) = unaudited {
            for allowed in alloweds {
                let audit_criteria = criteria_mapper.criteria_from_list(&allowed.criteria);
                let has_violation = violation_criterias
                    .iter()
                    .any(|v| audit_criteria.contains(v));
                if !has_violation {
                    continue;
                }
                if violation_range.matches(&allowed.version) {
                    violations.entry(pkgidx).or_default().push(
                        ViolationConflict::UnauditedConflict {
                            violation_source: violation_source.clone(),
                            violation: (*violation_entry).clone(),
                            unaudited: allowed.clone(),
                        },
                    );
                }
            }
        }

        // Note if this entry conflicts with any audits
        for audit in own_audits {
            let audit_criteria = criteria_mapper.criteria_from_entry(audit);
            let has_violation = violation_criterias
                .iter()
                .any(|v| audit_criteria.contains(v));
            if !has_violation {
                continue;
            }
            match &audit.kind {
                AuditKind::Full { version, .. } => {
                    if violation_range.matches(version) {
                        violations.entry(pkgidx).or_default().push(
                            ViolationConflict::AuditConflict {
                                violation_source: violation_source.clone(),
                                violation: (*violation_entry).clone(),
                                audit_source: AuditSource::OwnAudits,
                                audit: audit.clone(),
                            },
                        );
                    }
                }
                AuditKind::Delta { delta, .. } => {
                    if violation_range.matches(&delta.from) || violation_range.matches(&delta.to) {
                        violations.entry(pkgidx).or_default().push(
                            ViolationConflict::AuditConflict {
                                violation_source: violation_source.clone(),
                                violation: (*violation_entry).clone(),
                                audit_source: AuditSource::OwnAudits,
                                audit: audit.clone(),
                            },
                        );
                    }
                }
                AuditKind::Violation { .. } => {
                    // don't care
                }
            }
        }

        for (foreign_name, foreign_audits) in &store.imports.audits {
            for audit in foreign_audits
                .audits
                .get(package.name)
                .unwrap_or(&NO_AUDITS)
            {
                let audit_criteria = criteria_mapper.criteria_from_entry(audit);
                let has_violation = violation_criterias
                    .iter()
                    .any(|v| audit_criteria.contains(v));
                if !has_violation {
                    continue;
                }
                match &audit.kind {
                    AuditKind::Full { version, .. } => {
                        if violation_range.matches(version) {
                            violations.entry(pkgidx).or_default().push(
                                ViolationConflict::AuditConflict {
                                    violation_source: violation_source.clone(),
                                    violation: (*violation_entry).clone(),
                                    audit_source: AuditSource::Foreign(foreign_name.clone()),
                                    audit: audit.clone(),
                                },
                            );
                        }
                    }
                    AuditKind::Delta { delta, .. } => {
                        if violation_range.matches(&delta.from)
                            || violation_range.matches(&delta.to)
                        {
                            violations.entry(pkgidx).or_default().push(
                                ViolationConflict::AuditConflict {
                                    violation_source: violation_source.clone(),
                                    violation: (*violation_entry).clone(),
                                    audit_source: AuditSource::Foreign(foreign_name.clone()),
                                    audit: audit.clone(),
                                },
                            );
                        }
                    }
                    AuditKind::Violation { .. } => {
                        // don't care
                    }
                }
            }
        }

        // FIXME: this kind of violation is annoying to catch, but you kind of don't have to.
        //
        // It's impossible to validate a package with some criteria without an audit/unaudited
        // entry with that criteria (or a criteria that implies it) touching that version.
        // Therefore we can catch any "true" violations by just looking at the AuditGraph's
        // edges as we do above. However if you current version is a violation and but doesn't
        // have an audit, we may suggest an audit that *is* a violation. This is bad.
        //
        // This commented out code stands as a memorial to that problem for later.

        /*
        // Note if this entry conflicts with the current package's version
        if violation_range.matches(package.version) {
            violations
                .entry(pkgidx)
                .or_default()
                .push(ViolationConflict::CurVersionConflict {
                    source: violation_source.clone(),
                    violation: (*violation_entry).clone(),
                });
        }
        */
    }

    let mut directly_unaudited = false;
    // Unaudited entries are equivalent to full-audits
    if let Some(alloweds) = unaudited {
        for allowed in alloweds {
            if &allowed.version == package.version {
                directly_unaudited = true;
            }
            let from_ver = &ROOT_VERSION;
            let to_ver = &allowed.version;
            let criteria = criteria_mapper.criteria_from_list(&allowed.criteria);
            let dependency_criteria: FastMap<_, _> = allowed
                .dependency_criteria
                .iter()
                .map(|(pkg_name, criteria)| {
                    (&**pkg_name, criteria_mapper.criteria_from_list(criteria))
                })
                .collect();

            // For simplicity, turn 'unaudited' entries into deltas from 0.0.0
            forward_audits.entry(from_ver).or_default().push(DeltaEdge {
                version: to_ver,
                criteria: criteria.clone(),
                dependency_criteria: dependency_criteria.clone(),
                is_unaudited_entry: true,
            });
            backward_audits.entry(to_ver).or_default().push(DeltaEdge {
                version: from_ver,
                criteria,
                dependency_criteria,
                is_unaudited_entry: true,
            });
        }
    }

    let mut validated_criteria = criteria_mapper.no_criteria();
    let mut fully_audited_criteria = criteria_mapper.no_criteria();
    let mut search_results = vec![];
    for criteria in criteria_mapper.all_criteria_iter() {
        let result = search_for_path(
            criteria,
            &ROOT_VERSION,
            package.version,
            &forward_audits,
            graph,
            criteria_mapper,
            package,
            results,
        );
        match result {
            SearchResult::Connected { fully_audited } => {
                // We found a path, hooray, criteria validated!
                if fully_audited {
                    fully_audited_criteria.unioned_with(criteria);
                }
                validated_criteria.unioned_with(criteria);
                search_results.push(SearchResult::Connected { fully_audited });
            }
            SearchResult::PossiblyConnected { failed_deps } => {
                // We failed but found a possible solution if our dependencies were better.
                // Just forward this along so that we can blame them if it comes up!
                search_results.push(SearchResult::PossiblyConnected { failed_deps });
            }
            SearchResult::Disconnected {
                reachable_from_root,
                ..
            } => {
                // We failed to find a path, boo! Run the algorithm backwards to see what we
                // can reach from the other side, so we have our candidates for suggestions.
                let rev_result = search_for_path(
                    criteria,
                    package.version,
                    &ROOT_VERSION,
                    &backward_audits,
                    graph,
                    criteria_mapper,
                    package,
                    results,
                );
                if let SearchResult::Disconnected {
                    reachable_from_root: reachable_from_target,
                    ..
                } = rev_result
                {
                    search_results.push(SearchResult::Disconnected {
                        reachable_from_root,
                        reachable_from_target,
                    })
                } else {
                    unreachable!("We managed to find a path but only from one direction?!");
                }
            }
        }
    }

    // We've completed our graph analysis for this package, now record the results
    results[pkgidx] = ResolveResult {
        validated_criteria,
        fully_audited_criteria,
        directly_unaudited,
        search_results,
        // Only gets found out later, for now, assume not.
        needed_unaudited: false,
    };
}

#[allow(clippy::too_many_arguments)]
fn search_for_path<'a>(
    cur_criteria: &CriteriaSet,
    from_version: &'a Version,
    to_version: &'a Version,
    audit_graph: &AuditGraph<'a>,
    dep_graph: &DepGraph<'a>,
    criteria_mapper: &CriteriaMapper,
    package: &PackageNode<'a>,
    results: &mut [ResolveResult],
) -> SearchResult<'a> {
    // Search for any path through the graph with edges that satisfy cur_criteria.
    // Finding any path validates that we satisfy that criteria. All we're doing is
    // basic depth-first search with a manual stack.
    //
    // All full-audits and unaudited entries have been "desugarred" to a delta from 0.0.0,
    // meaning our graph now has exactly one source and one sink, significantly simplifying
    // the start and end conditions.
    //
    // Because we want to know if the validation can be done without ever using an
    // 'unaudited' entry, we initially "defer" using those edges. This is accomplished
    // by wrapping the entire algorithm in a loop, and only taking those edges on the
    // next iteration of the outer loop. So if we find a path in the first iteration,
    // then that's an unambiguous proof that we didn't need those edges.
    //
    // We apply this same "deferring" trick to edges which fail because of our dependencies.
    // Once we run out of both 'unaudited' entries and still don't have a path, we start
    // speculatively allowing ourselves to follow those edges. If we find a path by doing that
    // then we can reliably "blame" our deps for our own failings. Otherwise we there is
    // no possible path, and we are absolutely just missing reviews for ourself.

    // Conclusions
    let mut found_path = false;
    let mut needed_unaudited_entry = false;
    let mut needed_failed_edges = false;
    let mut failed_deps = SortedMap::<PackageIdx, CriteriaSet>::new();

    // Search State
    let mut search_stack = vec![from_version];
    let mut visited = SortedSet::new();
    let mut deferred_unaudited_entries = vec![];
    let mut deferred_failed_edges = vec![];

    // Loop until we find a path or run out of deferred edges.
    loop {
        // If there are any deferred edges (only possible on iteration 2+), try to follow them.
        // Always prefer following 'unaudited' edges, so that we only dip into failed edges when
        // we've completely run out of options.
        if let Some(node) = deferred_unaudited_entries.pop() {
            // Don't bother if we got to that node some other way.
            if visited.contains(node) {
                continue;
            }
            // Ok at this point we officially "need" the unaudited edge. If the search still
            // fails, then we won't mention that we used this, since the graph is just broken
            // and we can't make any conclusions about whether anything is needed or not!
            needed_unaudited_entry = true;
            search_stack.push(node);
        } else if let Some(node) = deferred_failed_edges.pop() {
            // Don't bother if we got to that node some other way.
            if visited.contains(node) {
                continue;
            }
            // Ok at this point we officially "need" the failed edge. If the search still
            // fails, then we won't mention that we used this, since the graph is just broken
            // and we can't make any conclusions about whether anything is needed or not!
            needed_failed_edges = true;
            search_stack.push(node);
        }

        // Do Depth-First-Search
        while let Some(cur_version) = search_stack.pop() {
            // Don't revisit nodes, there's never an advantage to doing so, and because deltas
            // can go both forwards and backwards in time, cycles are a real concern!
            visited.insert(cur_version);
            if cur_version == to_version {
                // Success! Nothing more to do.
                found_path = true;
                break;
            }

            // Apply deltas to move along to the next "layer" of the search
            if let Some(edges) = audit_graph.get(cur_version) {
                for edge in edges {
                    if !edge.criteria.contains(cur_criteria) {
                        // This edge never would have been useful to us
                        continue;
                    }
                    if visited.contains(edge.version) {
                        // We've been to this node already
                        continue;
                    }

                    // Deltas should only apply if dependencies satisfy dep_criteria
                    let mut deps_satisfied = true;
                    for &dependency in &package.normal_and_build_deps {
                        let dep_package = &dep_graph.nodes[dependency];
                        let dep_vet_result = &mut results[dependency];

                        // If no custom criteria is specified, then require our dependency to match
                        // the same criteria that we're trying to validate. This makes audits effectively
                        // break down their criteria into individually verifiable components instead of
                        // purely "all or nothing".
                        //
                        // e.g. a safe-to-deploy audit with some deps that are only safe-to-run
                        // still audits for safe-to-run, but not safe-to-deploy. Similarly so for
                        // `[safe-to-run, some-other-criteria]` validating each criteria individually.
                        let dep_req = edge
                            .dependency_criteria
                            .get(&*dep_package.name)
                            .unwrap_or(cur_criteria);

                        if !dep_vet_result.contains(dep_req) {
                            failed_deps
                                .entry(dependency)
                                .or_insert_with(|| criteria_mapper.no_criteria())
                                .unioned_with(dep_req);
                            deps_satisfied = false;
                        }
                    }

                    if deps_satisfied {
                        // Ok yep, this edge is usable! But defer it if it's an 'unaudited' entry.
                        if edge.is_unaudited_entry {
                            deferred_unaudited_entries.push(edge.version);
                        } else {
                            search_stack.push(edge.version);
                        }
                    } else {
                        // Remember this edge failed, if we can't find any path we'll speculatively
                        // re-enable it.
                        deferred_failed_edges.push(edge.version);
                    }
                }
            }
        }

        // Exit conditions
        if found_path || (deferred_unaudited_entries.is_empty() && deferred_failed_edges.is_empty())
        {
            break;
        }
    }

    // It's only a success if we found a path and used no 'failed' edges.
    if found_path && !needed_failed_edges {
        // Complete success!
        SearchResult::Connected {
            fully_audited: !needed_unaudited_entry,
        }
    } else if found_path {
        // Failure, but it's clearly the fault of our deps.
        SearchResult::PossiblyConnected { failed_deps }
    } else {
        // Complete failure, we need more audits of ourself,
        // so all that matters is what nodes were reachable.
        SearchResult::Disconnected {
            reachable_from_root: visited,
            // This will get filled in by the second pass
            reachable_from_target: Default::default(),
        }
    }
}

#[allow(clippy::too_many_arguments, clippy::ptr_arg)]
fn resolve_first_party<'a>(
    _metadata: &'a Metadata,
    store: &'a Store,
    graph: &DepGraph<'a>,
    criteria_mapper: &CriteriaMapper,
    results: &mut [ResolveResult<'a>],
    _violations: &mut SortedMap<PackageIdx, Vec<ViolationConflict>>,
    root_failures: &mut RootFailures,
    pkgidx: PackageIdx,
) {
    // Check the build-deps and normal-deps of this package. dev-deps are checking in `resolve_dep`
    // In this pass we properly use package.is_root, but in the next pass all nodes are "roots"
    let package = &graph.nodes[pkgidx];

    // Get custom policies for our dependencies
    let dep_criteria = store
        .config
        .policy
        .get(package.name)
        .map(|policy| {
            policy
                .dependency_criteria
                .iter()
                .map(|(dep_name, criteria)| {
                    (&**dep_name, criteria_mapper.criteria_from_list(criteria))
                })
                .collect::<FastMap<_, _>>()
        })
        .unwrap_or_default();

    // Compute whether we have each criteria based on our dependencies
    let mut validated_criteria = criteria_mapper.no_criteria();
    let mut search_results = vec![];
    for criteria in criteria_mapper.all_criteria_iter() {
        // Find any build/normal dependencies that don't satisfy this criteria
        let mut failed_deps = SortedMap::new();
        for &depidx in &package.normal_and_build_deps {
            // If we have an explicit policy for dependency, that's all that matters.
            // Otherwise just use the current criteria to "inherit" the results of our deps.
            let dep_name = graph.nodes[depidx].name;
            let required_criteria = dep_criteria.get(dep_name).unwrap_or(criteria);
            if !results[depidx].contains(required_criteria) {
                failed_deps
                    .entry(depidx)
                    .or_insert_with(|| criteria_mapper.no_criteria())
                    .unioned_with(required_criteria);
            }
        }

        if failed_deps.is_empty() {
            // All our deps passed the test, so we have this criteria
            search_results.push(SearchResult::Connected {
                fully_audited: true,
            });
            validated_criteria.unioned_with(criteria);
        } else {
            // Some of our deps failed to satisfy this criteria, record this
            search_results.push(SearchResult::PossiblyConnected { failed_deps })
        }
    }
    trace!(
        " first-party {}:{} initial validation: {:?}",
        package.name,
        package.version,
        criteria_mapper
            .criteria_names(&validated_criteria)
            .collect::<Vec<_>>()
    );
    // Save the results
    results[pkgidx].search_results = search_results;
    results[pkgidx].validated_criteria = validated_criteria;

    // Now check that we pass our own policy
    let entry = store.config.policy.get(package.name);
    let own_policy = if let Some(c) = entry.and_then(|p| p.criteria.as_ref()) {
        criteria_mapper.criteria_from_list(c)
    } else if package.is_root {
        criteria_mapper.criteria_from_list([format::DEFAULT_POLICY_CRITERIA])
    } else {
        trace!("   has no policy, done");
        // We have no policy, we're done
        return;
    };

    let mut policy_failures = PolicyFailures::new();
    for criteria_idx in own_policy.indices() {
        if let SearchResult::PossiblyConnected { failed_deps } =
            &results[pkgidx].search_results[criteria_idx]
        {
            for (&dep, failed_criteria) in failed_deps {
                policy_failures
                    .entry(dep)
                    .or_insert_with(|| criteria_mapper.no_criteria())
                    .unioned_with(failed_criteria);
            }
        }
    }

    if policy_failures.is_empty() {
        // We had a policy and it passed, so now we're validated for all criteria
        // because our parents can never require anything else of us. No need
        // to update search_results, they'll be masked out by validated_criteria(?)
        trace!("   passed policy");
        results[pkgidx].validated_criteria = criteria_mapper.all_criteria();
    } else {
        // We had a policy and it failed, so now we're invalid for all criteria(?)
        trace!("   failed policy");
        results[pkgidx].validated_criteria = criteria_mapper.no_criteria();
        root_failures.push((pkgidx, policy_failures, false));
    }
}

#[allow(clippy::too_many_arguments, clippy::ptr_arg)]
fn resolve_dev<'a>(
    _metadata: &'a Metadata,
    store: &'a Store,
    graph: &DepGraph<'a>,
    criteria_mapper: &CriteriaMapper,
    results: &mut [ResolveResult<'a>],
    _violations: &mut SortedMap<PackageIdx, Vec<ViolationConflict>>,
    root_failures: &mut RootFailures,
    pkgidx: PackageIdx,
) {
    // Check the dev-deps of this package. It is assumed to be a root in this context,
    // so the default root dev policy will always be applicable.
    let package = &graph.nodes[pkgidx];

    // Get custom policies for our dependencies
    let dep_criteria = store
        .config
        .policy
        .get(package.name)
        .map(|policy| {
            policy
                .dependency_criteria
                .iter()
                .map(|(dep_name, criteria)| {
                    (&**dep_name, criteria_mapper.criteria_from_list(criteria))
                })
                .collect::<FastMap<_, _>>()
        })
        .unwrap_or_default();

    // Compute whether we have each criteria based on our dependencies
    let mut validated_criteria = criteria_mapper.no_criteria();
    let mut search_results = vec![];
    for criteria in criteria_mapper.all_criteria_iter() {
        // Find any build/normal dependencies that don't satisfy this criteria
        let mut failed_deps = SortedMap::new();
        for &depidx in &package.dev_deps {
            // If we have an explicit policy for dependency, that's all that matters.
            // Otherwise just use the current criteria to "inherit" the results of our deps.
            let dep_name = graph.nodes[depidx].name;
            let required_criteria = dep_criteria.get(dep_name).unwrap_or(criteria);
            if !results[depidx].contains(required_criteria) {
                failed_deps
                    .entry(depidx)
                    .or_insert_with(|| criteria_mapper.no_criteria())
                    .unioned_with(required_criteria);
            }
        }

        if failed_deps.is_empty() {
            // All our deps passed the test, so we have this criteria
            search_results.push(SearchResult::Connected {
                fully_audited: true,
            });
            validated_criteria.unioned_with(criteria);
        } else {
            // Some of our deps failed to satisfy this criteria, record this
            search_results.push(SearchResult::PossiblyConnected { failed_deps })
        }
    }
    trace!(
        " first-party dev {}:{} initial validation: {:?}",
        package.name,
        package.version,
        criteria_mapper
            .criteria_names(&validated_criteria)
            .collect::<Vec<_>>()
    );
    // DON'T save the results, because we're analyzing this as a dev-node and anything that
    // depends on us only cares about the "normal" results.
    // results[pkgidx].search_results = search_results;
    // results[pkgidx].validated_criteria = validated_criteria;

    // Now check that we pass our own policy
    let entry = store.config.policy.get(package.name);
    let own_policy = if let Some(c) = entry.and_then(|p| p.dev_criteria.as_ref()) {
        criteria_mapper.criteria_from_list(c)
    } else {
        criteria_mapper.criteria_from_list([format::DEFAULT_POLICY_DEV_CRITERIA])
    };

    let mut policy_failures = PolicyFailures::new();
    for criteria_idx in own_policy.indices() {
        if let SearchResult::PossiblyConnected { failed_deps } = &search_results[criteria_idx] {
            for (&dep, failed_criteria) in failed_deps {
                policy_failures
                    .entry(dep)
                    .or_insert_with(|| criteria_mapper.no_criteria())
                    .unioned_with(failed_criteria);
            }
        }
    }

    if policy_failures.is_empty() {
        trace!("   passed dev policy");
    } else {
        trace!("   failed dev policy");
        root_failures.push((pkgidx, policy_failures, true));
    }
}

/// Traverse the build graph from the root failures to the leaf failures.
fn visit_failures<'a, T>(
    graph: &DepGraph<'a>,
    criteria_mapper: &CriteriaMapper,
    results: &[ResolveResult<'a>],
    root_failures: &RootFailures,
    resolve_depth: ResolveDepth,
    mut callback: impl FnMut(PackageIdx, usize, Option<&CriteriaFailureSet>) -> Result<(), T>,
) -> Result<(), T> {
    trace!(" traversing blame tree");

    // The crate graph can be messy in several ways:
    //
    // 1. The depth of the graph can be very large, so recursion could blow the stack.
    //
    // 2. The "tree" view of the graph can have an exponential number of nodes because
    //    of duplicated subgraphs from shared dependencies. Unfortunately, that is
    //    the representation we "have" to traverse to properly blame packages for
    //    specific policty failures.
    //
    // 3. Different "targets" for one package are actually logically separate crates,
    //    and naively unifying them can result in cycles. In particular, the "dev"
    //    version of a crate (tests and benches) can have dev-dependencies which depend
    //    on the "real" version of that crate, so if you combine "dev" and "normal"
    //    then you can have cycles. Horrifyingly, people do rely on this.
    //
    // Problem 1 is easy to fix: just use an explicit stack instead of recursion.
    //
    // Problem 2 can be solved by noting that, as long as we don't actually care about
    // *printing* the entire blame-tree and just want to figure out what the leaves
    // are and what criteria they need, we can use the usual "keep a set of visited
    // nodes and don't revisit nodes in that set" pattern *except* modified to include
    // the set of criteria it has been visited with. We then only revisit a node if
    // our current path has criteria that aren't yet in the visitor set.
    //
    // Problem 3 is trickier. Really we should "desugar" a node into its different
    // targets, but there are effectively infinite targets due to all the possible
    // cfg combinations and feature flags, so we'd *really* like to be able to abstractly
    // handle those. I *think* we only *really* need to split up "dev" from "everything else"
    // but I want to think about this more. For now we just rely on the solution to problem 2
    // to avoid infinite loops and just don't worry about the semantics.
    let mut search_stack = Vec::new();

    let mut immune_to_parent_demands = FastSet::new();
    for (failed_idx, policy_failures, is_dev) in root_failures {
        let failed_package = &graph.nodes[*failed_idx];
        trace!(
            " policy failure for {}:{}",
            failed_package.name,
            failed_package.version
        );
        for (&failed_dep_idx, failed_criteria) in policy_failures {
            let failed_dep = &graph.nodes[failed_dep_idx];
            trace!(
                "   {}:{} needed {:?}",
                failed_dep.name,
                failed_dep.version,
                criteria_mapper
                    .criteria_names(failed_criteria)
                    .collect::<Vec<_>>()
            );
            search_stack.push((
                failed_dep_idx,
                0,
                Some(CriteriaFailureSet::from(failed_criteria, true)),
            ));
        }
        if !is_dev {
            // If we have a root failure and it's not from the virtual dev-node, then
            // we have a self-policy that "shadows" anything a parent could require.
            // We will properly blame our children based on the existence of this entry,
            // so we should refuse any attempts from a parent to blame us for anything.
            immune_to_parent_demands.insert(failed_idx);
        }
    }
    let mut visited = FastMap::<PackageIdx, CriteriaFailureSet>::new();
    let no_criteria = criteria_mapper.no_criteria_failures();

    while let Some((failure_idx, depth, cur_criteria)) = search_stack.pop() {
        match visited.entry(failure_idx) {
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert(cur_criteria.clone().unwrap_or_else(|| no_criteria.clone()));
            }
            std::collections::hash_map::Entry::Occupied(mut entry) => {
                let cur = cur_criteria.as_ref().unwrap_or(&no_criteria);
                if entry.get().contains(cur) {
                    continue;
                } else {
                    entry.get_mut().unioned_with(cur);
                }
            }
        }

        let result = &results[failure_idx];
        let package = &graph.nodes[failure_idx];
        trace!(
            " {:width$}visiting {}:{} for {:?} + {:?}",
            "",
            package.name,
            package.version,
            cur_criteria.as_ref().map(|c| criteria_mapper
                .confident_criteria_names(c)
                .collect::<Vec<_>>()),
            cur_criteria.as_ref().map(|c| criteria_mapper
                .unconfident_criteria_names(c)
                .collect::<Vec<_>>()),
            width = depth
        );

        if let Some(failed_criteria) = cur_criteria {
            let mut own_fault = no_criteria.clone();
            let mut dep_faults = FastMap::<PackageIdx, CriteriaFailureSet>::new();

            // Collect up details of how we failed the criteria
            for criteria_idx in failed_criteria.all().indices() {
                let confident = failed_criteria.confident().has_criteria(criteria_idx);
                match &result.search_results[criteria_idx] {
                    SearchResult::Connected { .. } => {
                        // Do nothing, this package is good
                    }
                    SearchResult::PossiblyConnected { failed_deps } => {
                        // We're not to blame, it's our children who failed!
                        for (&failed_dep, failed_criteria) in failed_deps {
                            dep_faults
                                .entry(failed_dep)
                                .or_insert_with(|| no_criteria.clone())
                                .unioned_with(&CriteriaFailureSet::from(
                                    failed_criteria,
                                    confident,
                                ));
                        }
                    }
                    SearchResult::Disconnected { .. } => {
                        // Oh dang ok we *are* to blame, our bad
                        own_fault.set_criteria(criteria_idx, confident);

                        if resolve_depth != ResolveDepth::Shallow {
                            // Try to Guess Deeper by blaming our children for all |self| failures
                            // by assuming we would need them to conform to our own criteria too.
                            //
                            // Dev-deps should never be chased here because any issues with those show
                            // up as root_failures and have already been pushed into the search-stack.
                            // All recursive blaming is about deps for a "normal" build, which requires
                            // only these two kinds of deps.
                            for &dep_idx in &package.normal_and_build_deps {
                                let dep_result = &results[dep_idx];
                                if !dep_result.validated_criteria.has_criteria(criteria_idx) {
                                    dep_faults
                                        .entry(dep_idx)
                                        .or_insert_with(|| no_criteria.clone())
                                        .set_criteria(criteria_idx, false);
                                }
                            }
                        }
                    }
                }
            }

            // Visit ourselves based on whether we're to blame at all
            if own_fault.is_empty() {
                callback(failure_idx, depth, None)?;
            } else {
                callback(failure_idx, depth, Some(&own_fault))?;
            }

            // Now visit our children
            for (failed_dep, failed_criteria) in dep_faults {
                if immune_to_parent_demands.contains(&failed_dep) {
                    continue;
                }
                search_stack.push((failed_dep, depth + 1, Some(failed_criteria.clone())));
            }
        } else {
            unreachable!("I don't think this should happen..?");
        }
    }
    Ok(())
}

impl<'a> ResolveReport<'a> {
    pub fn has_errors(&self) -> bool {
        // Just check the conclusion
        !matches!(self.conclusion, Conclusion::Success(_))
    }

    pub fn _has_warnings(&self) -> bool {
        if let Conclusion::Success(success) = &self.conclusion {
            // If there are useless_unaudited, we'll warn about those
            !success.useless_unaudited.is_empty()
        } else {
            // Errors aren't warnings
            false
        }
    }

    pub fn compute_suggest(
        &self,
        cfg: &Config,
        network: Option<&Network>,
        allow_deltas: bool,
    ) -> Result<Option<Suggest>, SuggestError> {
        let _suggest_span = trace_span!("suggest").entered();
        let fail = if let Conclusion::FailForVet(fail) = &self.conclusion {
            fail
        } else {
            // Nothing to suggest unless we failed for vet
            return Ok(None);
        };

        let cache = Cache::acquire(cfg)?;

        let mut suggestions = tokio::runtime::Handle::current()
            .block_on(join_all(fail.failures.iter().map(
                |(failure_idx, audit_failure)| async {
                    let failure_idx = *failure_idx;
                    let package = &self.graph.nodes[failure_idx];
                    let result = &self.results[failure_idx];

                    // Precompute some "notable" parents
                    let notable_parents = {
                        let mut reverse_deps = self.graph.nodes[failure_idx]
                            .reverse_deps
                            .iter()
                            .map(|&parent| self.graph.nodes[parent].name.to_string())
                            .collect::<Vec<_>>();

                        // To keep the display compact, sort by name length and truncate long lists.
                        // We first sort by name because rust defaults to a stable sort and this will
                        // have by-name as the tie breaker.
                        reverse_deps.sort();
                        reverse_deps.sort_by_key(|item| item.len());
                        let cutoff_index = reverse_deps
                            .iter()
                            .scan(0, |sum, s| {
                                *sum += s.len();
                                Some(*sum)
                            })
                            .position(|count| count > 20);
                        let remainder = cutoff_index.map(|i| reverse_deps.len() - i).unwrap_or(0);
                        if remainder > 1 {
                            reverse_deps.truncate(cutoff_index.unwrap());
                            reverse_deps.push(format!("and {} others", remainder));
                        }
                        reverse_deps.join(", ")
                    };

                    // Collect up the details of how we failed
                    let mut from_root = None::<SortedSet<&Version>>;
                    let mut from_target = None::<SortedSet<&Version>>;
                    for criteria_idx in audit_failure.criteria_failures.all().indices() {
                        let search_result = &result.search_results[criteria_idx];
                        if let SearchResult::Disconnected {
                            reachable_from_root,
                            reachable_from_target,
                        } = search_result
                        {
                            if let (Some(from_root), Some(from_target)) =
                                (from_root.as_mut(), from_target.as_mut())
                            {
                                // FIXME: this is horrible but I'm tired and this avoids false-positives
                                // and duplicates. This does the right thing in the common cases, by
                                // restricting ourselves to the reachable nodes that are common to all
                                // failures, so that we can suggest just one change that will fix
                                // everything.
                                *from_root = &*from_root & reachable_from_root;
                                *from_target = &*from_target & reachable_from_target;
                            } else {
                                from_root = Some(reachable_from_root.clone());
                                from_target = Some(reachable_from_target.clone());
                            }
                        } else {
                            unreachable!("messed up suggest...");
                        }
                    }

                    // Now suggest solutions of those failures
                    let mut candidates = SortedSet::new();
                    if allow_deltas {
                        // If we're allowed deltas than try to find a bridge from src and dest
                        for &dest in from_target.as_ref().unwrap() {
                            let mut closest_above = None;
                            let mut closest_below = None;
                            for &src in from_root.as_ref().unwrap() {
                                if src < dest {
                                    if let Some(closest) = closest_below {
                                        if src > closest {
                                            closest_below = Some(src);
                                        }
                                    } else {
                                        closest_below = Some(src);
                                    }
                                } else if let Some(closest) = closest_above {
                                    if src < closest {
                                        closest_above = Some(src);
                                    }
                                } else {
                                    closest_above = Some(src);
                                }
                            }

                            for closest in closest_below.into_iter().chain(closest_above) {
                                candidates.insert(Delta {
                                    from: closest.clone(),
                                    to: dest.clone(),
                                });
                            }
                        }
                    } else {
                        // If we're not allowing deltas, just try everything reachable from the target
                        for &dest in from_target.as_ref().unwrap() {
                            candidates.insert(Delta {
                                from: ROOT_VERSION.clone(),
                                to: dest.clone(),
                            });
                        }
                    }

                    let diffstats = join_all(candidates.iter().map(|delta| async {
                        match cache
                            .fetch_and_diffstat_package(network, package.name, delta)
                            .await
                        {
                            Ok(diffstat) => Some(DiffRecommendation {
                                diffstat,
                                from: delta.from.clone(),
                                to: delta.to.clone(),
                            }),
                            Err(err) => {
                                // We don't want to actually error out completely here,
                                // as other packages might still successfully diff!
                                error!(
                                    "error diffing {}:{}: {:?}",
                                    package.name, package.version, err
                                );
                                None
                            }
                        }
                    }))
                    .await;

                    Some(SuggestItem {
                        package: failure_idx,
                        suggested_diff: diffstats
                            .into_iter()
                            .flatten()
                            .min_by_key(|diff| diff.diffstat.count)?,
                        suggested_criteria: audit_failure.criteria_failures.clone(),
                        notable_parents,
                    })
                },
            )))
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();

        let total_lines = suggestions
            .iter()
            .map(|s| s.suggested_diff.diffstat.count)
            .sum();

        suggestions.sort_by_key(|item| self.graph.nodes[item.package].version);
        suggestions.sort_by_key(|item| self.graph.nodes[item.package].name);
        suggestions.sort_by_key(|item| item.suggested_diff.diffstat.count);
        suggestions.sort_by_key(|item| item.suggested_criteria.is_fully_unconfident());

        let mut suggestions_by_criteria = SortedMap::<CriteriaName, Vec<SuggestItem>>::new();
        for s in suggestions.clone().into_iter() {
            let criteria_names = self
                .criteria_mapper
                .all_criteria_names(&s.suggested_criteria)
                .collect::<Vec<_>>()
                .join(", ");

            suggestions_by_criteria
                .entry(criteria_names)
                .or_default()
                .push(s);
        }

        Ok(Some(Suggest {
            suggestions,
            suggestions_by_criteria,
            total_lines,
        }))
    }

    /// Given a package name and a delta to be certified, determine the set of
    /// additional criteria for that delta/version pair which would have a
    /// healing impact on the audit graph.
    ///
    /// This is more reliable than running a suggest and looking for a matching
    /// output, as it will also select criteria for non-suggested audits.
    pub fn compute_suggested_criteria(
        &self,
        package_name: PackageStr<'_>,
        delta: &Delta,
    ) -> Vec<CriteriaName> {
        let fail = if let Conclusion::FailForVet(fail) = &self.conclusion {
            fail
        } else {
            return Vec::new();
        };

        let mut criteria = self.criteria_mapper.no_criteria();

        // Enumerate over the recorded failures, adding any criteria for this
        // delta which would connect that package version into the audit graph.
        for (&failure_idx, audit_failure) in &fail.failures {
            let package = &self.graph.nodes[failure_idx];
            if package.name != package_name {
                continue;
            }

            let result = &self.results[failure_idx];
            for criteria_idx in audit_failure.criteria_failures.all().indices() {
                let search_result = &result.search_results[criteria_idx];
                if let SearchResult::Disconnected {
                    reachable_from_root,
                    reachable_from_target,
                } = search_result
                {
                    if reachable_from_target.contains(&delta.to)
                        && reachable_from_root.contains(&delta.from)
                    {
                        criteria.set_criteria(criteria_idx);
                    }
                }
            }
        }

        self.criteria_mapper
            .criteria_names(&criteria)
            .map(str::to_owned)
            .collect()
    }

    /// Print a full human-readable report
    pub fn print_human(
        &self,
        out: &mut dyn Out,
        cfg: &Config,
        suggest: Option<&Suggest>,
    ) -> Result<(), std::io::Error> {
        match &self.conclusion {
            Conclusion::Success(res) => res.print_human(out, self, cfg),
            Conclusion::FailForViolationConflict(res) => res.print_human(out, self, cfg),
            Conclusion::FailForVet(res) => res.print_human(out, self, cfg, suggest),
        }
    }

    /// Print only the suggest portion of a human-readable report
    pub fn print_suggest_human(
        &self,
        out: &mut dyn Out,
        _cfg: &Config,
        suggest: Option<&Suggest>,
    ) -> Result<(), std::io::Error> {
        if let Some(suggest) = suggest {
            suggest.print_human(out, self)?;
        } else {
            // This API is only used for vet-suggest
            writeln!(out, "Nothing to suggest, you're fully audited!")?;
        }
        Ok(())
    }

    /// Print a full human-readable report
    pub fn print_json(
        &self,
        out: &mut dyn Out,
        _cfg: &Config,
        suggest: Option<&Suggest>,
    ) -> Result<(), miette::Report> {
        let result = match &self.conclusion {
            Conclusion::Success(success) => {
                let json_package = |pkgidx: &PackageIdx| {
                    let package = &self.graph.nodes[*pkgidx];
                    json!({
                        "name": package.name,
                        "version": package.version,
                    })
                };
                json!({
                    "conclusion": "success",
                    "vetted_fully": success.vetted_fully.iter().map(json_package).collect::<Vec<_>>(),
                    "vetted_partially": success.vetted_partially.iter().map(json_package).collect::<Vec<_>>(),
                    "vetted_with_unaudited": success.vetted_with_unaudited.iter().map(json_package).collect::<Vec<_>>(),
                    "useless_unaudited": success.useless_unaudited.iter().map(json_package).collect::<Vec<_>>(),
                })
            }
            Conclusion::FailForViolationConflict(fail) => json!({
                "conclusion": "fail (violation)",
                "violations": fail.violations.iter().map(|(pkgidx, violations)| {
                    let package = &self.graph.nodes[*pkgidx];
                    let key = format!("{}:{}", package.name, package.version);
                    (key, violations)
                }).collect::<SortedMap<_,_>>(),
            }),
            Conclusion::FailForVet(fail) => {
                // FIXME: How to report confidence for suggested criteria?
                let json_suggest_item = |item: &SuggestItem| {
                    let package = &self.graph.nodes[item.package];
                    json!({
                        "name": package.name,
                        "notable_parents": item.notable_parents,
                        "suggested_criteria": self.criteria_mapper.all_criteria_names(&item.suggested_criteria).collect::<Vec<_>>(),
                        "suggested_diff": item.suggested_diff,
                    })
                };
                json!({
                    "conclusion": "fail (vetting)",
                    "failures": fail.failures.iter().map(|(&pkgidx, audit_fail)| {
                        let package = &self.graph.nodes[pkgidx];
                        json!({
                            "name": package.name,
                            "version": package.version,
                            "missing_criteria": self.criteria_mapper.all_criteria_names(&audit_fail.criteria_failures).collect::<Vec<_>>(),
                        })
                    }).collect::<Vec<_>>(),
                    "suggest": suggest.map(|suggest| json!({
                        "suggestions": suggest.suggestions.iter().map(json_suggest_item).collect::<Vec<_>>(),
                        "suggest_by_criteria": suggest.suggestions_by_criteria.iter().map(|(criteria, items)| (criteria, items.iter().map(json_suggest_item).collect::<Vec<_>>())).collect::<SortedMap<_,_>>(),
                        "total_lines": suggest.total_lines,
                    })),
                })
            }
        };

        serde_json::to_writer_pretty(out, &result).into_diagnostic()?;

        Ok(())
    }
}

impl Success {
    pub fn print_human(
        &self,
        out: &mut dyn Out,
        report: &ResolveReport,
        _cfg: &Config,
    ) -> Result<(), std::io::Error> {
        let fully_audited_count = self.vetted_fully.len();
        let partially_audited_count: usize = self.vetted_partially.len();
        let unaudited_count = self.vetted_with_unaudited.len();

        // Figure out how many entries we're going to print
        let mut count_count = (fully_audited_count != 0) as usize
            + (partially_audited_count != 0) as usize
            + (unaudited_count != 0) as usize;

        // Print out a summary of how we succeeded
        if count_count == 0 {
            writeln!(
                out,
                "Vetting Succeeded (because you have no third-party dependencies)"
            )?;
        } else {
            write!(out, "Vetting Succeeded (")?;

            if fully_audited_count != 0 {
                write!(out, "{} fully audited", fully_audited_count)?;
                count_count -= 1;
                if count_count > 0 {
                    write!(out, ", ")?;
                }
            }
            if partially_audited_count != 0 {
                write!(out, "{} partially audited", partially_audited_count)?;
                count_count -= 1;
                if count_count > 0 {
                    write!(out, ", ")?;
                }
            }
            if unaudited_count != 0 {
                write!(out, "{} unaudited", unaudited_count)?;
                count_count -= 1;
                if count_count > 0 {
                    write!(out, ", ")?;
                }
            }

            writeln!(out, ")")?;
        }

        // Warn about useless unaudited entries
        if !self.useless_unaudited.is_empty() {
            writeln!(
                out,
                "  warning: some dependencies are listed in unaudited, but didn't need it:"
            )?;
            for &pkgidx in &self.useless_unaudited {
                let package = &report.graph.nodes[pkgidx];
                writeln!(out, "    {}:{}", package.name, package.version)?;
            }
        }

        Ok(())
    }
}

impl Suggest {
    pub fn print_human(
        &self,
        out: &mut dyn Out,
        report: &ResolveReport,
    ) -> Result<(), std::io::Error> {
        for (criteria, suggestions) in &self.suggestions_by_criteria {
            writeln!(out, "recommended audits for {}:", criteria)?;

            let strings = suggestions
                .iter()
                .map(|item| {
                    let package = &report.graph.nodes[item.package];
                    let cmd = if item.suggested_diff.from == ROOT_VERSION {
                        format!(
                            "cargo vet inspect {} {}",
                            package.name, item.suggested_diff.to
                        )
                    } else {
                        format!(
                            "cargo vet diff {} {} {}",
                            package.name, item.suggested_diff.from, item.suggested_diff.to
                        )
                    };
                    let parents = format!("(used by {})", item.notable_parents);
                    let diffstat = if item.suggested_diff.from == ROOT_VERSION {
                        format!("({} lines)", item.suggested_diff.diffstat.count)
                    } else {
                        format!("({})", item.suggested_diff.diffstat.raw.trim())
                    };
                    let style = if item.suggested_criteria.is_fully_unconfident() {
                        out.style().dim()
                    } else {
                        out.style()
                    };
                    (cmd, parents, diffstat, style)
                })
                .collect::<Vec<_>>();

            let mut max0 = 0;
            let mut max1 = 0;
            for (s0, s1, ..) in &strings {
                max0 = max0.max(console::measure_text_width(s0));
                max1 = max1.max(console::measure_text_width(s1));
            }

            for (s0, s1, s2, style) in strings {
                write!(
                    out,
                    "{}",
                    style
                        .clone()
                        .cyan()
                        .bold()
                        .apply_to(format_args!("    {s0:width$}", width = max0))
                )?;
                writeln!(
                    out,
                    "{}",
                    style.apply_to(format_args!("  {s1:width$}  {s2}", width = max1))
                )?;
            }

            writeln!(out)?;
        }

        writeln!(out, "estimated audit backlog: {} lines", self.total_lines)?;
        writeln!(out)?;
        writeln!(out, "Use |cargo vet certify| to record the audits.")?;

        Ok(())
    }
}

impl FailForVet {
    fn print_human(
        &self,
        out: &mut dyn Out,
        report: &ResolveReport,
        _cfg: &Config,
        suggest: Option<&Suggest>,
    ) -> Result<(), std::io::Error> {
        writeln!(out, "Vetting Failed!")?;
        writeln!(out)?;
        writeln!(out, "{} unvetted dependencies:", self.failures.len())?;
        let mut failures = self
            .failures
            .iter()
            .map(|(&failed_idx, failure)| (&report.graph.nodes[failed_idx], failure))
            .collect::<Vec<_>>();
        failures.sort_by_key(|(failed, _)| failed.version);
        failures.sort_by_key(|(failed, _)| failed.name);
        failures.sort_by_key(|(_, failure)| failure.criteria_failures.is_fully_unconfident());
        for (failed_package, failed_audit) in failures {
            let confident_criteria = report
                .criteria_mapper
                .confident_criteria_names(&failed_audit.criteria_failures)
                .collect::<Vec<_>>();
            let unconfident_criteria = report
                .criteria_mapper
                .unconfident_criteria_names(&failed_audit.criteria_failures)
                .collect::<Vec<_>>();

            let label = format!("  {}:{}", failed_package.name, failed_package.version);
            if !confident_criteria.is_empty() {
                writeln!(out, "{} missing {:?}", label, confident_criteria)?;
            }
            if !unconfident_criteria.is_empty() {
                writeln!(
                    out,
                    "{}",
                    out.style().dim().apply_to(format_args!(
                        "{} likely missing {:?}",
                        if confident_criteria.is_empty() {
                            label
                        } else {
                            format!("{:width$}", "", width = console::measure_text_width(&label))
                        },
                        unconfident_criteria
                    ))
                )?;
            }
        }

        // Suggest output generally requires hitting the network.
        if let Some(suggest) = suggest {
            writeln!(out)?;
            suggest.print_human(out, report)?;
        }

        Ok(())
    }
}

impl FailForViolationConflict {
    fn print_human(
        &self,
        out: &mut dyn Out,
        report: &ResolveReport,
        _cfg: &Config,
    ) -> Result<(), std::io::Error> {
        writeln!(out, "Violations Found!")?;

        for (&pkgidx, violations) in &self.violations {
            let package = &report.graph.nodes[pkgidx];
            writeln!(out, "  {}:{}", package.name, package.version)?;
            for violation in violations {
                match violation {
                    ViolationConflict::UnauditedConflict {
                        violation_source,
                        violation,
                        unaudited,
                    } => {
                        write!(out, "    the ")?;
                        print_unaudited_entry(out, unaudited)?;
                        write!(out, "    conflicts with ")?;
                        print_entry(out, violation_source, violation)?;
                    }
                    ViolationConflict::AuditConflict {
                        violation_source,
                        violation,
                        audit_source,
                        audit,
                    } => {
                        write!(out, "    the ")?;
                        print_entry(out, audit_source, audit)?;
                        write!(out, "    conflicts with ")?;
                        print_entry(out, violation_source, violation)?;
                    }
                }
                writeln!(out)?;
            }
        }

        fn print_unaudited_entry(
            out: &mut dyn Out,
            entry: &UnauditedDependency,
        ) -> Result<(), std::io::Error> {
            writeln!(out, "unaudited {}", entry.version)?;
            writeln!(out, "      criteria: {:?}", entry.criteria)?;
            if let Some(notes) = &entry.notes {
                writeln!(out, "      notes: {notes}")?;
            }
            Ok(())
        }

        fn print_entry(
            out: &mut dyn Out,
            source: &AuditSource,
            entry: &AuditEntry,
        ) -> Result<(), std::io::Error> {
            match source {
                AuditSource::OwnAudits => write!(out, "own ")?,
                AuditSource::Foreign(name) => write!(out, "foreign ({name}) ")?,
            }
            match &entry.kind {
                AuditKind::Full { version, .. } => {
                    writeln!(out, "audit {version}")?;
                }
                AuditKind::Delta { delta, .. } => {
                    writeln!(out, "audit {} -> {}", delta.from, delta.to)?;
                }
                AuditKind::Violation { violation } => {
                    writeln!(out, "violation against {violation}")?;
                }
            }
            writeln!(out, "      criteria: {:?}", entry.criteria)?;
            if let Some(who) = &entry.who {
                writeln!(out, "      who: {who}")?;
            }
            if let Some(notes) = &entry.notes {
                writeln!(out, "      notes: {notes}")?;
            }
            Ok(())
        }

        Ok(())
    }
}
