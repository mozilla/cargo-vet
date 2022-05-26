use core::fmt;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::io::Write;

use cargo_metadata::{DependencyKind, Metadata, Node, PackageId, Version};
use log::{error, trace, warn};

use crate::format::{self, AuditKind, Delta};
use crate::{
    AuditEntry, AuditsFile, Cache, Config, ConfigFile, CriteriaEntry, DiffRecommendation,
    ImportsFile, PackageExt, StableMap, VetError,
};

#[derive(Debug, Clone)]
pub struct Report<'a> {
    unaudited_count: u64,
    partially_audited_count: u64,
    fully_audited_count: u64,
    useless_unaudited: Vec<PackageIdx>,
    /// These packages are the roots of the graph that transitively failed.
    root_failures: Vec<PackageIdx>,
    /// These packages are to blame and need to be fixed
    leaf_failures: BTreeMap<PackageIdx, AuditFailure>,
    results: Vec<ResolveResult<'a>>,
    graph: DepGraph<'a>,
    violation_failed: Vec<PackageIdx>,
    criteria_mapper: CriteriaMapper,
}

/// Set of booleans, 64 should be Enough For Anyone (but abstracting in case not).
#[derive(Clone, Default)]
pub struct CriteriaSet(u64);
const MAX_CRITERIA: usize = u64::BITS as usize; // funnier this way

/// A processed version of config.toml's criteria definitions, for mapping
/// lists of criteria names to CriteriaSets.
#[derive(Debug, Clone)]
pub struct CriteriaMapper {
    /// All the criteria in their raw form
    list: Vec<(String, CriteriaEntry)>,
    /// name -> index in all lists
    index: HashMap<String, usize>,
    /// The transitive closure of all criteria implied by each criteria (including self)
    implied_criteria: Vec<CriteriaSet>,
}

type PackageIdx = usize;

#[derive(Debug, Clone)]
pub struct PackageNode<'a> {
    pub build_type: DependencyKind,
    pub package_id: &'a PackageId,
    pub name: &'a str,
    pub version: &'a Version,
    pub normal_deps: Vec<PackageIdx>,
    pub build_deps: Vec<PackageIdx>,
    pub dev_deps: Vec<PackageIdx>,
    pub all_deps: Vec<PackageIdx>,
    pub reverse_deps: HashSet<PackageIdx>,
    pub is_workspace_member: bool,
    pub is_third_party: bool,
    pub is_root: bool,
    pub has_non_dev_reverse_deps: bool,
}

/// The dependency graph in a form we can use more easily.
#[derive(Debug, Clone)]
pub struct DepGraph<'a> {
    pub nodes: Vec<PackageNode<'a>>,
    pub interner_by_pkgid: BTreeMap<&'a PackageId, PackageIdx>,
    pub interner_by_name_and_ver: BTreeMap<&'a str, BTreeMap<&'a Version, PackageIdx>>,
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
    /// Explicit policy checks for this node that failed.
    pub policy_failures: PolicyFailures<'a>,
    /// Whether there was an 'unaudited' entry for this exact version.
    pub directly_unaudited: bool,
    /// Whether we ever needed the not-fully_audited_criteria for our reverse-deps.
    pub needed_unaudited: bool,
}

pub type PolicyFailures<'a> = BTreeMap<PackageIdx, CriteriaSet>;

#[derive(Default, Debug, Clone)]
pub struct AuditFailure {
    pub criteria_failures: CriteriaSet,
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
        failed_deps: BTreeSet<PackageIdx>,
    },
    /// We failed to find any path, criteria not valid.
    Disconnected {
        /// Nodes we could reach from "root"
        reachable_from_root: BTreeSet<&'a Version>,
        /// Nodes we could reach from the "target"
        ///
        /// We will only ever fill in the other one, but on failure we run the algorithm
        /// in reverse and will merge that result into this value.
        reachable_from_target: BTreeSet<&'a Version>,
    },
}

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
    /// If a dependency isn't mentionned, then it defaults to `criteria`.
    dependency_criteria: HashMap<&'a str, CriteriaSet>,
    /// Whether this edge represents an 'unaudited' entry. These will initially
    /// be ignored, and then used only if we can't find a path.
    is_unaudited_entry: bool,
}

fn builtin_criteria() -> StableMap<String, CriteriaEntry> {
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
    pub fn new(criteria: &StableMap<String, CriteriaEntry>) -> CriteriaMapper {
        let builtins = builtin_criteria();
        let list = criteria
            .iter()
            .chain(builtins.iter())
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect::<Vec<_>>();
        let index: HashMap<String, usize> = list
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
                implies: &[String],
                index: &HashMap<String, usize>,
                list: &[(String, CriteriaEntry)],
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
        self.implied_criteria[self.index[&*entry.criteria]].clone()
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
    pub fn set_criteria(&self, set: &mut CriteriaSet, criteria: &str) {
        set.set_criteria(self.index[criteria])
    }

    /// An iterator over every criteria in order, with 'implies' fully applied.
    pub fn criteria_iter(&self) -> impl Iterator<Item = &CriteriaSet> {
        self.implied_criteria.iter()
    }

    pub fn len(&self) -> usize {
        self.list.len()
    }
    pub fn no_criteria(&self) -> CriteriaSet {
        CriteriaSet::none(self.len())
    }
    pub fn _all_criteria(&self) -> CriteriaSet {
        CriteriaSet::_all(self.len())
    }

    /// Yields all the names of the set criteria with implied members filtered out.
    pub fn criteria_names<'a>(
        &'a self,
        criteria: &'a CriteriaSet,
    ) -> impl Iterator<Item = &'a str> + 'a {
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

impl ResolveResult<'_> {
    fn with_no_criteria(empty: CriteriaSet) -> Self {
        Self {
            validated_criteria: empty.clone(),
            fully_audited_criteria: empty,
            search_results: vec![],
            directly_unaudited: false,
            needed_unaudited: false,
            policy_failures: PolicyFailures::new(),
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

    fn has_criteria(&mut self, criteria_idx: usize) -> bool {
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
    pub fn new(metadata: &'a Metadata) -> Self {
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
            .collect::<BTreeMap<_, _>>();
        let resolve_index_by_pkgid = resolve_list
            .iter()
            .enumerate()
            .map(|(idx, pkg)| (&pkg.id, idx))
            .collect();

        // Do a first-pass where we populate skeletons of the primary nodes
        // and setup the interners, which will only ever refer to these nodes
        let mut interner_by_pkgid = BTreeMap::<&PackageId, PackageIdx>::new();
        let mut interner_by_name_and_ver = BTreeMap::<&str, BTreeMap<&Version, PackageIdx>>::new();
        let mut nodes = vec![];
        for resolve_node in resolve_list {
            let idx = nodes.len();
            let package = &package_list[package_index_by_pkgid[&resolve_node.id]];
            nodes.push(PackageNode {
                build_type: DependencyKind::Normal,
                package_id: &resolve_node.id,
                name: &package.name,
                version: &package.version,
                is_third_party: package.is_third_party(),
                // These will get computed later
                normal_deps: vec![],
                build_deps: vec![],
                dev_deps: vec![],
                all_deps: vec![],
                reverse_deps: HashSet::new(),
                is_workspace_member: false,
                is_root: false,
                has_non_dev_reverse_deps: false,
            });
            assert!(interner_by_pkgid.insert(&resolve_node.id, idx).is_none());
            assert!(interner_by_name_and_ver
                .entry(&package.name)
                .or_default()
                .insert(&package.version, idx)
                .is_none());
        }

        // Do topological sort: just recursively visit all of a node's children, and only add it
        // to the node *after* visiting the children. In this way we have trivially already added
        // all of the dependencies of a node by the time we have

        let mut topo_index = vec![];
        {
            // FIXME: cargo uses BTreeSet, PackageIds are long strings, so maybe this makes sense?
            let mut visited = HashMap::new();
            // All of the roots can be found in the workspace_members.
            // It's fine if some aren't roots, toplogical sort works even if do all nodes.
            // FIXME: is it better to actually use resolve.root? Seems like it won't
            // work right for workspaces with multiple roots!
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
            fn visit_node<'a>(
                nodes: &mut Vec<PackageNode<'a>>,
                topo_index: &mut Vec<PackageIdx>,
                visited: &mut HashMap<PackageIdx, ()>,
                interner_by_pkgid: &BTreeMap<&'a PackageId, PackageIdx>,
                resolve_index_by_pkgid: &BTreeMap<&'a PackageId, usize>,
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
                    let build_deps = deps(resolve_node, DependencyKind::Build, interner_by_pkgid);
                    let normal_deps = deps(resolve_node, DependencyKind::Normal, interner_by_pkgid);
                    let dev_deps =
                        deps(resolve_node, DependencyKind::Development, interner_by_pkgid);

                    // Now visit all the build deps
                    for &child in &build_deps {
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
                        nodes[child].has_non_dev_reverse_deps = true;
                    }

                    // Now visit all the normal deps
                    for &child in &normal_deps {
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
                        nodes[child].has_non_dev_reverse_deps = true;
                    }

                    // Now visit the node itself
                    topo_index.push(normal_idx);

                    // Now visit all the dev deps
                    for &child in &dev_deps {
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
                        // NOTE: we don't set has_non_dev_reverse_deps here
                        // so that we don't think things aren't roots just because
                        // some tests import them.
                    }

                    // Now commit all the deps
                    let cur_node = &mut nodes[normal_idx];
                    cur_node.build_deps = build_deps;
                    cur_node.normal_deps = normal_deps;
                    cur_node.dev_deps = dev_deps;
                    cur_node.all_deps = all_deps;
                }
            }
            fn deps(
                resolve_node: &Node,
                kind: DependencyKind,
                interner_by_pkgid: &BTreeMap<&PackageId, PackageIdx>,
            ) -> Vec<PackageIdx> {
                // Note that dep_kinds has target cfg info. If we want to handle targets
                // we should gather those up with filter/fold instead of just 'any'.
                // TODO: map normal-deps that whose package has a "proc-macro" target to be build-deps
                resolve_node
                    .deps
                    .iter()
                    .filter(|dep| dep.dep_kinds.iter().any(|dep_kind| dep_kind.kind == kind))
                    .map(|dep| interner_by_pkgid[&dep.pkg])
                    .collect()
            }
        }

        // Now that we've visited the whole graph, mark the nodes that are workspace members
        for pkgid in &metadata.workspace_members {
            let node = &mut nodes[interner_by_pkgid[pkgid]];
            node.is_workspace_member = true;
            node.is_root = !node.has_non_dev_reverse_deps;
        }

        Self {
            interner_by_pkgid,
            interner_by_name_and_ver,
            nodes,
            topo_index,
        }
    }
}

// Dummy values for corner cases
pub static ROOT_VERSION: Version = Version::new(0, 0, 0);
static NO_AUDITS: Vec<AuditEntry> = Vec::new();

pub fn resolve<'a>(
    metadata: &'a Metadata,
    config: &'a ConfigFile,
    audits: &'a AuditsFile,
    imports: &'a ImportsFile,
    guess_deeper: bool,
) -> Report<'a> {
    // A large part of our algorithm is unioning and intersecting criteria, so we map all
    // the criteria into indexed boolean sets (*whispers* an integer with lots of bits).
    let graph = DepGraph::new(metadata);
    // trace!("built DepGraph: {:#?}", graph);
    trace!("built DepGraph!");

    let criteria_mapper = CriteriaMapper::new(&audits.criteria);

    // This uses the same indexing pattern as graph.resolve_index_by_pkgid
    let mut results =
        vec![ResolveResult::with_no_criteria(criteria_mapper.no_criteria()); graph.nodes.len()];
    let mut root_failures = vec![];
    let mut violation_failed = vec![];

    // Actually vet the build graph
    for &pkgidx in &graph.topo_index {
        let package = &graph.nodes[pkgidx];

        if package.is_third_party {
            resolve_third_party(
                metadata,
                config,
                audits,
                imports,
                &graph,
                &criteria_mapper,
                &mut results,
                &mut violation_failed,
                &mut root_failures,
                pkgidx,
            );
        } else {
            resolve_first_party(
                metadata,
                config,
                audits,
                imports,
                &graph,
                &criteria_mapper,
                &mut results,
                &mut violation_failed,
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
                config,
                audits,
                imports,
                &graph,
                &criteria_mapper,
                &mut results,
                &mut violation_failed,
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

    // Don't bother doing anything more if we had violations
    if !violation_failed.is_empty() {
        return Report {
            unaudited_count: 0,
            partially_audited_count: 0,
            fully_audited_count: 0,
            useless_unaudited: Default::default(),
            root_failures: Default::default(),
            leaf_failures: Default::default(),
            violation_failed,
            results,
            graph,
            criteria_mapper,
        };
    }

    // Gather statistics
    let mut leaf_failures = BTreeMap::<PackageIdx, AuditFailure>::new();
    visit_failures(
        &graph,
        &results,
        &root_failures,
        guess_deeper,
        |failure, _depth, own_failure| {
            if let Some(criteria_failures) = own_failure {
                leaf_failures
                    .entry(failure)
                    .or_default()
                    .criteria_failures
                    .unioned_with(criteria_failures);
            }
            Ok::<(), ()>(())
        },
    )
    .unwrap();

    let mut unaudited_count = 0;
    let mut fully_audited_count = 0;
    let mut partially_audited_count = 0;
    let mut useless_unaudited = vec![];
    for &pkgidx in &graph.topo_index {
        let node = &graph.nodes[pkgidx];
        let result = &results[pkgidx];

        if !result.needed_unaudited || !node.is_third_party {
            fully_audited_count += 1;
        } else if result.directly_unaudited {
            unaudited_count += 1;
        } else {
            partially_audited_count += 1;
        }

        if result.directly_unaudited && !result.needed_unaudited {
            useless_unaudited.push(pkgidx);
        }
    }

    Report {
        unaudited_count,
        partially_audited_count,
        fully_audited_count,
        useless_unaudited,
        root_failures,
        leaf_failures,
        violation_failed,
        results,
        graph,
        criteria_mapper,
    }
}

#[allow(clippy::too_many_arguments, clippy::ptr_arg)]
fn resolve_third_party<'a>(
    _metadata: &'a Metadata,
    config: &'a ConfigFile,
    audits: &'a AuditsFile,
    imports: &'a ImportsFile,
    graph: &DepGraph<'a>,
    criteria_mapper: &CriteriaMapper,
    results: &mut [ResolveResult<'a>],
    violation_failed: &mut Vec<PackageIdx>,
    _root_failures: &mut Vec<PackageIdx>,
    pkgidx: PackageIdx,
) {
    let package = &graph.nodes[pkgidx];
    assert!(
        package.dev_deps.is_empty(),
        "third-party packages shouldn't have dev-deps!"
    );
    let unaudited = config.unaudited.get(package.name);

    // Just merge all the entries from the foreign audit files and our audit file.
    let foreign_audits = imports
        .audits
        .values()
        .flat_map(|audit_file| audit_file.audits.get(package.name).unwrap_or(&NO_AUDITS));
    let own_audits = audits.audits.get(package.name).unwrap_or(&NO_AUDITS);

    // Deltas are flipped so that we have a map of 'to: [froms]'. This lets
    // us start at the current version and look up all the deltas that *end* at that
    // version. By repeating this over and over, we can loslowly walk back in time until
    // we run out of deltas or reach full audit or an unaudited entry.
    let mut forward_nodes = BTreeMap::<&Version, Vec<DeltaEdge>>::new();
    let mut backward_nodes = BTreeMap::<&Version, Vec<DeltaEdge>>::new();
    let mut violations = Vec::new();

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
                violations.push(entry);
                continue;
            }
        };

        let criteria = criteria_mapper.criteria_from_entry(entry);
        // Convert all the custom criteria to CriteriaSets
        let dependency_criteria: HashMap<_, _> = dependency_criteria
            .iter()
            .map(|(pkg_name, criteria)| (&**pkg_name, criteria_mapper.criteria_from_list(criteria)))
            .collect();

        forward_nodes.entry(from_ver).or_default().push(DeltaEdge {
            version: to_ver,
            criteria: criteria.clone(),
            dependency_criteria: dependency_criteria.clone(),
            is_unaudited_entry: false,
        });
        backward_nodes.entry(to_ver).or_default().push(DeltaEdge {
            version: from_ver,
            criteria,
            dependency_criteria,
            is_unaudited_entry: false,
        });
    }

    // Try to map foreign audits into our worldview
    for (foreign_name, foreign_audits) in &imports.audits {
        // Prep CriteriaSet machinery for comparing requirements
        let foreign_criteria_mapper = CriteriaMapper::new(&foreign_audits.criteria);
        let criteria_map = &config
            .imports
            .get(foreign_name)
            .expect("Foreign Import isn't in config file (imports.lock outdated?)")
            .criteria_map;
        let criteria_map: Vec<(&str, CriteriaSet)> = criteria_map
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
                    violations.push(entry);
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

            forward_nodes.entry(from_ver).or_default().push(DeltaEdge {
                version: to_ver,
                criteria: local_criteria.clone(),
                dependency_criteria: Default::default(),
                is_unaudited_entry: false,
            });
            backward_nodes.entry(to_ver).or_default().push(DeltaEdge {
                version: from_ver,
                criteria: local_criteria,
                dependency_criteria: Default::default(),
                is_unaudited_entry: false,
            });
        }
    }

    // Reject forbidden packages (violations)
    //
    // FIXME: should the "local" audit have a mechanism to override foreign forbids?
    for violation_entry in &violations {
        let violation_range = if let AuditKind::Violation { violation } = &violation_entry.kind {
            violation
        } else {
            unreachable!("violation_entry wasn't a Violation?");
        };

        // Hard error out if anything in our audits overlaps with a forbid entry!
        // (This clone isn't a big deal, it's just iterator adaptors for by-ref iteration)
        for entry in own_audits.iter().chain(foreign_audits.clone()) {
            match &entry.kind {
                AuditKind::Full { version, .. } => {
                    if violation_range.matches(version) {
                        error!(
                            "Integrity Failure! Audit and Violation Overlap for {}:",
                            package.name
                        );
                        error!("  audit: {:#?}", entry);
                        error!("  violation: {:#?}", violation_entry);
                        panic!("Integrity Failure! TODO: factor this out better");
                    }
                }
                AuditKind::Delta { delta, .. } => {
                    if violation_range.matches(&delta.from) || violation_range.matches(&delta.to) {
                        error!(
                            "Integrity Failure! Delta Audit and Violation Overlap for {}:",
                            package.name
                        );
                        error!("  audit: {:#?}", entry);
                        error!("  violation: {:#?}", violation_entry);
                        panic!("Integrity Failure! TODO: factor this out better");
                    }
                }
                AuditKind::Violation { .. } => {
                    // don't care
                }
            }
        }
        // Having current versions overlap with a violations is less horrifyingly bad,
        // so just gather them up as part of the normal report.
        if violation_range.matches(package.version) {
            violation_failed.push(pkgidx);
            return;
        }
    }

    let mut directly_unaudited = false;
    // Identify if this version is directly marked as allowed in 'unaudited'.
    // This implies that all dependency_criteria checks against it will succeed
    // as if its validated_criteria was all_criteria.
    //
    // Also register all the unaudited entries as "roots" for search.
    if let Some(alloweds) = unaudited {
        for allowed in alloweds {
            if &allowed.version == package.version {
                directly_unaudited = true;
            }
            let from_ver = &ROOT_VERSION;
            let to_ver = &allowed.version;
            let criteria = criteria_mapper.criteria_from_list([&allowed.criteria]);

            // For simplicity, turn 'unaudited' entries into deltas from 0.0.0
            forward_nodes.entry(from_ver).or_default().push(DeltaEdge {
                version: to_ver,
                criteria: criteria.clone(),
                dependency_criteria: Default::default(),
                is_unaudited_entry: true,
            });
            backward_nodes.entry(to_ver).or_default().push(DeltaEdge {
                version: from_ver,
                criteria,
                dependency_criteria: Default::default(),
                is_unaudited_entry: true,
            });
        }
    }

    let mut validated_criteria = criteria_mapper.no_criteria();
    let mut fully_audited_criteria = criteria_mapper.no_criteria();
    let mut search_results = vec![];
    for criteria in criteria_mapper.criteria_iter() {
        let result = search_for_path(
            criteria,
            &ROOT_VERSION,
            package.version,
            &forward_nodes,
            graph,
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
                    &backward_nodes,
                    graph,
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
        policy_failures: PolicyFailures::new(),
    };
}

#[allow(clippy::too_many_arguments, clippy::ptr_arg)]
fn resolve_first_party<'a>(
    _metadata: &'a Metadata,
    config: &'a ConfigFile,
    _audits: &'a AuditsFile,
    _imports: &'a ImportsFile,
    graph: &DepGraph<'a>,
    criteria_mapper: &CriteriaMapper,
    results: &mut [ResolveResult<'a>],
    _violation_failed: &mut Vec<PackageIdx>,
    root_failures: &mut Vec<PackageIdx>,
    pkgidx: PackageIdx,
) {
    // Check the build-deps and normal-deps of this package. dev-deps are checking in `resolve_dep`
    // In this pass we properly use package.is_root, but in the next pass all nodes are "roots"
    let package = &graph.nodes[pkgidx];
    let is_root = package.is_root;

    // Root nodes adopt this policy if they don't have an explicit one
    let default_root_policy = criteria_mapper.criteria_from_list([format::DEFAULT_POLICY_CRITERIA]);
    let _default_root_build_and_dev_policy =
        criteria_mapper.criteria_from_list([format::DEFAULT_POLICY_BUILD_AND_DEV_CRITERIA]);

    let mut policy_failures = PolicyFailures::new();

    // Any dependencies that have explicit policies are checked first
    let mut passed_dependencies = BTreeSet::new();
    if let Some(policy) = config.policy.get(package.name) {
        for &depidx in package.normal_deps.iter().chain(&package.build_deps) {
            let dep_package = &graph.nodes[depidx];
            let dep_policy = policy
                .dependency_criteria
                .get(dep_package.name)
                .map(|p| criteria_mapper.criteria_from_list(p))
                .unwrap_or_else(|| criteria_mapper.no_criteria());

            for criteria_idx in dep_policy.indices() {
                if results[depidx].has_criteria(criteria_idx) {
                    passed_dependencies.insert(depidx);
                } else {
                    policy_failures
                        .entry(depidx)
                        .or_insert_with(|| criteria_mapper.no_criteria())
                        .set_criteria(criteria_idx);
                }
            }
        }
    }

    if policy_failures.is_empty() {
        let mut validated_criteria = criteria_mapper.no_criteria();
        let mut search_results = vec![];
        for criteria in criteria_mapper.criteria_iter() {
            let mut failed_deps = BTreeSet::new();
            // TODO: this isn't quite right. We want to analyze build-deps distinctly but we're
            // just merging them in with normal deps... I need to think about this more.
            // The semantic of policies is unclear for build-deps, I think...
            for &depidx in package.normal_deps.iter().chain(&package.build_deps) {
                if passed_dependencies.contains(&depidx) {
                    // This dep is already fine, ignore it (implicitly all_criteria now)
                    continue;
                }
                if !results[depidx].contains(criteria) {
                    failed_deps.insert(depidx);
                }
            }

            if failed_deps.is_empty() {
                search_results.push(SearchResult::Connected {
                    fully_audited: true,
                });
                validated_criteria.unioned_with(criteria);
            } else {
                search_results.push(SearchResult::PossiblyConnected { failed_deps })
            }
        }

        // Now check that we pass our own policy
        let own_policy = if let Some(policy) = config.policy.get(package.name) {
            criteria_mapper.criteria_from_list(&policy.criteria)
        } else if is_root {
            default_root_policy
        } else {
            criteria_mapper.no_criteria()
        };

        for criteria_idx in own_policy.indices() {
            if let SearchResult::PossiblyConnected { failed_deps } = &search_results[criteria_idx] {
                for &dep in failed_deps {
                    policy_failures
                        .entry(dep)
                        .or_insert_with(|| criteria_mapper.no_criteria())
                        .set_criteria(criteria_idx);
                }
            }
        }

        if policy_failures.is_empty() {
            results[pkgidx].search_results = search_results;
            results[pkgidx].validated_criteria = validated_criteria;
        }
    }

    if !policy_failures.is_empty() && is_root {
        root_failures.push(pkgidx);
    }
    results[pkgidx].policy_failures.append(&mut policy_failures);
}

#[allow(clippy::too_many_arguments, clippy::ptr_arg)]
fn resolve_dev<'a>(
    _metadata: &'a Metadata,
    config: &'a ConfigFile,
    _audits: &'a AuditsFile,
    _imports: &'a ImportsFile,
    graph: &DepGraph<'a>,
    criteria_mapper: &CriteriaMapper,
    results: &mut [ResolveResult<'a>],
    _violation_failed: &mut Vec<PackageIdx>,
    root_failures: &mut Vec<PackageIdx>,
    pkgidx: PackageIdx,
) {
    // This is a copy of resolve_first_party but tweaked to handle dev-deps specifically.
    // In this version we are logically processing a "dev" (test/bench) node which depends
    // on the normal build. It is always a root, and so we don't need to record any details
    // if this passes. The only thing that needs to be recorded are explicitly policy failures
    // which can be folded in with the rest of the normal analysis.
    let package = &graph.nodes[pkgidx];
    let is_root = true;

    // Root nodes adopt this policy if they don't have an explicit one
    let _default_root_policy =
        criteria_mapper.criteria_from_list([format::DEFAULT_POLICY_CRITERIA]);
    let default_root_build_and_dev_policy =
        criteria_mapper.criteria_from_list([format::DEFAULT_POLICY_BUILD_AND_DEV_CRITERIA]);

    let mut policy_failures = PolicyFailures::new();

    // Any dependencies that have explicit policies are checked first
    let mut passed_dependencies = BTreeSet::new();
    if let Some(policy) = config.policy.get(package.name) {
        for &depidx in &package.dev_deps {
            let dep_package = &graph.nodes[depidx];
            let dep_policy = policy
                .dependency_criteria
                .get(dep_package.name)
                .map(|p| criteria_mapper.criteria_from_list(p))
                .unwrap_or_else(|| criteria_mapper.no_criteria());

            for criteria_idx in dep_policy.indices() {
                if results[depidx].has_criteria(criteria_idx) {
                    passed_dependencies.insert(depidx);
                } else {
                    policy_failures
                        .entry(depidx)
                        .or_insert_with(|| criteria_mapper.no_criteria())
                        .set_criteria(criteria_idx);
                }
            }
        }
    }

    if policy_failures.is_empty() {
        let mut validated_criteria = criteria_mapper.no_criteria();
        let mut search_results = vec![];
        for criteria in criteria_mapper.criteria_iter() {
            let mut failed_deps = BTreeSet::new();
            for &depidx in &package.dev_deps {
                if passed_dependencies.contains(&depidx) {
                    // This dep is already fine, ignore it (implicitly all_criteria now)
                    continue;
                }
                if !results[depidx].contains(criteria) {
                    failed_deps.insert(depidx);
                }
            }

            if failed_deps.is_empty() {
                search_results.push(SearchResult::Connected {
                    fully_audited: true,
                });
                validated_criteria.unioned_with(criteria);
            } else {
                search_results.push(SearchResult::PossiblyConnected { failed_deps })
            }
        }

        // Now check that we pass our own policy
        let own_policy = if let Some(policy) = config.policy.get(package.name) {
            criteria_mapper.criteria_from_list(&policy.build_and_dev_criteria)
        } else if is_root {
            default_root_build_and_dev_policy
        } else {
            unreachable!("dev nodes are always roots!")
        };

        // TODO: arguably we should also include our normal self's results because we
        // depend on it..?
        for criteria_idx in own_policy.indices() {
            if let SearchResult::PossiblyConnected { failed_deps } = &search_results[criteria_idx] {
                for &dep in failed_deps {
                    policy_failures
                        .entry(dep)
                        .or_insert_with(|| criteria_mapper.no_criteria())
                        .set_criteria(criteria_idx);
                }
            }
        }

        // Don't commit successes, this is the fake "dev" node which doesn't effect others,
        // so if there's no failures then we don't care about this node at all!
        /*
        if policy_failures.is_empty() {
            results[pkgidx].search_results = search_results;
            results[pkgidx].validated_criteria = validated_criteria;
        }
        */
    }

    if !policy_failures.is_empty() && is_root {
        root_failures.push(pkgidx);
    }
    results[pkgidx].policy_failures.append(&mut policy_failures);
}

fn search_for_path<'a>(
    cur_criteria: &CriteriaSet,
    from_version: &'a Version,
    to_version: &'a Version,
    version_nodes: &BTreeMap<&'a Version, Vec<DeltaEdge<'a>>>,
    dep_graph: &DepGraph<'a>,
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
    let mut failed_deps = BTreeSet::new();

    // Search State
    let mut search_stack = vec![from_version];
    let mut visited = BTreeSet::new();
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
            if let Some(edges) = version_nodes.get(cur_version) {
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
                    for &dependency in &package.all_deps {
                        let dep_package = &dep_graph.nodes[dependency];
                        let dep_vet_result = &mut results[dependency];

                        // If no custom criteria is specified, then require our dependency to match
                        // the same criteria that this delta claims to provide.
                        // e.g. a 'secure' audit requires all dependencies to be 'secure' by default.
                        let dep_req = edge
                            .dependency_criteria
                            .get(&*dep_package.name)
                            .unwrap_or(&edge.criteria);

                        if !dep_vet_result.contains(dep_req) {
                            failed_deps.insert(dependency);
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

impl<'a> Report<'a> {
    pub fn has_errors(&self) -> bool {
        !self.root_failures.is_empty() || !self.violation_failed.is_empty()
    }

    pub fn _has_warnings(&self) -> bool {
        !self.useless_unaudited.is_empty()
    }

    pub fn print_report(&self, out: &mut dyn Write, cfg: &Config) -> Result<(), VetError> {
        if self.has_errors() {
            self.print_failure(out)?;
            self.print_suggest(out, cfg)?;
        } else {
            self.print_success(out)?;
        }
        Ok(())
    }

    fn print_success(&self, out: &mut dyn Write) -> Result<(), VetError> {
        writeln!(
            out,
            "Vetting Succeeded ({} fully audited, {} partially audited, {} unaudited)",
            self.fully_audited_count, self.partially_audited_count, self.unaudited_count,
        )?;

        // Warn about useless unaudited entries
        if !self.useless_unaudited.is_empty() {
            writeln!(
                out,
                "  warning: some dependencies are listed in unaudited, but didn't need it:"
            )?;
            for &pkgidx in &self.useless_unaudited {
                let package = &self.graph.nodes[pkgidx];
                writeln!(out, "    {}:{}", package.name, package.version)?;
            }
        }

        Ok(())
    }

    fn print_failure(&self, out: &mut dyn Write) -> Result<(), VetError> {
        writeln!(out, "Vetting Failed!")?;
        writeln!(out)?;
        if !self.root_failures.is_empty() {
            writeln!(out, "{} unvetted dependencies:", self.leaf_failures.len())?;
            let mut failures = self
                .leaf_failures
                .iter()
                .map(|(&failed_idx, failure)| (&self.graph.nodes[failed_idx], failure))
                .collect::<Vec<_>>();
            failures.sort_by_key(|(failed, _)| failed.version);
            failures.sort_by_key(|(failed, _)| failed.name);
            for (failed_package, failed_audit) in failures {
                let criteria = self
                    .criteria_mapper
                    .criteria_names(&failed_audit.criteria_failures)
                    .collect::<Vec<_>>();
                writeln!(
                    out,
                    "  {}:{} missing {:?}",
                    failed_package.name, failed_package.version, &criteria
                )?;
            }

            writeln!(out)?;
        }
        if !self.violation_failed.is_empty() {
            writeln!(
                out,
                "{} forbidden dependencies:",
                self.violation_failed.len()
            )?;
            for &pkgidx in &self.violation_failed {
                let package = &self.graph.nodes[pkgidx];
                writeln!(out, "  {}:{}", package.name, package.version)?;
            }
            writeln!(out)?;
        }

        Ok(())
    }

    pub fn print_suggest(&self, out: &mut dyn Write, cfg: &Config) -> Result<(), VetError> {
        if self.leaf_failures.is_empty() {
            writeln!(out, "nothing to recommend")?;
            return Ok(());
        }

        struct SuggestItem<'a> {
            package: &'a PackageNode<'a>,
            rec: DiffRecommendation,
            criteria: String,
            parents: String,
        }

        let mut cache = Cache::acquire(cfg)?;
        let mut suggestions = vec![];
        let mut total_lines: u64 = 0;
        for (&failure_idx, audit_failure) in &self.leaf_failures {
            let package = &self.graph.nodes[failure_idx];
            let result = &self.results[failure_idx];

            // Collect up the details of how we failed
            let mut from_root = None::<BTreeSet<&Version>>;
            let mut from_target = None::<BTreeSet<&Version>>;
            for criteria_idx in audit_failure.criteria_failures.indices() {
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
            let mut candidates = BTreeSet::new();
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

            let criteria = self
                .criteria_mapper
                .criteria_names(&audit_failure.criteria_failures)
                .collect::<Vec<_>>()
                .join(", ");

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
            let parents = reverse_deps.join(", ");

            match cache.fetch_and_diffstat_all(package.name, &candidates) {
                Ok(rec) => {
                    total_lines += rec.diffstat.count;
                    suggestions.push(SuggestItem {
                        package,
                        rec,
                        criteria,
                        parents,
                    });
                }
                Err(err) => {
                    writeln!(
                        out,
                        "    error diffing {}:{} {}",
                        package.name, package.version, err
                    )?;
                }
            }
        }

        suggestions.sort_by_key(|item| item.package.version);
        suggestions.sort_by_key(|item| item.package.name);
        suggestions.sort_by_key(|item| item.rec.diffstat.count);
        let mut by_criteria = BTreeMap::new();
        for s in suggestions.into_iter() {
            by_criteria
                .entry(s.criteria.clone())
                .or_insert_with(Vec::new)
                .push(s);
        }

        for (criteria, suggestions) in by_criteria.into_iter() {
            writeln!(out, "recommended audits for {}:", criteria)?;

            let strings = suggestions
                .into_iter()
                .map(|item| {
                    (
                        if item.rec.from == ROOT_VERSION {
                            format!("cargo vet inspect {} {}", item.package.name, item.rec.to)
                        } else {
                            format!(
                                "cargo vet diff {} {} {}",
                                item.package.name, item.rec.from, item.rec.to
                            )
                        },
                        format!("(used by {})", item.parents),
                        if item.rec.from == ROOT_VERSION {
                            format!("({} lines)", item.rec.diffstat.count)
                        } else {
                            format!("({})", item.rec.diffstat.raw.trim())
                        },
                    )
                })
                .collect::<Vec<_>>();

            let max0 = strings.iter().max_by_key(|s| s.0.len()).unwrap().0.len();
            let max1 = strings.iter().max_by_key(|s| s.1.len()).unwrap().1.len();

            // Do not align the last one
            // let max3 = strings.iter().max_by_key(|s| s.3.len()).unwrap().3.len();

            for (s0, s1, s2) in strings {
                writeln!(
                    out,
                    "    {s0:width0$}  {s1:width1$}  {s2}",
                    width0 = max0,
                    width1 = max1,
                )?;
            }

            writeln!(out)?;
        }

        writeln!(out, "estimated audit backlog: {total_lines} lines")?;
        writeln!(out)?;
        writeln!(out, "Use |cargo vet certify| to record the audits.")?;

        Ok(())
    }
}

fn visit_failures<'a, T>(
    graph: &DepGraph<'a>,
    results: &[ResolveResult<'a>],
    failures: &[PackageIdx],
    guess_deeper: bool,
    mut callback: impl FnMut(PackageIdx, usize, Option<&CriteriaSet>) -> Result<(), T>,
) -> Result<(), T> {
    trace!("blame: traversing blame tree");

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
    let mut search_stack = failures.iter().map(|f| (*f, 0, None)).collect::<Vec<_>>();
    let mut visited = HashMap::<PackageIdx, CriteriaSet>::new();
    let no_criteria = CriteriaSet::default();

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
            "blame: {:width$}visiting {}:{}",
            "",
            package.name,
            package.version,
            width = depth
        );

        if !result.policy_failures.is_empty() {
            // We're not to blame, it's our children who failed our policies!
            callback(failure_idx, depth, None)?;
            for (&failed_dep, failed_criteria) in &result.policy_failures {
                search_stack.push((failed_dep, depth + 1, Some(failed_criteria.clone())));
            }
        } else if let Some(failed_criteria) = cur_criteria {
            let mut own_fault = CriteriaSet::default();
            let mut dep_faults = BTreeMap::<PackageIdx, CriteriaSet>::new();
            let mut deeper_faults = BTreeMap::<PackageIdx, CriteriaSet>::new();

            // Collect up details of how we failed the criteria
            for criteria_idx in failed_criteria.indices() {
                match &result.search_results[criteria_idx] {
                    SearchResult::Connected { .. } => {
                        // Do nothing, this package is good
                    }
                    SearchResult::PossiblyConnected { failed_deps } => {
                        // We're not to blame, it's our children who failed!
                        for &failed_dep in failed_deps {
                            dep_faults
                                .entry(failed_dep)
                                .or_default()
                                .set_criteria(criteria_idx);
                        }
                    }
                    SearchResult::Disconnected { .. } => {
                        // Oh dang ok we *are* to blame, our bad
                        own_fault.set_criteria(criteria_idx);

                        if guess_deeper {
                            // Try to Guess Deeper by blaming our children for all |self| failures
                            // by assuming we would need them to conform to our own criteria too.
                            for &dep_idx in &package.all_deps {
                                let dep_result = &results[dep_idx];
                                if !dep_result.validated_criteria.has_criteria(criteria_idx) {
                                    deeper_faults
                                        .entry(dep_idx)
                                        .or_default()
                                        .set_criteria(criteria_idx);
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
            for (failed_dep, failed_criteria) in deeper_faults {
                if dep_faults.contains_key(&failed_dep) {
                    // We already visited them more precisely
                    continue;
                }
                search_stack.push((failed_dep, depth + 1, Some(failed_criteria.clone())));
            }
            for (failed_dep, failed_criteria) in dep_faults {
                search_stack.push((failed_dep, depth + 1, Some(failed_criteria.clone())));
            }
        } else {
            unreachable!("I don't think this should happen..?");
        }
    }
    Ok(())
}
