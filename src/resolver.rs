use core::fmt;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::Write;

use cargo_metadata::{Metadata, Node, Package, PackageId, Version};
use log::{error, trace, warn};

use crate::{
    AuditEntry, AuditsFile, ConfigFile, CriteriaEntry, ImportsFile, PackageExt, StableMap, VetError,
};

#[derive(Debug, Clone)]
pub struct Report<'a> {
    unaudited_count: u64,
    partially_audited_count: u64,
    fully_audited_count: u64,
    failed_count: u64,
    useless_unaudited: Vec<&'a Package>,
    root_failures: Vec<&'a PackageId>,
    results: Vec<ResolveResult<'a>>,
    graph: DepGraph<'a>,
    violation_failed: Vec<&'a Package>,
}

/// Set of booleans, 64 should be Enough For Anyone (but abstracting in case not).
#[derive(Clone)]
pub struct CriteriaSet(u64);
const MAX_CRITERIA: usize = u64::BITS as usize; // funnier this way

/// A processed version of config.toml's criteria definitions, for mapping
/// lists of criteria names to CriteriaSets.
#[derive(Debug, Clone)]
pub struct CriteriaMapper<'a> {
    /// All the criteria in their raw form
    list: Vec<(&'a str, &'a CriteriaEntry)>,
    /// name -> index in all lists
    index: HashMap<&'a str, usize>,
    /// The default criteria for anything that says nothing (TODO: remove this?)
    default_criteria: CriteriaSet,
    /// The transitive closure of all criteria implied by each criteria (including self)
    implied_criteria: Vec<CriteriaSet>,
}

/// The dependency graph in a form we can use more easily.
#[derive(Debug, Clone)]
pub struct DepGraph<'a> {
    pub package_list: &'a [Package],
    pub resolve_list: &'a [cargo_metadata::Node],
    pub package_index_by_pkgid: BTreeMap<&'a PackageId, usize>,
    pub resolve_index_by_pkgid: BTreeMap<&'a PackageId, usize>,
    pub pkgid_by_name_and_ver: HashMap<&'a str, HashMap<&'a Version, &'a PackageId>>,
    /// Toplogical sorting of the dependencies (linear iteration will do things in dependency order)
    pub topo_index: Vec<&'a PackageId>,
}

/// Results and notes from running vet on a particular package.
#[derive(Debug, Clone)]
pub struct ResolveResult<'a> {
    /// The set of criteria we validated for this package.
    validated_criteria: CriteriaSet,
    /// The set of criteria we validated for this package without 'unaudited' entries.
    fully_audited_criteria: CriteriaSet,
    /// Individual search results for each criteria.
    search_results: Vec<SearchResult<'a>>,
    /// Whether there was an 'unaudited' entry for this exact version.
    directly_unaudited: bool,
    /// Whether we ever needed the not-fully_audited_criteria for our reverse-deps.
    needed_unaudited: bool,
    failed: bool,
}

impl<'a> CriteriaMapper<'a> {
    fn new(criteria: &'a StableMap<String, CriteriaEntry>) -> CriteriaMapper<'a> {
        let list = criteria.iter().map(|(k, v)| (&**k, v)).collect::<Vec<_>>();
        let index = criteria
            .keys()
            .enumerate()
            .map(|(idx, v)| (&**v, idx))
            .collect();

        let mut default_criteria = CriteriaSet::none(list.len());
        let mut implied_criteria = Vec::with_capacity(list.len());
        for (idx, (_name, entry)) in list.iter().enumerate() {
            // Precompute implied criteria (doing it later is genuinely a typesystem headache)
            let mut implied = CriteriaSet::none(list.len());
            implied.set_criteria(idx);
            recursive_implies(&mut implied, &entry.implies, &index, &list);

            if entry.default {
                default_criteria.unioned_with(&implied);
            }

            implied_criteria.push(implied);

            fn recursive_implies(
                result: &mut CriteriaSet,
                implies: &[String],
                index: &HashMap<&str, usize>,
                list: &[(&str, &CriteriaEntry)],
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
            default_criteria,
            implied_criteria,
        }
    }
    fn criteria_from_entry(&self, entry: &AuditEntry) -> CriteriaSet {
        if let Some(criteria_list) = entry.criteria.as_ref() {
            self.criteria_from_list(criteria_list.iter().map(|s| &**s))
        } else {
            self.default_criteria().clone()
        }
    }
    fn criteria_from_list<'b>(&self, list: impl IntoIterator<Item = &'b str>) -> CriteriaSet {
        let mut result = self.no_criteria();
        for criteria in list {
            let idx = self.index[criteria];
            result.unioned_with(&self.implied_criteria[idx]);
        }
        result
    }
    fn set_criteria(&self, set: &mut CriteriaSet, criteria: &str) {
        set.set_criteria(self.index[criteria])
    }

    /// An iterator over every criteria in order, with 'implies' fully applied.
    fn criteria_iter(&self) -> impl Iterator<Item = &CriteriaSet> {
        self.implied_criteria.iter()
    }

    fn len(&self) -> usize {
        self.list.len()
    }
    fn default_criteria(&self) -> &CriteriaSet {
        &self.default_criteria
    }
    fn no_criteria(&self) -> CriteriaSet {
        CriteriaSet::none(self.len())
    }
    fn all_criteria(&self) -> CriteriaSet {
        CriteriaSet::all(self.len())
    }
}

impl CriteriaSet {
    fn none(count: usize) -> Self {
        assert!(
            count <= MAX_CRITERIA,
            "{MAX_CRITERIA} was not Enough For Everyone ({count} criteria)"
        );
        CriteriaSet(0)
    }
    fn all(count: usize) -> Self {
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
    fn set_criteria(&mut self, idx: usize) {
        self.0 |= 1 << idx;
    }
    fn _has_criteria(&self, idx: usize) -> bool {
        (self.0 & (1 << idx)) != 0
    }
    fn _intersected_with(&mut self, other: &CriteriaSet) {
        self.0 &= other.0;
    }
    fn unioned_with(&mut self, other: &CriteriaSet) {
        self.0 |= other.0;
    }
    fn contains(&self, other: &CriteriaSet) -> bool {
        (self.0 & other.0) == other.0
    }
    fn is_empty(&self) -> bool {
        self.0 == 0
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
            failed: false,
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
}

impl<'a> DepGraph<'a> {
    pub fn new(metadata: &'a Metadata) -> Self {
        // FIXME: study the nature of the 'resolve' field more carefully.
        // In particular how resolver version 2 describes normal vs build/dev-deps.
        // Worst case we might need to invoke 'cargo metadata' multiple times to get
        // the proper description of both situations.

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
            .collect();
        let resolve_index_by_pkgid = resolve_list
            .iter()
            .enumerate()
            .map(|(idx, pkg)| (&pkg.id, idx))
            .collect();
        let mut pkgid_by_name_and_ver = HashMap::<&str, HashMap<&Version, &PackageId>>::new();
        for pkg in package_list {
            pkgid_by_name_and_ver
                .entry(&*pkg.name)
                .or_default()
                .insert(&pkg.version, &pkg.id);
        }

        // Do topological sort: just recursively visit all of a node's children, and only add it
        // to the node *after* visiting the children. In this way we have trivially already added
        // all of the dependencies of a node by the time we have
        let mut topo_index = Vec::with_capacity(package_list.len());
        {
            // FIXME: cargo uses BTreeSet, PackageIds are long strings, so maybe this makes sense?
            let mut visited = BTreeMap::new();
            // All of the roots can be found in the workspace_members.
            // It's fine if some aren't roots, toplogical sort works even if do all nodes.
            // FIXME: is it better to actually use resolve.root? Seems like it won't
            // work right for workspaces with multiple roots!
            for pkgid in &metadata.workspace_members {
                visit_node(
                    &mut topo_index,
                    &mut visited,
                    &resolve_index_by_pkgid,
                    resolve_list,
                    pkgid,
                );
            }
            fn visit_node<'a>(
                topo_index: &mut Vec<&'a PackageId>,
                visited: &mut BTreeMap<&'a PackageId, ()>,
                resolve_index_by_pkgid: &BTreeMap<&'a PackageId, usize>,
                resolve_list: &'a [cargo_metadata::Node],
                pkgid: &'a PackageId,
            ) {
                // Don't revisit a node (fine for correctness, wasteful for perf)
                let query = visited.entry(pkgid);
                if matches!(query, std::collections::btree_map::Entry::Vacant(..)) {
                    query.or_insert(());
                    let node = &resolve_list[resolve_index_by_pkgid[pkgid]];
                    for child in &node.dependencies {
                        visit_node(
                            topo_index,
                            visited,
                            resolve_index_by_pkgid,
                            resolve_list,
                            child,
                        );
                    }
                    topo_index.push(pkgid);
                }
            }
        }

        Self {
            package_list,
            resolve_list,
            package_index_by_pkgid,
            resolve_index_by_pkgid,
            pkgid_by_name_and_ver,
            topo_index,
        }
    }
}

/// The possible results of search for an audit chain for a Criteria
#[derive(Debug, Clone)]
enum SearchResult<'a> {
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
        failed_deps: BTreeSet<&'a PackageId>,
    },
    /// We failed to find any path, criteria not valid.
    Disconnected {
        /// Nodes we could reach from "root"
        reachable_from_root: BTreeSet<&'a Version>,
        /// Nodes we could reach from the "target"
        ///
        /// We will only ever fill in the other one, but on failure we run the algorithm
        /// in reverse and will merge that result into this value.
        _reachable_from_target: BTreeSet<&'a Version>,
    },
}

/// A directed edge in the graph of audits. This may be forward or backwards,
/// depending on if we're searching from "roots" (forward) or the target (backward).
/// The source isn't included because that's implicit in the Node.
#[derive(Debug, Clone)]
struct DeltaEdge<'a> {
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

// Dummy values for corner cases
static ROOT_VERSION: Version = Version::new(0, 0, 0);
static NO_AUDITS: Vec<AuditEntry> = Vec::new();

pub fn resolve<'a>(
    metadata: &'a Metadata,
    config: &'a ConfigFile,
    audits: &'a AuditsFile,
    imports: &'a ImportsFile,
) -> Report<'a> {
    let mut violation_failed = vec![];

    // A large part of our algorithm is unioning and intersecting criteria, so we map all
    // the criteria into indexed boolean sets (*whispers* an integer with lots of bits).
    let graph = DepGraph::new(metadata);
    trace!("graph: {:#?}", graph);

    let criteria_mapper = CriteriaMapper::new(&audits.criteria);
    let all_criteria = criteria_mapper.all_criteria();
    let no_criteria = criteria_mapper.no_criteria();

    // Compute the "policy" criteria
    let policy = config
        .policy
        .criteria
        .as_ref()
        .map(|c| criteria_mapper.criteria_from_list(c.iter().map(|s| &**s)))
        .unwrap_or_else(|| criteria_mapper.default_criteria().clone());
    let _build_and_dev_policy = config
        .policy
        .build_and_dev_criteria
        .as_ref()
        .map(|c| criteria_mapper.criteria_from_list(c.iter().map(|s| &**s)))
        .unwrap_or_else(|| policy.clone());
    let dep_policies: HashMap<_, _> = config
        .policy
        .dependency_criteria
        .as_ref()
        .map(|d| d.iter())
        .into_iter()
        .flatten()
        .map(|(pkg_name, criteria)| {
            (
                &**pkg_name,
                criteria_mapper.criteria_from_list(criteria.iter().map(|s| &**s)),
            )
        })
        .collect();

    // This uses the same indexing pattern as graph.resolve_index_by_pkgid
    let mut results =
        vec![ResolveResult::with_no_criteria(no_criteria.clone()); graph.resolve_list.len()];

    // Actually vet the dependencies
    'all_packages: for pkgid in &graph.topo_index {
        let resolve_idx = graph.resolve_index_by_pkgid[pkgid];
        let resolve = &graph.resolve_list[resolve_idx];
        let package = &graph.package_list[graph.package_index_by_pkgid[pkgid]];

        // Implicitly trust non-third-parties
        if !package.is_third_party() {
            // These get processed in the policy section
            // FIXME: I like breaking this into two loops but it might be problematic
            // if someone has their own fork of a crate that crates.io deps use...?
            continue;
        }
        let unaudited = config.unaudited.get(&package.name);

        // Just merge all the entries from the foreign audit files and our audit file.
        let foreign_audits = imports
            .audits
            .values()
            .flat_map(|audit_file| audit_file.audits.get(&package.name).unwrap_or(&NO_AUDITS));
        let own_audits = audits.audits.get(&package.name).unwrap_or(&NO_AUDITS);

        // Deltas are flipped so that we have a map of 'to: [froms]'. This lets
        // us start at the current version and look up all the deltas that *end* at that
        // version. By repeating this over and over, we can loslowly walk back in time until
        // we run out of deltas or reach full audit or an unaudited entry.
        let mut forward_nodes = BTreeMap::<&Version, Vec<DeltaEdge>>::new();
        let mut backward_nodes = BTreeMap::<&Version, Vec<DeltaEdge>>::new();
        let mut violations = Vec::new();

        // Collect up all the deltas, their criteria, and dependency_criteria
        for entry in own_audits.iter() {
            if entry.violation.is_some() {
                violations.push(entry);
                continue;
            };

            let criteria = criteria_mapper.criteria_from_entry(entry);
            // Convert all the custom criteria to CriteriaSets
            let dependency_criteria: HashMap<_, _> = entry
                .dependency_criteria
                .as_ref()
                .map(|d| d.iter())
                .into_iter()
                .flatten()
                .map(|(pkg_name, criteria)| {
                    (
                        &**pkg_name,
                        criteria_mapper.criteria_from_list(criteria.iter().map(|s| &**s)),
                    )
                })
                .collect();

            // For uniformity, model a Full Audit as `0.0.0 -> x.y.z`
            let (from_ver, to_ver) = if let Some(ver) = &entry.version {
                (&ROOT_VERSION, ver)
            } else if let Some(delta) = &entry.delta {
                (&delta.from, &delta.to)
            } else {
                unreachable!("audit wasn't a full entry, audit, or delta!?")
            };

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
                    let set = foreign_criteria_mapper
                        .criteria_from_list(mapping.theirs.iter().map(|s| &**s));
                    (&*mapping.ours, set)
                })
                .collect();

            for entry in foreign_audits
                .audits
                .get(&package.name)
                .unwrap_or(&NO_AUDITS)
            {
                // TODO: figure out a reasonable way to map foreign dependency_criteria
                if entry.dependency_criteria.is_some() {
                    // Just discard this entry for now
                    warn!("discarding foreign audit with dependency_criteria (TODO)");
                    continue;
                }
                if entry.violation.is_some() {
                    violations.push(entry);
                    continue;
                };

                // Map this entry's criteria into our worldview
                let mut local_criteria = no_criteria.clone();
                let foreign_criteria = foreign_criteria_mapper.criteria_from_entry(entry);
                for (local_implied, foreign_required) in &criteria_map {
                    if foreign_criteria.contains(foreign_required) {
                        criteria_mapper.set_criteria(&mut local_criteria, local_implied);
                    }
                }

                // For uniformity, model a Full Audit as `0.0.0 -> x.y.z`
                let (from_ver, to_ver) = if let Some(ver) = &entry.version {
                    (&ROOT_VERSION, ver)
                } else if let Some(delta) = &entry.delta {
                    (&delta.from, &delta.to)
                } else {
                    unreachable!("audit wasn't a full entry, audit, or delta!?")
                };

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
            let violation_range = violation_entry.violation.as_ref().unwrap();
            // Hard error out if anything in our audits overlaps with a forbid entry!
            // (This clone isn't a big deal, it's just iterator adaptors for by-ref iteration)
            for entry in own_audits.iter().chain(foreign_audits.clone()) {
                if let Some(ver) = &entry.version {
                    if violation_range.matches(ver) {
                        error!(
                            "Integrity Failure! Audit and Violation Overlap for {}:",
                            package.name
                        );
                        error!("  audit: {:#?}", entry);
                        error!("  violation: {:#?}", violation_entry);
                        panic!("Integrity Failure! TODO: factor this out better");
                    }
                }
                if let Some(delta) = &entry.delta {
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
            }
            // Having current versions overlap with a violations is less horrifyingly bad,
            // so just gather them up as part of the normal report.
            if violation_range.matches(&package.version) {
                violation_failed.push(package);
                continue 'all_packages;
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
                if allowed.version == package.version {
                    directly_unaudited = true;
                }
                let from_ver = &ROOT_VERSION;
                let to_ver = &allowed.version;
                let criteria = allowed
                    .criteria
                    .as_ref()
                    .map(|c| criteria_mapper.criteria_from_list(c.iter().map(|s| &**s)))
                    .unwrap_or_else(|| criteria_mapper.default_criteria().clone());

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

        let mut validated_criteria = no_criteria.clone();
        let mut fully_audited_criteria = no_criteria.clone();
        let mut search_results = vec![];
        for criteria in criteria_mapper.criteria_iter() {
            let result = search_for_path(
                criteria,
                &ROOT_VERSION,
                &package.version,
                &forward_nodes,
                &graph,
                resolve,
                &mut results,
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
                        &package.version,
                        &ROOT_VERSION,
                        &backward_nodes,
                        &graph,
                        resolve,
                        &mut results,
                    );
                    if let SearchResult::Disconnected {
                        reachable_from_root: reachable_from_target,
                        ..
                    } = rev_result
                    {
                        search_results.push(SearchResult::Disconnected {
                            reachable_from_root,
                            _reachable_from_target: reachable_from_target,
                        })
                    } else {
                        unreachable!("We managed to find a path but only from one direction?!");
                    }
                }
            }
        }
        // Just pre-mark ourselves as a failure if we have no validated criteria.
        let failed = validated_criteria.is_empty();

        // We've completed our graph analysis for this package, now record the results
        results[resolve_idx] = ResolveResult {
            validated_criteria,
            fully_audited_criteria,
            directly_unaudited,
            search_results,
            failed,
            // Only gets found out later, for now, assume not.
            needed_unaudited: false,
        };
    }

    // All third-party crates have been processed, now process policies and first-party crates.
    let mut root_failures = vec![];
    for pkgid in &graph.topo_index {
        let resolve_idx = graph.resolve_index_by_pkgid[pkgid];
        let resolve = &graph.resolve_list[resolve_idx];
        let package = &graph.package_list[graph.package_index_by_pkgid[pkgid]];

        if package.is_third_party() {
            // These have already been processed
            continue;
        }

        let mut failed_deps = BTreeSet::new();
        for dependency in &resolve.dependencies {
            let dep_resolve_idx = graph.resolve_index_by_pkgid[dependency];
            let dep_package = &graph.package_list[graph.package_index_by_pkgid[dependency]];
            let dep_vet_result = &mut results[dep_resolve_idx];

            // If no custom policy is specified, then require our dependencies to
            // satisfy the default policy.
            let dep_req = dep_policies.get(&*dep_package.name).unwrap_or(&policy);
            if !dep_vet_result.contains(dep_req) {
                failed_deps.insert(dependency);
                dep_vet_result.failed = true;
            }
        }

        let result = &mut results[resolve_idx];
        if failed_deps.is_empty() {
            result.validated_criteria.unioned_with(&all_criteria);
        } else {
            // It's always the fault of our dependencies!
            result
                .search_results
                .push(SearchResult::PossiblyConnected { failed_deps });
            result.failed = true;

            if metadata.workspace_members.contains(pkgid) {
                root_failures.push(*pkgid);
            }
        }
    }

    // Gather statistics
    let mut failed_count = 0;
    let mut unaudited_count = 0;
    let mut fully_audited_count = 0;
    let mut partially_audited_count = 0;
    let mut useless_unaudited = vec![];
    for pkgid in &graph.topo_index {
        let resolve_idx = graph.resolve_index_by_pkgid[pkgid];
        let package = &graph.package_list[graph.package_index_by_pkgid[pkgid]];
        let result = &results[resolve_idx];

        if result.failed {
            failed_count += 1;
        } else if !result.needed_unaudited || !package.is_third_party() {
            fully_audited_count += 1;
        } else if result.directly_unaudited {
            unaudited_count += 1;
        } else {
            partially_audited_count += 1;
        }

        if result.directly_unaudited && !result.needed_unaudited {
            useless_unaudited.push(package);
        }
    }

    Report {
        unaudited_count,
        partially_audited_count,
        fully_audited_count,
        failed_count,
        useless_unaudited,
        root_failures,
        violation_failed,
        results,
        graph,
    }
}

fn search_for_path<'a>(
    cur_criteria: &CriteriaSet,
    from_version: &'a Version,
    to_version: &'a Version,
    version_nodes: &BTreeMap<&'a Version, Vec<DeltaEdge<'a>>>,
    dep_graph: &DepGraph<'a>,
    resolve: &'a Node,
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
                    for dependency in &resolve.dependencies {
                        let dep_resolve_idx = dep_graph.resolve_index_by_pkgid[dependency];
                        let dep_package =
                            &dep_graph.package_list[dep_graph.package_index_by_pkgid[dependency]];
                        let dep_vet_result = &mut results[dep_resolve_idx];

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
            _reachable_from_target: Default::default(),
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

    pub fn print_report(&self, out: &mut dyn Write) -> Result<(), VetError> {
        if self.has_errors() {
            self.print_failure(out)
        } else {
            self.print_success(out)
        }
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
            for package in &self.useless_unaudited {
                writeln!(out, "    {}:{}", package.name, package.version)?;
            }
        }

        Ok(())
    }

    fn print_failure(&self, out: &mut dyn Write) -> Result<(), VetError> {
        writeln!(out, "Vetting Failed!")?;
        writeln!(out)?;
        if !self.root_failures.is_empty() {
            writeln!(out, "{} unvetted dependencies:", self.failed_count)?;
            for package in &self.root_failures {
                print_failures(out, 0, package, &self.graph, &self.results)?;
            }
            writeln!(out)?;

            fn print_failures(
                out: &mut dyn Write,
                depth: usize,
                pkgid: &PackageId,
                graph: &DepGraph,
                results: &[ResolveResult],
            ) -> Result<(), VetError> {
                let resolve_idx = graph.resolve_index_by_pkgid[pkgid];
                let package = &graph.package_list[graph.package_index_by_pkgid[pkgid]];
                let result = &results[resolve_idx];
                let indent = (depth + 1) * 2;
                writeln!(
                    out,
                    "{:width$}{}:{}",
                    "",
                    package.name,
                    package.version,
                    width = indent
                )?;

                // Try to blame our deps
                // TODO: filter this further by only selecting for criteria that was actually
                // needed by our policy, we don't care if our dependencies were preventing us
                // from satisfying some strict criteria we didn't even need!
                let all_failed_deps: BTreeSet<_> = result
                    .search_results
                    .iter()
                    .filter_map(|result| {
                        if let SearchResult::PossiblyConnected { failed_deps } = result {
                            Some(failed_deps.iter())
                        } else {
                            None
                        }
                    })
                    .flatten()
                    .collect();
                for dep_package in all_failed_deps {
                    print_failures(out, depth + 1, dep_package, graph, results)?;
                }
                Ok(())
            }
        }
        if !self.violation_failed.is_empty() {
            writeln!(
                out,
                "{} forbidden dependencies:",
                self.violation_failed.len()
            )?;
            for package in &self.violation_failed {
                writeln!(out, "  {}:{}", package.name, package.version)?;
            }
            writeln!(out)?;
        }
        {
            writeln!(out, "recommended audits:")?;
            writeln!(out, "  [TODO]")?;
            writeln!(out)?;
        }
        writeln!(out, "Use |cargo vet certify| to record the audits.")?;

        Ok(())
    }

    /* TODO
    fn print_suggest(&self, out: &mut dyn Write) -> Result<(), VetError> {

    }
     */
}
