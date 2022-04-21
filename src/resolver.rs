use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::Write;

use cargo_metadata::{Metadata, Package, PackageId, Version};
use log::{error, trace, warn};

use crate::{
    AuditEntry, AuditsFile, ConfigFile, CriteriaEntry, DependencyCriteria, ImportsFile, StableMap,
    VetError,
};

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
pub struct CriteriaMapper<'a> {
    list: Vec<(&'a str, &'a CriteriaEntry)>,
    index: HashMap<&'a str, usize>,
    default_criteria: CriteriaSet,
    implied_criteria: Vec<CriteriaSet>,
}

/// The dependency graph in a form we can use more easily.
#[derive(Debug)]
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
#[derive(Clone)]
pub struct ResolveResult<'a> {
    /// The set of criteria we validated for this package.
    validated_criteria: CriteriaSet,

    /// Whether we ever found a complete path in the vet graph (even if empty).
    /// This is used to hint that maybe some restrictions were too tight.
    found_any_path: bool,
    /// Whether the current version is actually directly listed in 'unaudited'.
    /// When checking the dependency requirements on an audit, this implies
    /// all_criteria, and therefore that the edge is always satisfied.
    directly_unaudited: bool,
    /// Whether any dependency_criteria check actually depended on this crate
    /// being directly unaudited. If directly_unaudited is true but this is false,
    /// we should emit a diagnostic and tell you to remove the unaudited entry!
    used_directly_unaudited: bool,
    /// Whether the validation terminated in a full audit.
    fully_audited: bool,
    /// Whether we determined this package failed to audit during policy checking.
    failed: bool,

    /// dependency_criteria that failed to resolve. This is populated for two reasons:
    ///
    /// * during third-party vetting, while walking through the delta graph with
    ///   non-empty cur_criteria, a dependency failed to satisfy our requirements.
    ///   This isn't inherently a problem, because it's possible we'll get a validation
    ///   via another path, but we eagerly "log" the result in case this fails to
    ///   meet expected criteria, and then try to blame the problem on these deps.
    ///   Note the "non-empty cur_criteria" qualifier: we keep searching with empty
    ///   criteria just to give better diagnostics, but failures at that point should
    ///   be ignored because we're just gathering extra info, and not actually vetting.
    ///
    /// * during first-party vetting, if any of these packages fail the policy.
    ///   This is a hard error, and these packages are 100% to blame.
    failed_deps: BTreeSet<&'a PackageId>,
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
            if entry.default {
                default_criteria.set_criteria(idx);
            }

            // Precompute implied criteria (doing it later is genuinely a typesystem headache)
            let mut implied = CriteriaSet::none(list.len());
            recursive_implies(&mut implied, &entry.implies, &index, &list);
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
            result.set_criteria(idx);
            result.unioned_with(&self.implied_criteria[idx]);
        }
        result
    }
    fn set_criteria(&self, set: &mut CriteriaSet, criteria: &str) {
        set.set_criteria(self.index[criteria])
    }

    fn _criteria<'b>(
        &'b self,
        set: &'b CriteriaSet,
    ) -> impl Iterator<Item = (&'a str, &'a CriteriaEntry)> + 'b {
        self.list
            .iter()
            .copied()
            .enumerate()
            .filter_map(|(idx, payload)| {
                if set._has_criteria(idx) {
                    Some(payload)
                } else {
                    None
                }
            })
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
    fn intersected_with(&mut self, other: &CriteriaSet) {
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

impl ResolveResult<'_> {
    fn with_no_criteria(empty: CriteriaSet) -> Self {
        Self {
            validated_criteria: empty,
            found_any_path: false,
            directly_unaudited: false,
            used_directly_unaudited: false,
            fully_audited: false,
            failed: false,
            failed_deps: Default::default(),
        }
    }

    fn contains(&mut self, other: &CriteriaSet) -> bool {
        if self.validated_criteria.contains(other) {
            true
        } else if self.directly_unaudited && !self.failed {
            // Note that the unaudited entry was (seemingly) needed.
            self.used_directly_unaudited = true;
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

pub fn resolve<'a>(
    metadata: &'a Metadata,
    config: &'a ConfigFile,
    audits: &'a AuditsFile,
    imports: &'a ImportsFile,
) -> Report<'a> {
    // Not sure which we want, so make it configurable to test.
    // Determines whether a delta must be == unaudited or just <=
    let unaudited_matching_is_strict = true;

    // Dummy values for corner cases
    let root_version = Version::new(0, 0, 0);
    let no_audits = Vec::new();
    let no_custom_dep_criteria = DependencyCriteria::new();

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
        .unwrap_or(&no_custom_dep_criteria)
        .iter()
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
        let is_third_party = package
            .source
            .as_ref()
            .map(|s| s.is_crates_io())
            .unwrap_or(false);

        if !is_third_party {
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
            .flat_map(|audit_file| audit_file.audits.get(&package.name).unwrap_or(&no_audits));
        let own_audits = audits.audits.get(&package.name).unwrap_or(&no_audits);

        // Deltas are flipped so that we have a map of 'to: [froms]'. This lets
        // us start at the current version and look up all the deltas that *end* at that
        // version. By repeating this over and over, we can loslowly walk back in time until
        // we run out of deltas or reach full audit or an unaudited entry.
        let mut deltas_to =
            HashMap::<&Version, Vec<(&Version, CriteriaSet, HashMap<&str, CriteriaSet>)>>::new();
        let mut violations = Vec::new();

        // Collect up all the deltas, their criteria, and dependency_criteria
        for entry in own_audits.iter() {
            let criteria = criteria_mapper.criteria_from_entry(entry);
            // Convert all the custom criteria to CriteriaSets
            let dep_criteria: HashMap<_, _> = entry
                .dependency_criteria
                .as_ref()
                .unwrap_or(&no_custom_dep_criteria)
                .iter()
                .map(|(pkg_name, criteria)| {
                    (
                        &**pkg_name,
                        criteria_mapper.criteria_from_list(criteria.iter().map(|s| &**s)),
                    )
                })
                .collect();
            // For uniformity, model a Full Audit as `0.0.0 -> x.y.z`
            if let Some(ver) = &entry.version {
                deltas_to
                    .entry(ver)
                    .or_default()
                    .push((&root_version, criteria, dep_criteria));
            } else if let Some(delta) = &entry.delta {
                deltas_to
                    .entry(&delta.to)
                    .or_default()
                    .push((&delta.from, criteria, dep_criteria));
            } else if entry.violation.is_some() {
                violations.push(entry);
            }
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
                .unwrap_or(&no_audits)
            {
                // TODO: figure out a reasonable way to map foreign dependency_criteria
                if entry.dependency_criteria.is_some() {
                    // Just discard this entry for now
                    warn!("discarding foreign audit with dependency_criteria (TODO)");
                    continue;
                }

                // Map this entry's criteria into our worldview
                let mut local_criteria = no_criteria.clone();
                let foreign_criteria = foreign_criteria_mapper.criteria_from_entry(entry);
                for (local_implied, foreign_required) in &criteria_map {
                    if foreign_criteria.contains(foreign_required) {
                        criteria_mapper.set_criteria(&mut local_criteria, local_implied);
                    }
                }

                // Now process it as normal
                if let Some(ver) = &entry.version {
                    deltas_to.entry(ver).or_default().push((
                        &root_version,
                        local_criteria,
                        Default::default(),
                    ));
                } else if let Some(delta) = &entry.delta {
                    deltas_to.entry(&delta.to).or_default().push((
                        &delta.from,
                        local_criteria,
                        Default::default(),
                    ));
                } else if entry.violation.is_some() {
                    violations.push(entry);
                }
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
        if let Some(allowed) = unaudited {
            let reached_unaudited = allowed.iter().any(|allowed| {
                if unaudited_matching_is_strict {
                    allowed.version == package.version
                } else {
                    allowed.version >= package.version
                }
            });
            if reached_unaudited {
                directly_unaudited = true;
            }
        }

        // Now try to resolve the deltas
        let mut working_queue = vec![(&package.version, all_criteria.clone())];
        let mut validated_criteria = no_criteria.clone();
        let mut found_any_path = false;
        let mut fully_audited = false;

        while let Some((cur_version, cur_criteria)) = working_queue.pop() {
            // Check if we've succeeded
            if let Some(allowed) = unaudited {
                // Check if we've reached an 'unaudited' entry
                let reached_unaudited = allowed.iter().any(|allowed| {
                    if unaudited_matching_is_strict {
                        allowed.version == *cur_version
                    } else {
                        allowed.version >= *cur_version
                    }
                });
                if reached_unaudited {
                    // If this is the original package version, don't treat this is as a real
                    // validation path so that we can tell if the we were directly relying on it.
                    if cur_version != &package.version {
                        found_any_path = true;
                        validated_criteria.unioned_with(&cur_criteria);

                        // Just keep running the workqueue in case we find more criteria by other paths
                        continue;
                    }
                }
            }
            if cur_version == &root_version {
                // Reached 0.0.0, which means we hit a Full Audit, that's perfect
                validated_criteria.unioned_with(&cur_criteria);
                found_any_path = true;

                // FIXME: this is mildly fuzzy with unioning
                // FIXME: should this only be true if cur_criteria is non-empty?
                fully_audited = true;

                // Just keep running the workqueue in case we find more criteria by other paths
                continue;
            }
            // Apply deltas to move along to the next "layer" of the search
            if let Some(deltas) = deltas_to.get(cur_version) {
                for (from_version, criteria, dep_criteria) in deltas {
                    let mut next_critera = cur_criteria.clone();
                    next_critera.intersected_with(criteria);

                    // Deltas should only apply if dependencies satisfy dep_criteria
                    let mut deps_satisfied = true;
                    for dependency in &resolve.dependencies {
                        let dep_resolve_idx = graph.resolve_index_by_pkgid[dependency];
                        let dep_package =
                            &graph.package_list[graph.package_index_by_pkgid[dependency]];
                        let dep_vet_result = &mut results[dep_resolve_idx];

                        // If no custom criteria is specified, then require our dependency to match
                        // the same criteria that this delta claims to provide.
                        // e.g. a 'secure' audit requires all dependencies to be 'secure' by default.
                        let dep_req = dep_criteria.get(&*dep_package.name).unwrap_or(criteria);
                        if !dep_vet_result.contains(dep_req) {
                            deps_satisfied = false;
                            // If this is resulting in an actual loss of criteria, tentatively blame
                            // this dependency for own future failings. If we end up resolving some
                            // other way, then we won't mention this horrendous treachery.
                            if !cur_criteria.is_empty() {
                                let own_result = &mut results[resolve_idx];
                                own_result.failed_deps.insert(dependency);
                            }
                        }
                    }

                    // NOTE: we explicitly don't stop if next_criteria is empty, because we want to
                    // understand the whole graph, and in particular figure out if it's even vaguely
                    // connected.
                    if deps_satisfied {
                        working_queue.push((from_version, next_critera));
                    }
                }
            }
        }

        let mut failed = false;
        let mut used_directly_unaudited = false;
        if !found_any_path {
            // If we didn't actually find any paths and we're directly unaudited,
            // make sure our deps make sense (has default criteria)
            if directly_unaudited {
                let mut deps_satisfied = true;
                for dependency in &resolve.dependencies {
                    let dep_resolve_idx = graph.resolve_index_by_pkgid[dependency];
                    let dep_vet_result = &mut results[dep_resolve_idx];

                    let dep_req = criteria_mapper.default_criteria();
                    if !dep_vet_result.contains(dep_req) {
                        let own_result = &mut results[resolve_idx];
                        deps_satisfied = false;
                        own_result.failed_deps.insert(dependency);
                    }
                }

                if deps_satisfied {
                    used_directly_unaudited = true;
                } else {
                    failed = true;
                }
            } else {
                failed = true;
            }
        }

        // We've completed our graph analysis for this package, now record the results
        let result = &mut results[resolve_idx];
        result.validated_criteria = validated_criteria;
        result.found_any_path = found_any_path;
        result.fully_audited = fully_audited;
        result.failed = failed;
        result.used_directly_unaudited = used_directly_unaudited;
        result.directly_unaudited = directly_unaudited;
    }

    // All third-party crates have been processed, now process policies and first-party crates.
    let mut root_failures = vec![];
    for pkgid in &graph.topo_index {
        let resolve_idx = graph.resolve_index_by_pkgid[pkgid];
        let resolve = &graph.resolve_list[resolve_idx];
        let package = &graph.package_list[graph.package_index_by_pkgid[pkgid]];

        let is_third_party = package
            .source
            .as_ref()
            .map(|s| s.is_crates_io())
            .unwrap_or(false);

        if is_third_party {
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
            result.failed_deps = failed_deps;
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
        } else if result.used_directly_unaudited {
            unaudited_count += 1;
        } else if result.fully_audited {
            fully_audited_count += 1;
        } else {
            partially_audited_count += 1;
        }

        if result.directly_unaudited && !result.used_directly_unaudited {
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
            "Vetting Succeeded ({} fully audited {} partially audited, {} unaudited)",
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
                for dep_package in &result.failed_deps {
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
}
