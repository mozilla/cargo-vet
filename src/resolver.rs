//! The Resolver is the heart of cargo-vet, and does all the work to validate the audits
//! for your current packages and to suggest fixes. This is done in 3 phases:
//!
//! 1. Resolving required criteria based on your policies
//! 2. Searching for audits which satisfy the required criteria
//! 3. Suggesting audits that would make your project pass validation
//!
//! # High-level Usage
//!
//! * [`resolve`] is the main entry point, Validating and Searching and producing a [`ResolveReport`]
//! * [`ResolveReport::compute_suggest`] does Suggesting and produces a [`Suggest`]
//! * various methods on [`ResolveReport`] and [`Suggest`] handle printing
//! * [`update_store`] handles automatically minimizing and generating exemptions and imports
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
//! * resolve_requirements: for each package, resolve what criteria it needs to be audited for
//!     * start with root targets and propagate requirements out towards leaf crates
//!     * policies can override requirements on the target crate and its dependencies
//!
//! * resolve_audits: for each package, resolve what criteria it's audited for
//!     * compute the [`AuditGraph`] and check for violations
//!     * for each criteria, search the for a connected path in the audit graph
//!     * check if the criteria are satisfied
//!         * if they are, record caveats which were required for the criteria
//!         * if they aren't record the criteria which failed, and how to fix them
//!
//!
//! ## Suggest
//!
//! * enumerate the failures and perform a number of diffstats based on the
//!   existing set of criteria, to suggest the best audit and criteria which could
//!   be used to allow the crate to vet successfully.

use cargo_metadata::{DependencyKind, Metadata, Node, PackageId};
use futures_util::future::join_all;
use miette::IntoDiagnostic;
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::sync::Arc;
use tracing::{trace, trace_span, warn};

use crate::cli::{DumpGraphArgs, GraphFilter, GraphFilterProperty, GraphFilterQuery, OutputFormat};
use crate::criteria::{CriteriaMapper, CriteriaSet};
use crate::errors::SuggestError;
use crate::format::{
    self, AuditEntry, AuditKind, AuditsFile, CratesCacheUser, CratesPublisher, CriteriaName, Delta,
    DiffStat, ExemptedDependency, FastMap, FastSet, ImportName, ImportsFile, JsonPackage,
    JsonReport, JsonReportConclusion, JsonReportFailForVet, JsonReportFailForViolationConflict,
    JsonReportSuccess, JsonSuggest, JsonSuggestItem, JsonVetFailure, PackageName, PackageStr,
    Policy, UnpublishedEntry, VetVersion, WildcardEntry,
};
use crate::format::{SortedMap, SortedSet};
use crate::network::Network;
use crate::out::{progress_bar, IncProgressOnDrop, Out};
use crate::storage::Cache;
use crate::string_format::FormatShortList;
use crate::{Config, PackageExt, Store};

pub struct ResolveReport<'a> {
    /// The Cargo dependency graph as parsed and understood by cargo-vet.
    ///
    /// All [`PackageIdx`][] values are indices into this graph's nodes.
    pub graph: DepGraph<'a>,

    /// Mappings between criteria names and CriteriaSets/Indices.
    pub criteria_mapper: CriteriaMapper,

    /// Low-level results for each package's individual criteria resolving
    /// analysis, indexed by [`PackageIdx`][]. Will be `None` for first-party
    /// crates or crates with violation conflicts.
    pub results: Vec<Option<ResolveResult>>,

    /// The final conclusion of our analysis.
    pub conclusion: Conclusion,
}

#[derive(Debug)]
pub enum Conclusion {
    Success(Success),
    FailForViolationConflict(FailForViolationConflict),
    FailForVet(FailForVet),
}

#[derive(Debug, Clone)]
pub struct Success {
    /// Third-party packages that were successfully vetted using only 'exemptions'
    pub vetted_with_exemptions: Vec<PackageIdx>,
    /// Third-party packages that were successfully vetted using both 'audits' and 'exemptions'
    pub vetted_partially: Vec<PackageIdx>,
    /// Third-party packages that were successfully vetted using only 'audits'
    pub vetted_fully: Vec<PackageIdx>,
}

#[derive(Debug, Clone)]
pub struct FailForViolationConflict {
    pub violations: Vec<(PackageIdx, Vec<ViolationConflict>)>,
}

#[derive(Debug)]
pub struct FailForVet {
    /// These packages are to blame and need to be fixed
    pub failures: Vec<(PackageIdx, AuditFailure)>,
    pub suggest: Option<Suggest>,
}

// FIXME: This format is pretty janky and unstable, so we probably should come
// up with an actually-useful format for this.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ViolationConflict {
    UnauditedConflict {
        violation_source: Option<ImportName>,
        violation: AuditEntry,
        exemptions: ExemptedDependency,
    },
    AuditConflict {
        violation_source: Option<ImportName>,
        violation: AuditEntry,
        audit_source: Option<ImportName>,
        audit: AuditEntry,
    },
}

#[derive(Debug, Default)]
pub struct Suggest {
    pub suggestions: Vec<SuggestItem>,
    pub suggestions_by_criteria: SortedMap<CriteriaName, Vec<SuggestItem>>,
    pub total_lines: u64,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct TrustHint {
    trusted_by: Vec<String>,
    publisher: CratesCacheUser,
    exact_version: bool,
}

#[derive(Debug, Clone)]
pub struct SuggestItem {
    pub package: PackageIdx,
    pub suggested_criteria: CriteriaSet,
    pub suggested_diff: DiffRecommendation,
    pub notable_parents: Vec<String>,
    pub publisher_login: Option<String>,
    pub trust_hint: Option<TrustHint>,
    pub is_sole_publisher: bool,
    pub registry_suggestion: Vec<RegistrySuggestion>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct DiffRecommendation {
    pub from: Option<VetVersion>,
    pub to: VetVersion,
    pub diffstat: DiffStat,
}

#[derive(Debug, Clone)]
pub struct RegistrySuggestion {
    pub name: ImportName,
    pub url: Vec<String>,
    pub diff: DiffRecommendation,
}

/// An "interned" cargo PackageId which is used to uniquely identify packages throughout
/// the code. This is simpler and faster than actually using PackageIds (strings) or name+version.
/// In the current implementation it can be used to directly index into the `graph` or `results`.
pub type PackageIdx = usize;

#[derive(Debug, Clone, Serialize)]
pub struct PackageNode<'a> {
    #[serde(skip)]
    /// The PackageId that cargo uses to uniquely identify this package
    ///
    /// This ID is not guaranteed to be stable across cargo versions, so is not
    /// serialized into graph JSON.
    ///
    /// Prefer using a [`DepGraph`] and its memoized [`PackageIdx`]'s.
    pub package_id: &'a PackageId,
    /// The name of the package
    pub name: PackageStr<'a>,
    /// The version of this package
    pub version: VetVersion,
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

/// The dependency graph in a form we can use more easily.
#[derive(Debug, Clone)]
pub struct DepGraph<'a> {
    pub nodes: Vec<PackageNode<'a>>,
    pub interner_by_pkgid: SortedMap<&'a PackageId, PackageIdx>,
    pub topo_index: Vec<PackageIdx>,
}

/// Results and notes from running vet on a particular package.
#[derive(Debug, Clone)]
pub struct ResolveResult {
    /// Cache of search results for each criteria.
    pub search_results: Vec<Result<Vec<DeltaEdgeOrigin>, SearchFailure>>,
}

#[derive(Debug, Clone)]
pub struct AuditFailure {
    pub criteria_failures: CriteriaSet,
}

/// Value indicating a failure to find a path in the audit graph between two nodes.
#[derive(Debug, Clone)]
pub struct SearchFailure {
    /// Nodes we could reach from "root"
    pub reachable_from_root: SortedSet<Option<VetVersion>>,
    /// Nodes we could reach from the "target"
    pub reachable_from_target: SortedSet<Option<VetVersion>>,
}

type DirectedAuditGraph<'a> = SortedMap<Option<&'a VetVersion>, Vec<DeltaEdge<'a>>>;

/// A graph of the audits for a package.
///
/// The nodes of the graph are Versions and the edges are audits.
/// An AuditGraph is directed, potentially cyclic, and potentially disconnected.
///
/// There are two important versions in each AuditGraph:
///
/// * The "root" version (None) which exists as a dummy node for full-audits
/// * The "target" version which is the current version of the package
///
/// The edges are constructed as follows:
///
/// * Delta Audits desugar directly to edges
/// * Full Audits and Unaudited desugar to None -> Some(Version)
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
#[derive(Debug, Clone)]
pub struct AuditGraph<'a> {
    forward_audits: DirectedAuditGraph<'a>,
    backward_audits: DirectedAuditGraph<'a>,
}

/// The precise origin of an edge in the audit graph.
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub enum DeltaEdgeOrigin {
    /// This edge represents an audit from the local audits.toml.
    StoredLocalAudit {
        audit_index: usize,
        importable: bool,
    },
    /// This edge represents an audit imported from a peer, potentially stored
    /// in the local imports.lock.
    ImportedAudit {
        import_index: usize,
        audit_index: usize,
    },
    /// This edge represents a reified wildcard audit.
    WildcardAudit {
        import_index: Option<usize>,
        audit_index: usize,
        publisher_index: usize,
    },
    /// This edge represents a trusted publisher.
    Trusted { publisher_index: usize },
    /// This edge represents an exemption from the local config.toml.
    Exemption { exemption_index: usize },
    /// This edge represents an unpublished entry in imports.lock.
    Unpublished { unpublished_index: usize },
    /// This edge represents brand new exemption which didn't previously exist
    /// in the audit graph. Will only ever be produced from
    /// SearchMode::RegenerateExemptions.
    FreshExemption { version: VetVersion },
}

/// An indication of a required local audit, imported entry, or exemption. Used to compute the
/// minimal set of possible imports for imports.lock and for pruning unused audits and exemptions.
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub enum RequiredEntry {
    LocalAudit {
        audit_index: usize,
    },
    Audit {
        import_index: usize,
        audit_index: usize,
    },
    WildcardAudit {
        import_index: usize,
        audit_index: usize,
    },
    Publisher {
        publisher_index: usize,
    },
    Exemption {
        exemption_index: usize,
    },
    Unpublished {
        unpublished_index: usize,
    },
    // NOTE: This variant must come last, as code in `update_store` depends on
    // `FreshExemption` entries sorting after all other entries.
    FreshExemption {
        version: VetVersion,
    },
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum DeltaEdgeFreshness {
    // All information requried for this delta edge is already stored within the store's
    // supply-chain. Using this edge will require no changes to imports.lock.
    Stale,
    // This edge originates from an already-imported or local wildcard audit, however will require
    // importing fresh publisher information into imports.lock.
    FreshPublisher,
    // This edge is fully fresh, and will require adding the audit entry to imports.lock to use.
    Fresh,
}

impl DeltaEdgeFreshness {
    fn new(is_fresh_audit: bool, is_fresh_publisher: bool) -> Self {
        if is_fresh_audit {
            DeltaEdgeFreshness::Fresh
        } else if is_fresh_publisher {
            DeltaEdgeFreshness::FreshPublisher
        } else {
            DeltaEdgeFreshness::Stale
        }
    }

    fn is_fresh(&self) -> bool {
        self != &DeltaEdgeFreshness::Stale
    }
}

/// A directed edge in the graph of audits. This may be forward or backwards,
/// depending on if we're searching from "roots" (forward) or the target (backward).
/// The source isn't included because that's implicit in the Node.
#[derive(Debug, Clone)]
struct DeltaEdge<'a> {
    /// The version this edge goes to.
    version: Option<&'a VetVersion>,
    /// The criteria that this edge is valid for.
    criteria: CriteriaSet,
    /// The origin of this edge. See `DeltaEdgeOrigin`'s documentation for more
    /// details.
    origin: DeltaEdgeOrigin,
    /// Whether or not the edge is a "fresh import", and should be
    /// de-prioritized to avoid unnecessary imports.lock updates.
    freshness: DeltaEdgeFreshness,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum SearchMode {
    /// Prefer exemptions over fresh imports when searching.
    PreferExemptions,
    /// Prefer fresh imports over exemptions when searching for paths.
    PreferFreshImports,
    /// Prefer fresh imports over exemptions, and allow introducing new
    /// exemptions or expanding their criteria beyond the written criteria
    /// (unless they are suggest=false).
    RegenerateExemptions,
}

impl<'a> DepGraph<'a> {
    pub fn new(
        metadata: &'a Metadata,
        filter_graph: Option<&Vec<GraphFilter>>,
        policy: Option<&Policy>,
    ) -> Self {
        let default_policy = Policy::default();
        let policy = policy.unwrap_or(&default_policy);
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
        let mut nodes = vec![];

        // Stub out the initial state of all the nodes
        for resolve_node in resolve_list {
            let package = &package_list[package_index_by_pkgid[&resolve_node.id]];
            nodes.push(PackageNode {
                package_id: &resolve_node.id,
                name: &package.name,
                version: package.vet_version(),
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

        // Sort the nodes by package name and version to make the graph as
        // stable as possible.  We avoid sorting by the package_id if possible,
        // as for some packages it may not be stable (e.g. file:///), and the
        // package_id format can also vary between cargo versions.
        nodes.sort_by(|a, b| {
            (a.name, &a.version, &a.package_id).cmp(&(b.name, &b.version, &b.package_id))
        });

        // Populate the interners based on the new ordering
        for (idx, node) in nodes.iter_mut().enumerate() {
            assert!(interner_by_pkgid.insert(node.package_id, idx).is_none());
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
                Version(val) => &package.version == val,
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
                version: package.version.clone(),
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
            topo_index,
        }
    }

    pub fn print_mermaid(
        &self,
        out: &Arc<dyn Out>,
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

        writeln!(out, "graph LR");

        writeln!(out, "    subgraph roots");
        for &idx in &visible_nodes {
            let package = &self.nodes[idx];
            if package.is_root && shown.insert(idx) {
                writeln!(
                    out,
                    "        node{idx}{{{}:{}}}",
                    package.name, package.version
                );
            }
        }
        writeln!(out, "    end");

        writeln!(out, "    subgraph workspace-members");
        for &idx in &visible_nodes {
            let package = &self.nodes[idx];
            if package.is_workspace_member && shown.insert(idx) {
                writeln!(
                    out,
                    "        node{idx}[/{}:{}/]",
                    package.name, package.version
                );
            }
        }
        writeln!(out, "    end");

        writeln!(out, "    subgraph first-party");
        for &idx in &visible_nodes {
            let package = &self.nodes[idx];
            if !package.is_third_party && shown.insert(idx) {
                writeln!(
                    out,
                    "        node{idx}[{}:{}]",
                    package.name, package.version
                );
            }
        }
        writeln!(out, "    end");

        writeln!(out, "    subgraph third-party");
        for &idx in &visible_nodes {
            let package = &self.nodes[idx];
            if shown.insert(idx) {
                writeln!(
                    out,
                    "        node{idx}({}:{})",
                    package.name, package.version
                );
            }
        }
        writeln!(out, "    end");

        for &idx in &nodes_with_children {
            let package = &self.nodes[idx];
            for &dep_idx in &package.all_deps {
                if visible_nodes.contains(&dep_idx) {
                    writeln!(out, "    node{idx} --> node{dep_idx}");
                }
            }
        }

        Ok(())
    }
}

pub fn resolve<'a>(
    metadata: &'a Metadata,
    filter_graph: Option<&Vec<GraphFilter>>,
    store: &Store,
) -> ResolveReport<'a> {
    // A large part of our algorithm is unioning and intersecting criteria, so we map all
    // the criteria into indexed boolean sets (*whispers* an integer with lots of bits).
    let graph = DepGraph::new(metadata, filter_graph, Some(&store.config.policy));
    // trace!("built DepGraph: {:#?}", graph);
    trace!("built DepGraph!");

    let criteria_mapper = CriteriaMapper::new(&store.audits.criteria);
    trace!("built CriteriaMapper!");

    let requirements = resolve_requirements(&graph, &store.config.policy, &criteria_mapper);

    let (results, conclusion) = resolve_audits(&graph, store, &criteria_mapper, &requirements);

    ResolveReport {
        graph,
        criteria_mapper,
        results,
        conclusion,
    }
}

fn resolve_requirements(
    graph: &DepGraph<'_>,
    policy: &Policy,
    criteria_mapper: &CriteriaMapper,
) -> Vec<CriteriaSet> {
    let _resolve_requirements = trace_span!("resolve_requirements").entered();

    let mut requirements = vec![criteria_mapper.no_criteria(); graph.nodes.len()];

    // For any packages which have dev-dependencies, apply policy-specified
    // dependency-criteria or dev-criteria to those dependencies.
    for package in &graph.nodes {
        if package.dev_deps.is_empty() {
            continue;
        }

        let policy = policy.get(package.name, &package.version);
        let dev_criteria = if let Some(c) = policy.and_then(|p| p.dev_criteria.as_ref()) {
            criteria_mapper.criteria_from_list(c)
        } else {
            criteria_mapper.criteria_from_list([format::DEFAULT_POLICY_DEV_CRITERIA])
        };

        for &depidx in &package.dev_deps {
            let dep_package = &graph.nodes[depidx];
            let dependency_criteria = policy
                .and_then(|policy| policy.dependency_criteria.get(dep_package.name))
                .map(|criteria| criteria_mapper.criteria_from_list(criteria));
            requirements[depidx]
                .unioned_with(dependency_criteria.as_ref().unwrap_or(&dev_criteria));
        }
    }

    // Walk the topo graph in reverse, so that we visit each package before any
    // dependencies.
    for &pkgidx in graph.topo_index.iter().rev() {
        let package = &graph.nodes[pkgidx];
        let policy = policy.get(package.name, &package.version);

        if let Some(c) = policy.and_then(|p| p.criteria.as_ref()) {
            // If we specify a policy on ourselves, override any requirements we've
            // had placed on us by reverse-dependencies.
            requirements[pkgidx] = criteria_mapper.criteria_from_list(c);
        } else if package.is_root {
            // If this is a root crate, it will require at least
            // `DEFAULT_POLICY_CRITERIA` by default, unless overridden.
            requirements[pkgidx].unioned_with(
                &criteria_mapper.criteria_from_list([format::DEFAULT_POLICY_CRITERIA]),
            );
        }
        let normal_criteria = requirements[pkgidx].clone();

        // For each dependency, elaborate the dependency criteria from the configured policy and add it to the dependency requirements.
        for &depidx in &package.normal_and_build_deps {
            let dep_package = &graph.nodes[depidx];
            let dependency_criteria = policy
                .and_then(|policy| policy.dependency_criteria.get(dep_package.name))
                .map(|criteria| criteria_mapper.criteria_from_list(criteria));
            requirements[depidx]
                .unioned_with(dependency_criteria.as_ref().unwrap_or(&normal_criteria));
        }
    }

    requirements
}

fn resolve_audits(
    graph: &DepGraph<'_>,
    store: &Store,
    criteria_mapper: &CriteriaMapper,
    requirements: &[CriteriaSet],
) -> (Vec<Option<ResolveResult>>, Conclusion) {
    let _resolve_audits = trace_span!("resolve_audits").entered();
    let mut violations = Vec::new();
    let mut failures = Vec::new();
    let mut vetted_with_exemptions = Vec::new();
    let mut vetted_partially = Vec::new();
    let mut vetted_fully = Vec::new();
    let results: Vec<_> = requirements
        .iter()
        .enumerate()
        .map(|(pkgidx, required_criteria)| {
            let package = &graph.nodes[pkgidx];
            if !package.is_third_party {
                return None; // first-party crates don't need audits
            }

            let audit_graph = AuditGraph::build(store, criteria_mapper, package.name, None)
                .map_err(|v| violations.push((pkgidx, v)))
                .ok()?;

            // NOTE: We currently always compute all search results even if we
            // only need those in `req_criteria` because some later passes using
            // the resolver results might need that information. We might want
            // to look into simplifying this in the future.
            let search_results: Vec<_> = (0..criteria_mapper.len())
                .map(|criteria_idx| {
                    audit_graph.search(criteria_idx, &package.version, SearchMode::PreferExemptions)
                })
                .collect();

            let mut needed_exemptions = false;
            let mut directly_exempted = false;
            let mut criteria_failures = criteria_mapper.no_criteria();
            for criteria_idx in required_criteria.indices() {
                match &search_results[criteria_idx] {
                    Ok(path) => {
                        needed_exemptions |= path
                            .iter()
                            .any(|o| matches!(o, DeltaEdgeOrigin::Exemption { .. }));
                        // Ignore `Unpublished` entries when deciding if a crate
                        // is directly exempted.
                        directly_exempted |= path.iter().all(|o| {
                            matches!(
                                o,
                                DeltaEdgeOrigin::Exemption { .. }
                                    | DeltaEdgeOrigin::Unpublished { .. }
                            )
                        });
                    }
                    Err(_) => criteria_failures.set_criteria(criteria_idx),
                }
            }

            if !criteria_failures.is_empty() {
                failures.push((pkgidx, AuditFailure { criteria_failures }));
            }

            // XXX: Callers using these fields in success should perhaps be
            // changed to instead walk the results?
            if !needed_exemptions {
                vetted_fully.push(pkgidx);
            } else if directly_exempted {
                vetted_with_exemptions.push(pkgidx);
            } else {
                vetted_partially.push(pkgidx);
            }

            Some(ResolveResult { search_results })
        })
        .collect();

    let conclusion = if !violations.is_empty() {
        Conclusion::FailForViolationConflict(FailForViolationConflict { violations })
    } else if !failures.is_empty() {
        Conclusion::FailForVet(FailForVet {
            failures,
            suggest: None,
        })
    } else {
        Conclusion::Success(Success {
            vetted_with_exemptions,
            vetted_partially,
            vetted_fully,
        })
    };

    (results, conclusion)
}

impl<'a> AuditGraph<'a> {
    /// Given the store, and a package name, builds up an audit graph. This can
    /// then be searched in order to find a specific path which satisfies a
    /// given criteria.
    pub fn build(
        store: &'a Store,
        criteria_mapper: &CriteriaMapper,
        package: PackageStr<'_>,
        extra_audits_file: Option<&'a AuditsFile>,
    ) -> Result<Self, Vec<ViolationConflict>> {
        // Pre-build the namespaces for each audit so that we can take a reference
        // to each one as-needed rather than cloning the name each time.
        let foreign_namespaces: Vec<Option<ImportName>> = store
            .imported_audits()
            .keys()
            .map(|import_name| Some(import_name.clone()))
            .collect();

        // Iterator over every audits file, including imported audits.
        let all_audits_files = store
            .imported_audits()
            .values()
            .enumerate()
            .map(|(import_index, audits_file)| {
                (
                    Some(import_index),
                    &foreign_namespaces[import_index],
                    audits_file,
                )
            })
            .chain([(None, &None, &store.audits)])
            .chain(
                // Consider extra audits as local for now - we don't care about
                // how the audits from it are prioritized.
                extra_audits_file
                    .iter()
                    .map(|&audits_file| (None, &None, audits_file)),
            );

        // Iterator over every normal audit.
        let all_audits =
            all_audits_files
                .clone()
                .flat_map(|(import_index, namespace, audits_file)| {
                    audits_file
                        .audits
                        .get(package)
                        .map(|v| &v[..])
                        .unwrap_or(&[])
                        .iter()
                        .enumerate()
                        .map(move |(audit_index, audit)| {
                            (
                                namespace,
                                match import_index {
                                    Some(import_index) => DeltaEdgeOrigin::ImportedAudit {
                                        import_index,
                                        audit_index,
                                    },
                                    None => DeltaEdgeOrigin::StoredLocalAudit {
                                        audit_index,
                                        importable: audit.importable,
                                    },
                                },
                                audit,
                            )
                        })
                });

        // Iterator over every wildcard audit.
        let all_wildcard_audits =
            all_audits_files
                .clone()
                .flat_map(|(import_index, namespace, audits_file)| {
                    audits_file
                        .wildcard_audits
                        .get(package)
                        .map(|v| &v[..])
                        .unwrap_or(&[])
                        .iter()
                        .enumerate()
                        .map(move |(audit_index, audit)| {
                            (namespace, import_index, audit_index, audit)
                        })
                });

        // Iterator over every trusted entry.
        let trusteds = store
            .audits
            .trusted
            .get(package)
            .map(|v| &v[..])
            .unwrap_or(&[]);

        let publishers = store
            .publishers()
            .get(package)
            .map(|v| &v[..])
            .unwrap_or(&[]);

        let unpublished = store
            .unpublished()
            .get(package)
            .map(|v| &v[..])
            .unwrap_or(&[]);

        let exemptions = store.config.exemptions.get(package);

        let mut forward_audits = DirectedAuditGraph::new();
        let mut backward_audits = DirectedAuditGraph::new();
        let mut violation_nodes = Vec::new();

        // Collect up all the deltas, and their criteria
        for (namespace, origin, entry) in all_audits.clone() {
            // For uniformity, model a Full Audit as `None -> x.y.z`
            let (from_ver, to_ver) = match &entry.kind {
                AuditKind::Full { version } => (None, version),
                AuditKind::Delta { from, to } => (Some(from), to),
                AuditKind::Violation { .. } => {
                    violation_nodes.push((namespace.clone(), entry));
                    continue;
                }
            };

            let criteria = criteria_mapper.criteria_from_list(&entry.criteria);
            let freshness = DeltaEdgeFreshness::new(entry.is_fresh_import, false);

            forward_audits.entry(from_ver).or_default().push(DeltaEdge {
                version: Some(to_ver),
                criteria: criteria.clone(),
                origin: origin.clone(),
                freshness,
            });
            backward_audits
                .entry(Some(to_ver))
                .or_default()
                .push(DeltaEdge {
                    version: from_ver,
                    criteria,
                    origin,
                    freshness,
                });
        }

        // For each published version of the crate we're aware of, check if any
        // wildcard audits apply and add full-audits to those versions if they
        // do.
        for (publisher_index, publisher) in publishers.iter().enumerate() {
            for (_, import_index, audit_index, entry) in all_wildcard_audits.clone() {
                if entry.user_id == publisher.user_id
                    && *entry.start <= publisher.when
                    && publisher.when < *entry.end
                {
                    let from_ver = None;
                    let to_ver = Some(&publisher.version);
                    let criteria = criteria_mapper.criteria_from_list(&entry.criteria);
                    let origin = DeltaEdgeOrigin::WildcardAudit {
                        import_index,
                        audit_index,
                        publisher_index,
                    };
                    let freshness =
                        DeltaEdgeFreshness::new(entry.is_fresh_import, publisher.is_fresh_import);

                    forward_audits.entry(from_ver).or_default().push(DeltaEdge {
                        version: to_ver,
                        criteria: criteria.clone(),
                        origin: origin.clone(),
                        freshness,
                    });
                    backward_audits.entry(to_ver).or_default().push(DeltaEdge {
                        version: from_ver,
                        criteria,
                        origin,
                        freshness,
                    });
                }
            }

            for entry in trusteds {
                if entry.user_id == publisher.user_id
                    && *entry.start <= publisher.when
                    && publisher.when < *entry.end
                {
                    let from_ver = None;
                    let to_ver = Some(&publisher.version);
                    let criteria = criteria_mapper.criteria_from_list(&entry.criteria);
                    let origin = DeltaEdgeOrigin::Trusted { publisher_index };
                    // While the import freshness is technically based on the publisher being a
                    // fresh import, we use this as the _audit_ freshness here because a trusted
                    // entry should be put at the same caveat level ordering as other audits (which
                    // is determined from freshness later on).
                    let freshness = DeltaEdgeFreshness::new(publisher.is_fresh_import, false);

                    forward_audits.entry(from_ver).or_default().push(DeltaEdge {
                        version: to_ver,
                        criteria: criteria.clone(),
                        origin: origin.clone(),
                        freshness,
                    });
                    backward_audits.entry(to_ver).or_default().push(DeltaEdge {
                        version: from_ver,
                        criteria,
                        origin,
                        freshness,
                    });
                }
            }
        }

        // For each unpublished entry for the crate we're aware of, generate a delta audit for that edge.
        for (unpublished_index, unpublished) in unpublished.iter().enumerate() {
            let from_ver = Some(&unpublished.audited_as);
            let to_ver = Some(&unpublished.version);
            let criteria = criteria_mapper.all_criteria();
            let origin = DeltaEdgeOrigin::Unpublished { unpublished_index };
            let freshness = DeltaEdgeFreshness::new(unpublished.is_fresh_import, false);

            forward_audits.entry(from_ver).or_default().push(DeltaEdge {
                version: to_ver,
                criteria: criteria.clone(),
                origin: origin.clone(),
                freshness,
            });
            backward_audits.entry(to_ver).or_default().push(DeltaEdge {
                version: from_ver,
                criteria,
                origin,
                freshness,
            });
        }

        // Exempted entries are equivalent to full-audits
        if let Some(alloweds) = exemptions {
            for (exemption_index, allowed) in alloweds.iter().enumerate() {
                let from_ver = None;
                let to_ver = Some(&allowed.version);
                let criteria = criteria_mapper.criteria_from_list(&allowed.criteria);
                let origin = DeltaEdgeOrigin::Exemption { exemption_index };

                // For simplicity, turn 'exemptions' entries into deltas from None.
                forward_audits.entry(from_ver).or_default().push(DeltaEdge {
                    version: to_ver,
                    criteria: criteria.clone(),
                    origin: origin.clone(),
                    freshness: DeltaEdgeFreshness::Stale,
                });
                backward_audits.entry(to_ver).or_default().push(DeltaEdge {
                    version: from_ver,
                    criteria,
                    origin,
                    freshness: DeltaEdgeFreshness::Stale,
                });
            }
        }

        // Reject forbidden packages (violations)
        let mut violations = Vec::new();
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
            let violation_range = if let AuditKind::Violation { violation } = &violation_entry.kind
            {
                violation
            } else {
                unreachable!("violation_entry wasn't a Violation?");
            };

            // Note if this entry conflicts with any exemptions
            if let Some(alloweds) = exemptions {
                for allowed in alloweds {
                    let audit_criteria = criteria_mapper.criteria_from_list(&allowed.criteria);
                    let has_violation = violation_criterias
                        .iter()
                        .any(|v| audit_criteria.contains(v));
                    if !has_violation {
                        continue;
                    }
                    if violation_range.matches(&allowed.version) {
                        violations.push(ViolationConflict::UnauditedConflict {
                            violation_source: violation_source.clone(),
                            violation: (*violation_entry).clone(),
                            exemptions: allowed.clone(),
                        });
                    }
                }
            }

            // Note if this entry conflicts with any audits
            for (namespace, _origin, audit) in all_audits.clone() {
                let audit_criteria = criteria_mapper.criteria_from_list(&audit.criteria);
                let has_violation = violation_criterias
                    .iter()
                    .any(|v| audit_criteria.contains(v));
                if !has_violation {
                    continue;
                }
                match &audit.kind {
                    AuditKind::Full { version, .. } => {
                        if violation_range.matches(version) {
                            violations.push(ViolationConflict::AuditConflict {
                                violation_source: violation_source.clone(),
                                violation: (*violation_entry).clone(),
                                audit_source: namespace.clone(),
                                audit: audit.clone(),
                            });
                        }
                    }
                    AuditKind::Delta { from, to, .. } => {
                        if violation_range.matches(from) || violation_range.matches(to) {
                            violations.push(ViolationConflict::AuditConflict {
                                violation_source: violation_source.clone(),
                                violation: (*violation_entry).clone(),
                                audit_source: namespace.clone(),
                                audit: audit.clone(),
                            });
                        }
                    }
                    AuditKind::Violation { .. } => {
                        // don't care
                    }
                }
            }
        }

        // If we enountered any violations, report them.
        if !violations.is_empty() {
            return Err(violations);
        }

        Ok(AuditGraph {
            forward_audits,
            backward_audits,
        })
    }

    /// Search for a path in this AuditGraph which indicates that the given
    /// version of the crate satisfies the given criteria. Returns the path used
    /// for that proof if successful, and information about the versions which
    /// could be reached from both the target and root if unsuccessful.
    pub fn search(
        &self,
        criteria_idx: usize,
        version: &VetVersion,
        mode: SearchMode,
    ) -> Result<Vec<DeltaEdgeOrigin>, SearchFailure> {
        // First, search backwards, starting from the target, as that's more
        // likely to have a limited graph to traverse.
        // This also interacts well with the search ordering from
        // search_for_path, which prefers edges closer to `None` when
        // traversing.
        search_for_path(
            &self.backward_audits,
            criteria_idx,
            Some(version),
            None,
            mode,
        )
        .map_err(|reachable_from_target| {
            assert!(
                mode != SearchMode::RegenerateExemptions,
                "RegenerateExemptions search mode cannot fail"
            );

            // The search failed, perform the search in the other direction
            // in order to also get the set of nodes reachable from the
            // root. We can `unwrap_err()` here, as we'll definitely fail.
            let reachable_from_root = search_for_path(
                &self.forward_audits,
                criteria_idx,
                None,
                Some(version),
                mode,
            )
            .unwrap_err();
            SearchFailure {
                reachable_from_root,
                reachable_from_target,
            }
        })
    }
}

/// Core algorithm used to search for a path between two versions within a
/// DirectedAuditGraph. A path with the fewest "caveats" will be used in order
/// to minimize dependence on exemptions and freshly imported audits.
fn search_for_path(
    audit_graph: &DirectedAuditGraph<'_>,
    criteria_idx: usize,
    from_version: Option<&VetVersion>,
    to_version: Option<&VetVersion>,
    mode: SearchMode,
) -> Result<Vec<DeltaEdgeOrigin>, SortedSet<Option<VetVersion>>> {
    assert!(
        mode != SearchMode::RegenerateExemptions || to_version.is_none(),
        "RegenerateExemptions requires searching towards root"
    );

    // Search for any path through the graph with edges that satisfy criteria.
    // Finding any path validates that we satisfy that criteria.
    //
    // All full-audits and exemptions have been "desugarred" to a delta from
    // None, meaning our graph now has exactly one source and one sink,
    // significantly simplifying the start and end conditions.
    //
    // Some edges have caveats which we want to avoid requiring, so we defer
    // edges with caveats to be checked later, after all edges without caveats
    // have been visited. This is done by storing work to do in a BinaryHeap,
    // sorted by the caveats which apply to each node. This means that if we
    // find a patch without using a node with caveats, it's unambiguous proof we
    // don't need edges with caveats.
    #[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
    enum CaveatLevel {
        None,
        NonImportableAudit,
        PreferredExemption,
        PreferredUnpublished,
        FreshPublisher,
        FreshImport,
        Exemption,
        Unpublished,
        FreshExemption,
    }

    #[derive(Debug)]
    struct Node<'a> {
        version: Option<&'a VetVersion>,
        origin_version: Option<&'a VetVersion>,
        path: Vec<DeltaEdgeOrigin>,
        caveat_level: CaveatLevel,
    }

    impl Node<'_> {
        fn key(&self) -> impl Ord + '_ {
            // Nodes are compared by caveat level. A lower caveat level makes
            // the node sort higher, as it will be stored in a max heap.
            //
            // Once we've sorted by all caveats, we sort by the version
            // (preferring lower versions), exemption origin version (preferring
            // smaller exemptions), the length of the path (preferring short
            // paths), and then the most recently added DeltaEdgeOrigin
            // (preferring more-local audits).
            //
            // NOTE: This ordering logic priorities assume `to_version == None`,
            // as we will only be searched in the other direction if the search
            // is guaranteed to fail, in which case ordering doesn't matter (as
            // we're going to visit every node).
            Reverse((
                self.caveat_level,
                self.version,
                self.exemption_origin_version(),
                self.path.len(),
                self.path.last(),
            ))
        }

        // To make better decisions when selecting exemptions, exemption edges
        // with lower origin versions are preferred over those with higher
        // origin versions. This is checked before path length, as a longer path
        // which uses a smaller exemption is generally preferred to a short one
        // which uses a full-exemption. This is ignored for other edge types.
        fn exemption_origin_version(&self) -> Option<&VetVersion> {
            if matches!(
                self.caveat_level,
                CaveatLevel::PreferredExemption
                    | CaveatLevel::Exemption
                    | CaveatLevel::FreshExemption
            ) {
                self.origin_version
            } else {
                None
            }
        }
    }
    impl<'a> PartialEq for Node<'a> {
        fn eq(&self, other: &Self) -> bool {
            self.key() == other.key()
        }
    }
    impl<'a> Eq for Node<'a> {}
    impl<'a> PartialOrd for Node<'a> {
        fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
            Some(self.cmp(other))
        }
    }
    impl<'a> Ord for Node<'a> {
        fn cmp(&self, other: &Self) -> std::cmp::Ordering {
            self.key().cmp(&other.key())
        }
    }

    let mut queue = BinaryHeap::new();
    queue.push(Node {
        version: from_version,
        origin_version: from_version,
        path: Vec::new(),
        caveat_level: CaveatLevel::None,
    });

    let mut visited = SortedSet::new();
    while let Some(Node {
        version,
        origin_version: _,
        path,
        caveat_level,
    }) = queue.pop()
    {
        // If We've been to a version before, We're not going to get a better
        // result revisiting it, as we visit the "best" edges first.
        if !visited.insert(version) {
            continue;
        }

        // We found a path! Return a search result reflecting what we
        // discovered.
        if version == to_version {
            return Ok(path);
        }

        // Apply deltas to move along to the next layer of the search, adding it
        // to our queue.
        let edges = audit_graph.get(&version).map(|v| &v[..]).unwrap_or(&[]);
        for edge in edges {
            // We'll allow any criteria if we're regenerating exemption edges.
            let allow_any_criteria = mode == SearchMode::RegenerateExemptions
                && matches!(edge.origin, DeltaEdgeOrigin::Exemption { .. });
            if !allow_any_criteria && !edge.criteria.has_criteria(criteria_idx) {
                // This edge never would have been useful to us.
                continue;
            }
            if visited.contains(&edge.version) {
                // We've been to the target of this edge already.
                continue;
            }

            // Compute the level of caveats which are being added by the current edge
            let edge_caveat_level = match &edge.origin {
                DeltaEdgeOrigin::StoredLocalAudit { importable, .. } if !importable => {
                    CaveatLevel::NonImportableAudit
                }
                DeltaEdgeOrigin::Exemption { .. } if mode == SearchMode::PreferExemptions => {
                    CaveatLevel::PreferredExemption
                }
                DeltaEdgeOrigin::Exemption { .. } => CaveatLevel::Exemption,
                DeltaEdgeOrigin::FreshExemption { .. } => unreachable!(),
                DeltaEdgeOrigin::Unpublished { .. } => match mode {
                    // When preferring exemptions, prefer existing unpublished
                    // entries to avoid imports.lock churn.
                    SearchMode::PreferExemptions if !edge.freshness.is_fresh() => {
                        CaveatLevel::PreferredUnpublished
                    }
                    SearchMode::PreferExemptions => CaveatLevel::Unpublished,
                    // Otherwise, prefer fresh to avoid outdated versions.
                    _ if edge.freshness.is_fresh() => CaveatLevel::PreferredUnpublished,
                    _ => CaveatLevel::Unpublished,
                },
                _ => match edge.freshness {
                    DeltaEdgeFreshness::Stale => CaveatLevel::None,
                    DeltaEdgeFreshness::FreshPublisher => CaveatLevel::FreshPublisher,
                    DeltaEdgeFreshness::Fresh => CaveatLevel::FreshImport,
                },
            };

            queue.push(Node {
                version: edge.version,
                origin_version: version,
                path: path.iter().cloned().chain([edge.origin.clone()]).collect(),
                caveat_level: caveat_level.max(edge_caveat_level),
            });
        }

        // If we're regenerating exemptions, add a fresh exemption edge which
        // directly leads to the root version.
        if mode == SearchMode::RegenerateExemptions {
            queue.push(Node {
                version: None,
                origin_version: version,
                path: path
                    .iter()
                    .cloned()
                    .chain([DeltaEdgeOrigin::FreshExemption {
                        version: version
                            .expect("RegenerateExemptions requires searching towards None")
                            .clone(),
                    }])
                    .collect(),
                caveat_level: caveat_level.max(CaveatLevel::FreshExemption),
            })
        }
    }

    // Complete failure, we need more audits for this package, so all that
    // matters is what nodes were reachable.
    Err(visited.into_iter().map(|v| v.cloned()).collect())
}

impl<'a> ResolveReport<'a> {
    pub fn has_errors(&self) -> bool {
        // Just check the conclusion
        !matches!(self.conclusion, Conclusion::Success(_))
    }

    pub fn _has_warnings(&self) -> bool {
        false
    }

    pub fn compute_suggest(
        &self,
        cfg: &Config,
        store: &Store,
        network: Option<&Network>,
    ) -> Result<Option<Suggest>, SuggestError> {
        let _suggest_span = trace_span!("suggest").entered();
        let fail = if let Conclusion::FailForVet(fail) = &self.conclusion {
            fail
        } else {
            // Nothing to suggest unless we failed for vet
            return Ok(None);
        };

        let cache = Cache::acquire(cfg)?;

        let warnings = RefCell::new(Vec::new());

        let mut store = store.clone_for_suggest(false);
        let registry = if let (false, OutputFormat::Human, Some(network)) = (
            cfg.cli.no_registry_suggestions,
            cfg.cli.output_format,
            network,
        ) {
            tokio::runtime::Handle::current()
                .block_on(store.fetch_registry_audits(cfg, network, &cache))
                .map_err(|error| warnings.borrow_mut().push(error.to_string()))
                .ok()
        } else {
            None
        };

        const THIS_PROJECT: &str = "this project";

        let mut trusted_publishers: FastMap<u64, SortedSet<ImportName>> = FastMap::new();
        for trusted_entry in store.audits.trusted.values().flatten() {
            trusted_publishers
                .entry(trusted_entry.user_id)
                .or_default()
                .insert(THIS_PROJECT.to_owned());
        }
        for (import_name, audits_file) in store.imported_audits() {
            for trusted_entry in audits_file.trusted.values().flatten() {
                trusted_publishers
                    .entry(trusted_entry.user_id)
                    .or_default()
                    .insert(import_name.clone());
            }
        }

        let suggest_progress =
            progress_bar("Suggesting", "relevant audits", fail.failures.len() as u64);

        let mut suggestions = tokio::runtime::Handle::current()
            .block_on(join_all(fail.failures.iter().map(
                |(failure_idx, audit_failure)| async {
                    let _guard = IncProgressOnDrop(&suggest_progress, 1);

                    let failure_idx = *failure_idx;
                    let package = &self.graph.nodes[failure_idx];
                    let result = self.results[failure_idx]
                        .as_ref()
                        .expect("failed package without ResolveResults?");

                    // Precompute some "notable" parents
                    let notable_parents: Vec<_> = self.graph.nodes[failure_idx]
                        .reverse_deps
                        .iter()
                        .map(|&parent| self.graph.nodes[parent].name.to_string())
                        .collect();

                    let Some((suggested_diff, extra_suggested_diff)) = suggest_delta(
                        &cfg.metadata,
                        network,
                        &cache,
                        package.name,
                        &package.version,
                        audit_failure
                            .criteria_failures
                            .indices()
                            .map(|criteria_idx| {
                                result.search_results[criteria_idx].as_ref().unwrap_err()
                            }),
                        &warnings,
                    )
                    .await
                    else {
                        return vec![];
                    };

                    // Attempt to look up the publisher of the target version
                    // for the suggested diff, and also record whether the given
                    // package has a sole publisher.
                    let mut is_sole_publisher = false;
                    let publisher_id =
                        if let (Some(network), None) = (&network, &suggested_diff.to.git_rev) {
                            let versions = cache
                                .get_publishers(
                                    Some(network),
                                    package.name,
                                    [&suggested_diff.to.semver].into_iter().collect(),
                                )
                                .await
                                .unwrap_or_default();
                            let publisher_count = versions
                                .iter()
                                .flat_map(|(_, details)| &details.published_by)
                                .collect::<FastSet<_>>()
                                .len();
                            is_sole_publisher = publisher_count == 1;
                            versions
                                .into_iter()
                                .find(|(v, _)| v == &suggested_diff.to.semver)
                                .and_then(|(_, d)| d.published_by)
                        } else {
                            None
                        };

                    // Compute the trust hint, which is the information used to generate "consider
                    // cargo trust FOO" messages. There can be multiple potential hints, but we
                    // only provide the most relevant one. If the publisher of the in-use version
                    // of the crate is potentially trustworthy, we suggest that. If not (and we
                    // don't already have at least one trusted entry for this crate), we iterate
                    // over the crate releases in reverse order to see if another version was
                    // published by a potentially-trustworth author. We pick the first one of
                    // those we find, if any.
                    let trust_hint = {
                        let mut exact_version = false;
                        let id_for_hint = if publisher_id
                            .map_or(false, |i| trusted_publishers.contains_key(&i))
                        {
                            exact_version = true;
                            publisher_id
                        } else if !store.audits.trusted.contains_key(package.name) {
                            cache
                                .get_cached_publishers(package.name)
                                .iter()
                                .rev()
                                .filter_map(|(_, details)| details.published_by)
                                .find(|i| trusted_publishers.contains_key(i))
                        } else {
                            None
                        };

                        id_for_hint.map(|id| {
                            let mut trusted_by: Vec<String> = trusted_publishers
                                .get(&id)
                                .unwrap()
                                .iter()
                                .cloned()
                                .collect();
                            // If we're already trusted by this project, don't
                            // bother listing anyone else.
                            if trusted_by.iter().any(|s| s == THIS_PROJECT) {
                                trusted_by.retain(|s| s == THIS_PROJECT);
                            }
                            let publisher = cache.get_crates_user_info(id).unwrap();
                            TrustHint {
                                trusted_by,
                                publisher,
                                exact_version,
                            }
                        })
                    };

                    let publisher_login = publisher_id
                        .and_then(|user_id| cache.get_crates_user_info(user_id))
                        .map(|pi| pi.login);

                    let mut registry_suggestion: Vec<_> = join_all(registry.iter().flatten().map(
                        |(name, entry, audits)| async {
                            // Don't search for git deltas in the registry.
                            if suggested_diff.to.git_rev.is_some() {
                                return None;
                            }

                            let audit_graph = AuditGraph::build(
                                &store,
                                &self.criteria_mapper,
                                package.name,
                                Some(audits),
                            )
                            .ok()?;

                            // If we have an extra diff, only try to search for
                            // a path to the "from" version in that diff, to
                            // make the results more comparable.
                            let target_version = extra_suggested_diff
                                .as_ref()
                                .and_then(|d| d.from.as_ref())
                                .unwrap_or(&package.version);

                            let failures: Vec<_> = audit_failure
                                .criteria_failures
                                .indices()
                                .filter_map(|criteria_idx| {
                                    audit_graph
                                        .search(
                                            criteria_idx,
                                            target_version,
                                            SearchMode::PreferExemptions,
                                        )
                                        .err()
                                })
                                .collect();

                            let (registry_suggested_diff, _) = suggest_delta(
                                &cfg.metadata,
                                network,
                                &cache,
                                package.name,
                                target_version,
                                failures.iter(),
                                &warnings,
                            )
                            .await?;

                            if registry_suggested_diff.diffstat.count()
                                < suggested_diff.diffstat.count()
                            {
                                Some(RegistrySuggestion {
                                    name: name.clone(),
                                    url: entry.url.clone(),
                                    diff: registry_suggested_diff,
                                })
                            } else {
                                None
                            }
                        },
                    ))
                    .await
                    .into_iter()
                    .flatten()
                    .collect();
                    registry_suggestion.sort_by_key(|suggestion| suggestion.diff.diffstat.count());

                    extra_suggested_diff
                        .into_iter()
                        .map(|suggested_diff| SuggestItem {
                            package: failure_idx,
                            suggested_diff,
                            suggested_criteria: audit_failure.criteria_failures.clone(),
                            notable_parents: notable_parents.clone(),
                            publisher_login: None,
                            trust_hint: None,
                            is_sole_publisher: false,
                            registry_suggestion: vec![],
                        })
                        .chain([SuggestItem {
                            package: failure_idx,
                            suggested_diff,
                            suggested_criteria: audit_failure.criteria_failures.clone(),
                            notable_parents: notable_parents.clone(),
                            publisher_login,
                            trust_hint,
                            is_sole_publisher,
                            registry_suggestion,
                        }])
                        .collect()
                },
            )))
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();

        // First sort by diff size (ascending), then package name, then version
        // being certified, to have stable output ordering.
        suggestions.sort_by_key(|item| {
            (
                item.suggested_diff.diffstat.count(),
                self.graph.nodes[item.package].name,
                item.suggested_diff.to.clone(),
            )
        });

        // If we have duplicate suggestions in the output, e.g. due to multiple
        // versions of the same crate requiring the same new audit, deduplicate
        // them in the output to avoid clutter.
        suggestions.dedup_by(|a, b| {
            if self.graph.nodes[a.package].name == self.graph.nodes[b.package].name
                && a.suggested_diff == b.suggested_diff
            {
                // Per the `dedup_by` documentation, if true is returned, `a`
                // will be removed. Preserve its notable parents.
                b.notable_parents.extend_from_slice(&a.notable_parents);
                true
            } else {
                false
            }
        });

        // Sort and remove any duplicate entries from `notable_parents`.
        for s in &mut suggestions {
            s.notable_parents.sort();
            s.notable_parents.dedup();
        }

        let total_lines = suggestions
            .iter()
            .map(|s| s.suggested_diff.diffstat.count())
            .sum();

        let mut suggestions_by_criteria = SortedMap::<CriteriaName, Vec<SuggestItem>>::new();
        for s in suggestions.clone().into_iter() {
            // Generate a suggestion for which criteria to use for the given
            // suggestion. For each criteria, also list out others which would
            // imply the required criteria to surface the full set of options.
            let criteria_names = self
                .criteria_mapper
                .minimal_indices(&s.suggested_criteria)
                .map(|criteria_idx| {
                    let name = self.criteria_mapper.criteria_name(criteria_idx);
                    let implied_by = self
                        .criteria_mapper
                        .implied_by_indices(criteria_idx)
                        .map(|idx| format!("or {}", self.criteria_mapper.criteria_name(idx)))
                        .collect::<Vec<_>>();

                    if implied_by.is_empty() {
                        name.to_owned()
                    } else {
                        format!("{} ({})", name, implied_by.join(", "))
                    }
                })
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
            warnings: warnings.into_inner(),
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
        from: Option<&VetVersion>,
        to: &VetVersion,
    ) -> Vec<CriteriaName> {
        let fail = if let Conclusion::FailForVet(fail) = &self.conclusion {
            fail
        } else {
            return Vec::new();
        };

        let mut criteria = self.criteria_mapper.no_criteria();

        // Make owned versions of the `Version` types, such that we can look
        // them up in search results more easily.
        let from = from.cloned();
        let to = Some(to.clone());

        // Enumerate over the recorded failures, adding any criteria for this
        // delta which would connect that package version into the audit graph.
        for (failure_idx, audit_failure) in &fail.failures {
            let package = &self.graph.nodes[*failure_idx];
            if package.name != package_name {
                continue;
            }

            let result = &self.results[*failure_idx]
                .as_ref()
                .expect("failure without ResolveResults?");
            for criteria_idx in audit_failure.criteria_failures.indices() {
                let search_result = &result.search_results[criteria_idx];
                if let Err(SearchFailure {
                    reachable_from_root,
                    reachable_from_target,
                }) = search_result
                {
                    if reachable_from_target.contains(&to) && reachable_from_root.contains(&from) {
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
        out: &Arc<dyn Out>,
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
        out: &Arc<dyn Out>,
        _cfg: &Config,
        suggest: Option<&Suggest>,
    ) -> Result<(), std::io::Error> {
        if let Some(suggest) = suggest {
            suggest.print_human(out, self)?;
        } else {
            // This API is only used for vet-suggest
            writeln!(out, "Nothing to suggest, you're fully audited!");
        }
        Ok(())
    }

    /// Print a full json report
    pub fn print_json(
        &self,
        out: &Arc<dyn Out>,
        suggest: Option<&Suggest>,
    ) -> Result<(), miette::Report> {
        let result = JsonReport {
            conclusion: match &self.conclusion {
                Conclusion::Success(success) => {
                    let json_package = |pkgidx: &PackageIdx| {
                        let package = &self.graph.nodes[*pkgidx];
                        JsonPackage {
                            name: package.name.to_owned(),
                            version: package.version.clone(),
                        }
                    };
                    JsonReportConclusion::Success(JsonReportSuccess {
                        vetted_fully: success.vetted_fully.iter().map(json_package).collect(),
                        vetted_partially: success
                            .vetted_partially
                            .iter()
                            .map(json_package)
                            .collect(),
                        vetted_with_exemptions: success
                            .vetted_with_exemptions
                            .iter()
                            .map(json_package)
                            .collect(),
                    })
                }
                Conclusion::FailForViolationConflict(fail) => {
                    JsonReportConclusion::FailForViolationConflict(
                        JsonReportFailForViolationConflict {
                            violations: fail
                                .violations
                                .iter()
                                .map(|(pkgidx, violations)| {
                                    let package = &self.graph.nodes[*pkgidx];
                                    let key = format!("{}:{}", package.name, package.version);
                                    (key, violations.clone())
                                })
                                .collect(),
                        },
                    )
                }
                Conclusion::FailForVet(fail) => {
                    // FIXME: How to report confidence for suggested criteria?
                    let json_suggest_item = |item: &SuggestItem| {
                        let package = &self.graph.nodes[item.package];
                        JsonSuggestItem {
                            name: package.name.to_owned(),
                            notable_parents: FormatShortList::string(item.notable_parents.clone()),
                            suggested_criteria: self
                                .criteria_mapper
                                .criteria_names(&item.suggested_criteria)
                                .map(|s| s.to_owned())
                                .collect(),
                            suggested_diff: item.suggested_diff.clone(),
                        }
                    };
                    JsonReportConclusion::FailForVet(JsonReportFailForVet {
                        failures: fail
                            .failures
                            .iter()
                            .map(|(pkgidx, audit_fail)| {
                                let package = &self.graph.nodes[*pkgidx];
                                JsonVetFailure {
                                    name: package.name.to_owned(),
                                    version: package.version.clone(),
                                    missing_criteria: self
                                        .criteria_mapper
                                        .criteria_names(&audit_fail.criteria_failures)
                                        .map(|s| s.to_owned())
                                        .collect(),
                                }
                            })
                            .collect(),
                        suggest: suggest.as_ref().map(|suggest| JsonSuggest {
                            suggestions: suggest
                                .suggestions
                                .iter()
                                .map(json_suggest_item)
                                .collect(),
                            suggest_by_criteria: suggest
                                .suggestions_by_criteria
                                .iter()
                                .map(|(criteria, items)| {
                                    (
                                        criteria.to_owned(),
                                        items.iter().map(json_suggest_item).collect::<Vec<_>>(),
                                    )
                                })
                                .collect(),
                            total_lines: suggest.total_lines,
                        }),
                    })
                }
            },
        };

        serde_json::to_writer_pretty(&**out, &result).into_diagnostic()?;

        Ok(())
    }
}

impl Success {
    pub fn print_human(
        &self,
        out: &Arc<dyn Out>,
        _report: &ResolveReport<'_>,
        _cfg: &Config,
    ) -> Result<(), std::io::Error> {
        let fully_audited_count = self.vetted_fully.len();
        let partially_audited_count: usize = self.vetted_partially.len();
        let exemptions_count = self.vetted_with_exemptions.len();

        // Figure out how many entries we're going to print
        let mut count_count = (fully_audited_count != 0) as usize
            + (partially_audited_count != 0) as usize
            + (exemptions_count != 0) as usize;

        // Print out a summary of how we succeeded
        if count_count == 0 {
            writeln!(
                out,
                "Vetting Succeeded (because you have no third-party dependencies)"
            );
        } else {
            write!(out, "Vetting Succeeded (");

            if fully_audited_count != 0 {
                write!(out, "{fully_audited_count} fully audited");
                count_count -= 1;
                if count_count > 0 {
                    write!(out, ", ");
                }
            }
            if partially_audited_count != 0 {
                write!(out, "{partially_audited_count} partially audited");
                count_count -= 1;
                if count_count > 0 {
                    write!(out, ", ");
                }
            }
            if exemptions_count != 0 {
                write!(out, "{exemptions_count} exempted");
                count_count -= 1;
                if count_count > 0 {
                    write!(out, ", ");
                }
            }

            writeln!(out, ")");
        }
        Ok(())
    }
}

impl Suggest {
    pub fn print_human(
        &self,
        out: &Arc<dyn Out>,
        report: &ResolveReport<'_>,
    ) -> Result<(), std::io::Error> {
        for (criteria, suggestions) in &self.suggestions_by_criteria {
            writeln!(out, "recommended audits for {criteria}:");

            let mut strings = suggestions
                .iter()
                .map(|item| {
                    let package = &report.graph.nodes[item.package];
                    let cmd = match &item.suggested_diff.from {
                        Some(from) => format!(
                            "cargo vet diff {} {} {}",
                            package.name, from, item.suggested_diff.to
                        ),
                        None => format!(
                            "cargo vet inspect {} {}",
                            package.name, item.suggested_diff.to
                        ),
                    };
                    let publisher = item
                        .publisher_login
                        .clone()
                        .unwrap_or_else(|| "UNKNOWN".into());
                    let parents = FormatShortList::string(item.notable_parents.clone());
                    let diffstat = match &item.suggested_diff.from {
                        Some(_) => format!("{}", item.suggested_diff.diffstat),
                        None => format!("{} lines", item.suggested_diff.diffstat.count()),
                    };
                    (cmd, publisher, parents, diffstat, item)
                })
                .collect::<Vec<_>>();

            let (h0, h1, h2, h3) = ("Command", "Publisher", "Used By", "Audit Size");
            let mut max0 = console::measure_text_width(h0);
            let mut max1 = console::measure_text_width(h1);
            let mut max2 = console::measure_text_width(h2);
            for (s0, s1, s2, ..) in &mut strings {
                // If the command is too long (happens occasionally, particularly with @git
                // version specifiers), wrap subsequent columns to the next line.
                const MAX_COMMAND_CHARS: usize = 52;
                let command_width = console::measure_text_width(s0);
                if command_width > MAX_COMMAND_CHARS {
                    s0.push('\n');
                    s0.push_str(&" ".repeat(MAX_COMMAND_CHARS + 4));
                }
                max0 = max0.max(command_width.min(MAX_COMMAND_CHARS));
                max1 = max1.max(console::measure_text_width(s1));
                max2 = max2.max(console::measure_text_width(s2));
            }

            writeln!(
                out,
                "{}",
                out.style()
                    .bold()
                    .dim()
                    .apply_to(format_args!("    {h0:max0$}  {h1:max1$}  {h2:max2$}  {h3}"))
            );
            for (s0, s1, s2, s3, item) in strings {
                let package = &report.graph.nodes[item.package];

                write!(
                    out,
                    "{}",
                    out.style()
                        .cyan()
                        .bold()
                        .apply_to(format_args!("    {s0:max0$}"))
                );
                writeln!(out, "  {s1:max1$}  {s2:max2$}  {s3}");

                let dim = out.style().dim();
                for suggestion in &item.registry_suggestion {
                    writeln!(
                        out,
                        "      {} {} {}",
                        dim.clone().apply_to("NOTE:"),
                        dim.clone()
                            .cyan()
                            .bold()
                            .apply_to(format_args!("cargo vet import {}", suggestion.name)),
                        dim.clone()
                            .apply_to(match suggestion.diff.diffstat.count() {
                                0 => "would eliminate this".to_owned(),
                                n => format!("would reduce this to a {n}-line diff"),
                            }),
                    );
                }
                if let Some(hint) = &item.trust_hint {
                    let trust = if hint.trusted_by.len() == 1 {
                        "trusts"
                    } else {
                        "trust"
                    };
                    let caveat = if !hint.exact_version {
                        ", who published another version of this crate"
                    } else {
                        ""
                    };
                    let publisher = hint.publisher.clone();
                    let trusted_by = FormatShortList::new(hint.trusted_by.clone());
                    writeln!(
                        out,
                        "      {} {}",
                        dim.clone().apply_to(format_args!(
                            "NOTE: {trusted_by} {trust} {publisher}{caveat} - consider",
                        )),
                        if item.is_sole_publisher {
                            let this_cmd = format!("cargo vet trust {}", package.name);
                            let all_cmd = format!("cargo vet trust --all {}", publisher.login);
                            format!(
                                "{} {} {}",
                                dim.clone().cyan().apply_to(this_cmd),
                                dim.clone().apply_to("or"),
                                dim.clone().cyan().apply_to(all_cmd),
                            )
                        } else {
                            let cmd =
                                format!("cargo vet trust {} {}", package.name, publisher.login);
                            dim.clone().cyan().apply_to(cmd).to_string()
                        }
                    );
                }
            }

            writeln!(out);
        }

        writeln!(out, "estimated audit backlog: {} lines", self.total_lines);

        if !self.warnings.is_empty() {
            writeln!(out);
            for warning in &self.warnings {
                writeln!(
                    out,
                    "{}: {warning}",
                    out.style().yellow().apply_to("WARNING"),
                );
            }
        }

        writeln!(out);
        writeln!(out, "Use |cargo vet certify| to record the audits.");

        Ok(())
    }
}

impl FailForVet {
    fn print_human(
        &self,
        out: &Arc<dyn Out>,
        report: &ResolveReport<'_>,
        _cfg: &Config,
        suggest: Option<&Suggest>,
    ) -> Result<(), std::io::Error> {
        writeln!(out, "Vetting Failed!");
        writeln!(out);
        writeln!(out, "{} unvetted dependencies:", self.failures.len());
        let mut failures = self
            .failures
            .iter()
            .map(|(failed_idx, failure)| (&report.graph.nodes[*failed_idx], failure))
            .collect::<Vec<_>>();
        failures.sort_by_key(|(failed, _)| &failed.version);
        failures.sort_by_key(|(failed, _)| failed.name);
        for (failed_package, failed_audit) in failures {
            let criteria = report
                .criteria_mapper
                .criteria_names(&failed_audit.criteria_failures)
                .collect::<Vec<_>>();

            let label = format!("  {}:{}", failed_package.name, failed_package.version);
            writeln!(out, "{label} missing {criteria:?}");
        }

        // Suggest output generally requires hitting the network.
        if let Some(suggest) = suggest {
            writeln!(out);
            suggest.print_human(out, report)?;
        }

        Ok(())
    }
}

impl FailForViolationConflict {
    fn print_human(
        &self,
        out: &Arc<dyn Out>,
        report: &ResolveReport<'_>,
        _cfg: &Config,
    ) -> Result<(), std::io::Error> {
        writeln!(out, "Violations Found!");

        for (pkgidx, violations) in &self.violations {
            let package = &report.graph.nodes[*pkgidx];
            writeln!(out, "  {}:{}", package.name, package.version);
            for violation in violations {
                match violation {
                    ViolationConflict::UnauditedConflict {
                        violation_source,
                        violation,
                        exemptions,
                    } => {
                        write!(out, "    the ");
                        print_exemption(out, exemptions)?;
                        write!(out, "    conflicts with ");
                        print_entry(out, violation_source, violation)?;
                    }
                    ViolationConflict::AuditConflict {
                        violation_source,
                        violation,
                        audit_source,
                        audit,
                    } => {
                        write!(out, "    the ");
                        print_entry(out, audit_source, audit)?;
                        write!(out, "    conflicts with ");
                        print_entry(out, violation_source, violation)?;
                    }
                }
                writeln!(out);
            }
        }

        fn print_exemption(
            out: &Arc<dyn Out>,
            entry: &ExemptedDependency,
        ) -> Result<(), std::io::Error> {
            writeln!(out, "exemption {}", entry.version);
            writeln!(out, "      criteria: {:?}", entry.criteria);
            if let Some(notes) = &entry.notes {
                writeln!(out, "      notes: {notes}");
            }
            Ok(())
        }

        fn print_entry(
            out: &Arc<dyn Out>,
            source: &Option<ImportName>,
            entry: &AuditEntry,
        ) -> Result<(), std::io::Error> {
            match source {
                None => write!(out, "own "),
                Some(name) => write!(out, "foreign ({name}) "),
            }
            match &entry.kind {
                AuditKind::Full { version, .. } => {
                    writeln!(out, "audit {version}");
                }
                AuditKind::Delta { from, to, .. } => {
                    writeln!(out, "audit {from} -> {to}");
                }
                AuditKind::Violation { violation } => {
                    writeln!(out, "violation against {violation}");
                }
            }
            writeln!(out, "      criteria: {:?}", entry.criteria);
            for (idx, who) in entry.who.iter().enumerate() {
                if idx == 0 {
                    write!(out, "      who: {who}");
                } else {
                    write!(out, ", {who}");
                }
            }
            if !entry.who.is_empty() {
                writeln!(out);
            }
            if let Some(notes) = &entry.notes {
                writeln!(out, "      notes: {notes}");
            }
            Ok(())
        }

        Ok(())
    }
}

async fn suggest_delta(
    metadata: &cargo_metadata::Metadata,
    network: Option<&Network>,
    cache: &Cache,
    package_name: PackageStr<'_>,
    package_version: &VetVersion,
    failures: impl Iterator<Item = &SearchFailure>,
    warnings: &RefCell<Vec<String>>,
) -> Option<(DiffRecommendation, Option<DiffRecommendation>)> {
    // Fetch the set of known versions from crates.io so we know which versions
    // we'll have sources for.
    let known_versions = cache.get_versions(network, package_name).await.ok();

    // Collect up the details of how we failed
    struct Reachable<'a> {
        from_root: SortedSet<&'a Option<VetVersion>>,
        from_target: SortedSet<&'a Option<VetVersion>>,
    }
    let mut reachable = None::<Reachable<'_>>;
    for SearchFailure {
        reachable_from_root,
        reachable_from_target,
    } in failures
    {
        if let Some(Reachable {
            from_root,
            from_target,
        }) = reachable.as_mut()
        {
            // This does the right thing in the common cases, by restricting
            // ourselves to the reachable nodes that are common to all failures,
            // so that we can suggest just one change that will fix everything.
            from_root.retain(|ver| reachable_from_root.contains(ver));
            from_target.retain(|ver| reachable_from_target.contains(ver));
        } else {
            let version_has_sources = |ver: &&Option<VetVersion>| -> bool {
                // We always have sources for an empty crate.
                let Some(ver) = ver else {
                    return true;
                };
                // We only have git sources for the package itself.
                if ver.git_rev.is_some() {
                    return ver == package_version;
                }
                // We have sources if the version has been published to crates.io.
                //
                // For testing fallbacks, assume we always have sources if the
                // index is unavailable.
                known_versions
                    .as_ref()
                    .map_or(true, |versions| versions.contains(&ver.semver))
            };
            reachable = Some(Reachable {
                from_root: reachable_from_root
                    .iter()
                    .filter(version_has_sources)
                    .collect(),
                from_target: reachable_from_target
                    .iter()
                    .filter(version_has_sources)
                    .collect(),
            });
        }
    }

    let Some(Reachable {
        from_root,
        from_target,
    }) = &mut reachable
    else {
        // Nothing failed, return a dummy suggestion for an empty diff.
        return Some((
            DiffRecommendation {
                from: Some(package_version.clone()),
                to: package_version.clone(),
                diffstat: DiffStat {
                    insertions: 0,
                    deletions: 0,
                    files_changed: 0,
                },
            },
            None,
        ));
    };

    // If we have a git revision, we want to ensure the nearest published
    // version has been audited before we suggest an audit for the git revision
    // itself.
    let published_version;
    let mut extra_delta = None;
    if package_version.git_rev.is_some() {
        // Find the largest published revision with an equal or lower semver
        // than the git revision. This will be the published version we
        // encourage auditing first.
        let closest_below = if let Some(known_versions) = &known_versions {
            known_versions
                .iter()
                .filter(|&v| v <= &package_version.semver)
                .max()
        } else {
            // For testing fallbacks, assume the bare version has been published
            // to crates.io.
            Some(&package_version.semver)
        };
        published_version = closest_below.map(|semver| VetVersion {
            semver: semver.clone(),
            git_rev: None,
        });
        // If the closest published version is not already audited, replace the
        // target version with `published_version` in the reachable from target
        // set, ensuring that a delta to that version is suggested rather than a
        // full audit for the git revision.
        if !from_root.contains(&published_version) {
            from_target.remove(&Some(package_version.clone()));
            if from_target.insert(&published_version) {
                extra_delta = Some(Delta {
                    from: published_version.clone(),
                    to: package_version.clone(),
                });
            }
        }
    }

    // Now suggest solutions of those failures
    let mut candidates = Vec::new();
    for &dest in &*from_target {
        let closest_above = from_root.range::<&Option<VetVersion>, _>(dest..).next();
        let closest_below = from_root
            .range::<&Option<VetVersion>, _>(..dest)
            .next_back();

        for &closest in closest_below.into_iter().chain(closest_above) {
            candidates.push(Delta {
                from: closest.clone(),
                to: dest.clone().unwrap(),
            });
        }
    }

    let do_fetch_and_diffstat = |delta| async move {
        match cache
            .fetch_and_diffstat_package(metadata, network, package_name, &delta)
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
                warnings
                    .borrow_mut()
                    .push(format!("error diffing {}:{}: {}", package_name, delta, err));
                None
            }
        }
    };

    let diffstats = join_all(candidates.into_iter().map(do_fetch_and_diffstat)).await;

    // If we need an "extra delta" due to a git revision, also get the diffstat
    // for that entry.
    let extra_diffstat = if let Some(delta) = extra_delta {
        do_fetch_and_diffstat(delta).await
    } else {
        None
    };

    let recommendation = diffstats
        .into_iter()
        .flatten()
        .min_by_key(|diff| diff.diffstat.count())?;

    Some((recommendation, extra_diffstat))
}

/// Resolve which entries in the store and imports.lock are required to
/// successfully audit this package. May return `None` if the package cannot
/// successfully vet given the restrictions placed upon it.
///
/// NOTE: A package which does not exist in the dependency will return the empty
/// set, as it does not have any audit requirements.
///
/// [`SearchMode`] controls how edges are selected when searching for paths.
#[tracing::instrument(skip(graph, criteria_mapper, requirements, store))]
fn resolve_package_required_entries(
    graph: &DepGraph<'_>,
    criteria_mapper: &CriteriaMapper,
    requirements: &[CriteriaSet],
    store: &Store,
    package_name: PackageStr<'_>,
    search_mode: SearchMode,
) -> Option<SortedMap<RequiredEntry, CriteriaSet>> {
    assert_eq!(graph.nodes.len(), requirements.len());

    // Collect the list of third-party packages with the given name, along with their requirements.
    let packages: Vec<_> = graph
        .nodes
        .iter()
        .zip(requirements)
        .filter(|(package, _)| package.name == package_name && package.is_third_party)
        .collect();

    // If there are no third-party packages with the name, we definitely don't need any entries.
    if packages.is_empty() {
        return Some(SortedMap::new());
    }

    let Ok(audit_graph) = AuditGraph::build(store, criteria_mapper, package_name, None) else {
        // There were violations when building the audit graph, return `None` to
        // indicate that this package is failing.
        return None;
    };

    let mut required_entries = SortedMap::new();
    for &(package, reqs) in &packages {
        // Do the minimal set of searches to validate that the required criteria
        // are matched.
        for criteria_idx in criteria_mapper.minimal_indices(reqs) {
            let Ok(path) = audit_graph.search(criteria_idx, &package.version, search_mode) else {
                // This package failed to vet, return `None`.
                return None;
            };

            let mut add_entry = |entry: RequiredEntry| {
                required_entries
                    .entry(entry)
                    .or_insert_with(|| criteria_mapper.no_criteria())
                    .set_criteria(criteria_idx);
            };

            for origin in path {
                match origin {
                    DeltaEdgeOrigin::Exemption { exemption_index } => {
                        add_entry(RequiredEntry::Exemption { exemption_index });
                    }
                    DeltaEdgeOrigin::FreshExemption { version } => {
                        add_entry(RequiredEntry::FreshExemption { version });
                    }
                    DeltaEdgeOrigin::ImportedAudit {
                        import_index,
                        audit_index,
                    } => {
                        add_entry(RequiredEntry::Audit {
                            import_index,
                            audit_index,
                        });
                    }
                    DeltaEdgeOrigin::WildcardAudit {
                        import_index,
                        audit_index,
                        publisher_index,
                    } => {
                        if let Some(import_index) = import_index {
                            add_entry(RequiredEntry::WildcardAudit {
                                import_index,
                                audit_index,
                            })
                        }
                        add_entry(RequiredEntry::Publisher { publisher_index })
                    }
                    DeltaEdgeOrigin::Trusted { publisher_index } => {
                        add_entry(RequiredEntry::Publisher { publisher_index })
                    }
                    DeltaEdgeOrigin::Unpublished { unpublished_index } => {
                        add_entry(RequiredEntry::Unpublished { unpublished_index })
                    }
                    DeltaEdgeOrigin::StoredLocalAudit { audit_index, .. } => {
                        add_entry(RequiredEntry::LocalAudit { audit_index })
                    }
                }
            }
        }
        continue;
    }

    Some(required_entries)
}

/// Per-package options to control store pruning.
#[derive(Copy, Clone)]
pub struct UpdateMode {
    pub search_mode: SearchMode,
    pub prune_exemptions: bool,
    pub prune_non_importable_audits: bool,
    pub prune_imports: bool,
}

pub(crate) struct StoreUpdates {
    pub audits: SortedMap<String, Vec<AuditEntry>>,
    pub imports: ImportsFile,
    pub exemptions: SortedMap<PackageName, Vec<ExemptedDependency>>,
}

impl StoreUpdates {
    pub fn apply(self, store: &mut Store) {
        store.audits.audits = self.audits;
        store.imports = self.imports;
        store.config.exemptions = self.exemptions;
    }
}

/// Refresh the state of the store, importing required audits, and optionally
/// pruning unnecessary exemptions, audits, and/or imports.
pub fn update_store(
    cfg: &Config,
    store: &mut Store,
    mode: impl FnMut(PackageStr<'_>) -> UpdateMode,
) {
    get_store_updates(cfg, store, mode).apply(store);
}

/// The non-mutating core of `update_store` for use in non-mutating situations.
pub(crate) fn get_store_updates(
    cfg: &Config,
    store: &Store,
    mut mode: impl FnMut(PackageStr<'_>) -> UpdateMode,
) -> StoreUpdates {
    // Compute the set of required entries from the store for all packages in
    // the dependency graph.
    let graph = DepGraph::new(
        &cfg.metadata,
        cfg.cli.filter_graph.as_ref(),
        Some(&store.config.policy),
    );
    let criteria_mapper = CriteriaMapper::new(&store.audits.criteria);
    let requirements = resolve_requirements(&graph, &store.config.policy, &criteria_mapper);

    let mut required_entries = SortedMap::new();
    for package in &graph.nodes {
        required_entries.entry(package.name).or_insert_with(|| {
            resolve_package_required_entries(
                &graph,
                &criteria_mapper,
                &requirements,
                store,
                package.name,
                mode(package.name).search_mode,
            )
        });
    }

    // Remove unused non-importable audits.
    let mut new_audits = store.audits.audits.clone();
    for (pkg, entries) in &required_entries {
        if !mode(pkg).prune_non_importable_audits {
            continue;
        }
        let Some(entries) = entries else { continue };

        if let Some(audit_entries) = new_audits.get_mut(*pkg) {
            *audit_entries = std::mem::take(audit_entries)
                .into_iter()
                .enumerate()
                .filter(|&(audit_index, ref entry)| {
                    // Keep the entry if it's importable (i.e. it could be used externally) or it's
                    // used locally.
                    entry.importable
                        || entries.contains_key(&RequiredEntry::LocalAudit { audit_index })
                })
                .map(|(_, entry)| entry)
                .collect();
        }
    }

    // Dummy value to use if a package isn't found in `required_entries` - no
    // edges will be required.
    let no_required_entries = Some(SortedMap::new());

    let mut new_imports = ImportsFile {
        unpublished: SortedMap::new(),
        publisher: SortedMap::new(),
        audits: SortedMap::new(),
    };

    // Determine which live imports to keep in the imports.lock file.
    for (import_index, (import_name, live_audits_file)) in
        store.imported_audits().iter().enumerate()
    {
        let new_audits_file = AuditsFile {
            criteria: live_audits_file.criteria.clone(),

            wildcard_audits: live_audits_file
                .wildcard_audits
                .iter()
                .map(|(pkgname, wildcard_audits)| {
                    let prune_imports = mode(&pkgname[..]).prune_imports;
                    let required_entries = required_entries
                        .get(&pkgname[..])
                        .unwrap_or(&no_required_entries);
                    (
                        pkgname,
                        wildcard_audits
                            .iter()
                            .enumerate()
                            .filter(|&(audit_index, entry)| {
                                // Keep existing if we're not pruning imports.
                                if !prune_imports && !entry.is_fresh_import {
                                    return true;
                                }

                                if let Some(required_entries) = required_entries {
                                    required_entries.contains_key(&RequiredEntry::WildcardAudit {
                                        import_index,
                                        audit_index,
                                    })
                                } else {
                                    !entry.is_fresh_import
                                }
                            })
                            .map(|(_, entry)| WildcardEntry {
                                is_fresh_import: false,
                                ..entry.clone()
                            })
                            .collect::<Vec<_>>(),
                    )
                })
                .filter(|(_, l)| !l.is_empty())
                .map(|(n, mut l)| {
                    l.sort();
                    (n.clone(), l)
                })
                .collect(),

            audits: live_audits_file
                .audits
                .iter()
                .map(|(pkgname, audits)| {
                    let prune_imports = mode(&pkgname[..]).prune_imports;
                    let (uses_package, required_entries) = match required_entries.get(&pkgname[..])
                    {
                        Some(e) => (true, e),
                        None => (false, &no_required_entries),
                    };
                    (
                        pkgname,
                        audits
                            .iter()
                            .enumerate()
                            .filter(|&(audit_index, entry)| {
                                // Keep existing if we're not pruning imports.
                                if !prune_imports && !entry.is_fresh_import {
                                    return true;
                                }

                                // Keep violations if the package is used in the graph.
                                if matches!(entry.kind, AuditKind::Violation { .. }) {
                                    return uses_package;
                                }

                                if let Some(required_entries) = required_entries {
                                    required_entries.contains_key(&RequiredEntry::Audit {
                                        import_index,
                                        audit_index,
                                    })
                                } else {
                                    !entry.is_fresh_import
                                }
                            })
                            .map(|(_, entry)| AuditEntry {
                                is_fresh_import: false,
                                ..entry.clone()
                            })
                            .collect::<Vec<_>>(),
                    )
                })
                .filter(|(_, l)| !l.is_empty())
                .map(|(n, mut l)| {
                    l.sort();
                    (n.clone(), l)
                })
                .collect(),

            // We never import trusted entries in imports.lock.
            trusted: SortedMap::new(),
        };
        new_imports
            .audits
            .insert(import_name.clone(), new_audits_file);
    }

    // Determine which live publisher information to keep in the imports.lock file.
    for (pkgname, publishers) in store.publishers() {
        let prune_imports = mode(&pkgname[..]).prune_imports;
        let required_entries = required_entries
            .get(&pkgname[..])
            .unwrap_or(&no_required_entries);
        let mut publishers: Vec<_> = publishers
            .iter()
            .enumerate()
            .filter(|&(publisher_index, entry)| {
                // Keep existing if we're not pruning imports.
                if !prune_imports && !entry.is_fresh_import {
                    return true;
                }

                if let Some(required_entries) = required_entries {
                    required_entries.contains_key(&RequiredEntry::Publisher { publisher_index })
                } else {
                    !entry.is_fresh_import
                }
            })
            .map(|(_, entry)| CratesPublisher {
                is_fresh_import: false,
                ..entry.clone()
            })
            .collect();
        publishers.sort();
        if !publishers.is_empty() {
            new_imports.publisher.insert(pkgname.clone(), publishers);
        }
    }

    // Determine which live publisher information to keep in the imports.lock file.
    for (pkgname, unpublished) in store.unpublished() {
        // Although `unpublished` entries are stored in imports.lock, they're
        // more like automatically-managed delta-exemptions than imports, so
        // we'll prune them when pruning exemptions.
        let prune_exemptions = mode(&pkgname[..]).prune_exemptions;
        let required_entries = required_entries
            .get(&pkgname[..])
            .unwrap_or(&no_required_entries);
        let mut unpublished: Vec<_> = unpublished
            .iter()
            .enumerate()
            .filter(|&(unpublished_index, entry)| {
                // Keep existing if we're not pruning exemptions.
                if !prune_exemptions && !entry.is_fresh_import {
                    return true;
                }

                if let Some(required_entries) = required_entries {
                    required_entries.contains_key(&RequiredEntry::Unpublished { unpublished_index })
                } else {
                    !entry.is_fresh_import
                }
            })
            .map(|(_, entry)| UnpublishedEntry {
                is_fresh_import: false,
                ..entry.clone()
            })
            .collect();
        unpublished.sort();
        // Clean up any duplicate Unpublished entries now that `is_fresh_import`
        // has been cleared.  This ensures that even if we end up using
        // `PreferFreshImports` when not pruning exemptions, we won't end up
        // with duplicate unpublished entries.
        unpublished.dedup();
        if !unpublished.is_empty() {
            new_imports.unpublished.insert(pkgname.clone(), unpublished);
        }
    }

    let mut all_new_exemptions = SortedMap::new();

    // Enumerate existing exemptions to check for criteria changes.
    for (pkgname, exemptions) in &store.config.exemptions {
        let prune_exemptions = mode(pkgname).prune_exemptions;
        let required_entries = required_entries
            .get(&pkgname[..])
            .unwrap_or(&no_required_entries);

        let mut new_exemptions = Vec::with_capacity(exemptions.len());
        for (exemption_index, entry) in exemptions.iter().enumerate() {
            let original_criteria = criteria_mapper.criteria_from_list(&entry.criteria);

            // Determine the set of useful criteria from required_entries,
            // falling back to `original_criteria` if it failed to audit.
            let mut useful_criteria = if let Some(required_entries) = required_entries {
                required_entries
                    .get(&RequiredEntry::Exemption { exemption_index })
                    .cloned()
                    .unwrap_or_else(|| criteria_mapper.no_criteria())
            } else {
                original_criteria.clone()
            };

            // If we're not pruning exemptions, maintain all existing criteria.
            if !prune_exemptions {
                useful_criteria.unioned_with(&original_criteria);
            }
            if useful_criteria.is_empty() {
                continue; // Skip this exemption
            }

            // If we're expanding the criteria set and are `suggest = false`, we
            // can't update the existing entry, so try adding a new one, and
            // reset the existing node to the original criteria.
            // XXX: The behaviour around suggest here is a bit jank, we might
            // want to change it.
            if !entry.suggest && !original_criteria.contains(&useful_criteria) {
                let mut extra_criteria = useful_criteria.clone();
                extra_criteria.clear_criteria(&original_criteria);
                new_exemptions.push(ExemptedDependency {
                    version: entry.version.clone(),
                    criteria: criteria_mapper
                        .criteria_names(&extra_criteria)
                        .map(|n| n.to_owned().into())
                        .collect(),
                    suggest: true,
                    notes: None,
                });
                useful_criteria = original_criteria;
            }

            // Add the exemption with the determined minimal useful criteria.
            new_exemptions.push(ExemptedDependency {
                version: entry.version.clone(),
                criteria: criteria_mapper
                    .criteria_names(&useful_criteria)
                    .map(|n| n.to_owned().into())
                    .collect(),
                suggest: entry.suggest,
                notes: entry.notes.clone(),
            });
        }
        if !new_exemptions.is_empty() {
            all_new_exemptions.insert(pkgname.clone(), new_exemptions);
        }
    }

    // Check if we have any FreshExemption entries which should be converted
    // into new exemptions.
    for (&pkgname, required_entries) in &required_entries {
        let Some(required_entries) = required_entries else {
            continue;
        };

        for (entry, criteria) in required_entries.iter().rev() {
            let RequiredEntry::FreshExemption { version } = entry else {
                // FreshExemption entries always sort last in the BTreeMap, so
                // we can rely on there being no more FreshExemption entries
                // after we've seen one.
                break;
            };

            all_new_exemptions
                .entry(pkgname.to_owned())
                .or_default()
                .push(ExemptedDependency {
                    version: version.clone(),
                    criteria: criteria_mapper
                        .criteria_names(criteria)
                        .map(|n| n.to_owned().into())
                        .collect(),
                    suggest: true,
                    notes: None,
                });
        }
    }

    for exemptions in all_new_exemptions.values_mut() {
        exemptions.sort();
    }

    StoreUpdates {
        audits: new_audits,
        imports: new_imports,
        exemptions: all_new_exemptions,
    }
}
