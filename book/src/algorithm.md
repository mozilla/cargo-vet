# The Cargo Vet Algorithm

The heart of `vet` is the "[resolver](https://github.com/mozilla/cargo-vet/blob/main/src/resolver.rs)" which takes in your build graph and your supply_chain dir, and determines whether `vet check` should pass.

If `check` fails, it tries to determine the reason for that failure (which as we'll see is a non-trivial question). If you request a `suggest` it will then try to suggest "good" audits that will definitely satisfy `check` (which is again non-trivial).

These results are a basic building block that most other commands will defer to:

* `vet check` (the command run with bare `vet`) is just this operation
* `vet suggest` is this operation with all suggestable exemptions deleted
* `vet certify` fills in any unspecified information using this operation
* `vet regenerate` generally uses this operation to know what to do

For the sake of clarity, this chapter will also include some discussion of "initialization" which gathers up the input state that the resolver needs.

## Initialization Steps

This phase is generally just a bunch of loading, parsing, and validating. Different commands
may vary slightly in how they do these steps, as they may implicitly be --locked or --frozen,
or want to query hypothetical states.

1. Acquire the build graph ([cargo metadata][] via the [cargo_metadata][] crate)
2. Acquire the store (`supply_chain`) (load, parse, validate)
3. Update the imports (fetch, parse, validate)
4. Check `audit-as-crates-io` (check against local cargo registry)


## Resolve Steps

These are the logical steps of the resolver, although they are more interleaved than this
initial summary implies:

1. Build data structures
    1. Construct the `DepGraph`
    2. Construct the `CriteriaMapper`
2. Determine the required criteria for each package
    1. Apply requirements for dev-dependencies
    2. Propagate policy requirements from roots out to leaves
3. Resolve the validated criteria for each third party (crates.io) package
    1. Construct the `AuditGraphs` for each package (and check violations)
    2. Search for paths in the audit graph validating each requirement
4. Check if each crate validates for the required criteria
    1. Record caveats which were required in order to satisfy these criteria
5. Suggest audits to fix leaf failures (the dance of a thousand diffs)

Here in all of its glory is the entirety of the resolver algorithm today in
abbreviated pseudo-rust. Each of these steps will be elaborated on in the
subsequent sections.

```rust ,ignore
// Step 1a: Build the DepGraph
let graph = DepGraph::new(..);
// Step 1b: Build the CriteriaMapper
let mapper = CriteriaMapper::new(..);

// Step 2: Determine the required criteria for each package
let requirements = resolve_requirements(..);

// Step 3: Resolve the validated criteria for each third-party package
for package in &graph.nodes {
    if !package.is_third_party {
        continue;
    }

    // Step 3a: Construct the AuditGraph for each package
    let audit_graph = AuditGraph::build(..);
    // Step 3b: Search for paths in the audit graph validating each requirement
    let search_results = all_criteria.map(|criteria| audit_graph.search(criteria, ..));

    // Step 4: Check if the crate validates for the required criteria
    for criteria in requirements[package] {
        match &search_results[criteria] {
            ..
        }
    }
}

// If there were any conflicts with violation entries, bail!
if !violations.is_empty() {
    return ResolveReport { conclusion: Conclusion::FailForViolationConflict(..), .. };
}

// If there were no failures, we're done!
if failures.is_empty() {
    return ResolveReport { conclusion: Conclusion::Success(..), .. };
}

// Step 5: Suggest time! Compute the simplest audits to fix the failures!
let suggest = compute_suggest(..);

return ResolveReport { conclusion: Conclusion::FailForVet(..), .. };
```

As we determine the required criteria in an separate pass, all analysis after
that point can be performed in any order. Requirements analysis starts on root
nodes and is propagated downwards to leaf nodes.




# Step 1a: The DepGraph (Processing Cargo Metadata)

All of our analysis derives from the output of [cargo metadata][] and our
interpretation of that, so it's worth discussing how we use it, and what we
believe to be true of its output.

Our interpretation of the metadata is the DepGraph. You can dump the DepGraph with
`cargo vet dump-graph`. Most commands take a `--filter-graph` argument which will
force us to discard certain parts of the DepGraph before performing the operation
of the command. This can be useful for debugging issues, but we recommend only doing
this while `--locked` to avoid corrupting your store.

By default we run `cargo metadata --locked --all-features`. If you pass `--locked` to vet,
we will instead pass `--frozen` to `cargo metadata`. `--all-features` can be negated
by passing `--no-all-features` to vet. We otherwise expose the usual feature flags of
cargo directly.

The reason we pass `--all-features` is because we want the "maximal" build graph, which
all "real" builds are simply a subset of. Cargo metadata in general provides this, but
will omit optional dependencies that are locked behind disabled features. By enabling them all,
we should get every possible dependency for every possible feature and platform.

By validating that the maximal build graph is vetted, all possible builds should in turn
be vetted, because they are simply subsets of that graph.

Cargo metadata produces the build graph in a kind of awkward way where some information
for the packages is in `"packages"` and some information is in  `"resolve"`, and we need
to manually compute lots of facts like "roots", "only for tests", and "[topological sort][]"
(metadata has a notion of roots, but it's not what you think, and mostly reflects an 
internal concept of cargo that isn't useful to us).

If we knew about it at the time we might have used [guppy][] to handle interpretting
cargo metadata's results. As it stands, we've hand-rolled all that stuff.

Cargo metadata largely uses [PackageId][]s as primary keys for identifying a package
in your build, and we largely agree with that internally, but some human-facing interfaces
like audits also treat (PackageName, [Version][]) as a valid key. This is a true
statement on crates.io itself, but may not hold when you include unpublished packages,
patches/renames(?), or third party registries. We don't really have a solid disambiguation
strategy at the moment, we just assume it doesn't happen and don't worry about it.

The resolver primarily use a PackageIdx as a primary key for packages, which is an interned PackageId.
The DepGraph holds this interner.



## Dealing With Cycles From Tests

The resolver assumes the maximal graph is a [DAG][], which is an almost true statement
that we can make true with a minor desugaring of the graph. There is only one situation
where the cargo build graph is not a DAG: the tests for a crate. This can happen very
easily, and is kind of natural, but also very evil when you first learn about it.

As a concrete example, there is kind of a conceptual cycle between [serde](https://github.com/serde-rs/serde/blob/master/serde/Cargo.toml) and [serde_derive](https://github.com/serde-rs/serde/blob/master/serde_derive/Cargo.toml). However serde_derive is a standalone crate, and serde (optionally)
pulls in serde_derive as a dependency... unless you're testing serde_derive, and then serde_derive
quite reasonably depends on serde to test its output, creating a cyclic dependency on itself!

The way to resolve this monstrosity is to realize that the *tests* for serde_derive are actually
a different package from serde_derive, which we call serde_derive_dev (because cargo calls test
edges "dev dependencies"). So although the graph reported by cargo_metadata looks like a cycle:

```
serde <-----+
  |         |
  |         |
  +--> serde_derive
```

In actuality, serde_derive_dev breaks the cycle and creates a nice clean DAG:

```
  +--serde_derive_dev ---+
  |          |           |
  v          |           v
serde        |     test_only_dep
  |          |           |
  |          v          ...
  +--> serde_derive
```

There is a subtle distinction to be made here for packages *only* used for tests:
these wouldn't be part of the build graph without dev-dependencies (dev edges) but
they are still "real" nodes, and all of their dependencies are "real" and still
must form a proper DAG. The only packages which can have cycle-causing dev-dependencies,
and therefore require a desugaring to produce "fake" nodes, are *workspace members*.
These are the packages that will be tested if you run `cargo test --workspace`.

Actually doing this desugaring is really messy, because a lot of things about the "real"
node are still true about the "fake" node, and we generally want to talk about the "real"
node and the "fake" node as if they were one thing. So we actually just analyze the build graph
in two steps. To understand how this works, we need to first look at how DAGs are analyzed.

Any analysis on a [DAG][] generally starts with a [topological sort][], which is just a fancy way of saying you do depth-first-search ([DFS][]) on every root and only use a node only after you've searched all its children (this is the post-order, for graph people). Note that each iteration of DFS reuses the
"visited" from the previous iterations, because we only want to visit each node once.

Also note that knowing the roots is simply an optimization, you can just run DFS on every node and you will get a valid topological order -- we run it for all the workspace members, which includes all of
the roots, but none of the test-only packages, which will be useful for identifying test-only packages
when we get to our desugaring. (You may have workspace members which in fact are only for testing,
but as far as `vet` is concerned those are proper packages in their own right -- those packages are
however good candidates for a `safe-to-run` policy override.)

The key property of a DAG is that if you visit every node in a topological
order, then all the transitive dependencies of a node will be visited before it.
You can use this fact to compute any property of a node which recursively
depends on the properties of its dependencies. More plainly, you can just have a
for-loop that computes the properties of each node, and blindly assume that any
query about your dependencies will have its results already computed. Nice!

In our algorithm, however, we actually visit in reverse-topological order, so
that we know all reverse-dependencies of a node will be visited before it. This
is because criteria requirements are inherited by reverse-dependency, (or pushed
out from a crate to its dependencies).

With that established, here is the *actual* approach we use to emulate the "fake" node desugaring:

1. analyze the build graph without dev deps (edges), which is definitely a DAG
2. add back the dev deps and reprocess all the nodes as if they were the "fake" node

The key insight to this approach is that the implicit dev nodes are all roots -- nothing
depends on them. As a result, adding these nodes can't change which packages the "real"
nodes depend on, and any analysis done on them is valid without the dev edges!

When doing the topological sort, because we only run DFS from workspace members,
the result of this is that we will visit all the nodes that are part of a "real" build
in the first pass, and then the test-only packages in the second pass. This makes computing
"test only" packages a convenient side-effect of the topological sort. Hopefully it's clear
to you that the resulting ordering functions as a topological sort as long as our recrusive
analyses take the form of two loops as so:

```
for node in topological_sort:
    analysis_that_DOESNT_query_dev_dependencies(node)
for node in topological_sort:
    analysis_that_CAN_query_dev_dependencies(node)
```

The second loop is essentially handling all the "fake" dev nodes.

Note that when we run this in a reversed manner to ensure that
reverse-dependencies have been checked before a crate is visited, we need to do
the dev-dependency analysis first, as the dev-dependency "fake" nodes are
effectively appended to the topological sort.



## The DepGraph's Contents

The hardest task of the DepGraph is computing the topological sort of the packages as
described in the previous section, but it also computes the following facts for each package
(node):

* [PackageId][] (primary key)
* [Version][]
* name
* is_third_party (is_crates_io)
* is_root
* is_workspace_member
* is_dev_only
* normal_deps
* build_deps
* dev_deps
* reverse_deps

Whether a package is third party is deferred to [cargo_metadata][]'s [is_crates_io][] method
but overrideable by `audit-as-crates-io` in config.toml. This completely changes how the
resolver handles validating criteria for that package. Packages which aren't third party
are referred to as "first party".

Roots are simply packages which have no reverse-deps, which matters because those will
implicitly be required to pass the default root policy (safe-to-deploy) if no other policy
is specified for them.

Workspace members must pass a dev-policy check, which is the only place where
we query dev-dependencies (in the fabled "second pass" from the previous section).

Dev-only packages are only used in tests, and therefore will only by queried in
dev-policy checks (and so by default only need to be safe-to-run).





# Step 1b: The CriteriaMapper

The CriteriaMapper handles the process of converting between criteria names and
CriteriaIndices. It's basically an interner, but made more complicated by the existence
of builtins, namespaces (from imported audits.toml files), and "implies" relationships.

The resolver primarily operates on CriteriaSets, which are sets of CriteriaIndices.
The purpose of this is to try to handle all the subtleties of criteria in one place
to avoid bugs, and to make everything more efficient.

Most of the resolver's operations are things like "union these criteria sets" or
"check if this criteria set is a superset of the required one".

There is currently an artificial maximum limit of 64 criteria for you and all
your imports to make CriteriaSets efficient (they're just a u64 internally).
The code is designed to allow this limit to be easily raised if anyone ever hits
it (either with a u128 or a proper BitSet).

The biggest complexity of this process is handling "implies" (and the mapping of
imported criteria onto local criteria, which is basically another form of "implies"
where both criteria imply eachother).

This makes a criteria like safe-to-deploy *actually* safe-to-deploy AND safe-to-run
in most situations. The CriteriaMapper will precompute the [transitive closure][] of
implies relationships for each criteria as a CriteriaSet. When mapping the name of
a criteria to CriteriaIndices, this CriteriaSet is the thing returned.

When mapping a criteria set to a list of criteria names, we will add `import_name::`
in front of any imported criteria. So if you import a "fuzzed" criteria from "google",
we will print `google::fuzzed`. We will also elide implied criteria
(so a `["safe-to-deploy", "safe-to-run"]` will just be `["safe-to-deploy"]`).
If an imported criteria is mapped onto a local criteria, we will only show the local
criteria (so `["fuzzed", "google::fuzzed"]` will just be `["fuzzed"]`).



## Computing The Transitive Closure of Criteria

The [transitive closure][] of a criteria is the CriteriaSet that would result if you
add the criteria itself, and every criteria that implies, and every criteria THEY imply,
and so on. This resulting CriteriaSet is effectively the "true" value of a criteria.

We do this by constructing a directed "criteria graph" where an "implies" is an edge.
The transitive closure for each criteria can then be computed by running depth-first-search
([DFS][]) on that node, and adding every reachable node to the CriteriaSet.

That's it!

Being able to precompute the transitive closure massively simplifies the resolver,
as it means we never have to re-evaulate the implies relationships when unioning
CriteriaSets, making potentially O(n<sup>3</sup>) operations into constant time ones,
where n is the number of criteria (the criteria graph can have O(n<sup>2</sup>) criteria,
and a criteria set can have O(n) criteria, and we might have to look at every edge of
the graph for every criteria whenever we add one).

The *existence* of the transitive closure is however not a fundamental truth. It
exists because we have artifically limited what import maps and implies is allowed to
do. In particular, if you ever allowed an implies relationship that requires
*two different criteria* to imply another, the transitive closure would not be
a useful concept, and we'd be forced to re-check every implies rule whenever
a criteria got added to a criteria set (which is happening constantly in the resolver).

[See this issue for a detailed example demonstrating this problem](https://github.com/mozilla/cargo-vet/issues/240).






# Step 2: Determine the required criteria for each package

In general, every package requires that all dependencies satisfy the same
criteria which were required for the original package. This is handled by
starting at the root crates, and propagating the required `CriteriaSet` outwards
towards the leaves. In some cases, the `policy` table will specify alternative
criteria to place as a requirement on dependencies, which will be used instead
of normal propagation.

In order to avoid the cyclic nature of dev-deps, these targets are handled
first. As all dependencies of dev-dependencies are normal dependencies, we can
rely on the normal non-cyclic requirement propagation after the first edge, so
we only need to apply the requirements one-level deep in this first phase. By
default, this requirement is `safe-to-run`, though it cna be customized through
the `policy`.

Afterwards, we start at the root crate in the graph and work outwards, checking
if we need to apply policy requirements, and then propagating requirements to
dependencies. This results in every crate having a corresponding `CritseriaSet`
of the criteria required for the audit.






# Step 3a: The AuditGraph

The AuditGraph is the graph of all audits for a particular package *name*.
The nodes of the graph are [Version][]s and the edges are delta audits (e.g. `0.1.0 -> 0.2.0`).
Each edge has a list of criteria it claims to certify, and dependency criteria that the
dependencies of this package must satisfy for the edge to be considered "valid" (see
the next section for details).

There is an implicit Root Version which represents an empty package, meaning that throughout
much of the audit graph, versions are represented as `Option<Version>`.

When trying to validate whether a particular version of a package is audited, we also add
a Target Version to the graph (if it doesn't exist already).

Full audits are desugarred to delta audits from the Root Version (so an audit for `0.2.0` would
be lowered to a delta audit from `Root -> 0.2.0`).

Exemptions are desugared to full audits (and therefore deltas) with a flag indicating their origin.
This flag is used to deprioritize the edges so that we can more easily detect exemptions that
aren't needed anymore.

Imported audits are lowered in the exact same way as local criteria, except their criteria names are
treated as namespaced when feeding them into the CriteriaMapper. In the future, another flag may be
set indicating their origin. This flag would similarly lets us deprioritize imported audits, to
help determine if they're needed.

With all of this established. the problem of determining whether a package is audited for a given
criteria can be reduced to determining if there *exists* a path from the Root Version to the
Target Version along edges that certify that criteria. Suggesting an audit similarly becomes
finding the "best" edge to add to make the Root and Target connected for the desired criteria.


## Checking Violations

During AuditGraph construction violations are also checked. Violations have a [VersionReq][] and
a list of violated criteria. They claim that, for all versions covered by the VersionReq, you believe
that the listed criteria are explicitly violated. An error is produced if any edge is
added to the AuditGraph where *either* endpoint matches the VersionReq and *any* criteria
it claims to be an audit for is listed by the violation.

This is an extremely complicated statement to parse, so let's look at some examples:

```
violation: safe-to-deploy, audit: safe-to-deploy -- ERROR!
violation: safe-to-deploy, audit: safe-to-run    -- OK!
violation: safe-to-run,    audit: safe-to-deploy -- ERROR!
violation: [a, b],         audit: [a, c]         -- ERROR!
```

One very notable implication of this is that a violation for `["safe-to-run", "safe-to-deploy"]`
is actually equivalent to `["safe-to-run"]`, not `["safe-to-deploy"]`! This means that the normal
way of handling things, turning the violation's criteria into one CriteriaSet and checking
if `audit.contains(violation)` is incorrect!

We must instead do this check for each individual item in the violation:

```rust
let has_violation = violation.iter().any(|item| audit.contains(item));
```

It may seem a bit strange to produce an error if *any* audit is in any way contradicted
by *any* violation. Is that necessary? Is that sufficient?

It's definitely sufficient: it's impossible to validate a version without having an audit edge
with an end-point in that version.

I would argue that it's also *necessary*: the existence of any audit (or exemption)
that is directly contradicted by a violation is essentially an integrity error on the
claims that we are working with. Even if you don't even use the audit for anything
anymore, people who are peering with you and importing your audits might be, so you
should do something about those audits as soon as you find out they might be wrong!

There is currently no mechanism for mechanically dealing with such an integrity error,
even if the audit or violation comes from a foreign import. Such a situation is serious
enough that it merits direct discussion between humans. That said, if this becomes
enough of a problem we may eventually add such a feature.



# Step 3b: Searching for paths in the `AuditGraph`

A lot of the heavy lifting for this task is in Step 3a (AuditGraph).

Trying to validate all criteria at once is slightly brain-melty (because
different criteria may be validated by different paths), so as a simplifying
step we validate each criteria individually (so everything I'm about to
describe happens in a for loop).

If all we care about is finding out if a package has some criteria, then all
we need to do is run depth-first-search ([DFS][]) from the Root Node and see if it reaches
the Target Node, with the constraint that we'll only follow edges that are
valid (based on the already validated criteria of our dependencies).

If it does, we've validated the criteria for the Target Version. If it doesn't,
then we haven't.

But things are much more complicated because we want to provide more feedback
about the state of the audits:

* Did this validation require an exemption? (Is it fully audited?)
* Did this validation even use any audits? (Is it at least partially audited?)
* Did this validation need any new imports? (Should we update imports.lock?)
* What nodes were reachable from the Root and reverse-reachable from the Target? (candidates for suggest)

This is accomplished by running the search off of a priority queue, rather than
using a stack, such that we only try to use the "best" edges first, and can
be certain that we don't try to use a "worse" edge until we've tried all of the
paths using better edges.

The best edge of all is a local audit. If we can find a path using only
those edges, then we're fully audited, we don't need any exemptions we
might have for this package (a lot of caveats to this, so we don't really
make that conclusion reliably), and the imports.lock doesn't need to be updated.

If we need to add back in exemptions to find a path, then the exemptions
were necessary to validate this criteria.

If we need to add back in new imports to find a path, then we need to update
imports.lock to cache necessary audits for --locked executions. (The fact
that this comes after exemptions means we may be slightly imprecise about
whether something is "fully audited" when updating imports, as subsequent
runs won't get this far. We think this is worth the upside of minimizing
imports.lock updates.)

If any of those succeed, then we return Ok(..), communicating both that the
package validates this criteria, plus any caveats back to the caller.

Otherwise, we'll return Err(..), and consider the current node to blame. If this
criteria is required, this package will require additional audits or exemptions
to successfully vet.

In doing this, we also compute the nodes that are reachable from the Root
Version and the nodes that are reverse-reachable from the Target Version.
The latter is computed by following all edges backwards, which is to say
in Step 3a the AuditGraph also contains another directed graph with the edges
all reversed, and rerun the algorithm with Root and Target reversed.

This information is useful because in the Err case we want to suggest a diff to
audit, and any diff from the Root Reachable nodes to the Target Reachable nodes
is sufficient.

All search results are stored in the ResolveResult for a node along with
validated criteria and other fun facts we found along the way. The
contents of the ResolveResult will be used by our reverse-dependencies
in steps 2 and 3.

It's worth noting here that delta audits can "go backwards" (i.e. `1.0.1 -> 1.0.0`),
and all of this code handles that perfectly fine without any special cases.
It *does* make it possible for there to be cycles in the AuditGraph, but
[DFS][] doesn't care about cycles at all since you keep track of nodes you've
visited to avoid revisits (slightly complicated by us iteratively introducing edges).



# Step 4: Checking if each crate validates for the required criteria

This step is a fairly trivial combination of the results from Step 2 (computing
requirements) and Step 3 (resolving validated criteria) - for each package, we
check if the validated criteria is a superset of the requirements, and if it is
then we're successful, otherwise we're not.

We'll record which criteria failed so we can suggest better audits in the
errored case, and combine the caveats from successful runs in the success case
to get a combined result for each crate, rather than for each individual
criteria.



# Step 5: Suggesting Audits (Death By A Thousand Diffs)

This step takes the failed packages from Step 4 and recommends audits that will
fix them. In Step 3b we compute the Root Reachable Nodes and the Target
Reachable Nodes for a disconnected package.  In this phase we use those as
candidates and try to find the best possible diff audit.

More specifically, we use the intersection of all the Root Reachable Nodes
for every criteria this package failed (ditto for Target Reachable).
By using the intersection, any diff we recommend from one set to the other
is guaranteed to cover all required criteria, allowing us to suggest a single
diff to fix everything. Since the Root and Target are always in their respective
sets, we are guaranteed that the intersections are non-empty.

So how do we pick the *best* diff? Well, we straight up download every version of the package that
we have audits for and diff-stat all the combinations. Smallest diff wins! Does that sound horrible
and slow? It is! That's why we have a secret global diff-stat cache on your system.

Also we don't *literally* diff every combination. We turn the O(n<sup>2</sup>) diffs
into only O(n) diffs with a simple heuristic: for each Target Reachable Node,
we find the package closest version *smaller* than that version and the closest version
*bigger* than that version. We then diff that version against only those two versions.
This may potentially miss some magical diff where a big change is made and then reverted,
but this diffing stuff needs some amount of taming!

It's worth noting that [Version]s don't form a proper metric space: We cannot compute
the "distance" between two Versions in the abstract, and then compare that to the "distance"
between two other versions. Versions *do* however have a total ordering, so we *can*
compute minimum and maximum versions, and say whether a version is bigger or smaller
than another. As a result it's possible to compute "the largest version that's smaller than X"
and "the smallest version that's larger than X", which is what we use. There is however
no way to say whether the smaller-maximum or the bigger-minimum is closer to X, so we must
try both.

It's also worth reiterating here that diffs *can* go backwards. If you're on 1.0.0 and
have an audit for 1.0.1, we will happily recommend the reverse-diff from `1.0.1 -> 1.0.0`.
This is slightly brain melty at first but nothing really needs to specially handle this,
it Just Works.

Any diff we recommend from the Root Version is "resugared" into recommending a full audit,
(and is also computed by diffing against an empty directory). It is impossible
to recommend a diff to the Root Version, because there cannot be audits of the
Root Version.






[cargo metadata]: https://doc.rust-lang.org/cargo/commands/cargo-metadata.html
[cargo_metadata]: https://docs.rs/cargo_metadata/latest/cargo_metadata/
[is_crates_io]: https://docs.rs/cargo_metadata/latest/cargo_metadata/struct.Source.html#method.is_crates_io
[DAG]: https://en.wikipedia.org/wiki/Directed_acyclic_graph
[PackageId]: https://docs.rs/cargo_metadata/latest/cargo_metadata/struct.PackageId.html
[Version]: https://docs.rs/semver/latest/semver/struct.Version.html
[VersionReq]: https://docs.rs/semver/latest/semver/struct.VersionReq.html
[guppy]: https://docs.rs/guppy/latest/guppy/
[topological sort]: https://en.wikipedia.org/wiki/Topological_sorting
[transitive closure]: https://en.wikipedia.org/wiki/Transitive_closure
[DFS]: https://en.wikipedia.org/wiki/Depth-first_search
