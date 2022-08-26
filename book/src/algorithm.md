# The Cargo Vet Algorithm

The heart of `vet` is the "[resolver](https://github.com/mozilla/cargo-vet/blob/main/src/resolver.rs)" which takes in your build graph and your supply_chain dir, and determines whether `vet check` should pass.

If `check` fails, it tries to determine the reason for that failure (which as we'll see is a non-trivial question). If you request a `suggest` it will then try to suggest "good" audits that will definitely satisfy `check` (which is again, non-trivial).

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
    3. Construct the `AuditGraphs` for each package (and check violations)
2. Resolve the validated criteria for each package
    1. Resolve third parties (crates.io)
    2. Resolve first parties (non-crates.io)
3. Check that policies are satisfied (find "root failures")
    1. Check explicit self-policies and root packages
    2. Check tests (dev-policies)
4. Blame packages for policy failures (find "leaf failures")
5. Suggest audits to fix leaf failures (the dance of a thousand diffs)

Here in all of its glory is the entirety of the resolver algorithm today in
abbreviated pseudo-rust. Each of these steps will of course be elaborated on
in the previous sections or subsequent sections.

```rust ,ignore
// Step 1: Build Datastructures
let violations = vec![];
let root_failures = vec![];

// Step 1a: Build the DepGraph
let graph = DepGraph::new(..);
// Step 1b: Build the CriteriaMapper
let mapper = CriteriaMapper::new(..);


// Analyze all the packages, ignoring dev-dependencies
for package in &graph.topo_index {
    // Step 2: Resolve Validated Criteria
    if package.is_third_party {
        // Step 2a: Compute validated criteria (also Step 1c: Build AuditGraph)
        resolve_third_party(package, ..);
    } else {
        // Step 2b: Inherit validated criteria from dependencies
        resolve_first_party(package, ..);
    }

    // Step 3a: Check any policy on self, or default root policies
    resolve_self_policy(package, ..);
}

// Step 3b: Check dev-dependencies (dev-policy)
for package in &graph.topo_index {
    if package.is_workspace_member {
        resolve_dev_policy(package, ..);
    }
}

// If there were any conflicts with violation entries, bail!
if !violations.is_empty() {
    return ResolveReport { conclusion: Conclusion::FailForViolationConflict(..), .. };
}

// If there were no failures, we're done!
if root_failures.is_empty() {
    return ResolveReport { conclusion: Conclusion::Success(..), .. };
}

// Step 4: Blame time! If there were root failures, find the leaf failures that caused them!
let leaf_failures = visit_failures(..);

// Step 5: Suggest time! Compute the simplest audits to fix the leaf failures!
let suggest = compute_suggest(..);

return ResolveReport { conclusion: Conclusion::FailForVet(..), .. };
```

One perhaps surprising detail of all of this is that **analysis is inherently bottom-up**.
We start at the leaves of your dependency tree and work our way up to the roots. As a
result of this, we don't know any of the policies that are our actual *goals* until
we work our way up to a node with a policy (usually a root).

Only if we find root failures do we then descend back down to compute the leaves which
are the origin of these failures, because only then do we actually know that they
weren't good enough, and why not. However the "blame edges" that we descend are all
precomputed during the bottom-up analysis, we're just choosing which ones to follow
based on the required criteria.




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

Any analysis on a [DAG][] generally starts with a [toplogical sort][], which is just a fancy way of saying you do depth-first-search ([DFS][]) on every root and only use a node only after you've searched all its children (this is the post-order, for graph people). Note that each iteration of DFS reuses the
"visited" from the previous iterations, because we only want to visit each node once.

Also note that knowing the roots is simply an optimization, you can just run DFS on every node and you will get a valid topological order -- we run it for all the workspace members, which includes all of
the roots, but none of the test-only packages, which will be useful for identifying test-only packages
when we get to our desugaring. (You may have workspace members which in fact are only for testing,
but as far as `vet` is concerned those are proper packages in their own right -- those packages are
however good candidates for a `safe-to-run` policy override.)

The key property of a DAG is that if you visit every node in a topological order, then all the transitive dependencies of a node will be visited before it. You can use this fact to compute any
property of a node which recursively depends on the properties of its dependencies. More plainly,
you can just have a for-loop that computes the properties of each node, and blindly assume that
any query about your dependencies will have its results already computed. Nice!

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

There is currently an artificial maximum limit of 64 criteria for you and all your
imports to make CriteriaSets effecient (they're just a u64 internally). 
The code is designed to allow this limit to be easily raised if anyone ever hits it
(either with a u128 or a proper BitSet).

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
as it means we never have to "re-evaulate" the implies relationships when unioning
CriteriaSets, making potentially O(n<sup>3</sup>) operations into constant time ones,
where n is the number of criteria (the criteria graph can have O(n<sup>2</sup>) criteria,
and a criteria set can have O(n) criteria, and we might have to look at every edge of
the graph for every criteria whenever we add a criteria).

The *existence* of the transitive closure is however not a fundamental truth. It
exists because we have artifically limited what import maps and implies is allowed to
do. In particular, if you ever allowed an implies relationship that requires
*two different criteria* to imply another, the transitive closure would not be
a useful concept, and we'd be forced to re-check every implies rule whenever
a criteria got added to a criteria set (which is happening constantly in the resolver).

[See this issue for a detailed example demonstrating this problem](https://github.com/mozilla/cargo-vet/issues/240).






# Step 1c: The AuditGraph

The AuditGraph is the graph of all audits for a particular package *name*.
The nodes of the graph are [Version][]s and the edges are delta audits (e.g. `0.1.0 -> 0.2.0`).
Each edge has a list of criteria is claims to certify, and dependency_criteria that the
dependencies of this package must satisfy for the edge to be considered "valid" (see
the next section for details).

There is an implicit Root Version which represents an empty package, meaning that throughout
much of the audit graph, versions are represented as `Option<Version>`.

When trying to validate whether a particular version of a package is audited, we also add
a Target Version to the graph (if it doesn't exist already).

Full audits are desugarred to delta audits from the Root Version (so an audit for `0.2.0` would
be lowered to a delta audit from `Root -> 0.2.0`).

Exemptions are desugarred to full audits (and therefore deltas) with a flag indicating their origin.
This flag is used to "deprioritize" the edges so that we can more easily detect exemptions that
aren't needed anymore.

Imported audits are lowered in the exact same way as local criteria, except their criteria names are
treated as namespaced when feeding them into the CriteriaMapper. (In the future, another flag may be
set indicating their origin. This flag would similarly lets us "deprioritize" imported audits, to
help determine if they're needed.)

With all of this established. the problem of determining whether a package is audited for a given
criteria can be reduced to determining if there *exists* a path from the Root Version to the
Target Version along edges that certify that criteria. Suggesting an audit similarly becomes
finding the "best" edge to add to make the Root and Target connected for the desired criteria.


## Dependency Criteria

dependency_criteria are the source of basically all complexity in cargo-vet, and why
the resolver isn't completely precise when blaming packages for errors, and therefore
suggesting fixes for errors.

When an edge (audit/exemption) has explicit dependency_criteria, the edge is only
valid (traversable when searching for a path) if the dependency satisfies that criteria.

The absence of a dependency_criteria for a dependency is *almost* equivalent to
the certified criteria, but is more powerful than that. This is because audits are
considered "decomposable" into audits for each of their individual criteria, including
inherited criteria.

So for instance, if an audit claimed `["safe-to-deploy", "fuzzed"]`
then this is equivalent to three separate audits for "safe-to-deploy", "safe-to-run",
and "fuzzed". This distinction doesn't matter with explicit dependency criteria,
but with implicit dependency criteria this means that if some of your dependencies
are only "safe-to-run", the edge will still be valid for certifying "safe-to-run".

We originally considered requiring you to be explicit about this and manually
make 3 different audits, but we couldn't think of any particular realistic situations
where this wasn't desirable (and you can use explicit dependency criteria if you
don't want this behaviour).

## The Fundamental Imprecision Of The Resolver

If the search for a path ever reaches an edge that has the desired criteria but isn't valid,
because of dependency criteria, this is noted for the purposes of the blaming step.

This is the fundamental imprecision of resolving: at best it's difficult to say why
a path doesn't exist, and at worse it's genuinely ambiguous. You could have two
possible paths with different edges failing for different dependencies. Fixing either
one would work, so which one do we recommend? This is only made more complicated by
the possibility of a path that requires multiple edges to be fixed with
various different dependencies and criteria.

To be completely conservative, the resolver generally just takes the union of
every problem it finds and recommends you fix them all. In the vast majority of
cases this will be perfectly precise, (in particular, I believe this will always
be precise if you only use implicit dependency_criteria). Only in situations
where there are multiple possible paths and explicit dependency_criteria
will we start conservatively recommending potentially excessive things.

Also if there's no possible path regardless of dependency_criteria, any
audits we recommend for dependencies have to in some sense be a guess, because
the way you resolve this package can change the requirements for your dependencies.

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



# Step 2a: Resolving Third Parties (Analyzing Audits)

A lot of the heavy lifting for this task is in Step 1c (AuditGraph).

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
* If we failed, was there a possible path? (Should we blame our deps for our failure?)
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

If any of those succeed, then we return SearchResult::Connected and the
criteria is unioned into the this package's validated_criteria.

If none of that worked, then we start allowing ourselves to follow *invalid*
edges (edges which exist but have unsatisfied dependency_criteria). If we
manage to find a path with those edges, then in some sense we are "blameless"
for our failure, and we return SearchResult::PossiblyConnected with a list
of the failed edges. During blaming (Step 4) we will use these results
to compute leaf failures.

If even invalid edges are insufficient, then we will return
SearchResult::Disconnected and consider ourselves fundamentally to blame
for our failures, and this node will be a leaf failure if blaming reaches
it with this required criteria.

In doing this, we also compute the nodes that are reachable from the Root
Version and the nodes that are reverse-reachable from the Target Version.
The latter is computed by following all edges backwards, which is to say
in Step 1c we actually build another copy of the AuditGraph, with the edges
all reversed, and rerun the algorithm with Root and Target reversed.

This information is useful because in the Disconnected case we want
to suggest a diff to audit, and any diff from the Root Reachable nodes
to the Target Reachable nodes is sufficient.

All SearchResults are stored in the ResolveResult for a node along with
validated criteria and other fun facts we found along the way. The
contents of the ResolveResult will be used by our reverse-dependencies
in steps 2 and 3.

It's worth noting here that delta audits can "go backwards" (i.e. `1.0.1 -> 1.0.0`),
and all of this code handles that perfectly fine without any special cases.
It *does* make it possible for there to be cycles in the AuditGraph, but
[DFS][] doesn't care about cycles at all since you keep track of nodes you've
visited to avoid revisits (slightly complicated by us iteratively introducing edges).

Note that when checking dependencies, dependencies that are dev-only
are ignored (this only matters for workspace members).


# Step 2b: Resolving First Parties (Inheriting Audits)

First parties (non-crates.io packages) simply "inherit" the intersection of the
validated criteria of all their dependencies. If they have no dependencies then
the become validated for *all* criteria by default. 

If they have a dependency_criteria in their policy then that dependency is
treated as either having all_criteria or no_criteria based on whether it passed
the dependency_criteria. This is equivalent to how explicit dependency_criteria
are handled in step 2a, and self-policies are handled in step 3a.

If a criteria isn't in the intersection, then we record the dependencies that
failed to satisfy this condition as a SearchResult::PossiblyConnected, as
first parties are *never* to blame. It's those dang peasant third-parties! 

Note that when checking dependencies, dependencies that are dev-only
are ignored (this only matters for workspace members).

...That's it! Everything's a lot easier when audits aren't involved!




# Step 3a: Checking Self-Policies

Any package which is a root of the DepGraph or has a `policy.criteria` needs to
check their validated criteria against that self_policy (if it's only a root,
then the default root policy, safe-to-deploy, is used). If the policy is satisfied
(`validated_criteria.contains(self_policy)`), then everything's fine.

If the policy fails, then this node becomes a "root failure" (as in, it's a root
of the "failure/blame graph", it doesn't have to be a root in the DepGraph,
although it's usually also that). When registering the root failure, we record
which criteria were missing, which will be used in blaming (Step 4).

It's worth noting that if a package has an explicit `policy.criteria`, then
its reverse-dependencies (parents) can never make any demands of it. This is necessary
to allow a self_policy to be either *weaker* or *stronger* than the requirements
of the reverse-dependency.

To further indicate this, when checking a self_policy we either set the node's
validated criteria to all_criteria or no_criteria.

It's also worth noting that, due to audit-as-crates-io and `[patch]`
declarations, you can end up in a situation where a third-party depends on a
first-party, or third-parties have `policy.criteria` entries. This is why
Step 3a is interleaved with Step 2.




# Step 3b: Checking Dev-Policies (Tests)

This is the one and only place where we consider dev-dependencies, and happens
strictly after the primary loop that processes Step 2, and 3a. In this step
we're validating the "fake" test node that's required to break cycles, as 
discussed in Step 1a.

We essentially repeat the steps of 2b here, but include *all* dependencies,
where in 2b we ignored dev-dependencies. The resulting dev_validated_criteria
is then checked against the dev_policy for this node.

If the node has a policy.dev-criteria then that's the dev_policy. Otherwise
it gets the default dev_policy, safe-to-run. If the dev_policy is satisfied
(`dev_validated_criteria.contains(dev_policy)`), then we silently continue
on. Unlike in Step 3a we don't update the validated_criteria.

If the node fails the dev_policy, then we register the "root failure" as in
Step 3a.

(It's perhaps notable that we recheck the normal dependencies of the package,
and don't use the validated_criteria of the package itself. I don't *think*
this really matters but there's an argument that this is semantically wrong,
as the "fake" node depends on the "real" node. But the "fake" node also
contains all the same code as the "real" node and the only source of
divergence is a self_policy, which will handle its own root failure reporting.
I think the only situation where this could matter is if the dev_policy is *stronger*
than the self_policy, which feels like... An Incorrect Decision.)



# Step 4: Blaming Children For Our Problems

If there are any "root failures" recorded by 3a or 3b, then we need to
descend down the "blame graph" to find the dependencies that *caused*
this failure (the "leaf failures"). Blame The Children!

The blame graph is something we've already implicitly constructed.
The nodes of the blame graph are the ResolveResults for each package
(populated in Step 2), and the edges of the blame graph are SearchResults
inside those ResolveResults which have SearchResult::PossiblyConnected
for the criteria that we are trying to blame. Any node which has
SearchResult::Disconnected for the criteria we're interested in is a leaf.

At a high level, the idea is to run depth-first-search ([DFS][]) from the
root failures and report any leaves we reach.

However this is complicated by two factors:

* Our traversals have criteria associated with them, so the notion of
"visited" must keep which blame-criteria a node has been visited with

* To get as much information as possible at once, we want to speculatively
blame "deeper" than a leaf. This may be useful if e.g. you update both of
serde and serde_derive at once, and therefore need audits for both, even
if the latter only appears as a dependency of the former.

To handle these problems, we use augmented CriteriaSets -- CriteriaFailureSets.
These contain *two* criteria sets, "confident" and "all". Each search path
originates from a "root failure" and has a CriteriaFailureSet for the missing
criteria that caused that failure.

Initially, all search paths have the same values for "confident" and "all".
However, whenever a search path speculatively pushes "deeper" than a leaf,
that part of the path is marked as a "guess" and any node visited from there
will only mark "all".

When a search path reaches a node, we union the current CriteriaFailureSet
into the visited entry for that node. If this doesn't change the value
of the CriteriaFailureSet then visiting it won't change anything and
we don't need to perform the visit. We also refuse to visit any node
which was itself a root failure, as this indicates they had a self-policy
and are therefore immune to parent demands.

The edges that a search path will try to follow are the SearchResult::PossiblyConnected
entries for the criteria this search path is currently trying to blame for
(it's CriteriaFailureSet). Explicit dependency_criteria may modify the blame
criteria, as for instance if we're blaming for "safe-to-deploy" but a dependency
explicitly only needed to be "safe-to-run" we don't want to claim that it should
have been "safe-to-deploy".

If a search path reaches a node that has some SearchResult::Disconnected entries
then we record that overlap as a leaf failure (unioning into a CriteriaFailureSet
for that node's leaf failures).

This is where the guessing is performed. We assume any audit you add to fix
this package will only have default dependency_criteria, and therefore any
dependency that *also* doesn't have any of the leaf's blamed criteria will
cause a cascading failure. We push the search path onto those nodes as if
there was a PartiallyConnected entry for them, and then mark those search
heads as "guesses" as disucssed above.

This is *probably* correct, and is perfectly precise in the happy path where
no one ever uses custom dependency_criteria. But the auditor may add any
explicit dependency_criteria they please, invalidating our guess.

Now the *reason* we do all this careful work to track whether things are
guesses or not is so that, when we're done all our searching, we can determine
if all the blames for a leaf failure are "confident" (whether "confident" == "all").
We always report "all" to the end-user, but we de-emphasize any result
that isn't completely confident, indicating that they should prefer resolving
the fully confident (parent) failures first, because it might change the suggestion
(or completely eliminate the failure!).

The guesses are useful for helping the user gauge how much work they have
ahead of them, and let us have *something* to use if they disregard our
recommendation and decide they want to work bottom up and start `certify`ing
those packages.



# Step 5: Suggesting Audits (Death By A Thousand Diffs)

This step takes the "blamed" "leaf failures" from Step 4 and recommends
audits that will fix them. In Step 2a we compute the Root Reachable Nodes
and the Target Reachable Nodes for a SearchResult::Disconnected package.
In this phase we use those as candidates and try to find the best possible
diff audit.

More specifically, we use the intersection of all the Root Reachable Nodes
for every criteria this package was blamed for (ditto for Target Reachable).
By using the intersection, any diff we recommend from one set to the other
is guaranteed to cover all required criteria, allowing us to suggest a single
diff to fix everything. Since the Root and Target are always in their respective
sets, we are guaranteed that the intersections are non-empty.

So how do we pick the *best* diff? Well, we straight up download every version of the package that
we have audits for and diff-stat all the combinations. Smallest diff wins! Does that sound horrible
and slow? It is! That's why we have a secret global diff-stat cache on your system.

Also we don't *literally* diff every combination. We turn the O(n<sup>2</sup>) diffs
into "only" O(n) diffs with a simple heuristic: for each Target Reachable Node,
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
no way to say whether the smaller-maximum or the bigger-minimum is closer to X, so we "must"
try both.

It's also worth reiterating here that diffs *can* "go backwards". If you're on 1.0.0 and
have an audit for 1.0.1, we will happily recommend the reverse-diff from `1.0.1 -> 1.0.0`.
This is slightly brain melty at first but nothing really needs to specially handle this,
it Just Works.

Any diff we recommend from the Root Version is "resugared" into recommending a full audit,
(and is also computed by diffing against an empty directory). It is impossible
to recommend a diff *to* the Root Version, because there cannot be audits of the
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