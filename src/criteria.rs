//! Helper types for working with criteria and criteria sets.

use std::fmt;

use crate::format::{
    CriteriaEntry, CriteriaName, CriteriaStr, FastMap, SortedMap, SAFE_TO_DEPLOY, SAFE_TO_RUN,
};

/// Set of booleans, 64 should be Enough For Anyone (but abstracting in case not).
///
/// Note that this intentionally doesn't implement Default to allow the implementation
/// to require the CriteriaMapper to provide the count of items at construction time.
/// Which will be useful if we ever decide to give it ~infinite capacity and wrap
/// a BitSet.
#[derive(Clone)]
pub struct CriteriaSet(u64);
const MAX_CRITERIA: usize = u64::BITS as usize; // funnier this way

/// A processed version of config.toml's criteria definitions, for mapping
/// lists of criteria names to CriteriaSets.
#[derive(Debug, Clone)]
pub struct CriteriaMapper {
    /// name -> index in all lists
    index: FastMap<CriteriaName, usize>,
    /// Names for every criteria
    names: Vec<CriteriaName>,
    /// The transitive closure of all criteria implied by each criteria (including self)
    implied_criteria: Vec<CriteriaSet>,
}

impl CriteriaMapper {
    pub fn new(criteria: &SortedMap<CriteriaName, CriteriaEntry>) -> CriteriaMapper {
        // Fixed indices for built-in criteria
        const SAFE_TO_RUN_IDX: usize = 0;
        const SAFE_TO_DEPLOY_IDX: usize = 1;

        // Build the list of possible criteria
        let names: Vec<CriteriaName> = [SAFE_TO_RUN.to_owned(), SAFE_TO_DEPLOY.to_owned()]
            .into_iter()
            .chain(criteria.keys().cloned())
            .collect();
        assert_eq!(names[SAFE_TO_RUN_IDX], SAFE_TO_RUN);
        assert_eq!(names[SAFE_TO_DEPLOY_IDX], SAFE_TO_DEPLOY);

        // Populate the index from the list to allow fast by-name look-ups
        let mut index = FastMap::with_capacity(names.len());
        for (idx, name) in names.iter().enumerate() {
            if index.insert(name.clone(), idx).is_some() {
                // XXX: Consider producing a better error here?
                panic!("Cannot specify multiple criteria with the name '{name}'");
            }
        }

        // Create the list containing implied criteria and pre-populate it with
        // the SAFE_TO_DEPLOY->SAFE_TO_RUN imply.
        let mut direct_implies = vec![CriteriaSet::none(names.len()); names.len()];
        direct_implies[SAFE_TO_DEPLOY_IDX].set_criteria(SAFE_TO_RUN_IDX);
        for (name, entry) in criteria {
            let idx = index[name];
            for implied in &entry.implies {
                direct_implies[idx].set_criteria(index[&**implied]);
            }
        }

        let implied_criteria = (0..names.len())
            .map(|idx| {
                // Helper to recursively add all criteria implied by the given
                // criteria to the CriteriaSet.
                fn recurse_implies(
                    result: &mut CriteriaSet,
                    direct_implies: &[CriteriaSet],
                    cur_idx: usize,
                ) {
                    for idx in direct_implies[cur_idx].indices() {
                        if !result.has_criteria(idx) {
                            result.set_criteria(idx);
                            recurse_implies(result, direct_implies, idx);
                        }
                    }
                }

                // Determine all criteria implied by each index, ensure each
                // criteria does not imply itself, and then complete the set.
                let mut implied = CriteriaSet::none(names.len());
                recurse_implies(&mut implied, &direct_implies, idx);
                if implied.has_criteria(idx) {
                    // XXX: Consider producing a better error here?
                    panic!("criteria '{}' implies itself", names[idx]);
                }
                implied.set_criteria(idx);
                implied
            })
            .collect();

        CriteriaMapper {
            index,
            names,
            implied_criteria,
        }
    }

    /// Builds a CriteriaSet from a list of criteria.
    pub fn criteria_from_list<'b, S: AsRef<str> + 'b + ?Sized>(
        &self,
        list: impl IntoIterator<Item = &'b S>,
    ) -> CriteriaSet {
        let mut result = self.no_criteria();
        for criteria in list {
            self.set_criteria(&mut result, criteria.as_ref());
        }
        result
    }

    /// Set the given named criteria and all criteria implied by it within the
    /// given CriteriaSet.
    pub fn set_criteria(&self, set: &mut CriteriaSet, criteria: CriteriaStr) {
        set.unioned_with(&self.implied_criteria[self.index[criteria]])
    }

    /// An iterator over every criteria in order, with 'implies' fully applied.
    pub fn all_criteria_iter(&self) -> impl Iterator<Item = &CriteriaSet> {
        self.implied_criteria.iter()
    }

    /// Get the total number of criteria.
    pub fn len(&self) -> usize {
        self.names.len()
    }

    /// Get a CriteriaSet of the correct size for this CriteriaMap containing no criteria
    pub fn no_criteria(&self) -> CriteriaSet {
        CriteriaSet::none(self.len())
    }

    /// Get a CriteriaSet of the correct size for this CriteriaMap containing all criteria
    pub fn all_criteria(&self) -> CriteriaSet {
        CriteriaSet::all(self.len())
    }

    /// Like [`CriteriaSet::indices`] but uses knowledge of things like
    /// `implies` relationships to remove redundant information. For
    /// instance, if safe-to-deploy is set, we don't also yield safe-to-run.
    pub fn minimal_indices<'a>(
        &'a self,
        criteria: &'a CriteriaSet,
    ) -> impl Iterator<Item = usize> + 'a {
        criteria.indices().filter(|&cur_idx| {
            criteria.indices().all(|other_idx| {
                // Ignore our own index
                let is_identity = cur_idx == other_idx;
                // Discard this criteria if it's implied by another
                let isnt_implied = !self.implied_criteria[other_idx].has_criteria(cur_idx);
                is_identity || isnt_implied
            })
        })
    }

    /// Yields all the names of the set criteria with implied members filtered out.
    pub fn criteria_names<'a>(
        &'a self,
        criteria: &'a CriteriaSet,
    ) -> impl Iterator<Item = CriteriaStr<'a>> + 'a {
        self.minimal_indices(criteria).map(|idx| &*self.names[idx])
    }

    /// Yields the names for all criteria
    pub fn all_criteria_names(&self) -> impl Iterator<Item = CriteriaStr<'_>> + '_ {
        self.names.iter().map(|s| &s[..])
    }

    /// Yields the name of a specific criteria by index.
    pub fn criteria_name(&self, criteria_idx: usize) -> CriteriaStr<'_> {
        &self.names[criteria_idx][..]
    }

    /// Yields the index for the given criteria
    pub fn criteria_index(&self, criteria_name: CriteriaStr<'_>) -> usize {
        self.index[criteria_name]
    }

    /// Yields the indices for all criteria which imply the given criteria.
    pub fn implied_by_indices(&self, criteria_idx: usize) -> impl Iterator<Item = usize> + '_ {
        self.all_criteria_iter()
            .enumerate()
            .filter(move |&(idx, implies_set)| {
                implies_set.has_criteria(criteria_idx) && criteria_idx != idx
            })
            .map(|(idx, _)| idx)
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
    pub fn all(count: usize) -> Self {
        assert!(
            count <= MAX_CRITERIA,
            "{MAX_CRITERIA} was not Enough For Everyone ({count} criteria)"
        );
        CriteriaSet((1u64 << count).wrapping_sub(1))
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
