/// Dimensions of an n-dimentional matrix.
///
/// [2, 4, 3] would represent a 2x4x3 matrix.
#[derive(Clone, Debug, PartialEq)]
struct Dimensions(Vec<usize>);

impl Dimensions {
    /// Returns the number of dimensions.
    fn count(&self) -> usize {
        self.0.len()
    }

    /// Returns the number of elements in a matrix with these dimensions.
    fn num_elements(&self) -> usize {
        if self.0.is_empty() {
            0
        } else {
            self.0.iter().fold(1, |acc, dim| acc * dim)
        }
    }

    /// Iterates over all the slots in an n-dimensional matrix of the given
    /// dimensions.
    fn iter(&self) -> MatrixIndex {
        MatrixIndex {
            index: 0,
            dimensions: self,
        }
    }
}

/// Index into an n-dimensional matrix, represented as a scalar index into the
/// backing array.
#[derive(Clone, Copy, Debug, PartialEq)]
struct MatrixIndex<'a> {
    index: usize,
    dimensions: &'a Dimensions,
}

/// Index into an n-dimensional matrix, represented as (x, y, z, ...) coordinates.
struct VectorMatrixIndex<'a> {
    indices: Vec<usize>,
    dimensions: &'a Dimensions,
}

impl<'a> From<MatrixIndex<'a>> for VectorMatrixIndex<'a> {
    fn from(other: MatrixIndex<'a>) -> Self {
        let dimensions = other.dimensions;
        let mut indices = vec![0; dimensions.count()];
        let mut mult = 1;
        for i in 0..dimensions.count() {
            let next_mult = mult * dimensions.0[i];
            // modulo off the higher dimensions and divide off the lower dimensions.
            indices[i] = (other.index % (next_mult)) / mult;
            mult = next_mult;
        }

        VectorMatrixIndex { indices, dimensions }
    }
}

impl<'a> From<VectorMatrixIndex<'a>> for MatrixIndex<'a> {
    fn from(other: VectorMatrixIndex<'a>) -> Self {
        let dimensions = other.dimensions;
        let mut index = 0;
        let mut mult = 1;
        for i in 0..dimensions.count() {
            index += other.indices[i] * mult;
            mult *= dimensions.0[i];
        }

        MatrixIndex { index, dimensions }
    }
}

impl<'a> Iterator for MatrixIndex<'a> {
    type Item = MatrixIndex<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.index == self.dimensions.num_elements() {
            return None;
        }

        let result = self.clone();
        self.index += 1;
        Some(result)
    }
}

/// An n-dimensional matrix of bits.
struct BitMatrix {
    dimensions: Dimensions,
    // TODO: Optimize
    values: Vec<bool>,
}

impl BitMatrix {
    fn new(dimensions: Dimensions) -> Self {
        let values = vec![false; dimensions.num_elements()];
        BitMatrix { dimensions, values }
    }

    fn get(&self, idx: &MatrixIndex) -> bool {
        self.values[idx.index]
    }

    fn set(&mut self, idx: &MatrixIndex, value: bool) {
        self.values[idx.index] = value;
    }

    fn popcount(&self) -> usize {
        self.values.iter().fold(0, |acc, x| acc + (*x as usize))
    }
}

impl core::ops::BitAndAssign<&BitMatrix> for BitMatrix {
    fn bitand_assign(&mut self, rhs: &BitMatrix) {
        debug_assert!(self.dimensions == rhs.dimensions);
        for (left, right) in self.values.iter_mut().zip(rhs.values.iter()) {
            *left &= right;
        }
    }
}

/// Description of a particular axis in the target matrix.
#[derive(Clone, Eq, PartialEq)]
struct Axis {
    /// e.g. "target_os".
    name: String,
    /// e.g. ["android", "macos"]. Sorted lexographically.
    values: Vec<String>,
}

/// Sorted list of axes in the target matrix.
#[derive(Clone, Eq, PartialEq)]
struct Axes(Vec<Axis>);

impl Axes {
    /// Computes the dimensions of the target matrix corresponding to these axes.
    fn dimensions(&self) -> Dimensions {
        Dimensions(self.0.iter().map(|x| x.values.len()).collect())
    }

    /// True if these correspond to a zero-dimensional matrix.
    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns the union of two axes.
    fn union(&self, other: &Axes) -> Axes {
        unimplemented!()
    }
}

/// Represents a target specifier config string, e.g.
/// |all(any(target_os = "macos", target_os = "ios"), target_pointer_width = "64")|.
struct TargetString(String);
impl TargetString {
    /// Returns a description of the minimal target matrix axes which can describe
    /// the values in this config string.
    fn compute_axes(&self) -> Axes {
        unimplemented!();
    }

    /// Tests this target string against the provided config values.
    fn test(&self, values: &[(&str, &str)]) -> bool {
        unimplemented!();
    }
}

struct TargetRestriction {
    axes: Axes,
    matrix: BitMatrix,
}

impl From<TargetString> for TargetRestriction {
    fn from(s: TargetString) -> Self {
        let axes = s.compute_axes();
        let dimensions = axes.dimensions();
        let matrix = BitMatrix::new(dimensions);

        TargetRestriction { axes, matrix }
    }
}

impl TargetRestriction {
    fn is_unity(&self) -> bool {
        self.axes.is_empty()
    }

    fn intersect(mut self, other: &TargetRestriction) -> Self {
        /// Common case: intersecting with unity.
        if other.is_unity() {
            return self;
        }

        /// Medium case: identical axes.
        if self.axes == other.axes {
            self.matrix &= &other.matrix;
            return self;
        }

        /// Slow case: we need to grow both matrices into the union of the
        /// two axes, and then we can & them.
        let new_axes = self.axes.union(&other.axes);
        let expanded_other = other.expand(new_axes.clone());
        let mut result = self.expand(new_axes);
        result.matrix &= &expanded_other.matrix;
        result
    }

    fn expand(&self, axes: Axes) -> Self {
        let mut new_matrix = BitMatrix::new(axes.dimensions());
        for index in new_matrix.iter() {
            let vec_index = VectorMatrixIndex::from(index);

        }
        unimplemented!();
    }
}


#[cfg(test)]
mod tests {
use super::*;

#[test]
fn test_bitmatrix() {
    let dimensions = Dimensions(vec![2, 5, 4]);
    let matrix_size = 2 * 5 * 4;
    let mut m = BitMatrix::new(dimensions.clone());
    assert_eq!(m.popcount(), 0);
    let mut iter_count = 0;
    for index in dimensions.iter() {
        iter_count += 1;
        let vector_index = VectorMatrixIndex::from(index);
        let value = vector_index.indices[1] != 2;
        m.set(&index, value);
        assert_eq!(index, MatrixIndex::from(vector_index));
    }
    assert_eq!(iter_count, matrix_size);
    assert_eq!(m.popcount(), matrix_size - 2 * 4);
}

}
