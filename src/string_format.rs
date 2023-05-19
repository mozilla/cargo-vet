//! String formatting utilities.

use std::fmt::{self, Display, Formatter, Write};

/// Format a short list with commas and an "and" before the last item in a multi-item list.
///
/// If there are 2 or fewer items, they are always displayed (regardless of formatting width
/// limit), and the first item is also always displayed.
///
/// The default width is 40 characters.
pub struct FormatShortList<S> {
    items: Vec<S>,
}

impl<S: AsRef<str>> FormatShortList<S> {
    pub fn new(mut items: Vec<S>) -> Self {
        // To keep the display compact, sort by name length and truncate long lists.
        // We first sort by name because rust defaults to a stable sort and this will
        // have by-name as the tie breaker.
        items.sort_by(|a, b| {
            let a = a.as_ref();
            let b = b.as_ref();
            a.len().cmp(&b.len()).then_with(|| a.cmp(b))
        });
        FormatShortList { items }
    }

    pub fn string(items: Vec<S>) -> String {
        Self::new(items).to_string()
    }
}

impl<S: AsRef<str>> Display for FormatShortList<S> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let width = f.width().unwrap_or(40);

        // The character count for these constants is obtained with `len` (because we author this
        // text and there's no reason to do anything more expensive to get the length), so keep
        // these ASCII.
        const CONJUNCTION: &str = " and ";
        const REMAINDER: &str = " other";
        const REMAINDER_PLURAL: &str = "s";

        fn remainder_length(n: usize) -> usize {
            let num_length = n / 10 + 1;
            num_length + REMAINDER.len() + if n > 1 { REMAINDER_PLURAL.len() } else { 0 }
        }

        match self.items.as_slice() {
            [] => Ok(()),
            [a] => f.write_str(a.as_ref()),
            [a, b] => write!(f, "{}{CONJUNCTION}{}", a.as_ref(), b.as_ref()),
            items => {
                // Decide how many items we can show based on the width limit.
                let items_len = items.len();
                let too_large_index = items
                    .iter()
                    .enumerate()
                    .scan(0, |prior_length, (index, item)| {
                        // prior_length represents the length of the previous items up to and including
                        // the trailing comma.
                        let item_chars = console::measure_text_width(item.as_ref());
                        if index == items_len - 1 {
                            return Some(*prior_length + CONJUNCTION.len() + item_chars);
                        }
                        *prior_length += item_chars + 1; // item and trailing comma
                        Some(
                            *prior_length - usize::from(index == 0) /* no comma in this case, "FOO and X others" */
                                + CONJUNCTION.len()
                                + remainder_length(items_len - (index + 1)),
                        )
                    })
                    .position(|length| length > width);
                let large_enough_index = too_large_index.unwrap_or(items_len).saturating_sub(1);

                // Write out the items based on `large_enough_index`.
                f.write_str(items[0].as_ref())?;
                if large_enough_index == 0 {
                    f.write_str(CONJUNCTION)?;
                    write!(f, "{}{REMAINDER}{REMAINDER_PLURAL}", items_len - 1)?;
                } else {
                    for item in &items[1..=std::cmp::min(large_enough_index, items_len - 2)] {
                        write!(f, ", {}", item.as_ref())?;
                    }
                    f.write_char(',')?;
                    f.write_str(CONJUNCTION)?;
                    if large_enough_index == items_len - 1 {
                        f.write_str(items[large_enough_index].as_ref())?;
                    } else {
                        let remaining = items_len - (large_enough_index + 1);
                        write!(
                            f,
                            "{}{REMAINDER}{}",
                            remaining,
                            if remaining > 1 { REMAINDER_PLURAL } else { "" }
                        )?;
                    }
                }

                Ok(())
            }
        }
    }
}
