use crate::Cow;
use std::collections::{BTreeMap, BTreeSet};

use std::ffi::OsStr;
use std::io;

#[derive(Default)]
pub(crate) struct UniqueFilter<'a> {
    items: BTreeSet<Cow<'a, OsStr>>,
}

impl<'a> UniqueFilter<'a> {
    pub(crate) fn insert<I: Into<Cow<'a, OsStr>>>(
        &mut self,
        item: I,
    ) -> std::io::Result<Option<Cow<'a, OsStr>>> {
        let item = item.into();

        if item.is_empty() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "empty item"));
        }
        Ok(self.items.replace(item))
    }

    pub(crate) fn contains(&self, item: &OsStr) -> bool {
        self.items.contains(item)
    }

    pub(crate) fn len(&self) -> usize {
        self.items.len()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    pub fn to_iter(&self) -> btree_set::Iter<'_, Cow<'a, OsStr>> {
        self.items.iter()
    }
}

use std::collections::{btree_map, btree_set};

#[derive(Default)]
pub(crate) struct Filter<'a> {
    items: BTreeMap<Cow<'a, OsStr>, BTreeSet<Cow<'a, OsStr>>>,
}

impl<'a> Filter<'a> {
    pub(crate) fn insert<K: Into<Cow<'a, OsStr>>>(
        &mut self,
        key: K,
        val: Option<impl Into<Cow<'a, OsStr>>>,
    ) -> std::io::Result<Option<Cow<'a, OsStr>>> {
        let key = key.into();

        if key.is_empty() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "empty key"));
        }

        if let Some(val) = val.map(Into::into) {
            if val.is_empty() {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, "empty value"));
            }

            if let Some(existing) = self.items.get_mut(&*key) {
                return Ok(existing.replace(val));
            } else {
                let mut set = BTreeSet::new();
                set.insert(val);
                self.items.insert(key, set);
            }
        } else if !self.items.contains_key(&*key) {
            self.items.insert(key, Default::default());
        }

        Ok(None)
    }

    pub(crate) fn get(&self, key: &OsStr) -> Option<&BTreeSet<Cow<'a, OsStr>>> {
        self.items.get(key)
    }

    pub(crate) fn contains(&self, key: &OsStr) -> bool {
        self.items.contains_key(key)
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    pub fn to_iter(&self) -> btree_map::Iter<'_, Cow<'a, OsStr>, BTreeSet<Cow<'a, OsStr>>> {
        self.items.iter()
    }
}
