//! Ordered keys in an AVL tree backed by one reusable slot array.
//! Admission and removal only relink slots. The zero link denotes an empty
//! child. Vacant slots link to the next reusable slot through their left link.

use std::{alloc::Layout, cmp::Ordering};

/// Failure to represent or reserve the entire negotiated index.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The slot count or array layout is not representable.
    Layout,
    /// The allocator could not supply the exact requested array.
    Allocation,
    /// A new key would exceed the number of reserved slots.
    Full,
}

#[derive(Clone, Copy)]
struct Node<K, V> {
    key: K,
    value: V,
    left: u32,
    right: u32,
    height: u8,
}

/// Fixed-capacity map for copyable protocol identifiers and inline metadata.
pub struct Index<K, V> {
    nodes: Vec<Node<K, V>>,
    root: u32,
    free: u32,
    len: usize,
}

impl<K: Ord + Copy, V: Copy> Index<K, V> {
    /// Exact heap layout, excluding the inline owner.
    pub fn planned_bytes(limit: usize) -> Result<usize, Error> {
        u32::try_from(limit).map_err(|_| Error::Layout)?;
        Layout::array::<Node<K, V>>(limit)
            .map(|l| l.size())
            .map_err(|_| Error::Layout)
    }

    /// Reserve without constructing dummy keys or allocating later on insert.
    pub fn new(limit: usize) -> Result<Self, Error> {
        Self::planned_bytes(limit)?;
        let mut nodes = Vec::new();
        nodes
            .try_reserve_exact(limit)
            .map_err(|_| Error::Allocation)?;
        if nodes.capacity() != limit {
            return Err(Error::Allocation);
        }
        Ok(Self {
            nodes,
            root: 0,
            free: 0,
            len: 0,
        })
    }

    /// Actual retained array capacity in bytes.
    pub fn capacity_bytes(&self) -> usize {
        self.nodes.capacity() * size_of::<Node<K, V>>()
    }

    /// Number of occupied keys.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether every key has been removed.
    pub fn is_empty(&self) -> bool {
        self.root == 0
    }

    fn node(&self, i: u32) -> &Node<K, V> {
        &self.nodes[(i - 1) as usize]
    }
    fn node_mut(&mut self, i: u32) -> &mut Node<K, V> {
        &mut self.nodes[(i - 1) as usize]
    }
    fn height(&self, i: u32) -> u8 {
        if i == 0 { 0 } else { self.node(i).height }
    }
    fn fix_height(&mut self, i: u32) {
        let n = self.node(i);
        self.node_mut(i).height = 1 + self.height(n.left).max(self.height(n.right));
    }
    fn left(&mut self, i: u32) -> u32 {
        let top = self.node(i).right;
        self.node_mut(i).right = self.node(top).left;
        self.node_mut(top).left = i;
        self.fix_height(i);
        self.fix_height(top);
        top
    }
    fn right(&mut self, i: u32) -> u32 {
        let top = self.node(i).left;
        self.node_mut(i).left = self.node(top).right;
        self.node_mut(top).right = i;
        self.fix_height(i);
        self.fix_height(top);
        top
    }
    fn balance(&mut self, i: u32) -> u32 {
        let (l, r) = (self.node(i).left, self.node(i).right);
        if self.height(l) > self.height(r) + 1 {
            if self.height(self.node(l).right) > self.height(self.node(l).left) {
                self.node_mut(i).left = self.left(l);
            }
            self.right(i)
        } else if self.height(r) > self.height(l) + 1 {
            if self.height(self.node(r).left) > self.height(self.node(r).right) {
                self.node_mut(i).right = self.right(r);
            }
            self.left(i)
        } else {
            self.fix_height(i);
            i
        }
    }

    /// Insert or replace a key. Replacement is also allowed at full capacity.
    pub fn insert(&mut self, key: K, value: V) -> Result<Option<V>, Error> {
        let (root, old) = self.put(self.root, key, value)?;
        self.root = root;
        Ok(old)
    }
    fn put(&mut self, i: u32, key: K, value: V) -> Result<(u32, Option<V>), Error> {
        if i == 0 {
            let node = Node {
                key,
                value,
                left: 0,
                right: 0,
                height: 1,
            };
            let slot = if self.free != 0 {
                let slot = self.free;
                self.free = self.node(slot).left;
                *self.node_mut(slot) = node;
                slot
            } else {
                if self.nodes.len() == self.nodes.capacity() {
                    return Err(Error::Full);
                }
                self.nodes.push(node);
                self.nodes.len() as u32
            };
            self.len += 1;
            return Ok((slot, None));
        }
        let old = match key.cmp(&self.node(i).key) {
            Ordering::Equal => {
                return Ok((
                    i,
                    Some(std::mem::replace(&mut self.node_mut(i).value, value)),
                ));
            }
            Ordering::Less => {
                let (child, old) = self.put(self.node(i).left, key, value)?;
                self.node_mut(i).left = child;
                old
            }
            Ordering::Greater => {
                let (child, old) = self.put(self.node(i).right, key, value)?;
                self.node_mut(i).right = child;
                old
            }
        };
        Ok((self.balance(i), old))
    }

    /// Release the matching slot for immediate reuse.
    pub fn remove(&mut self, key: K) -> Option<V> {
        let (root, value) = self.erase(self.root, key);
        self.root = root;
        value
    }
    fn erase(&mut self, i: u32, key: K) -> (u32, Option<V>) {
        if i == 0 {
            return (0, None);
        }
        let node = *self.node(i);
        let old = match key.cmp(&node.key) {
            Ordering::Less => {
                let (child, old) = self.erase(node.left, key);
                self.node_mut(i).left = child;
                old
            }
            Ordering::Greater => {
                let (child, old) = self.erase(node.right, key);
                self.node_mut(i).right = child;
                old
            }
            Ordering::Equal if node.left == 0 || node.right == 0 => {
                self.node_mut(i).left = self.free;
                self.free = i;
                self.len -= 1;
                return (node.left.max(node.right), Some(node.value));
            }
            Ordering::Equal => {
                let successor = *self.node(self.smallest(node.right));
                let (right, _) = self.erase(node.right, successor.key);
                let target = self.node_mut(i);
                target.key = successor.key;
                target.value = successor.value;
                target.right = right;
                Some(node.value)
            }
        };
        (self.balance(i), old)
    }

    fn smallest(&self, mut i: u32) -> u32 {
        while self.node(i).left != 0 {
            i = self.node(i).left;
        }
        i
    }

    /// Smallest retained key and value.
    pub fn first(&self) -> Option<(K, V)> {
        (self.root != 0).then(|| {
            let n = self.node(self.smallest(self.root));
            (n.key, n.value)
        })
    }

    /// Value of an exact matching key.
    pub fn get(&self, key: K) -> Option<V> {
        self.floor(key).filter(|(k, _)| *k == key).map(|(_, v)| v)
    }

    /// Mutably borrow a value while keeping its ordered key fixed.
    pub fn get_mut(&mut self, key: K) -> Option<&mut V> {
        let mut i = self.root;
        while i != 0 {
            let n = self.node(i);
            i = match key.cmp(&n.key) {
                Ordering::Equal => return Some(&mut self.node_mut(i).value),
                Ordering::Less => n.left,
                Ordering::Greater => n.right,
            };
        }
        None
    }

    /// Greatest retained key at or below the supplied key.
    pub fn floor(&self, key: K) -> Option<(K, V)> {
        self.neighbor(key, true)
    }

    /// Smallest retained key at or above the supplied key.
    pub fn ceil(&self, key: K) -> Option<(K, V)> {
        self.neighbor(key, false)
    }

    fn neighbor(&self, key: K, floor: bool) -> Option<(K, V)> {
        let mut i = self.root;
        let mut candidate = None;
        while i != 0 {
            let n = self.node(i);
            let ordering = n.key.cmp(&key);
            if ordering == Ordering::Equal {
                return Some((n.key, n.value));
            }
            let smaller = ordering == Ordering::Less;
            if smaller == floor {
                candidate = Some((n.key, n.value));
            }
            i = if smaller { n.right } else { n.left };
        }
        candidate
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn growing_full_reused_and_rotated_indexes_match_the_ordered_oracle() -> Result<(), Error> {
        let mut tree = Index::new(64)?;
        let mut oracle = BTreeMap::new();
        for round in 0..16u32 {
            for i in 0..64 {
                let key = round * 100 + (i * 19 % 64);
                assert_eq!(tree.insert(key, i)?, oracle.insert(key, i));
            }
            assert_eq!(tree.insert(u32::MAX, 5), Err(Error::Full));
            assert_eq!(
                tree.insert(round * 100, 72)?,
                oracle.insert(round * 100, 72)
            );
            for i in 0..64 {
                let key = round * 100 + (i * 37 % 64);
                assert_eq!(
                    tree.first(),
                    oracle.first_key_value().map(|(&k, &v)| (k, v))
                );
                assert_eq!(tree.remove(key), oracle.remove(&key));
                assert_eq!(
                    tree.floor(key),
                    oracle.range(..=key).next_back().map(|(&k, &v)| (k, v))
                );
                assert_eq!(
                    tree.ceil(key),
                    oracle.range(key..).next().map(|(&k, &v)| (k, v))
                );
                assert_eq!(tree.len(), oracle.len());
            }
            assert!(tree.is_empty());
            assert_eq!(tree.capacity_bytes(), Index::<u32, u32>::planned_bytes(64)?);
        }
        Ok(())
    }
}
