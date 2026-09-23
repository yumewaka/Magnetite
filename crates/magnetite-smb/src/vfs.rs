//! The SYSVOL filesystem the SMB server exposes, built from a **provisioned GPO**
//! ([`magnetite_gpo`]): the `GPT.INI` + `Machine/Registry.pol` + `User/Registry.pol`
//! for the Default Domain Policy, plus the directories that contain them.
//!
//! Paths are looked up case-insensitively with `\` separators (as SMB delivers
//! them); each node keeps its display name for directory listings. The tree is
//! inferred from the provisioned file paths.

use std::collections::HashMap;

/// A node's contents.
pub enum Kind {
    /// A file with its bytes.
    File(Vec<u8>),
    /// A directory listing child node indices.
    Dir(Vec<usize>),
}

/// One SYSVOL node.
pub struct Node {
    /// The display (basename) shown in directory listings.
    pub name: String,
    pub kind: Kind,
}

/// The SYSVOL filesystem.
pub struct Vfs {
    nodes: Vec<Node>,
    index: HashMap<String, usize>,
}

/// Normalise an SMB path for case-insensitive lookup.
fn normalize(path: &str) -> String {
    path.replace('/', "\\").trim_matches('\\').to_lowercase()
}

/// The provisioned Default Domain Policy's SYSVOL files as `(path, bytes)` — the
/// baseline a DC seeds into its replicated SYSVOL store.
pub fn default_sysvol_files() -> Vec<(String, Vec<u8>)> {
    magnetite_gpo::default_domain_policy().sysvol_files
}

impl Vfs {
    /// Resolve a path to a node index.
    pub fn lookup(&self, path: &str) -> Option<usize> {
        self.index.get(&normalize(path)).copied()
    }

    /// The node at `index`, or `None` if the index is out of range. Indices can come
    /// from a client-supplied FileId (decoded from wire bytes) or from an open handle
    /// held across a SYSVOL tree swap (`set_sysvol`), so a bounds check here turns a
    /// bogus/stale index into a clean protocol error instead of a panic.
    pub fn node(&self, index: usize) -> Option<&Node> {
        self.nodes.get(index)
    }

    /// A file's size (0 for a directory or an out-of-range index).
    pub fn size(&self, index: usize) -> u64 {
        match self.nodes.get(index).map(|n| &n.kind) {
            Some(Kind::File(data)) => data.len() as u64,
            _ => 0,
        }
    }

    /// The SYSVOL tree for the provisioned Default Domain Policy.
    pub fn sysvol() -> Self {
        Self::from_files(default_sysvol_files())
    }

    /// Build a tree from `(path, bytes)` files, creating the directory chain each
    /// path implies. Paths are `\`-separated relative to the share root.
    pub fn from_files(files: Vec<(String, Vec<u8>)>) -> Self {
        let mut nodes = vec![Node {
            name: String::new(),
            kind: Kind::Dir(Vec::new()),
        }];
        let mut index = HashMap::from([(String::new(), 0usize)]);

        for (path, content) in files {
            let parts: Vec<&str> = path.split('\\').filter(|p| !p.is_empty()).collect();
            let Some((file_name, dirs)) = parts.split_last() else {
                continue;
            };

            // Walk/create the directory chain.
            let mut parent = 0usize;
            let mut cur = String::new();
            for dir in dirs {
                cur = join(&cur, dir);
                parent = ensure_child(&mut nodes, &mut index, parent, dir, &cur, true, Vec::new());
            }

            // Add the file leaf.
            let leaf_path = join(&cur, file_name);
            ensure_child(
                &mut nodes, &mut index, parent, file_name, &leaf_path, false, content,
            );
        }

        Self { nodes, index }
    }
}

fn join(base: &str, part: &str) -> String {
    if base.is_empty() {
        part.to_lowercase()
    } else {
        format!("{base}\\{}", part.to_lowercase())
    }
}

/// Ensure a child node exists under `parent`, returning its index. `is_dir`
/// selects the node kind; `content` is the file bytes (ignored for dirs).
fn ensure_child(
    nodes: &mut Vec<Node>,
    index: &mut HashMap<String, usize>,
    parent: usize,
    name: &str,
    path: &str,
    is_dir: bool,
    content: Vec<u8>,
) -> usize {
    if let Some(&existing) = index.get(path) {
        return existing;
    }
    let new_idx = nodes.len();
    nodes.push(Node {
        name: name.to_string(),
        kind: if is_dir {
            Kind::Dir(Vec::new())
        } else {
            Kind::File(content)
        },
    });
    index.insert(path.to_string(), new_idx);
    if let Kind::Dir(children) = &mut nodes[parent].kind {
        children.push(new_idx);
    }
    new_idx
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_provisioned_policy_files() {
        let vfs = Vfs::sysvol();
        let base = "example.com/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}";

        let gpt = vfs.lookup(&format!("{base}/GPT.INI")).unwrap();
        assert!(matches!(vfs.node(gpt).unwrap().kind, Kind::File(_)));
        assert!(vfs.size(gpt) > 0);

        let reg = vfs.lookup(&format!("{base}/Machine/Registry.pol")).unwrap();
        let Kind::File(bytes) = &vfs.node(reg).unwrap().kind else {
            panic!("Registry.pol should be a file");
        };
        assert_eq!(&bytes[0..4], b"PReg", "real MS-GPREG Registry.pol");

        // Directories inferred from the file paths.
        assert!(vfs.lookup(&format!("{base}/Machine")).is_some());
        assert!(vfs.lookup(&format!("{base}/User")).is_some());
        assert!(vfs.lookup(base).is_some());
        assert!(vfs.lookup("no/such/path").is_none());
    }

    #[test]
    fn builds_a_served_tree_from_replicated_files() {
        // The serving side of SYSVOL replication: a DC builds its SMB tree from
        // the `(path, bytes)` it pulled into the DB store (`list_sysvol_files`).
        let files = vec![
            (
                "example.com\\Policies\\{NEW}\\GPT.INI".to_string(),
                b"[General]\r\nVersion=65536\r\n".to_vec(),
            ),
            (
                "example.com\\Policies\\{NEW}\\Machine\\Registry.pol".to_string(),
                b"PReg\x01\x00\x00\x00".to_vec(),
            ),
        ];
        let vfs = Vfs::from_files(files);
        let gpt = vfs
            .lookup("example.com/Policies/{NEW}/GPT.INI")
            .expect("replicated GPT.INI is served");
        let Kind::File(bytes) = &vfs.node(gpt).unwrap().kind else {
            panic!("GPT.INI should be a file");
        };
        assert!(bytes.starts_with(b"[General]"));
        assert!(vfs
            .lookup("example.com/Policies/{NEW}/Machine/Registry.pol")
            .is_some());
        assert!(vfs.lookup("example.com/Policies/{NEW}/Machine").is_some());
    }
}
