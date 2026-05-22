// This file is ai generated, I got lazy and wanted to just get something working.

use std::collections::BTreeMap;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, RwLock};

use crate::traits::{OpenOptionsConfig, Vfs, VfsFile, VfsMetadata, VfsPermissions};

fn normalize_path(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::from("/");
    for component in path.components() {
        match component {
            Component::ParentDir => {
                if normalized != Path::new("/") {
                    normalized.pop();
                }
            }
            Component::CurDir | Component::RootDir | Component::Prefix(_) => {}
            _ => {
                normalized.push(component);
            }
        }
    }
    normalized
}

#[derive(Clone)]
enum Node {
    File {
        contents: Arc<RwLock<Vec<u8>>>,
        mode: u32,
        readonly: bool,
    },
    Dir {
        mode: u32,
        readonly: bool,
    },
    Symlink {
        target: PathBuf,
    },
}

#[derive(Clone)]
pub struct MemoryVfs {
    nodes: Arc<RwLock<BTreeMap<PathBuf, Node>>>,
}

impl MemoryVfs {
    pub fn new() -> Self {
        let mut nodes = BTreeMap::new();
        nodes.insert(
            PathBuf::from("/"),
            Node::Dir {
                mode: 0o755,
                readonly: false,
            },
        );
        Self {
            nodes: Arc::new(RwLock::new(nodes)),
        }
    }

    fn resolve(&self, path: &PathBuf) -> io::Result<Node> {
        let guard = self.nodes.read().unwrap();
        let mut current = path.clone();
        for _ in 0..10 {
            if let Some(node) = guard.get(&current) {
                if let Node::Symlink { target } = node {
                    if target.is_absolute() {
                        current = normalize_path(target);
                    } else {
                        let mut parent = current.clone();
                        parent.pop();
                        parent.push(target);
                        current = normalize_path(&parent);
                    }
                    continue;
                }
                return Ok(node.clone());
            }
            // console::log_1(&format!("DEBUG: resolve failed to find path: {:?}", current).into());
            // console::log_1(&"DEBUG: Current VFS keys:".into());
            // for key in guard.keys() {
            //     console::log_1(&format!("DEBUG:   - {:?}", key).into());
            // }
            return Err(io::Error::from(io::ErrorKind::NotFound));
        }
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Too many symlinks",
        ))
    }
}

impl Default for MemoryVfs {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub struct MemoryFileHandle {
    contents: Arc<RwLock<Vec<u8>>>,
    cursor: u64,
    can_read: bool,
    can_write: bool,
    append: bool,
    mode: u32,
    readonly: bool,
}

impl Read for MemoryFileHandle {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if !self.can_read {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "File not open for reading",
            ));
        }
        let guard = self.contents.read().unwrap();
        if self.cursor >= guard.len() as u64 {
            return Ok(0);
        }
        let available = guard.len() as u64 - self.cursor;
        let to_read = std::cmp::min(available, buf.len() as u64) as usize;
        buf[..to_read]
            .copy_from_slice(&guard[self.cursor as usize..self.cursor as usize + to_read]);
        self.cursor += to_read as u64;
        Ok(to_read)
    }
}

impl Write for MemoryFileHandle {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if !self.can_write {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "File not open for writing",
            ));
        }
        let mut guard = self.contents.write().unwrap();
        if self.append {
            self.cursor = guard.len() as u64;
        }
        let cur = self.cursor as usize;
        let new_len = cur + buf.len();
        if new_len > guard.len() {
            guard.resize(new_len, 0);
        }
        guard[cur..cur + buf.len()].copy_from_slice(buf);
        self.cursor += buf.len() as u64;
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Seek for MemoryFileHandle {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let guard = self.contents.read().unwrap();
        let len = guard.len() as i64;
        let target = match pos {
            SeekFrom::Start(p) => p as i64,
            SeekFrom::End(p) => len + p,
            SeekFrom::Current(p) => self.cursor as i64 + p,
        };
        if target < 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "Invalid seek"));
        }
        self.cursor = target as u64;
        Ok(self.cursor)
    }
}

impl VfsFile for MemoryFileHandle {
    fn set_len(&self, size: u64) -> io::Result<()> {
        let mut guard = self.contents.write().unwrap();
        guard.resize(size as usize, 0);
        Ok(())
    }
    fn metadata(&self) -> io::Result<Box<dyn VfsMetadata>> {
        let guard = self.contents.read().unwrap();
        Ok(Box::new(MemoryMetadata {
            is_dir: false,
            is_file: true,
            is_symlink: false,
            len: guard.len() as u64,
            mode: self.mode,
            readonly: self.readonly,
        }))
    }
    fn set_permissions(&mut self, perms: Box<dyn VfsPermissions>) -> io::Result<()> {
        self.mode = perms.mode();
        self.readonly = perms.readonly();

        Ok(())
    }

    fn sync_all(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub struct MemoryMetadata {
    is_dir: bool,
    is_file: bool,
    is_symlink: bool,
    len: u64,
    mode: u32,
    readonly: bool,
}

impl VfsMetadata for MemoryMetadata {
    fn is_dir(&self) -> bool {
        self.is_dir
    }
    fn is_file(&self) -> bool {
        self.is_file
    }
    fn is_symlink(&self) -> bool {
        self.is_symlink
    }
    fn len(&self) -> u64 {
        self.len
    }
    fn permissions(&self) -> Box<dyn VfsPermissions> {
        Box::new(MemoryPermissions {
            mode: self.mode,
            readonly: self.readonly,
        })
    }
}

#[derive(Clone)]
pub struct MemoryPermissions {
    mode: u32,
    readonly: bool,
}

impl VfsPermissions for MemoryPermissions {
    fn readonly(&self) -> bool {
        self.readonly
    }
    fn set_readonly(&mut self, readonly: bool) {
        self.readonly = readonly;
    }
    fn mode(&self) -> u32 {
        self.mode
    }
    fn set_mode(&mut self, mode: u32) {
        self.mode = mode;
    }
}

impl Vfs for MemoryVfs {
    fn open_file(&self, path: &Path, options: &OpenOptionsConfig) -> io::Result<Box<dyn VfsFile>> {
        let path = normalize_path(path);
        let mut guard = self.nodes.write().unwrap();

        let exists = guard.contains_key(&path);
        if !exists && (!options.create && !options.create_new) {
            return Err(io::Error::from(io::ErrorKind::NotFound));
        }
        if exists && options.create_new {
            return Err(io::Error::from(io::ErrorKind::AlreadyExists));
        }

        let contents = if !exists {
            let c = Arc::new(RwLock::new(Vec::new()));
            guard.insert(
                path.clone(),
                Node::File {
                    contents: c.clone(),
                    mode: 0o644,
                    readonly: false,
                },
            );
            c
        } else {
            match guard.get(&path).unwrap() {
                Node::File { contents, .. } => {
                    if options.truncate {
                        contents.write().unwrap().clear();
                    }
                    contents.clone()
                }
                Node::Dir { .. } => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "Is a directory",
                    ));
                }
                Node::Symlink { .. } => {
                    return Err(io::Error::new(io::ErrorKind::InvalidInput, "Is a symlink"));
                }
            }
        };

        let (mode, readonly) = match guard.get(&path).unwrap() {
            Node::File { mode, readonly, .. } => (*mode, *readonly),
            _ => (0o644, false),
        };

        Ok(Box::new(MemoryFileHandle {
            contents,
            cursor: 0,
            can_read: options.read,
            can_write: options.write || options.append,
            append: options.append,
            mode,
            readonly,
        }))
    }

    fn read(&self, path: &Path) -> io::Result<Vec<u8>> {
        let path = normalize_path(path);
        let node = self.resolve(&path)?;
        match node {
            Node::File { contents, .. } => Ok(contents.read().unwrap().clone()),
            _ => Err(io::Error::new(io::ErrorKind::InvalidInput, "Not a file")),
        }
    }

    fn write(&self, path: &Path, contents: &[u8]) -> io::Result<()> {
        let path = normalize_path(path);
        let mut guard = self.nodes.write().unwrap();
        guard.insert(
            path,
            Node::File {
                contents: Arc::new(RwLock::new(contents.to_vec())),
                mode: 0o644,
                readonly: false,
            },
        );
        Ok(())
    }

    fn copy(&self, from: &Path, to: &Path) -> io::Result<u64> {
        let from_path = normalize_path(from);
        let to_path = normalize_path(to);
        let mut guard = self.nodes.write().unwrap();

        let (contents, mode, readonly) = match guard.get(&from_path) {
            Some(Node::File {
                contents,
                mode,
                readonly,
            }) => (contents.read().unwrap().clone(), *mode, *readonly),
            Some(_) => return Err(io::Error::new(io::ErrorKind::InvalidInput, "Not a file")),
            None => return Err(io::Error::from(io::ErrorKind::NotFound)),
        };
        guard.insert(
            to_path,
            Node::File {
                contents: Arc::new(RwLock::new(contents.clone())),
                mode: mode.clone(),
                readonly: readonly.clone(),
            },
        );
        Ok(contents.len() as u64)
    }

    fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
        let from_path = normalize_path(from);
        let to_path = normalize_path(to);
        let mut guard = self.nodes.write().unwrap();
        let node = guard
            .remove(&from_path)
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;
        guard.insert(to_path, node);
        Ok(())
    }

    fn remove_file(&self, path: &Path) -> io::Result<()> {
        let path = normalize_path(path);
        let mut guard = self.nodes.write().unwrap();
        if let Some(Node::File { .. }) = guard.get(&path) {
            guard.remove(&path);
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Not a file or not found",
            ))
        }
    }

    fn remove_dir(&self, path: &Path) -> io::Result<()> {
        let path = normalize_path(path);
        let mut guard = self.nodes.write().unwrap();
        if let Some(Node::Dir { .. }) = guard.get(&path) {
            let mut prefix = path.clone().into_os_string();
            prefix.push("/");
            let has_children = guard.keys().any(|k| {
                k.as_os_str()
                    .as_encoded_bytes()
                    .starts_with(prefix.as_encoded_bytes())
            });
            if has_children {
                return Err(io::Error::new(io::ErrorKind::Other, "Directory not empty"));
            }
            guard.remove(&path);
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Not a directory or not found",
            ))
        }
    }

    fn remove_dir_all(&self, path: &Path) -> io::Result<()> {
        let path = normalize_path(path);
        let mut guard = self.nodes.write().unwrap();
        let mut to_remove = Vec::new();
        to_remove.push(path.clone());
        let mut prefix = path.into_os_string();
        prefix.push("/");
        for k in guard.keys() {
            if k.as_os_str()
                .as_encoded_bytes()
                .starts_with(prefix.as_encoded_bytes())
            {
                to_remove.push(k.clone());
            }
        }
        for k in to_remove {
            guard.remove(&k);
        }
        Ok(())
    }

    fn create_dir(&self, path: &Path) -> io::Result<()> {
        let path = normalize_path(path);
        let mut guard = self.nodes.write().unwrap();
        if guard.contains_key(&path) {
            return Err(io::Error::from(io::ErrorKind::AlreadyExists));
        }
        guard.insert(
            path,
            Node::Dir {
                mode: 0o755,
                readonly: false,
            },
        );
        Ok(())
    }

    fn create_dir_all(&self, path: &Path) -> io::Result<()> {
        let path = normalize_path(path);
        let mut guard = self.nodes.write().unwrap();
        let mut p = PathBuf::new();
        for comp in path.components() {
            p.push(comp);
            if !guard.contains_key(&p) {
                guard.insert(
                    p.clone(),
                    Node::Dir {
                        mode: 0o755,
                        readonly: false,
                    },
                );
            }
        }
        Ok(())
    }

    fn read_link(&self, path: &Path) -> io::Result<PathBuf> {
        let path = normalize_path(path);
        let guard = self.nodes.read().unwrap();
        if let Some(Node::Symlink { target }) = guard.get(&path) {
            Ok(target.clone())
        } else {
            Err(io::Error::new(io::ErrorKind::InvalidInput, "Not a symlink"))
        }
    }

    fn set_permissions(&self, path: &Path, perms: Box<dyn VfsPermissions>) -> io::Result<()> {
        let path = normalize_path(path);
        let mut guard = self.nodes.write().unwrap();
        if let Some(node) = guard.get_mut(&path) {
            match node {
                Node::File { mode, readonly, .. } => {
                    *mode = perms.mode();
                    *readonly = perms.readonly();
                }
                Node::Dir { mode, readonly } => {
                    *mode = perms.mode();
                    *readonly = perms.readonly();
                }
                Node::Symlink { .. } => {}
            }
            Ok(())
        } else {
            Err(io::Error::from(io::ErrorKind::NotFound))
        }
    }

    fn metadata(&self, path: &Path) -> io::Result<Box<dyn VfsMetadata>> {
        let path = normalize_path(path);
        let node = self.resolve(&path)?;
        match node {
            Node::File {
                contents,
                mode,
                readonly,
            } => Ok(Box::new(MemoryMetadata {
                is_dir: false,
                is_file: true,
                is_symlink: false,
                len: contents.read().unwrap().len() as u64,
                mode,
                readonly,
            })),
            Node::Dir { mode, readonly } => Ok(Box::new(MemoryMetadata {
                is_dir: true,
                is_file: false,
                is_symlink: false,
                len: 0,
                mode,
                readonly,
            })),
            Node::Symlink { .. } => Err(io::Error::new(
                io::ErrorKind::Other,
                "Resolved to symlink unexpectedly",
            )),
        }
    }

    fn symlink_metadata(&self, path: &Path) -> io::Result<Box<dyn VfsMetadata>> {
        let path = normalize_path(path);
        let guard = self.nodes.read().unwrap();
        if let Some(node) = guard.get(&path) {
            match node {
                Node::File {
                    contents,
                    mode,
                    readonly,
                } => Ok(Box::new(MemoryMetadata {
                    is_dir: false,
                    is_file: true,
                    is_symlink: false,
                    len: contents.read().unwrap().len() as u64,
                    mode: *mode,
                    readonly: *readonly,
                })),
                Node::Dir { mode, readonly } => Ok(Box::new(MemoryMetadata {
                    is_dir: true,
                    is_file: false,
                    is_symlink: false,
                    len: 0,
                    mode: *mode,
                    readonly: *readonly,
                })),
                Node::Symlink { .. } => Ok(Box::new(MemoryMetadata {
                    is_dir: false,
                    is_file: false,
                    is_symlink: true,
                    len: 0,
                    mode: 0o777,
                    readonly: false,
                })),
            }
        } else {
            Err(io::Error::from(io::ErrorKind::NotFound))
        }
    }

    fn temp_dir(&self) -> PathBuf {
        PathBuf::from("/")
    }
    fn read_dir(&self, path: &Path) -> io::Result<Vec<PathBuf>> {
        let path = normalize_path(path);
        let guard = self.nodes.read().unwrap();
        if !guard.contains_key(&path) {
            return Err(io::Error::from(io::ErrorKind::NotFound));
        }
        let mut entries = Vec::new();
        for k in guard.keys() {
            if let Ok(suffix) = k.strip_prefix(&path) {
                if suffix.components().count() == 1 {
                    entries.push(k.clone());
                }
            }
        }
        Ok(entries)
    }

    fn symlink(&self, target: &Path, link: &Path) -> io::Result<()> {
        let target = normalize_path(target);
        let link = normalize_path(link);
        let mut guard = self.nodes.write().unwrap();
        if !guard.contains_key(&target) {
            return Err(io::Error::from(io::ErrorKind::NotFound));
        }
        if guard.contains_key(&link) {
            return Err(io::Error::from(io::ErrorKind::AlreadyExists));
        }
        guard.insert(link, Node::Symlink { target });
        Ok(())
    }
}
