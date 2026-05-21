use std::io::{self, Read, Write, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use crate::traits::{OpenOptionsConfig, VfsMetadata, VfsPermissions};
use crate::with_vfs;

pub struct File {
    inner: Box<dyn crate::traits::VfsFile>,
}

impl File {
    pub fn open<P: AsRef<Path>>(path: P) -> io::Result<File> {
        OpenOptions::new().read(true).open(path)
    }

    pub fn create<P: AsRef<Path>>(path: P) -> io::Result<File> {
        OpenOptions::new().write(true).create(true).truncate(true).open(path)
    }

    pub fn options() -> OpenOptions {
        OpenOptions::new()
    }
    
    pub fn set_len(&self, size: u64) -> io::Result<()> { self.inner.set_len(size) }
    
    pub fn metadata(&self) -> io::Result<Metadata> {
        self.inner.metadata().map(|inner| Metadata { inner })
    }
    
    pub fn set_permissions(&mut self, perm: Permissions) -> io::Result<()> {
        self.inner.set_permissions(perm.inner)
    }
}

impl Read for File {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> { self.inner.read(buf) }
}
impl Write for File {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> { self.inner.write(buf) }
    fn flush(&mut self) -> io::Result<()> { self.inner.flush() }
}
impl Seek for File {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> { self.inner.seek(pos) }
}

#[derive(Clone, Default)]
pub struct OpenOptions {
    config: OpenOptionsConfig,
}

impl OpenOptions {
    pub fn new() -> Self {
        Self { config: OpenOptionsConfig::default() }
    }
    pub fn read(&mut self, read: bool) -> &mut Self { self.config.read = read; self }
    pub fn write(&mut self, write: bool) -> &mut Self { self.config.write = write; self }
    pub fn create(&mut self, create: bool) -> &mut Self { self.config.create = create; self }
    pub fn create_new(&mut self, create_new: bool) -> &mut Self { self.config.create_new = create_new; self }
    pub fn append(&mut self, append: bool) -> &mut Self { self.config.append = append; self }
    pub fn truncate(&mut self, truncate: bool) -> &mut Self { self.config.truncate = truncate; self }
    pub fn open<P: AsRef<Path>>(&self, path: P) -> io::Result<File> {
        with_vfs(|vfs| {
            vfs.open_file(path.as_ref(), &self.config).map(|inner| File { inner })
        })
    }
}

pub struct Metadata {
    inner: Box<dyn VfsMetadata>,
}

pub struct FileType {
    is_dir: bool,
    is_file: bool,
    is_symlink: bool,
}

impl FileType {
    pub fn is_dir(&self) -> bool { self.is_dir }
    pub fn is_file(&self) -> bool { self.is_file }
    pub fn is_symlink(&self) -> bool { self.is_symlink }
}

impl Metadata {
    pub fn is_dir(&self) -> bool { self.inner.is_dir() }
    pub fn is_file(&self) -> bool { self.inner.is_file() }
    pub fn is_symlink(&self) -> bool { self.inner.is_symlink() }
    pub fn len(&self) -> u64 { self.inner.len() }
    pub fn permissions(&self) -> Permissions {
        Permissions { inner: self.inner.permissions() }
    }
    pub fn file_type(&self) -> FileType {
        FileType {
            is_dir: self.is_dir(),
            is_file: self.is_file(),
            is_symlink: self.is_symlink(),
        }
    }
}

pub struct Permissions {
    inner: Box<dyn VfsPermissions>,
}

impl Permissions {
    pub fn readonly(&self) -> bool { self.inner.readonly() }
    pub fn set_readonly(&mut self, readonly: bool) { self.inner.set_readonly(readonly) }
}

pub trait PermissionsExt {
    fn mode(&self) -> u32;
    fn set_mode(&mut self, mode: u32);
}

impl PermissionsExt for Permissions {
    fn mode(&self) -> u32 { self.inner.mode() }
    fn set_mode(&mut self, mode: u32) { self.inner.set_mode(mode) }
}

pub fn read<P: AsRef<Path>>(path: P) -> io::Result<Vec<u8>> {
    with_vfs(|vfs| vfs.read(path.as_ref()))
}

pub fn write<P: AsRef<Path>, C: AsRef<[u8]>>(path: P, contents: C) -> io::Result<()> {
    with_vfs(|vfs| vfs.write(path.as_ref(), contents.as_ref()))
}

pub fn copy<P: AsRef<Path>, Q: AsRef<Path>>(from: P, to: Q) -> io::Result<u64> {
    with_vfs(|vfs| vfs.copy(from.as_ref(), to.as_ref()))
}

pub fn rename<P: AsRef<Path>, Q: AsRef<Path>>(from: P, to: Q) -> io::Result<()> {
    with_vfs(|vfs| vfs.rename(from.as_ref(), to.as_ref()))
}

pub fn remove_file<P: AsRef<Path>>(path: P) -> io::Result<()> {
    with_vfs(|vfs| vfs.remove_file(path.as_ref()))
}

pub fn remove_dir<P: AsRef<Path>>(path: P) -> io::Result<()> {
    with_vfs(|vfs| vfs.remove_dir(path.as_ref()))
}

pub fn remove_dir_all<P: AsRef<Path>>(path: P) -> io::Result<()> {
    with_vfs(|vfs| vfs.remove_dir_all(path.as_ref()))
}

pub fn create_dir<P: AsRef<Path>>(path: P) -> io::Result<()> {
    with_vfs(|vfs| vfs.create_dir(path.as_ref()))
}

pub fn create_dir_all<P: AsRef<Path>>(path: P) -> io::Result<()> {
    with_vfs(|vfs| vfs.create_dir_all(path.as_ref()))
}

pub fn read_link<P: AsRef<Path>>(path: P) -> io::Result<PathBuf> {
    with_vfs(|vfs| vfs.read_link(path.as_ref()))
}

pub fn metadata<P: AsRef<Path>>(path: P) -> io::Result<Metadata> {
    with_vfs(|vfs| vfs.metadata(path.as_ref()).map(|inner| Metadata { inner }))
}

pub fn symlink_metadata<P: AsRef<Path>>(path: P) -> io::Result<Metadata> {
    with_vfs(|vfs| vfs.symlink_metadata(path.as_ref()).map(|inner| Metadata { inner }))
}

pub fn set_permissions<P: AsRef<Path>>(path: P, perm: Permissions) -> io::Result<()> {
    with_vfs(|vfs| vfs.set_permissions(path.as_ref(), perm.inner))
}

pub struct ReadDir {
    entries: std::vec::IntoIter<PathBuf>,
}

impl Iterator for ReadDir {
    type Item = io::Result<DirEntry>;
    fn next(&mut self) -> Option<Self::Item> {
        self.entries.next().map(|path| Ok(DirEntry { path }))
    }
}

pub struct DirEntry {
    path: PathBuf,
}

impl DirEntry {
    pub fn path(&self) -> PathBuf { self.path.clone() }
    pub fn file_name(&self) -> std::ffi::OsString {
        self.path.file_name().unwrap_or_default().to_os_string()
    }
    pub fn metadata(&self) -> io::Result<Metadata> {
        symlink_metadata(&self.path)
    }
}

pub fn read_dir<P: AsRef<Path>>(path: P) -> io::Result<ReadDir> {
    with_vfs(|vfs| {
        let entries = vfs.read_dir(path.as_ref())?;
        Ok(ReadDir {
            entries: entries.into_iter(),
        })
    })
}
