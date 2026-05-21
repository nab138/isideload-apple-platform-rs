use std::io::{Read, Write, Seek};
use std::path::{Path, PathBuf};
use std::io;

pub trait VfsFile: Read + Write + Seek + Send + Sync {
    fn set_len(&self, _size: u64) -> io::Result<()> { Err(io::Error::new(io::ErrorKind::Unsupported, "set_len not supported on File")) }
    fn metadata(&self) -> io::Result<Box<dyn VfsMetadata>> { Err(io::Error::new(io::ErrorKind::Unsupported, "metadata not supported on File")) }
    fn set_permissions(&mut self, _perms: Box<dyn VfsPermissions>) -> io::Result<()> { Err(io::Error::new(io::ErrorKind::Unsupported, "set_permissions not supported on File")) }
}

pub trait VfsMetadata: Send + Sync {
    fn is_dir(&self) -> bool;
    fn is_file(&self) -> bool;
    fn is_symlink(&self) -> bool;
    fn len(&self) -> u64;
    fn permissions(&self) -> Box<dyn VfsPermissions>;
}

pub trait VfsPermissions: Send + Sync {
    fn readonly(&self) -> bool;
    fn set_readonly(&mut self, readonly: bool);
    fn mode(&self) -> u32;
    fn set_mode(&mut self, mode: u32);
}

#[derive(Debug, Clone, Default)]
pub struct OpenOptionsConfig {
    pub read: bool,
    pub write: bool,
    pub create: bool,
    pub create_new: bool,
    pub append: bool,
    pub truncate: bool,
}

pub trait Vfs: Send + Sync {
    fn open_file(&self, path: &Path, options: &OpenOptionsConfig) -> io::Result<Box<dyn VfsFile>>;
    fn read(&self, path: &Path) -> io::Result<Vec<u8>>;
    fn write(&self, path: &Path, contents: &[u8]) -> io::Result<()>;
    fn copy(&self, from: &Path, to: &Path) -> io::Result<u64>;
    fn rename(&self, from: &Path, to: &Path) -> io::Result<()>;
    fn remove_file(&self, path: &Path) -> io::Result<()>;
    fn remove_dir(&self, path: &Path) -> io::Result<()>;
    fn remove_dir_all(&self, path: &Path) -> io::Result<()>;
    fn create_dir(&self, path: &Path) -> io::Result<()>;
    fn create_dir_all(&self, path: &Path) -> io::Result<()>;
    fn read_link(&self, path: &Path) -> io::Result<PathBuf>;
    fn set_permissions(&self, path: &Path, perms: Box<dyn VfsPermissions>) -> io::Result<()>;
    fn metadata(&self, path: &Path) -> io::Result<Box<dyn VfsMetadata>>;
    fn symlink_metadata(&self, path: &Path) -> io::Result<Box<dyn VfsMetadata>>;
    fn read_dir(&self, path: &Path) -> io::Result<Vec<PathBuf>>;
}
