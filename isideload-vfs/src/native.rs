use crate::traits::{OpenOptionsConfig, Vfs, VfsFile, VfsMetadata, VfsPermissions};
use std::fs;
use std::io::{self, Read, Seek, Write};
use std::path::{Path, PathBuf};

#[cfg(not(target_arch = "wasm32"))]
pub struct NativeVfs;

#[cfg(not(target_arch = "wasm32"))]
struct NativePermissions(fs::Permissions);

#[cfg(not(target_arch = "wasm32"))]
impl VfsPermissions for NativePermissions {
    fn readonly(&self) -> bool {
        self.0.readonly()
    }
    fn set_readonly(&mut self, readonly: bool) {
        self.0.set_readonly(readonly);
    }
    fn mode(&self) -> u32 {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            self.0.mode()
        }
        #[cfg(not(unix))]
        {
            0
        }
    }
    fn set_mode(&mut self, mode: u32) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            self.0.set_mode(mode);
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
struct NativeMetadata(fs::Metadata);

#[cfg(not(target_arch = "wasm32"))]
impl VfsMetadata for NativeMetadata {
    fn is_dir(&self) -> bool {
        self.0.is_dir()
    }
    fn is_file(&self) -> bool {
        self.0.is_file()
    }
    fn is_symlink(&self) -> bool {
        self.0.file_type().is_symlink()
    }
    fn len(&self) -> u64 {
        self.0.len()
    }
    fn permissions(&self) -> Box<dyn VfsPermissions> {
        Box::new(NativePermissions(self.0.permissions()))
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl Vfs for NativeVfs {
    fn open_file(&self, path: &Path, options: &OpenOptionsConfig) -> io::Result<Box<dyn VfsFile>> {
        let file = fs::OpenOptions::new()
            .read(options.read)
            .write(options.write)
            .create(options.create)
            .create_new(options.create_new)
            .append(options.append)
            .truncate(options.truncate)
            .open(path)?;
        Ok(Box::new(NativeWrappedFile(file)))
    }
    fn read(&self, path: &Path) -> io::Result<Vec<u8>> {
        fs::read(path)
    }
    fn write(&self, path: &Path, contents: &[u8]) -> io::Result<()> {
        fs::write(path, contents)
    }
    fn copy(&self, from: &Path, to: &Path) -> io::Result<u64> {
        fs::copy(from, to)
    }
    fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
        fs::rename(from, to)
    }
    fn remove_file(&self, path: &Path) -> io::Result<()> {
        fs::remove_file(path)
    }
    fn remove_dir(&self, path: &Path) -> io::Result<()> {
        fs::remove_dir(path)
    }
    fn remove_dir_all(&self, path: &Path) -> io::Result<()> {
        fs::remove_dir_all(path)
    }
    fn create_dir(&self, path: &Path) -> io::Result<()> {
        fs::create_dir(path)
    }
    fn create_dir_all(&self, path: &Path) -> io::Result<()> {
        fs::create_dir_all(path)
    }
    fn read_link(&self, path: &Path) -> io::Result<PathBuf> {
        fs::read_link(path)
    }
    fn set_permissions(&self, path: &Path, perms: Box<dyn VfsPermissions>) -> io::Result<()> {
        let mut fs_perms = fs::metadata(path)?.permissions();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs_perms.set_mode(perms.mode());
        }
        fs_perms.set_readonly(perms.readonly());
        fs::set_permissions(path, fs_perms)
    }
    fn metadata(&self, path: &Path) -> io::Result<Box<dyn VfsMetadata>> {
        Ok(Box::new(NativeMetadata(fs::metadata(path)?)))
    }
    fn symlink_metadata(&self, path: &Path) -> io::Result<Box<dyn VfsMetadata>> {
        Ok(Box::new(NativeMetadata(fs::symlink_metadata(path)?)))
    }
    fn temp_dir(&self) -> PathBuf {
        std::env::temp_dir()
    }
    fn read_dir(&self, path: &Path) -> io::Result<Vec<PathBuf>> {
        let mut entries = Vec::new();
        for entry in fs::read_dir(path)? {
            entries.push(entry?.path());
        }
        Ok(entries)
    }
    fn symlink(&self, target: &Path, link: &Path) -> io::Result<()> {
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(target, link)
        }
        #[cfg(windows)]
        {
            let metadata = fs::metadata(target)?;
            if metadata.is_dir() {
                std::os::windows::fs::symlink_dir(target, link)
            } else {
                std::os::windows::fs::symlink_file(target, link)
            }
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug)]
pub struct NativeWrappedFile(pub fs::File);

#[cfg(not(target_arch = "wasm32"))]
impl Read for NativeWrappedFile {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}
#[cfg(not(target_arch = "wasm32"))]
impl Write for NativeWrappedFile {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}
#[cfg(not(target_arch = "wasm32"))]
impl Seek for NativeWrappedFile {
    fn seek(&mut self, pos: io::SeekFrom) -> io::Result<u64> {
        self.0.seek(pos)
    }
}
#[cfg(not(target_arch = "wasm32"))]
impl VfsFile for NativeWrappedFile {
    fn set_len(&self, size: u64) -> io::Result<()> {
        self.0.set_len(size)
    }
    fn metadata(&self) -> io::Result<Box<dyn VfsMetadata>> {
        Ok(Box::new(NativeMetadata(self.0.metadata()?)))
    }
    fn set_permissions(&mut self, perms: Box<dyn VfsPermissions>) -> io::Result<()> {
        let mut fs_perms = self.0.metadata()?.permissions();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs_perms.set_mode(perms.mode());
        }
        fs_perms.set_readonly(perms.readonly());
        self.0.set_permissions(fs_perms)
    }

    fn sync_all(&mut self) -> io::Result<()> {
        self.0.sync_all()
    }
}
