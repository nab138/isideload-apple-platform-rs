use std::sync::RwLock;
use std::io;

pub mod fs;
pub mod native;
pub mod memory;
pub mod traits;

pub use traits::*;

static GLOBAL_VFS: RwLock<Option<Box<dyn Vfs>>> = RwLock::new(None);

pub fn set_vfs(vfs: Box<dyn Vfs>) {
    *GLOBAL_VFS.write().unwrap() = Some(vfs);
}

pub(crate) fn with_vfs<F, R>(f: F) -> io::Result<R>
where
    F: FnOnce(&dyn Vfs) -> io::Result<R>,
{
    let guard = GLOBAL_VFS.read().map_err(|_| {
        io::Error::new(io::ErrorKind::Other, "VFS lock poisoned")
    })?;
    
    if let Some(vfs) = guard.as_ref() {
        f(vfs.as_ref())
    } else {
        #[cfg(not(target_arch = "wasm32"))]
        {
            let native = native::NativeVfs;
            f(&native)
        }
        #[cfg(target_arch = "wasm32")]
        {
            Err(io::Error::new(io::ErrorKind::Unsupported, "No VFS configured for WASM"))
        }
    }
}
