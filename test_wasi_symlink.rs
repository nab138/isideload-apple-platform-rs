use std::path::Path;
pub fn create_symlink(path: impl AsRef<Path>, target: impl AsRef<Path>) -> Result<(), std::io::Error> {
    std::os::wasi::fs::symlink(target, path)
}
