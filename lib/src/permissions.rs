//! File permission utilities for secure file operations.
//!
//! This module provides platform-specific functions to set restrictive
//! permissions on sensitive files like config and keystores.

use crate::error::Result;
use std::path::Path;

/// Set secure permissions on a file (0600 - owner read/write only).
#[cfg(unix)]
pub fn set_secure_file_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let permissions = std::fs::Permissions::from_mode(0o600);
    std::fs::set_permissions(path, permissions)?;
    Ok(())
}

/// No-op on non-Unix systems - rely on OS-level file protection.
#[cfg(not(unix))]
pub fn set_secure_file_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

/// Set secure permissions on a directory (0700 - owner only).
#[cfg(unix)]
pub fn set_secure_dir_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let permissions = std::fs::Permissions::from_mode(0o700);
    std::fs::set_permissions(path, permissions)?;
    Ok(())
}

/// No-op on non-Unix systems - rely on OS-level file protection.
#[cfg(not(unix))]
pub fn set_secure_dir_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    #[cfg(unix)]
    fn test_set_secure_file_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test_file");
        std::fs::write(&file_path, "test content").unwrap();

        set_secure_file_permissions(&file_path).unwrap();

        let metadata = std::fs::metadata(&file_path).unwrap();
        let mode = metadata.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    #[cfg(unix)]
    fn test_set_secure_dir_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let temp_dir = TempDir::new().unwrap();
        let dir_path = temp_dir.path().join("test_dir");
        std::fs::create_dir(&dir_path).unwrap();

        set_secure_dir_permissions(&dir_path).unwrap();

        let metadata = std::fs::metadata(&dir_path).unwrap();
        let mode = metadata.permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
    }
}
