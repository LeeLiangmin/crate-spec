use crate::error::{Result, CrateSpecError};
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;

/// 验证输入文件是否存在
pub fn validate_input_file(input: &str) -> Result<PathBuf> {
    let path = PathBuf::from_str(input)
        .map_err(|e| CrateSpecError::ValidationError(format!("无效的输入路径: {}", e)))?;
    if !path.exists() {
        return Err(CrateSpecError::FileNotFound(path));
    }
    Ok(path)
}

/// 确保输出目录存在，如果不存在则创建
pub fn ensure_output_dir(output: &str) -> Result<PathBuf> {
    let path = PathBuf::from_str(output)
        .map_err(|e| CrateSpecError::ValidationError(format!("无效的输出路径: {}", e)))?;
    fs::create_dir_all(&path)
        .map_err(|e| CrateSpecError::Io(e))?;
    Ok(path)
}

/// 写入二进制文件
pub fn write_file(path: &Path, content: &[u8]) -> Result<()> {
    fs::write(path, content)
        .map_err(|e| CrateSpecError::Io(e))?;
    println!("文件已输出到: {}", path.display());
    Ok(())
}

/// 写入文本文件
pub fn write_text_file(path: &Path, content: &str) -> Result<()> {
    fs::write(path, content)
        .map_err(|e| CrateSpecError::Io(e))?;
    println!("文件已输出到: {}", path.display());
    Ok(())
}

/// 读取文件内容
pub fn read_file(path: &Path) -> Result<Vec<u8>> {
    fs::read(path)
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                CrateSpecError::FileNotFound(path.to_path_buf())
            } else {
                CrateSpecError::Io(e)
            }
        })
}

