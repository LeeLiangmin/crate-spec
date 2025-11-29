use std::fmt;
use std::io;
use std::path::PathBuf;

/// 项目统一的错误类型
#[derive(Debug)]
pub enum CrateSpecError {
    /// IO 错误
    Io(io::Error),
    /// 文件不存在
    FileNotFound(PathBuf),
    /// 配置文件错误
    ConfigError(String),
    /// 参数验证错误
    ValidationError(String),
    /// 网络请求错误
    NetworkError(String),
    /// PKI 平台错误
    PkiError(String),
    /// 签名错误
    SignatureError(String),
    /// 解码错误
    DecodeError(String),
    /// 编码错误
    EncodeError(String),
    /// 解析错误
    ParseError(String),
    /// 其他错误
    Other(String),
}

impl fmt::Display for CrateSpecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CrateSpecError::Io(e) => write!(f, "IO 错误: {}", e),
            CrateSpecError::FileNotFound(path) => write!(f, "文件不存在: {}", path.display()),
            CrateSpecError::ConfigError(msg) => write!(f, "配置错误: {}", msg),
            CrateSpecError::ValidationError(msg) => write!(f, "参数验证错误: {}", msg),
            CrateSpecError::NetworkError(msg) => write!(f, "网络错误: {}", msg),
            CrateSpecError::PkiError(msg) => write!(f, "PKI 平台错误: {}", msg),
            CrateSpecError::SignatureError(msg) => write!(f, "签名错误: {}", msg),
            CrateSpecError::DecodeError(msg) => write!(f, "解码错误: {}", msg),
            CrateSpecError::EncodeError(msg) => write!(f, "编码错误: {}", msg),
            CrateSpecError::ParseError(msg) => write!(f, "解析错误: {}", msg),
            CrateSpecError::Other(msg) => write!(f, "错误: {}", msg),
        }
    }
}

impl std::error::Error for CrateSpecError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            CrateSpecError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for CrateSpecError {
    fn from(err: io::Error) -> Self {
        CrateSpecError::Io(err)
    }
}

impl From<String> for CrateSpecError {
    fn from(err: String) -> Self {
        CrateSpecError::Other(err)
    }
}

impl From<&str> for CrateSpecError {
    fn from(err: &str) -> Self {
        CrateSpecError::Other(err.to_string())
    }
}

/// Result 类型别名，使用项目统一的错误类型
pub type Result<T> = std::result::Result<T, CrateSpecError>;

