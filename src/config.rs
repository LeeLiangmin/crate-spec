use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

pub const DEFAULT_CONFIG_PATH: &str = "config/config.toml";



#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncodeConfig {
    pub cert_path: Option<String>,
    pub root_ca_path: Option<String>,
    pub private_key_path: Option<String>,
    pub output_path: Option<String>,
    pub input_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecodeConfig {
    pub root_ca_path: Option<String>,
    pub output_path: Option<String>,
    pub input_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub encode: Option<EncodeConfig>,
    pub decode: Option<DecodeConfig>,
}

impl Config {
    /// 从文件加载配置
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, String> {
        let content =
            fs::read_to_string(path.as_ref()).map_err(|e| format!("无法读取配置文件: {}", e))?;

        toml::from_str(&content).map_err(|e| format!("解析配置文件失败: {}", e))
    }

    /// 从默认配置文件加载
    pub fn from_default() -> Result<Self, String> {
        Self::from_file(Path::new(DEFAULT_CONFIG_PATH))
    }

    /// 获取编码配置
    pub fn get_encode_config(&self) -> Option<&EncodeConfig> {
        self.encode.as_ref()
    }

    /// 获取解码配置
    pub fn get_decode_config(&self) -> Option<&DecodeConfig> {
        self.decode.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_serialization() {
        let config = Config {
            encode: Some(EncodeConfig {
                cert_path: Some("test/cert.pem".to_string()),
                root_ca_path: Some("test/root-ca.pem".to_string()),
                private_key_path: Some("test/key.pem".to_string()),
                output_path: Some("test/output/".to_string()),
                input_path: Some("../crate-spec".to_string()),
            }),
            decode: Some(DecodeConfig {
                root_ca_path: Some("test/root-ca.pem".to_string()),
                output_path: Some("test/output/".to_string()),
                input_path: Some("test/output/crate-spec-0.1.0.scrate".to_string()),
            }),
        };

        let toml_str = toml::to_string(&config).unwrap();
        println!("{}", toml_str);
    }
}
