use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

pub const DEFAULT_CONFIG_PATH: &str = "config/config.toml";

// 本地签名模式的配置结构
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalEncodeConfig {
    pub cert_path: Option<String>,
    pub root_ca_path: Option<String>,
    pub private_key_path: Option<String>,
    pub output_path: Option<String>,
    pub input_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalDecodeConfig {
    pub root_ca_path: Option<String>,
    pub output_path: Option<String>,
    pub input_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalConfig {
    pub encode: Option<LocalEncodeConfig>,
    pub decode: Option<LocalDecodeConfig>,
}

// 网络签名模式的配置结构
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkEncodeConfig {
    pub input_path: Option<String>,
    pub output_path: Option<String>,
    pub key_pair_path: Option<String>,
    pub algo: Option<String>,
    pub flow: Option<String>,
    pub kms: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkDecodeConfig {
    pub input_path: Option<String>,
    pub output_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    pub encode: Option<NetworkEncodeConfig>,
    pub decode: Option<NetworkDecodeConfig>,
}

// 网络配置段 [net]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetConfig {
    pub algo: Option<String>,
    pub flow: Option<String>,
    pub kms: Option<String>,
    pub pki_base_url: Option<String>,
    pub key_pair_path: Option<String>,
    pub retry_times: Option<u32>,
    pub retry_delay: Option<u64>, // 单位：毫秒
}

// 主配置结构
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub local: Option<LocalConfig>,
    pub network: Option<NetworkConfig>,
    #[serde(rename = "net")]
    pub net: Option<NetConfig>,
}

// 为了向后兼容，保留旧的配置结构（用于从 [encode] 和 [decode] 读取）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LegacyEncodeConfig {
    pub cert_path: Option<String>,
    pub root_ca_path: Option<String>,
    pub private_key_path: Option<String>,
    pub output_path: Option<String>,
    pub input_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LegacyDecodeConfig {
    pub root_ca_path: Option<String>,
    pub output_path: Option<String>,
    pub input_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LegacyConfig {
    pub encode: Option<LegacyEncodeConfig>,
    pub decode: Option<LegacyDecodeConfig>,
}

impl Config {
    /// 从文件加载配置
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, String> {
        let content =
            fs::read_to_string(path.as_ref()).map_err(|e| format!("无法读取配置文件: {}", e))?;

        // 首先尝试解析新格式 [local.encode] 和 [local.decode]
        match toml::from_str::<Config>(&content) {
            Ok(config) => {
                // 如果成功解析，检查是否有 local 配置
                if config.local.is_some() {
                    return Ok(config);
                }
                // 如果没有 local 配置，尝试解析旧格式
            }
            Err(_) => {
                // 如果解析失败，尝试解析旧格式
            }
        }

        // 尝试解析旧格式 [encode] 和 [decode]（向后兼容）
        match toml::from_str::<LegacyConfig>(&content) {
            Ok(legacy) => {
                // 将旧格式转换为新格式
                let local = LocalConfig {
                    encode: legacy.encode.map(|e| LocalEncodeConfig {
                        cert_path: e.cert_path,
                        root_ca_path: e.root_ca_path,
                        private_key_path: e.private_key_path,
                        output_path: e.output_path,
                        input_path: e.input_path,
                    }),
                    decode: legacy.decode.map(|d| LocalDecodeConfig {
                        root_ca_path: d.root_ca_path,
                        output_path: d.output_path,
                        input_path: d.input_path,
                    }),
                };
                Ok(Config {
                    local: Some(local),
                    network: None,
                    net: None,
                })
            }
            Err(e) => Err(format!("解析配置文件失败: {}", e)),
        }
    }

    /// 从默认配置文件加载
    pub fn from_default() -> Result<Self, String> {
        Self::from_file(Path::new(DEFAULT_CONFIG_PATH))
    }

    /// 获取本地编码配置
    pub fn get_local_encode_config(&self) -> Option<&LocalEncodeConfig> {
        self.local.as_ref()?.encode.as_ref()
    }

    /// 获取本地解码配置
    pub fn get_local_decode_config(&self) -> Option<&LocalDecodeConfig> {
        self.local.as_ref()?.decode.as_ref()
    }

    /// 获取网络编码配置
    pub fn get_network_encode_config(&self) -> Option<&NetworkEncodeConfig> {
        self.network.as_ref()?.encode.as_ref()
    }

    /// 获取网络解码配置
    pub fn get_network_decode_config(&self) -> Option<&NetworkDecodeConfig> {
        self.network.as_ref()?.decode.as_ref()
    }

    // 为了向后兼容，保留旧的方法名
    /// 获取编码配置（本地模式）
    pub fn get_encode_config(&self) -> Option<&LocalEncodeConfig> {
        self.get_local_encode_config()
    }

    /// 获取解码配置（本地模式）
    pub fn get_decode_config(&self) -> Option<&LocalDecodeConfig> {
        self.get_local_decode_config()
    }

    /// 获取网络配置
    pub fn get_net_config(&self) -> Option<&NetConfig> {
        self.net.as_ref()
    }

    /// 验证配置
    pub fn validate(&self) -> Result<(), String> {
        use std::path::Path;

        // 验证本地配置
        if let Some(local) = &self.local {
            if let Some(encode) = &local.encode {
                if let Some(cert_path) = &encode.cert_path {
                    if !Path::new(cert_path).exists() {
                        return Err(format!("证书文件不存在: {}", cert_path));
                    }
                }
                if let Some(pkey_path) = &encode.private_key_path {
                    if !Path::new(pkey_path).exists() {
                        return Err(format!("私钥文件不存在: {}", pkey_path));
                    }
                }
                if let Some(root_ca_path) = &encode.root_ca_path {
                    if !Path::new(root_ca_path).exists() {
                        return Err(format!("根CA文件不存在: {}", root_ca_path));
                    }
                }
            }
            if let Some(decode) = &local.decode {
                if let Some(root_ca_path) = &decode.root_ca_path {
                    if !Path::new(root_ca_path).exists() {
                        return Err(format!("根CA文件不存在: {}", root_ca_path));
                    }
                }
            }
        }

        // 验证网络配置
        if let Some(net) = &self.net {
            // 验证 URL 格式
            if let Some(url) = &net.pki_base_url {
                if !url.starts_with("http://") && !url.starts_with("https://") {
                    return Err(format!("无效的 PKI URL: {}", url));
                }
            }

            // 验证重试次数范围
            if let Some(retry_times) = net.retry_times {
                if retry_times == 0 {
                    return Err("重试次数不能为 0".to_string());
                }
                if retry_times > 100 {
                    return Err("重试次数不能超过 100".to_string());
                }
            }

            // 验证重试延迟范围
            if let Some(retry_delay) = net.retry_delay {
                if retry_delay == 0 {
                    return Err("重试延迟不能为 0".to_string());
                }
                if retry_delay > 60000 {
                    return Err("重试延迟不能超过 60000 毫秒".to_string());
                }
            }

            // 验证密钥对路径
            if let Some(key_pair_path) = &net.key_pair_path {
                if let Some(parent) = Path::new(key_pair_path).parent() {
                    if !parent.exists() {
                        return Err(format!("密钥对文件目录不存在: {}", parent.display()));
                    }
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_serialization() {
        let config = Config {
            local: Some(LocalConfig {
                encode: Some(LocalEncodeConfig {
                    cert_path: Some("test/cert.pem".to_string()),
                    root_ca_path: Some("test/root-ca.pem".to_string()),
                    private_key_path: Some("test/key.pem".to_string()),
                    output_path: Some("test/output/".to_string()),
                    input_path: Some("../crate-spec".to_string()),
                }),
                decode: Some(LocalDecodeConfig {
                    root_ca_path: Some("test/root-ca.pem".to_string()),
                    output_path: Some("test/output/".to_string()),
                    input_path: Some("test/output/crate-spec-0.1.0.scrate".to_string()),
                }),
            }),
            network: None,
        };

        let toml_str = toml::to_string(&config).unwrap();
        println!("{}", toml_str);
    }

    #[test]
    fn test_config_parse_new_format() {
        let toml_content = r#"
[local.encode]
cert_path = "test/cert.pem"
root_ca_path = "test/root-ca.pem"
private_key_path = "test/key.pem"
output_path = "test/output/"
input_path = "../crate-spec"

[local.decode]
root_ca_path = "test/root-ca.pem"
output_path = "test/output/"
input_path = "test/output/crate-spec-0.1.0.scrate"
"#;

        let config: Config = toml::from_str(toml_content).unwrap();
        assert!(config.local.is_some());
        assert!(config.local.as_ref().unwrap().encode.is_some());
        assert!(config.local.as_ref().unwrap().decode.is_some());
        
        let encode = config.get_local_encode_config().unwrap();
        assert_eq!(encode.cert_path.as_ref().unwrap(), "test/cert.pem");
        assert_eq!(encode.input_path.as_ref().unwrap(), "../crate-spec");
    }

    #[test]
    fn test_config_parse_legacy_format() {
        let toml_content = r#"
[encode]
cert_path = "test/cert.pem"
root_ca_path = "test/root-ca.pem"
private_key_path = "test/key.pem"
output_path = "test/output/"
input_path = "../crate-spec"

[decode]
root_ca_path = "test/root-ca.pem"
output_path = "test/output/"
input_path = "test/output/crate-spec-0.1.0.scrate"
"#;

        // 尝试解析旧格式 [encode] 和 [decode]（向后兼容）
        let legacy: LegacyConfig = toml::from_str(toml_content).unwrap();
        let local = LocalConfig {
            encode: legacy.encode.map(|e| LocalEncodeConfig {
                cert_path: e.cert_path,
                root_ca_path: e.root_ca_path,
                private_key_path: e.private_key_path,
                output_path: e.output_path,
                input_path: e.input_path,
            }),
            decode: legacy.decode.map(|d| LocalDecodeConfig {
                root_ca_path: d.root_ca_path,
                output_path: d.output_path,
                input_path: d.input_path,
            }),
        };
        let config = Config {
            local: Some(local),
            network: None,
        };
        
        assert!(config.local.is_some());
        assert!(config.local.as_ref().unwrap().encode.is_some());
        
        let encode = config.get_local_encode_config().unwrap();
        assert_eq!(encode.cert_path.as_ref().unwrap(), "test/cert.pem");
    }
}
