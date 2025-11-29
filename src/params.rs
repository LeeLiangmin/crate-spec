use crate::config::Config;
use crate_spec::error::{Result, CrateSpecError};
use crate::commands::encode::{LocalEncodeParams, NetworkEncodeParams};
use crate::commands::decode::{LocalDecodeParams, NetworkDecodeParams};

/// 参数构建器
pub struct ParamsBuilder {
    pub encode: bool,
    pub decode: bool,
    pub root_ca_paths: Vec<String>,
    pub cert_path: Option<String>,
    pub pkey_path: Option<String>,
    pub output: Option<String>,
    pub input: Option<String>,
    pub config: Option<Config>,
}

impl ParamsBuilder {
    pub fn from_args(args: &crate::Args, config: Option<Config>) -> Self {
        Self {
            encode: args.encode,
            decode: args.decode,
            root_ca_paths: args.root_ca_paths.clone(),
            cert_path: args.cert_path.clone(),
            pkey_path: args.pkey_path.clone(),
            output: args.output.clone(),
            input: args.input.clone(),
            config,
        }
    }

    /// 获取本地编码参数
    pub fn build_local_encode_params(&self) -> Result<LocalEncodeParams> {
        if let Some(cfg) = &self.config {
            Self::extract_local_encode_from_config(cfg)
        } else {
            Self::extract_local_encode_from_cli(self)
        }
    }

    fn extract_local_encode_from_config(config: &Config) -> Result<LocalEncodeParams> {
        let encode_config = config
            .get_encode_config()
            .ok_or_else(|| CrateSpecError::ConfigError("配置文件中没有 [local.encode] 部分".to_string()))?;

        Ok(LocalEncodeParams {
            cert_path: encode_config.cert_path.clone()
                .ok_or_else(|| CrateSpecError::ConfigError("配置文件中缺少 cert_path".to_string()))?,
            pkey_path: encode_config.private_key_path.clone()
                .ok_or_else(|| CrateSpecError::ConfigError("配置文件中缺少 private_key_path".to_string()))?,
            root_ca_paths: encode_config.root_ca_path.as_ref()
                .map(|p| vec![p.clone()])
                .filter(|v| !v.is_empty())
                .ok_or_else(|| CrateSpecError::ConfigError("配置文件中缺少 root_ca_path".to_string()))?,
            output: encode_config.output_path.clone()
                .ok_or_else(|| CrateSpecError::ConfigError("配置文件中缺少 output_path".to_string()))?,
            input: encode_config.input_path.clone()
                .ok_or_else(|| CrateSpecError::ConfigError("配置文件中缺少 input_path".to_string()))?,
        })
    }

    fn extract_local_encode_from_cli(builder: &ParamsBuilder) -> Result<LocalEncodeParams> {
        Ok(LocalEncodeParams {
            cert_path: builder.cert_path.clone()
                .ok_or_else(|| CrateSpecError::ValidationError("必须提供证书路径 (-c)".to_string()))?,
            pkey_path: builder.pkey_path.clone()
                .ok_or_else(|| CrateSpecError::ValidationError("必须提供私钥路径 (-p)".to_string()))?,
            root_ca_paths: if builder.root_ca_paths.is_empty() {
                return Err(CrateSpecError::ValidationError("必须提供根CA路径 (-r)".to_string()));
            } else {
                builder.root_ca_paths.clone()
            },
            output: builder.output.clone()
                .ok_or_else(|| CrateSpecError::ValidationError("必须提供输出路径 (-o)".to_string()))?,
            input: builder.input.clone()
                .ok_or_else(|| CrateSpecError::ValidationError("必须提供输入路径".to_string()))?,
        })
    }

    /// 获取本地解码参数
    pub fn build_local_decode_params(&self) -> Result<LocalDecodeParams> {
        if let Some(cfg) = &self.config {
            Self::extract_local_decode_from_config(cfg)
        } else {
            Self::extract_local_decode_from_cli(self)
        }
    }

    fn extract_local_decode_from_config(config: &Config) -> Result<LocalDecodeParams> {
        let decode_config = config
            .get_decode_config()
            .ok_or_else(|| CrateSpecError::ConfigError("配置文件中没有 [local.decode] 部分".to_string()))?;

        Ok(LocalDecodeParams {
            root_ca_paths: decode_config.root_ca_path.as_ref()
                .map(|p| vec![p.clone()])
                .filter(|v| !v.is_empty())
                .ok_or_else(|| CrateSpecError::ConfigError("配置文件中缺少 root_ca_path".to_string()))?,
            output: decode_config.output_path.clone()
                .ok_or_else(|| CrateSpecError::ConfigError("配置文件中缺少 output_path".to_string()))?,
            input: decode_config.input_path.clone()
                .ok_or_else(|| CrateSpecError::ConfigError("配置文件中缺少 input_path".to_string()))?,
        })
    }

    fn extract_local_decode_from_cli(builder: &ParamsBuilder) -> Result<LocalDecodeParams> {
        Ok(LocalDecodeParams {
            root_ca_paths: if builder.root_ca_paths.is_empty() {
                return Err(CrateSpecError::ValidationError("必须提供根CA路径 (-r)".to_string()));
            } else {
                builder.root_ca_paths.clone()
            },
            output: builder.output.clone()
                .ok_or_else(|| CrateSpecError::ValidationError("必须提供输出路径 (-o)".to_string()))?,
            input: builder.input.clone()
                .ok_or_else(|| CrateSpecError::ValidationError("必须提供输入路径".to_string()))?,
        })
    }

    /// 获取网络编码参数
    pub fn build_network_encode_params(&self) -> Result<NetworkEncodeParams> {
        let config = self.config.as_ref()
            .ok_or_else(|| CrateSpecError::ConfigError("网络模式需要配置文件".to_string()))?;
        let encode_config = config.get_network_encode_config()
            .ok_or_else(|| CrateSpecError::ConfigError("配置文件中缺少 [network.encode] 配置段".to_string()))?;
        
        Ok(NetworkEncodeParams {
            input: encode_config.input_path.clone()
                .ok_or_else(|| CrateSpecError::ConfigError("配置文件中缺少 input_path".to_string()))?,
            output: encode_config.output_path.clone()
                .ok_or_else(|| CrateSpecError::ConfigError("配置文件中缺少 output_path".to_string()))?,
        })
    }

    /// 获取网络解码参数
    pub fn build_network_decode_params(&self) -> Result<NetworkDecodeParams> {
        let config = self.config.as_ref()
            .ok_or_else(|| CrateSpecError::ConfigError("网络模式需要配置文件".to_string()))?;
        let decode_config = config.get_network_decode_config()
            .ok_or_else(|| CrateSpecError::ConfigError("配置文件中缺少 [network.decode] 配置段".to_string()))?;
        
        Ok(NetworkDecodeParams {
            input: decode_config.input_path.clone()
                .ok_or_else(|| CrateSpecError::ConfigError("配置文件中缺少 input_path".to_string()))?,
            output: decode_config.output_path.clone()
                .ok_or_else(|| CrateSpecError::ConfigError("配置文件中缺少 output_path".to_string()))?,
        })
    }
}

