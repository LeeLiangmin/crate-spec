use crate::config::{Config, NetConfig};
use crate_spec::error::{Result, CrateSpecError};
use crate_spec::network::{BaseConfig, PkiClient, KeyPair};
use std::sync::Arc;

/// 网络配置扩展方法
impl Config {
    /// 获取网络配置，如果不存在则返回错误
    pub fn require_net_config(&self) -> Result<&NetConfig> {
        self.get_net_config()
            .ok_or_else(|| CrateSpecError::ConfigError("配置文件中缺少 [net] 配置段".to_string()))
    }

    /// 创建 PKI 客户端
    pub fn create_pki_client(&self) -> Result<PkiClient> {
        let net_config = self.require_net_config()?;
        let pki_base_url = net_config.pki_base_url.as_ref()
            .ok_or_else(|| CrateSpecError::ConfigError("配置文件中缺少 pki_base_url".to_string()))?;
        let retry_times = net_config.retry_times.unwrap_or(crate_spec::network::DEFAULT_RETRY_TIMES);
        let retry_delay = net_config.retry_delay.unwrap_or(crate_spec::network::DEFAULT_RETRY_DELAY_MS);
        
        PkiClient::new(pki_base_url.clone(), retry_times, retry_delay)
            .map_err(|e| CrateSpecError::NetworkError(e))
    }

    /// 创建 BaseConfig
    pub fn create_base_config(&self) -> Result<BaseConfig> {
        let net_config = self.require_net_config()?;
        let algo = net_config.algo.as_ref()
            .ok_or_else(|| CrateSpecError::ConfigError("配置文件中缺少 algo".to_string()))?;
        let flow = net_config.flow.as_ref()
            .ok_or_else(|| CrateSpecError::ConfigError("配置文件中缺少 flow".to_string()))?;
        let kms = net_config.kms.as_ref().map(|s| s.as_str()).unwrap_or("");
        
        Ok(BaseConfig {
            algo: algo.clone(),
            flow: flow.clone(),
            kms: kms.to_string(),
        })
    }

    /// 获取或加载密钥对
    pub fn get_or_fetch_keypair(&self) -> Result<Arc<KeyPair>> {
        let net_config = self.require_net_config()?;
        let pki_base_url = net_config.pki_base_url.as_ref()
            .ok_or_else(|| CrateSpecError::ConfigError("配置文件中缺少 pki_base_url".to_string()))?;
        let key_pair_path = net_config.key_pair_path.as_ref()
            .ok_or_else(|| CrateSpecError::ConfigError("配置文件中缺少 key_pair_path".to_string()))?;
        let base_config = self.create_base_config()?;
        
        KeyPair::get_or_fetch(key_pair_path, pki_base_url, &base_config)
            .map(|kp| Arc::new(kp))
            .map_err(|e| CrateSpecError::PkiError(e))
    }
}

