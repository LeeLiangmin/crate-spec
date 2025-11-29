use bincode::{Decode, Encode};
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use std::thread;
use std::time::Duration;

// 网络相关常量
/// 默认 HTTP 请求超时时间（秒）
pub const DEFAULT_HTTP_TIMEOUT_SECS: u64 = 30;

/// 密钥对文件权限（仅所有者可读写）
#[cfg(unix)]
pub const KEYPAIR_FILE_MODE: u32 = 0o600;

/// 默认重试次数
pub const DEFAULT_RETRY_TIMES: u32 = 3;

/// 默认重试延迟（毫秒）
pub const DEFAULT_RETRY_DELAY_MS: u64 = 1000;

// BaseConfig 用于 API 请求和 KeyPair 序列化
#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct BaseConfig {
    pub algo: String,
    pub kms: String,
    pub flow: String,
}

// KeyPair 结构体（使用 bincode 序列化）
#[derive(Debug, Clone, Encode, Decode)]
pub struct KeyPair {
    pub priv_key: String,
    pub pub_key: String,
    pub key_id: String,
    pub base_config: BaseConfig,
}

// NetworkSignature 结构体（使用 bincode 序列化，存储到签名段）
#[derive(Debug, Clone, Encode, Decode)]
pub struct NetworkSignature {
    pub pub_key: String,
    pub signature: String,
    pub algo: String,
    pub flow: String,
    pub kms: Option<String>,
    pub key_id: Option<String>,
}

// API 请求/响应结构体
#[derive(Debug, Serialize, Deserialize)]
struct KeyPairRequest {
    algo: String,
    kms: String,
    flow: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct KeyPairResponse {
    base_config: BaseConfig,
    #[serde(rename = "priv")]
    priv_key: String,
    #[serde(rename = "pub")]
    pub_key: String,
    #[serde(rename = "keyId", default)]
    key_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct SignDigestRequest {
    base_config: BaseConfig,
    #[serde(rename = "priv")]
    priv_key: String,
    digest: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct SignDigestResponse {
    base_config: BaseConfig,
    signature: String,
    #[serde(default)]
    cert: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct VerifyDigestRequest {
    base_config: BaseConfig,
    #[serde(rename = "pub")]
    pub_key: String,
    digest: String,
    signature: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct VerifyDigestResponse {
    base_config: BaseConfig,
    result: String,
    #[serde(default)]
    error: Option<String>,
}

impl KeyPair {
    /// 从文件加载密钥对
    pub fn load_from_file(path: &str) -> Result<Self, String> {
        let bin = fs::read(path).map_err(|e| format!("无法读取密钥对文件 {}: {}", path, e))?;
        bincode::decode_from_slice(&bin, bincode::config::standard())
            .map(|(keypair, _)| keypair)
            .map_err(|e| format!("无法解析密钥对文件 {}: {}", path, e))
    }

    /// 保存密钥对到文件
    pub fn save_to_file(&self, path: &str) -> Result<(), String> {
        let encoded = bincode::encode_to_vec(self, bincode::config::standard())
            .map_err(|e| format!("无法序列化密钥对: {}", e))?;
        
        // 确保目录存在
        if let Some(parent) = Path::new(path).parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("无法创建目录: {}", e))?;
        }
        
        fs::write(path, encoded)
            .map_err(|e| format!("无法写入密钥对文件 {}: {}", path, e))?;
        
        // 设置文件权限（仅所有者可读写）
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(path)
                .map_err(|e| format!("无法获取文件元数据: {}", e))?
                .permissions();
            perms.set_mode(KEYPAIR_FILE_MODE);
            fs::set_permissions(path, perms)
                .map_err(|e| format!("无法设置文件权限: {}", e))?;
        }
        
        Ok(())
    }

    /// 从 PKI 平台获取新密钥对
    pub fn fetch_from_pki(base_url: &str, base_config: &BaseConfig) -> Result<Self, String> {
        let client = Client::builder()
            .timeout(Duration::from_secs(DEFAULT_HTTP_TIMEOUT_SECS))
            .build()
            .map_err(|e| format!("无法创建 HTTP 客户端: {}", e))?;
        
        let url = format!("{}/v1/keypair", base_url);
        let request = KeyPairRequest {
            algo: base_config.algo.clone(),
            kms: base_config.kms.clone(),
            flow: base_config.flow.clone(),
        };
        
        let response = client
            .post(&url)
            .json(&request)
            .send()
            .map_err(|e| format!("网络请求失败: {}", e))?;
        
        if !response.status().is_success() {
            return Err(format!(
                "PKI 平台返回错误: {} {}",
                response.status(),
                response.text().unwrap_or_default()
            ));
        }
        
        let keypair_resp: KeyPairResponse = response
            .json()
            .map_err(|e| format!("无法解析响应: {}", e))?;
        
        Ok(KeyPair {
            priv_key: keypair_resp.priv_key,
            pub_key: keypair_resp.pub_key,
            key_id: keypair_resp.key_id.unwrap_or_default(),
            base_config: keypair_resp.base_config,
        })
    }

    /// 优先从本地加载，不存在或损坏则从平台获取并保存
    pub fn get_or_fetch(
        path: &str,
        base_url: &str,
        base_config: &BaseConfig,
    ) -> Result<Self, String> {
        // 尝试从本地加载
        match Self::load_from_file(path) {
            Ok(keypair) => Ok(keypair),
            Err(_) => {
                // 本地不存在或损坏，从平台获取
                println!("从 PKI 平台获取新密钥对...");
                let keypair = Self::fetch_from_pki(base_url, base_config)?;
                // 保存到本地
                keypair.save_to_file(path)?;
                println!("密钥对已保存到: {}", path);
                Ok(keypair)
            }
        }
    }
}

/// PKI API 客户端
pub struct PkiClient {
    base_url: String,
    retry_times: u32,
    retry_delay: u64, // 毫秒
    client: Client,
}

impl std::fmt::Debug for PkiClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PkiClient")
            .field("base_url", &self.base_url)
            .field("retry_times", &self.retry_times)
            .field("retry_delay", &self.retry_delay)
            .finish()
    }
}

impl PkiClient {
    /// 创建新的 PKI 客户端
    pub fn new(base_url: String, retry_times: u32, retry_delay: u64) -> Result<Self, String> {
        let client = Client::builder()
            .timeout(Duration::from_secs(DEFAULT_HTTP_TIMEOUT_SECS))
            .build()
            .map_err(|e| format!("无法创建 HTTP 客户端: {}", e))?;
        
        Ok(PkiClient {
            base_url,
            retry_times,
            retry_delay,
            client,
        })
    }

    /// 调用签名接口
    pub fn sign_digest(
        &self,
        priv_key: &str,
        digest: &str,
        base_config: &BaseConfig,
    ) -> Result<(String, Option<String>), String> {
        let url = format!("{}/v1/sign/digest", self.base_url);
        let request = SignDigestRequest {
            base_config: base_config.clone(),
            priv_key: priv_key.to_string(),
            digest: digest.to_string(),
        };
        
        let mut last_error: Option<String> = None;
        for attempt in 0..=self.retry_times {
            match self.client.post(&url).json(&request).send() {
                Ok(response) => {
                    // 收到响应，无论状态码如何都不重试
                    let status = response.status();
                    if !status.is_success() {
                        let error_text = response.text().unwrap_or_else(|_| "无法读取错误信息".to_string());
                        return Err(format!(
                            "PKI 平台返回错误 (HTTP {}): {}",
                            status,
                            error_text
                        ));
                    }
                    
                    let sign_resp: SignDigestResponse = response
                        .json()
                        .map_err(|e| format!("无法解析响应 JSON: {}", e))?;
                    
                    return Ok((sign_resp.signature, sign_resp.cert));
                }
                Err(e) => {
                    // 检查是否是网络连接错误（超时、连接失败等）
                    let is_retryable = e.is_timeout() || e.is_connect() || e.is_request();
                    
                    if is_retryable && attempt < self.retry_times {
                        eprintln!("网络连接失败（{}），{} 毫秒后重试 (尝试 {}/{})...", 
                            e, self.retry_delay, attempt + 1, self.retry_times + 1);
                        thread::sleep(Duration::from_millis(self.retry_delay));
                        last_error = Some(format!("网络连接失败: {} (URL: {})", e, url));
                        continue;
                    } else {
                        // 非可重试错误或已达到最大重试次数，直接返回错误
                        return Err(format!("网络请求失败: {} (URL: {})", e, url));
                    }
                }
            }
        }
        
        // 理论上不会到达这里（所有路径都已返回），但为了代码完整性保留
        Err(format!(
            "签名请求失败（已重试 {} 次）: {}",
            self.retry_times,
            last_error.unwrap_or_else(|| "未知错误".to_string())
        ))
    }

    /// 调用验签接口
    pub fn verify_digest(
        &self,
        pub_key: &str,
        digest: &str,
        signature: &str,
        base_config: &BaseConfig,
    ) -> Result<bool, String> {
        let url = format!("{}/v1/verify/digest", self.base_url);
        let request = VerifyDigestRequest {
            base_config: base_config.clone(),
            pub_key: pub_key.to_string(),
            digest: digest.to_string(),
            signature: signature.to_string(),
        };
        
        let mut last_error: Option<String> = None;
        for attempt in 0..=self.retry_times {
            match self.client.post(&url).json(&request).send() {
                Ok(response) => {
                    // 收到响应，无论状态码如何都不重试
                    let status = response.status();
                    if !status.is_success() {
                        let error_text = response.text().unwrap_or_else(|_| "无法读取错误信息".to_string());
                        return Err(format!(
                            "PKI 平台返回错误 (HTTP {}): {}",
                            status,
                            error_text
                        ));
                    }
                    
                    let verify_resp: VerifyDigestResponse = response
                        .json()
                        .map_err(|e| format!("无法解析响应 JSON: {}", e))?;
                    
                    if verify_resp.result == "OK" {
                        return Ok(true);
                    } else {
                        return Err(format!(
                            "验签失败: {}",
                            verify_resp.error.unwrap_or_else(|| "未知错误".to_string())
                        ));
                    }
                }
                Err(e) => {
                    // 检查是否是网络连接错误（超时、连接失败等）
                    let is_retryable = e.is_timeout() || e.is_connect() || e.is_request();
                    
                    if is_retryable && attempt < self.retry_times {
                        eprintln!("网络连接失败（{}），{} 毫秒后重试 (尝试 {}/{})...", 
                            e, self.retry_delay, attempt + 1, self.retry_times + 1);
                        thread::sleep(Duration::from_millis(self.retry_delay));
                        last_error = Some(format!("网络连接失败: {} (URL: {})", e, url));
                        continue;
                    } else {
                        // 非可重试错误或已达到最大重试次数，直接返回错误
                        return Err(format!("网络请求失败: {} (URL: {})", e, url));
                    }
                }
            }
        }
        
        // 理论上不会到达这里，但为了安全起见保留
        Err(format!(
            "验签请求失败（已重试 {} 次）: {}",
            self.retry_times,
            last_error.unwrap_or_else(|| "未知错误".to_string())
        ))
    }
}

/// 将 SHA256 二进制摘要转换为十六进制字符串（小写）
pub fn digest_to_hex_string(digest: &[u8]) -> String {
    digest.iter().map(|b| format!("{:02x}", b)).collect()
}

