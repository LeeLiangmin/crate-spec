use crate::pack::{pack_context, pack_name};
use crate::config::Config;
use crate_spec::error::Result;
use crate_spec::utils::context::SIGTYPE;
use crate_spec::utils::file_ops::{validate_input_file, ensure_output_dir, write_file};
use crate_spec::utils::pkcs::PKCS;
use std::sync::Arc;

/// 本地编码参数
#[derive(Debug, Clone)]
pub struct LocalEncodeParams {
    pub cert_path: String,
    pub pkey_path: String,
    pub root_ca_paths: Vec<String>,
    pub output: String,
    pub input: String,
}

/// 网络编码参数
#[derive(Debug, Clone)]
pub struct NetworkEncodeParams {
    pub input: String,
    pub output: String,
}

/// 本地编码命令
pub struct LocalEncodeCommand;

impl LocalEncodeCommand {
    /// 执行本地编码操作
    pub fn execute(params: LocalEncodeParams) -> Result<()> {
        // 验证输入文件
        validate_input_file(&params.input)?;

        // 打包
        let mut pack_context = pack_context(&params.input)?;

        // 设置签名工具
        let mut pkcs = PKCS::new();
        pkcs.load_from_file_writer(
            params.cert_path,
            params.pkey_path,
            params.root_ca_paths,
        )?;

        pack_context.add_sig(pkcs, SIGTYPE::CRATEBIN);

        // 编码为二进制
        let (_, _, bin) = pack_context.encode_to_crate_package()?;

        // 输出文件
        let output_dir = ensure_output_dir(&params.output)?;
        let mut bin_path = output_dir;
        bin_path.push(pack_name(&pack_context));
        write_file(&bin_path, &bin)?;

        Ok(())
    }
}

/// 网络编码命令
pub struct NetworkEncodeCommand;

impl NetworkEncodeCommand {
    /// 执行网络编码操作
    pub fn execute(params: NetworkEncodeParams, config: &Config) -> Result<()> {
        // 验证输入文件
        validate_input_file(&params.input)?;

        // 从配置获取网络资源
        let pki_client = config.create_pki_client()?;
        let keypair = config.get_or_fetch_keypair()?;

        // 打包
        let mut pack_context = pack_context(&params.input)?;

        // 设置网络客户端和密钥对
        pack_context.network_client = Some(Arc::new(pki_client));
        pack_context.network_keypair = Some(keypair);

        // 添加网络签名（使用空的 PKCS，因为网络签名不需要本地证书）
        pack_context.add_sig(PKCS::new(), SIGTYPE::NETWORK);

        // 编码为二进制
        let (_, _, bin) = pack_context.encode_to_crate_package()?;

        // 输出文件
        let output_dir = ensure_output_dir(&params.output)?;
        let mut bin_path = output_dir;
        bin_path.push(pack_name(&pack_context));
        write_file(&bin_path, &bin)?;

        Ok(())
    }
}

