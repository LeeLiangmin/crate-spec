use crate::unpack::unpack_context;
use crate::config::Config;
use crate_spec::error::Result;
use crate_spec::utils::context::PackageContext;
use crate_spec::utils::file_ops::{validate_input_file, ensure_output_dir, write_file, write_text_file, read_file};
use std::sync::Arc;

/// 本地解码参数
#[derive(Debug, Clone)]
pub struct LocalDecodeParams {
    pub root_ca_paths: Vec<String>,
    pub output: String,
    pub input: String,
}

/// 网络解码参数
#[derive(Debug, Clone)]
pub struct NetworkDecodeParams {
    pub input: String,
    pub output: String,
}

/// 本地解码命令
pub struct LocalDecodeCommand;

impl LocalDecodeCommand {
    /// 执行本地解码操作
    pub fn execute(params: LocalDecodeParams) -> Result<()> {
        // 验证输入文件
        validate_input_file(&params.input)?;

        // 解码
        let pack_context = unpack_context(&params.input, params.root_ca_paths)?;

        // 输出文件
        let output_path = ensure_output_dir(&params.output)?;

        // 提取 crate bin 文件
        let mut bin_path = output_path.clone();
        bin_path.push(format!(
            "{}-{}.crate",
            pack_context.pack_info.name, pack_context.pack_info.version
        ));
        write_file(&bin_path, &pack_context.crate_binary.bytes)?;

        // 输出元数据
        let mut metadata_path = output_path;
        metadata_path.push(format!(
            "{}-{}-metadata.txt",
            pack_context.pack_info.name, pack_context.pack_info.version
        ));
        write_text_file(
            &metadata_path,
            &format!(
                "{:#?}\n{:#?}",
                pack_context.pack_info, pack_context.dep_infos
            ),
        )?;

        Ok(())
    }
}

/// 网络解码命令
pub struct NetworkDecodeCommand;

impl NetworkDecodeCommand {
    /// 执行网络解码操作
    pub fn execute(params: NetworkDecodeParams, config: &Config) -> Result<()> {
        // 验证输入文件
        let input_path = validate_input_file(&params.input)?;

        // 从配置创建 PKI 客户端
        let pki_client = config.create_pki_client()?;

        // 读取文件并解码
        let bin = read_file(&input_path)?;
        
        let mut pack_context = PackageContext::new();
        // 设置网络客户端
        pack_context.network_client = Some(Arc::new(pki_client));
        
        // 解码并验证签名
        let (_crate_package, _str_table) = pack_context.decode_from_crate_package(&bin)?;

        // 输出文件
        let output_path = ensure_output_dir(&params.output)?;

        // 提取 crate bin 文件
        let mut bin_path = output_path.clone();
        bin_path.push(format!(
            "{}-{}.crate",
            pack_context.pack_info.name, pack_context.pack_info.version
        ));
        write_file(&bin_path, &pack_context.crate_binary.bytes)?;

        // 输出元数据
        let mut metadata_path = output_path;
        metadata_path.push(format!(
            "{}-{}-metadata.txt",
            pack_context.pack_info.name, pack_context.pack_info.version
        ));
        write_text_file(
            &metadata_path,
            &format!(
                "{:#?}\n{:#?}",
                pack_context.pack_info, pack_context.dep_infos
            ),
        )?;

        Ok(())
    }
}

