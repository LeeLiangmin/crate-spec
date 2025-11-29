use crate::config::Config;
use crate_spec::error::{CrateSpecError, Result};
use clap::Parser;
use crate::commands::{LocalEncodeCommand, NetworkEncodeCommand, LocalDecodeCommand, NetworkDecodeCommand};
use crate::params::ParamsBuilder;

pub mod pack;
pub mod unpack;
pub mod config;
pub mod config_ext;
pub mod network;
pub mod commands;
pub mod params;
use config::DEFAULT_CONFIG_PATH;

#[derive(Parser, Debug, Clone)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    ///encode crate
    #[clap(short, long, required = false)]
    encode: bool,
    ///decode crate
    #[clap(short, long, required = false)]
    decode: bool,
    ///mode: net or local (default: local)
    #[clap(long, value_name = "MODE", default_value = "local")]
    mode: String,
    ///config file path (default: config/config.toml, use config file when provided)
    #[clap(long, value_name = "PATH", num_args = 0..=1, default_missing_value = DEFAULT_CONFIG_PATH)]
    config: Option<String>,
    ///use command line arguments for local mode (mutually exclusive with --config)
    #[clap(long, required = false)]
    cli: bool,
    ///root-ca file paths
    #[clap(short, long, required = false)]
    root_ca_paths: Vec<String>,
    ///certification file path
    #[clap(short, long, required = false)]
    cert_path: Option<String>,
    ///private key path
    #[clap(short, long, required = false)]
    pkey_path: Option<String>,
    ///output file path
    #[clap(short, long, required = false)]
    output: Option<String>,
    ///input file path
    #[clap(required = false)]
    input: Option<String>,
}

/// 从指定路径加载配置文件
fn load_config(config_path: &str) -> Result<Config> {
    Config::from_file(config_path)
        .map_err(|e| CrateSpecError::ConfigError(format!("无法加载配置文件 {}: {}", config_path, e)))
}

/// 确定配置加载方式
fn determine_config(mode: &str, cli: bool, config_path: Option<&str>) -> Result<Option<Config>> {
    match mode {
        "local" => {
            if cli {
                Ok(None) // 使用命令行参数
            } else {
                let path = config_path.unwrap_or(DEFAULT_CONFIG_PATH);
                load_config(path).map(Some)
            }
        }
        "net" => {
            let path = config_path.unwrap_or(DEFAULT_CONFIG_PATH);
            load_config(path).map(Some)
        }
        _ => Err(CrateSpecError::ValidationError(format!("无效的模式: {}，必须是 'local' 或 'net'", mode))),
    }
}

/// 执行编码操作
fn execute_encode(mode: &str, params_builder: &ParamsBuilder) -> Result<()> {
    match mode {
        "local" => {
            let params = params_builder.build_local_encode_params()?;
            LocalEncodeCommand::execute(params)
        }
        "net" => {
            let config = params_builder.config.as_ref()
                .ok_or_else(|| CrateSpecError::ConfigError("网络模式需要配置文件".to_string()))?;
            let params = params_builder.build_network_encode_params()?;
            NetworkEncodeCommand::execute(params, config)
        }
        _ => unreachable!(),
    }
}

/// 执行解码操作
fn execute_decode(mode: &str, params_builder: &ParamsBuilder) -> Result<()> {
    match mode {
        "local" => {
            let params = params_builder.build_local_decode_params()?;
            LocalDecodeCommand::execute(params)
        }
        "net" => {
            let config = params_builder.config.as_ref()
                .ok_or_else(|| CrateSpecError::ConfigError("网络模式需要配置文件".to_string()))?;
            let params = params_builder.build_network_decode_params()?;
            NetworkDecodeCommand::execute(params, config)
        }
        _ => unreachable!(),
    }
}

fn main() {
    let args = Args::parse();
    let mode = args.mode.as_str();

    // 加载配置
    let config = match determine_config(mode, args.cli, args.config.as_deref()) {
        Ok(cfg) => {
            if cfg.is_some() {
                println!("从配置文件加载: {}", args.config.as_deref().unwrap_or(DEFAULT_CONFIG_PATH));
            }
            cfg
        }
        Err(e) => {
            eprintln!("错误: {}", e);
            std::process::exit(1);
        }
    };

    // 创建参数构建器
    let params_builder = ParamsBuilder::from_args(&args, config);

    // 执行操作
    let result = match (args.encode, args.decode) {
        (true, false) => execute_encode(mode, &params_builder),
        (false, true) => execute_decode(mode, &params_builder),
        _ => Err(CrateSpecError::ValidationError("必须指定 -e (编码) 或 -d (解码)".to_string())),
    };

    // 处理结果
    if let Err(e) = result {
        eprintln!("错误: {}", e);
        std::process::exit(1);
    }
}
