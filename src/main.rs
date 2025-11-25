use crate::pack::{pack_context, pack_name};
use crate::unpack::unpack_context;
use crate::config::Config;
use clap::Parser;
use crate_spec::utils::context::SIGTYPE;
use crate_spec::utils::pkcs::PKCS;
use std::fs;
use std::path::PathBuf;
use std::str::FromStr;

pub mod pack;
pub mod unpack;
pub mod config;
use config::DEFAULT_CONFIG_PATH;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    ///encode crate
    #[clap(short, long, required = false)]
    encode: bool,
    ///decode crate
    #[clap(short, long, required = false)]
    decode: bool,
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
    ///config file path (if provided without value, uses default config/config.toml)
    #[clap(short = 'f', long, num_args = 0..=1, default_missing_value = DEFAULT_CONFIG_PATH)]
    config: Option<String>,
}

#[derive(Debug, Clone)]
struct EncodeParams {
    cert_path: String,
    pkey_path: String,
    root_ca_paths: Vec<String>,
    output: String,
    input: String,
}

#[derive(Debug, Clone)]
struct DecodeParams {
    root_ca_paths: Vec<String>,
    output: String,
    input: String,
}

/// 加载配置文件
fn load_config(config_path: Option<&String>) -> Option<Config> {
    if let Some(path) = config_path {
        match Config::from_file(path) {
            Ok(cfg) => {
                println!("从配置文件加载: {}", path);
                Some(cfg)
            }
            Err(e) => {
                eprintln!("错误: 无法加载配置文件 {}: {}", path, e);
                None
            }
        }
    } else {
        match Config::from_default() {
            Ok(cfg) => {
                println!("从默认配置文件加载: {}", DEFAULT_CONFIG_PATH);
                Some(cfg)
            }
            Err(_) => None,
        }
    }
}

/// 验证并获取编码参数
fn get_encode_params(args: &Args, config: &Option<Config>) -> Result<EncodeParams, String> {
    if let Some(cfg) = config {
        // 从配置文件获取参数
        let encode_config = cfg
            .get_encode_config()
            .ok_or("配置文件中没有 [encode] 部分")?;

        let cert_path = encode_config
            .cert_path
            .clone()
            .ok_or("配置文件中缺少 cert_path")?;
        let pkey_path = encode_config
            .private_key_path
            .clone()
            .ok_or("配置文件中缺少 private_key_path")?;
        let root_ca_paths = encode_config
            .root_ca_path
            .as_ref()
            .map(|p| vec![p.clone()])
            .unwrap_or_default();
        if root_ca_paths.is_empty() {
            return Err("配置文件中缺少 root_ca_path".to_string());
        }
        let output = encode_config
            .output_path
            .clone()
            .ok_or("配置文件中缺少 output_path")?;
        let input = encode_config
            .input_path
            .clone()
            .ok_or("配置文件中缺少 input_path")?;

        Ok(EncodeParams {
            cert_path,
            pkey_path,
            root_ca_paths,
            output,
            input,
        })
    } else {
        // 从命令行参数获取
        let cert_path = args
            .cert_path
            .clone()
            .ok_or("必须提供证书路径 (-c)")?;
        let pkey_path = args
            .pkey_path
            .clone()
            .ok_or("必须提供私钥路径 (-p)")?;
        let root_ca_paths = args.root_ca_paths.clone();
        if root_ca_paths.is_empty() {
            return Err("必须提供根CA路径 (-r)".to_string());
        }
        let output = args.output.clone().ok_or("必须提供输出路径 (-o)")?;
        let input = args.input.clone().ok_or("必须提供输入路径")?;

        Ok(EncodeParams {
            cert_path,
            pkey_path,
            root_ca_paths,
            output,
            input,
        })
    }
}

/// 验证并获取解码参数
fn get_decode_params(args: &Args, config: &Option<Config>) -> Result<DecodeParams, String> {
    if let Some(cfg) = config {
        // 从配置文件获取参数
        let decode_config = cfg
            .get_decode_config()
            .ok_or("配置文件中没有 [decode] 部分")?;

        let root_ca_paths = decode_config
            .root_ca_path
            .as_ref()
            .map(|p| vec![p.clone()])
            .unwrap_or_default();
        if root_ca_paths.is_empty() {
            return Err("配置文件中缺少 root_ca_path".to_string());
        }
        let output = decode_config
            .output_path
            .clone()
            .ok_or("配置文件中缺少 output_path")?;
        let input = decode_config
            .input_path
            .clone()
            .ok_or("配置文件中缺少 input_path")?;

        Ok(DecodeParams {
            root_ca_paths,
            output,
            input,
        })
    } else {
        // 从命令行参数获取
        let root_ca_paths = args.root_ca_paths.clone();
        if root_ca_paths.is_empty() {
            return Err("必须提供根CA路径 (-r)".to_string());
        }
        let output = args.output.clone().ok_or("必须提供输出路径 (-o)")?;
        let input = args.input.clone().ok_or("必须提供输入路径")?;

        Ok(DecodeParams {
            root_ca_paths,
            output,
            input,
        })
    }
}

/// 验证输入文件是否存在
fn validate_input_file(input: &str) -> Result<(), String> {
    let path = PathBuf::from_str(input)
        .map_err(|e| format!("无效的输入路径: {}", e))?;
    if !path.exists() {
        return Err(format!("输入文件不存在: {}", input));
    }
    Ok(())
}

/// 确保输出目录存在
fn ensure_output_dir(output: &str) -> Result<(), String> {
    let path = PathBuf::from_str(output)
        .map_err(|e| format!("无效的输出路径: {}", e))?;
    fs::create_dir_all(&path)
        .map_err(|e| format!("无法创建输出目录 {}: {}", path.display(), e))?;
    Ok(())
}

/// 写入文件并输出日志
fn write_file(path: &PathBuf, content: &[u8]) -> Result<(), String> {
    fs::write(path, content)
        .map_err(|e| format!("无法写入文件 {}: {}", path.display(), e))?;
    println!("文件已输出到: {}", path.display());
    Ok(())
}

/// 写入文本文件并输出日志
fn write_text_file(path: &PathBuf, content: String) -> Result<(), String> {
    fs::write(path, content)
        .map_err(|e| format!("无法写入文件 {}: {}", path.display(), e))?;
    println!("文件已输出到: {}", path.display());
    Ok(())
}

/// 执行编码操作
fn execute_encode(params: EncodeParams) -> Result<(), String> {
    validate_input_file(&params.input)?;

    // pack package
    let mut pack_context = pack_context(&params.input);

    // setup sign tool
    let mut pkcs = PKCS::new();
    pkcs.load_from_file_writer(
        params.cert_path,
        params.pkey_path,
        params.root_ca_paths,
    );

    pack_context.add_sig(pkcs, SIGTYPE::CRATEBIN);

    // encode package to binary
    let (_, _, bin) = pack_context.encode_to_crate_package();

    // dump binary path/<name>.scrate
    ensure_output_dir(&params.output)?;
    let mut bin_path = PathBuf::from_str(&params.output)
        .map_err(|e| format!("无效的输出路径: {}", e))?;
    bin_path.push(pack_name(&pack_context));
    write_file(&bin_path, &bin)?;

    Ok(())
}

/// 执行解码操作
fn execute_decode(params: DecodeParams) -> Result<(), String> {
    validate_input_file(&params.input)?;

    // decode package from binary
    let pack_context = unpack_context(&params.input, params.root_ca_paths)
        .map_err(|e| e.to_string())?;

    ensure_output_dir(&params.output)?;
    let output_path = PathBuf::from_str(&params.output)
        .map_err(|e| format!("无效的输出路径: {}", e))?;

    // extract crate bin file
    let mut bin_path = output_path.clone();
    bin_path.push(format!(
        "{}-{}.crate",
        pack_context.pack_info.name, pack_context.pack_info.version
    ));
    write_file(&bin_path, &pack_context.crate_binary.bytes)?;

    // dump scrate metadata
    let mut metadata_path = output_path;
    metadata_path.push(format!(
        "{}-{}-metadata.txt",
        pack_context.pack_info.name, pack_context.pack_info.version
    ));
    write_text_file(
        &metadata_path,
        format!(
            "{:#?}\n{:#?}",
            pack_context.pack_info, pack_context.dep_infos
        ),
    )?;

    Ok(())
}

fn main() {
    let args = Args::parse();

    // 根据是否有 -f 参数决定是否使用配置文件
    let config = if args.config.is_some() {
        load_config(args.config.as_ref())
    } else {
        None
    };

    // 根据模式执行相应操作
    if args.encode && !args.decode {
        // 编码模式
        match get_encode_params(&args, &config) {
            Ok(params) => {
                if let Err(e) = execute_encode(params) {
                    eprintln!("错误: {}", e);
                    std::process::exit(1);
                }
            }
            Err(e) => {
                eprintln!("错误: {}", e);
                std::process::exit(1);
            }
        }
    } else if !args.encode && args.decode {
        // 解码模式
        match get_decode_params(&args, &config) {
            Ok(params) => {
                if let Err(e) = execute_decode(params) {
                    eprintln!("错误: {}", e);
                    std::process::exit(1);
                }
            }
            Err(e) => {
                eprintln!("错误: {}", e);
                std::process::exit(1);
            }
        }
    } else {
        eprintln!("错误: 必须指定 -e (编码) 或 -d (解码)");
        std::process::exit(1);
    }
}
