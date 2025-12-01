use crate_spec::utils::context::PackageContext;
use crate_spec::utils::from_toml::CrateToml;
use crate_spec::{Result, CrateSpecError};
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::str::FromStr;

fn run_cmd(cmd: &str, args: Vec<&str>, cur_dir: Option<&PathBuf>) -> Result<String> {
    let mut output = Command::new(cmd);
    if !args.is_empty() {
        output.args(args);
    }
    if let Some(cd) = cur_dir {
        output.current_dir(cd);
    }
    let output = output
        .output()
        .map_err(|e| CrateSpecError::Other(format!("执行命令 {} 失败: {}", cmd, e)))?;
    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        Ok(stdout.to_string())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(CrateSpecError::Other(format!("命令 {} 执行失败: {}", cmd, stderr)))
    }
}

struct Packing {
    pack_context: PackageContext,
    crate_path: PathBuf,
}

impl Packing {
    fn new(crate_path: &str) -> Result<Self> {
        Ok(Packing {
            pack_context: PackageContext::new(),
            crate_path: PathBuf::from_str(crate_path)
                .map_err(|e| CrateSpecError::ValidationError(format!("无效的路径: {}", e)))?,
        })
    }

    /// 执行 cargo package 命令
    /// 
    /// 性能优化说明：
    /// - 当前使用 `cargo package --allow-dirty`，会执行完整的验证步骤
    /// - 如需提升性能，可以添加 `--no-verify` 选项：
    ///   ```rust
    ///   ["package", "--allow-dirty", "--no-verify"].to_vec()
    ///   ```
    /// 
    /// `--no-verify` 选项说明：
    /// - 跳过编译验证（`cargo build`）和测试（`cargo test`）
    /// - 可以显著提升打包速度（通常节省 80-95% 时间）
    /// - 适用于：项目已编译、CI/CD 环境、快速迭代场景
    /// - 不适用于：需要确保代码可编译的生产环境
    /// 
    /// 注意：当前实现不使用 `--no-verify`，以确保代码质量。
    /// 如需使用，请根据实际场景修改上述代码。
    fn cmd_cargo_package(&self) -> Result<()> {
        let res = run_cmd(
            "cargo",
            ["package", "--allow-dirty"].to_vec(),
            Some(&self.crate_path),
        )?;
        println!("{}", res);
        Ok(())
    }

    // read .crate file and parse toml file, then 
    // we can get the package info and dependency info
    // and then we can add the crate binary to the pack_context
    // read .crate file and parse toml file, then 
    // we can get the package info and dependency info
    // and then we can add the crate binary to the pack_context
    // read .crate file and parse toml file, then 
    // we can get the package info and dependency info
    // and then we can add the crate binary to the pack_context
    fn read_crate(&mut self) -> Result<()> {
        //parse crate toml file
        let mut toml_path = self.crate_path.clone();
        toml_path.push("Cargo.toml");
        let toml_path = fs::canonicalize(&toml_path)
            .map_err(|_e| CrateSpecError::FileNotFound(toml_path.clone()))?;
        let toml_path_str = toml_path.to_str()
            .ok_or_else(|| CrateSpecError::Other("无法将路径转换为字符串".to_string()))?;
        let toml = CrateToml::from_file(toml_path_str.to_string())?;
        toml.write_info_to_package_context(&mut self.pack_context)?;

        //read crate binary
        let crate_bin_file = format!(
            "{}-{}.crate",
            self.pack_context.pack_info.name, self.pack_context.pack_info.version
        );
        let mut crate_bin_path = self.crate_path.clone();
        crate_bin_path.push(format!("target/package/{}", crate_bin_file));
        let crate_bin_path = fs::canonicalize(&crate_bin_path)
            .map_err(|_e| CrateSpecError::FileNotFound(crate_bin_path.clone()))?;
        if !crate_bin_path.exists() {
            return Err(CrateSpecError::FileNotFound(crate_bin_path));
        }
        let bin = fs::read(&crate_bin_path)
            .map_err(|e| CrateSpecError::Io(e))?;

        //write to pack_context
        self.pack_context.add_crate_bin(bin);
        Ok(())
    }

    fn pack_context(mut self) -> Result<PackageContext> {
        self.cmd_cargo_package()?;
        self.read_crate()?;
        Ok(self.pack_context)
    }
}

pub fn pack_context(path: &str) -> Result<PackageContext> {
    Packing::new(path)?.pack_context()
}

pub fn pack_name(pack: &PackageContext) -> String {
    format!("{}-{}.scrate", pack.pack_info.name, pack.pack_info.version)
}

#[test]
fn test_cmd_cargo_package() {
    let pac = pack_context("../crate-spec");
    println!("{:#?}", pac);
}
