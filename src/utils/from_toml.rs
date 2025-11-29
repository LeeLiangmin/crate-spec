use crate::utils::context::{DepInfo, PackageContext, SrcTypePath};
use crate::error::{Result, CrateSpecError};
use std::collections::HashSet;
use std::fs;
use std::path::Path;
use std::str::FromStr;
use toml::Table;

#[derive(Default)]
pub struct CrateToml {
    t: Table,
}

impl CrateToml {
    pub fn from_file(path: String) -> Result<Self> {
        let path_buf = Path::new(path.as_str());
        let f = fs::read(path_buf)
            .map_err(|_e| CrateSpecError::FileNotFound(path_buf.to_path_buf()))?;
        CrateToml::from_vec(f)
    }

    pub fn from_vec(st_vec: Vec<u8>) -> Result<Self> {
        let st = String::from_utf8(st_vec)
            .map_err(|e| CrateSpecError::ParseError(format!("UTF-8 解码失败: {}", e)))?;
        CrateToml::from_string(&st)
    }

    pub fn from_string(st: &str) -> Result<Self> {
        Ok(CrateToml {
            t: Table::from_str(st)
                .map_err(|e| CrateSpecError::ParseError(format!("TOML 解析失败: {}", e)))?,
        })
    }
}

impl CrateToml {
    fn write_package_info_to_package_context(
        &self,
        package_context: &mut PackageContext,
        package: &Table,
    ) -> Result<()> {
        let name = package["name"].as_str()
            .ok_or_else(|| CrateSpecError::ParseError("缺少 'name' 字段".to_string()))?
            .to_string();
        let version = package["version"].as_str()
            .ok_or_else(|| CrateSpecError::ParseError("缺少 'version' 字段".to_string()))?
            .to_string();
        let mut license = "".to_string();
        let mut authors = Vec::<String>::new();
        if package.contains_key("license") {
            license = package["license"].as_str()
                .ok_or_else(|| CrateSpecError::ParseError("'license' 字段格式错误".to_string()))?
                .to_string();
        }
        if package.contains_key("authors") {
            authors = package["authors"]
                .as_array()
                .ok_or_else(|| CrateSpecError::ParseError("'authors' 字段格式错误".to_string()))?
                .iter()
                .map(|x| x.as_str()
                    .ok_or_else(|| CrateSpecError::ParseError("'authors' 数组元素格式错误".to_string()))
                    .map(|s| s.to_string()))
                .collect::<Result<Vec<String>>>()?;
        }
        package_context.set_package_info(name, version, license, authors);
        Ok(())
    }

    fn write_dep_info_to_package_context(
        &self,
        package_context: &mut PackageContext,
        deps: &Table,
        platform: String,
    ) -> Result<Vec<String>> {
        let mut irresolve_depinfos = vec![];
        for dep in deps.iter() {
            let mut dep_info = DepInfo {
                src_platform: platform.to_string(),
                name: dep.0.to_string(),
                ..Default::default()
            };
            let val = dep.1;
            if val.is_str() {
                dep_info.ver_req = val.as_str()
                    .ok_or_else(|| CrateSpecError::ParseError("依赖版本格式错误".to_string()))?
                    .to_string();
            } else {
                let attri_map = val.as_table()
                    .ok_or_else(|| CrateSpecError::ParseError("依赖配置格式错误".to_string()))?;
                let allow_keys = HashSet::from([
                    "version".to_string(),
                    "git".to_string(),
                    "registry".to_string(),
                ]);
                for attri in attri_map.keys() {
                    if !allow_keys.contains(attri) {
                        dep_info.dump = false;
                    }
                }
                if attri_map.contains_key("version") {
                    dep_info.ver_req = attri_map["version"].as_str()
                        .ok_or_else(|| CrateSpecError::ParseError("'version' 字段格式错误".to_string()))?
                        .to_string();
                }
                if attri_map.contains_key("git") {
                    dep_info.src = SrcTypePath::Git(attri_map["git"].as_str()
                        .ok_or_else(|| CrateSpecError::ParseError("'git' 字段格式错误".to_string()))?
                        .to_string());
                }
                if attri_map.contains_key("registry") {
                    dep_info.src = SrcTypePath::Registry(attri_map["registry"].as_str()
                        .ok_or_else(|| CrateSpecError::ParseError("'registry' 字段格式错误".to_string()))?
                        .to_string());
                }
            }
            if dep_info.dump {
                package_context.add_dep_info(
                    dep_info.name,
                    dep_info.ver_req,
                    dep_info.src,
                    dep_info.src_platform,
                );
            } else {
                irresolve_depinfos.push(dep_info.name);
            }
        }
        Ok(irresolve_depinfos)
    }

    // write package info and dependency info to package context at current
    pub fn write_info_to_package_context(
        &self,
        package_context: &mut PackageContext,
    ) -> Result<Vec<String>> {
        if !self.t.contains_key("package") {
            return Err(CrateSpecError::ParseError("缺少 [package] 段".to_string()));
        }
        self.write_package_info_to_package_context(
            package_context,
            self.t.get("package")
                .ok_or_else(|| CrateSpecError::ParseError("缺少 [package] 段".to_string()))?
                .as_table()
                .ok_or_else(|| CrateSpecError::ParseError("[package] 段格式错误".to_string()))?,
        )?;
        //FIXME current platform is not considered, we only consider [dependencies], see https://course.rs/cargo/reference/specify-deps.html#build-dependencies
        let excluded_crate = self.write_dep_info_to_package_context(
            package_context,
            self.t.get("dependencies")
                .ok_or_else(|| CrateSpecError::ParseError("缺少 [dependencies] 段".to_string()))?
                .as_table()
                .ok_or_else(|| CrateSpecError::ParseError("[dependencies] 段格式错误".to_string()))?,
            "".to_string(),
        )?;
        Ok(excluded_crate)
    }
}

#[test]
fn test_toml() {
    let toml = CrateToml::from_file("test/test.toml".to_string());
    let mut pack_context = PackageContext::new();
    println!(
        "{:?}",
        toml.write_info_to_package_context(&mut pack_context)
    );
    println!("{:#?}", pack_context);
}
