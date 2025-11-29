use crate::utils::context::{DepInfo, PackageContext, SigInfo, StringTable, DATASECTIONTYPE, SIGTYPE};
use crate::utils::package::{
    CrateBinarySection, CratePackage, DataSection, DepTableSection, PackageSection, SectionIndex,
    SigStructureSection, FINGERPRINT_LEN,
};
use crate::error::Result;

use crate::utils::pkcs::PKCS;
use crate::network::{NetworkSignature, BaseConfig, digest_to_hex_string};

impl SectionIndex {
    pub fn section_id_by_type(&self, typ: usize) -> Result<usize> {
        for (i, entry) in self.entries.arr.iter().enumerate() {
            if entry.sh_type as usize == typ {
                return Ok(i);
            }
        }
        Err(crate::error::CrateSpecError::DecodeError(format!("未找到类型为 {} 的数据段", typ)))
    }
}

impl CratePackage {
    pub fn data_section_by_id(&self, id: usize) -> &DataSection {
        &self.data_sections.col.arr[id]
    }

    pub fn data_section_by_type(&self, typ: usize) -> Result<&DataSection> {
        Ok(self.data_section_by_id(self.section_index.section_id_by_type(typ)?))
    }

    pub fn package_section(&self) -> Result<&PackageSection> {
        match self.data_section_by_type(DATASECTIONTYPE::PACK.as_u8() as usize)? {
            DataSection::PackageSection(pak) => Ok(pak),
            _ => {
                Err(crate::error::CrateSpecError::DecodeError("package section not found!".to_string()))
            }
        }
    }

    pub fn dep_table_section(&self) -> Result<&DepTableSection> {
        match self.data_section_by_type(DATASECTIONTYPE::DEPTABLE.as_u8() as usize)? {
            DataSection::DepTableSection(dep) => Ok(dep),
            _ => {
                Err(crate::error::CrateSpecError::DecodeError("dep table section not found!".to_string()))
            }
        }
    }

    pub fn crate_binary_section(&self) -> Result<&CrateBinarySection> {
        match self.data_section_by_type(DATASECTIONTYPE::CRATEBIN.as_u8() as usize)? {
            DataSection::CrateBinarySection(cra) => Ok(cra),
            _ => {
                Err(crate::error::CrateSpecError::DecodeError("crate binary section not found!".to_string()))
            }
        }
    }

    pub fn sig_structure_section(&self, no: usize) -> Result<&SigStructureSection> {
        let base = self.section_index.section_id_by_type(DATASECTIONTYPE::SIGSTRUCTURE.as_u8() as usize)?;
        match self.data_section_by_id(no + base) {
            DataSection::SigStructureSection(sig) => Ok(sig),
            _ => {
                Err(crate::error::CrateSpecError::DecodeError("sig structure section not found!".to_string()))
            }
        }
    }
}

impl PackageContext {
    pub fn binary_before_digest(&self, bin: &[u8]) -> Vec<u8> {
        bin[..bin.len() - FINGERPRINT_LEN].to_vec()
    }

    fn pack_info(&mut self, crate_package: &CratePackage, str_table: &StringTable) -> Result<()> {
        self.pack_info
            .read_from_package_section(crate_package.package_section()?, str_table)?;
        Ok(())
    }

    fn deps(&mut self, crate_package: &CratePackage, str_table: &StringTable) -> Result<()> {
        for entry in crate_package.dep_table_section()?.entries.arr.iter() {
            let mut dep_info = DepInfo::default();
            dep_info.read_from_dep_table_entry(entry, str_table)?;
            self.dep_infos.push(dep_info);
        }
        Ok(())
    }

    fn binary(&mut self, crate_package: &CratePackage) -> Result<()> {
        self.crate_binary.bytes = crate_package.crate_binary_section()?.bin.arr.clone();
        Ok(())
    }

    fn sigs(&mut self, crate_package: &CratePackage) -> Result<()> {
        let sig_num = crate_package.section_index.sig_num();
        for no in 0..sig_num {
            let sig = crate_package.sig_structure_section(no)?;
            let mut sig_info = SigInfo::new();
            sig_info.read_from_sig_structure_section(sig)?;
            self.sigs.push(sig_info);
        }
        Ok(())
    }

    fn check_fingerprint(&self, bin_all: &[u8]) -> Result<bool> {
        let calculated = PKCS::new().gen_digest_256(&bin_all[..bin_all.len() - FINGERPRINT_LEN])?;
        Ok(calculated == bin_all[bin_all.len() - FINGERPRINT_LEN..])
    }

    fn check_sigs(&self, crate_package: &CratePackage, bin_all: &[u8]) -> Result<()> {
        let bin_all = self.binary_before_sig(crate_package, bin_all);
        let bin_crate = crate_package.crate_binary_section()?.bin.arr.as_slice();
        
        for siginfo in self.sigs.iter() {
            match siginfo.typ {
                typ if typ == SIGTYPE::FILE.as_u32() || typ == SIGTYPE::CRATEBIN.as_u32() => {
                    // 本地签名验证
                    let actual_digest = match siginfo.typ {
                        typ if typ == SIGTYPE::FILE.as_u32() => siginfo.pkcs.gen_digest_256(bin_all.as_slice())?,
                        typ if typ == SIGTYPE::CRATEBIN.as_u32() => siginfo.pkcs.gen_digest_256(bin_crate)?,
                        _ => unreachable!(),
                    };
                    let expect_digest = PKCS::decode_pkcs_bin(siginfo.bin.as_slice(), &self.root_cas)?;
                    if actual_digest != expect_digest {
                        return Err(crate::error::CrateSpecError::SignatureError("本地签名验证失败".to_string()));
                    }
                }
                typ if typ == SIGTYPE::NETWORK.as_u32() => {
                    // 网络签名验证
                    // 从 PackageContext 获取 PkiClient
                    let pki_client = self.network_client.as_ref()
                        .ok_or_else(|| crate::error::CrateSpecError::Other("网络签名需要设置 network_client".to_string()))?;
                    
                    // 从 siginfo.bin 反序列化 NetworkSignature
                    let network_sig: NetworkSignature = bincode::decode_from_slice(
                        &siginfo.bin,
                        bincode::config::standard(),
                    )
                    .map_err(|e| crate::error::CrateSpecError::DecodeError(format!("无法反序列化网络签名: {}", e)))?
                    .0;
                    
                    // 计算内容摘要（网络签名统一使用 CRATEBIN 类型，只对 crate binary 签名）
                    let actual_digest = siginfo.pkcs.gen_digest_256(bin_crate)?;
                    
                    // 转换为十六进制字符串
                    let digest_hex = digest_to_hex_string(&actual_digest);
                    
                    // 使用从签名段提取的算法信息构建 BaseConfig
                    let base_config = BaseConfig {
                        algo: network_sig.algo.clone(),
                        flow: network_sig.flow.clone(),
                        kms: network_sig.kms.clone().unwrap_or_default(),
                    };
                    
                    // 调用 PKI 平台验签接口
                    match pki_client.verify_digest(
                        &network_sig.pub_key,
                        &digest_hex,
                        &network_sig.signature,
                        &base_config,
                    ) {
                        Ok(true) => {
                            // 验签成功
                        }
                        Ok(false) => {
                            return Err(crate::error::CrateSpecError::SignatureError("网络签名验证失败".to_string()));
                        }
                        Err(e) => {
                            return Err(crate::error::CrateSpecError::PkiError(e));
                        }
                    }
                }
                _ => {
                    return Err(crate::error::CrateSpecError::Other(format!("不支持的签名类型: {}", siginfo.typ)));
                }
            }
        }
        Ok(())
    }

    pub fn decode_from_crate_package(
        &mut self,
        bin: &[u8],
    ) -> Result<(CratePackage, StringTable)> {
        if !self.check_fingerprint(bin)? {
            return Err(crate::error::CrateSpecError::DecodeError("fingerprint not right".to_string()));
        }
        let crate_package = CratePackage::decode_from_slice(bin)
            .map_err(|e| crate::error::CrateSpecError::DecodeError(format!("解码失败: {}", e)))?;
        let mut str_table = StringTable::new();
        str_table.read_bytes(crate_package.string_table.arr.as_slice())?;
        self.pack_info(&crate_package, &str_table)?;
        self.deps(&crate_package, &str_table)?;
        self.binary(&crate_package)?;
        self.sigs(&crate_package)?;
        self.check_sigs(&crate_package, bin)?;
        Ok((crate_package, str_table))
    }
}

#[test]
fn test_encode_decode() {
    use crate::utils::context::{PackageInfo, SrcTypePath, SIGTYPE};
    fn pack_info() -> PackageInfo {
        PackageInfo {
            name: "rust-crate".to_string(),
            version: "1.0.0".to_string(),
            license: "MIT".to_string(),
            authors: vec!["shuibing".to_string(), "rust".to_string()],
        }
    }

    fn dep_info1() -> DepInfo {
        DepInfo {
            name: "toml".to_string(),
            ver_req: "1.0.0".to_string(),
            src: SrcTypePath::CratesIo,
            src_platform: "ALL".to_string(),
            dump: true,
        }
    }

    fn dep_info2() -> DepInfo {
        DepInfo {
            name: "crate-spec".to_string(),
            ver_req: ">=0.8.0".to_string(),
            src: SrcTypePath::Git("http://git.com".to_string()),
            src_platform: "windows".to_string(),
            dump: true,
        }
    }

    fn crate_binary() -> Vec<u8> {
        // 测试用的二进制数据
        vec![0u8; 100]
    }

    fn sign() -> PKCS {
        let mut pkcs1 = PKCS::new();
        pkcs1.load_from_file_writer(
            "test/cert.pem".to_string(),
            "test/key.pem".to_string(),
            ["test/root-ca.pem".to_string()].to_vec(),
        );
        pkcs1
    }

    let mut package_context = PackageContext::new();

    package_context.pack_info = pack_info();
    package_context.dep_infos.push(dep_info1());
    package_context.dep_infos.push(dep_info2());
    package_context.crate_binary.bytes = crate_binary();
    package_context.add_sig(sign(), SIGTYPE::CRATEBIN);
    package_context.add_sig(sign(), SIGTYPE::FILE);

    let (_crate_package, _str_table, bin) = package_context.encode_to_crate_package();

    let mut package_context_new = PackageContext::new();
    package_context_new.set_root_cas_bin(PKCS::root_ca_bins(
        ["test/root-ca.pem".to_string()].to_vec(),
    ));
    let (_crate_package_new, _str_table) = package_context_new
        .decode_from_crate_package(bin.as_slice())
        .unwrap();

    assert_eq!(pack_info(), package_context_new.pack_info);
    assert_eq!(dep_info1(), package_context_new.dep_infos[0]);
    assert_eq!(dep_info2(), package_context_new.dep_infos[1]);
    assert_eq!(crate_binary(), package_context_new.crate_binary.bytes);
}
