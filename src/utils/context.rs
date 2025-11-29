use crate::utils::package::{
    CrateBinarySection, CratePackage, DepTableEntry, LenArrayType, PackageSection, RawArrayType,
    SigStructureSection, Size, Type,
};
use crate::utils::pkcs::PKCS;
use crate::network::{NetworkSignature, PkiClient, KeyPair};
use crate::error::{Result, CrateSpecError};
use std::collections::HashMap;
use std::sync::Arc;


pub const NOT_SIG_NUM: usize = 3;

/// 字符串长度前缀字节数
pub const STRING_LENGTH_PREFIX_BYTES: usize = 4;

pub enum SIGTYPE {
    FILE,
    CRATEBIN,
    NETWORK,
}

impl SIGTYPE {
    /// 获取签名类型的数值表示
    pub fn as_u32(&self) -> u32 {
        match self {
            SIGTYPE::FILE => 0,
            SIGTYPE::CRATEBIN => 1,
            SIGTYPE::NETWORK => 2,
        }
    }
}

pub enum DATASECTIONTYPE {
    PACK = 0,
    DEPTABLE = 1,
    CRATEBIN = 3,
    SIGSTRUCTURE = 4,
}

impl DATASECTIONTYPE {
    /// 获取数据段类型的数值表示
    pub fn as_u8(&self) -> u8 {
        match self {
            DATASECTIONTYPE::PACK => 0,
            DATASECTIONTYPE::DEPTABLE => 1,
            DATASECTIONTYPE::CRATEBIN => 3,
            DATASECTIONTYPE::SIGSTRUCTURE => 4,
        }
    }
}

///package context contains package's self and dependency package info
#[derive(Debug)]
pub struct PackageContext {
    pub pack_info: PackageInfo,
    pub dep_infos: Vec<DepInfo>,
    pub crate_binary: CrateBinary,
    pub sigs: Vec<SigInfo>,
    pub root_cas: Vec<Vec<u8>>,
    pub network_client: Option<Arc<PkiClient>>,
    pub network_keypair: Option<Arc<KeyPair>>,
}

impl PackageContext {
    pub fn new() -> Self {
        Self {
            pack_info: PackageInfo::default(),
            crate_binary: CrateBinary::new(),
            dep_infos: vec![],
            sigs: vec![],
            root_cas: vec![],
            network_client: None,
            network_keypair: None,
        }
    }

    pub fn set_package_info(
        &mut self,
        name: String,
        version: String,
        license: String,
        authors: Vec<String>,
    ) {
        self.pack_info = PackageInfo {
            name,
            version,
            license,
            authors,
        }
    }

    pub fn add_dep_info(
        &mut self,
        name: String,
        ver_req: String,
        src: SrcTypePath,
        src_platform: String,
    ) {
        self.dep_infos.push(DepInfo {
            name,
            ver_req,
            src,
            src_platform,
            dump: true,
        });
    }

    pub fn dep_num(&self) -> usize {
        self.dep_infos.len()
    }

    pub fn add_sig(&mut self, pkcs: PKCS, sign_type: SIGTYPE) -> usize {
        let mut siginfo = SigInfo::new();
        siginfo.pkcs = pkcs;
        siginfo.typ = sign_type.as_u32();
        self.sigs.push(siginfo);
        self.sigs.len() - 1
    }

    pub fn sig_num(&self) -> usize {
        self.sigs.len()
    }

    pub fn set_root_cas_bin(&mut self, root_ca_bins: Vec<Vec<u8>>) {
        self.root_cas = root_ca_bins;
    }

    pub fn add_root_cas(&mut self, root_ca: Vec<u8>) {
        self.root_cas.push(root_ca);
    }

    pub fn add_crate_bin(&mut self, bin: Vec<u8>) {
        let mut c = CrateBinary::new();
        c.set_bin(bin);
        self.crate_binary = c;
    }

    /// Get binary data before signature section for signing/verification.
    /// This function removes the signature-related parts from section_index to break circular dependency:
    /// - section_index depends on sigStructure values
    /// - sigStructure calculation depends on section_index
    /// Solution: zero out the signature-related parts in section_index when calculating signature digest.
    pub fn binary_before_sig(&self, crate_package: &CratePackage, bin: &[u8]) -> Vec<u8> {
        let ds_size = crate_package
            .section_index
            .datasection_size_without_sig();
        let total_size = crate_package.crate_header.ds_offset as usize + ds_size;
        if crate_package.section_index.sig_num() != self.sigs.len() && !self.sigs.is_empty() {
            assert_eq!(crate_package.section_index.sig_num(), 0);
        }
        let mut buf = bin[..total_size].to_vec();
        let zero_begin = crate_package.crate_header.si_offset as usize
            + crate_package.section_index.none_sig_size();
        let zero_end = crate_package.crate_header.si_offset as usize
            + crate_package.crate_header.si_size as usize;
        // Zero out the signature-related parts in section_index
        for i in buf.iter_mut().take(zero_end).skip(zero_begin) {
            *i = 0;
        }

        buf
    }
}

impl Default for PackageContext {
    fn default() -> Self {
        Self::new()
    }
}

///package's info
#[derive(Debug, PartialEq)]
pub struct PackageInfo {
    pub name: String,
    pub version: String,
    pub license: String,
    pub authors: Vec<String>,
}

impl Default for PackageInfo {
    fn default() -> Self {
        Self {
            name: "".to_string(),
            version: "".to_string(),
            license: "".to_string(),
            authors: vec![],
        }
    }
}

impl PackageInfo {
    pub fn new(name: String, version: String, lisense: String, authors: Vec<String>) -> Self {
        Self {
            name,
            version,
            license: lisense,
            authors,
        }
    }

    pub fn write_to_package_section(&self, ps: &mut PackageSection, str_table: &mut StringTable) {
        ps.pkg_name = str_table.insert_str(self.name.clone());
        ps.pkg_version = str_table.insert_str(self.version.clone());
        ps.pkg_license = str_table.insert_str(self.license.clone());
        let mut authors_off = vec![];
        self.authors.iter().for_each(|author| {
            authors_off.push(str_table.insert_str(author.clone()));
        });
        ps.pkg_authors = LenArrayType::copy_from_vec(&authors_off);
    }

    pub fn read_from_package_section(&mut self, ps: &PackageSection, str_table: &StringTable) -> Result<()> {
        self.name = str_table.str_by_off(&ps.pkg_name)?;
        self.version = str_table.str_by_off(&ps.pkg_version)?;
        self.license = str_table.str_by_off(&ps.pkg_license)?;
        let authors_off = ps.pkg_authors.to_vec();
        for author_off in authors_off.iter() {
            self.authors.push(str_table.str_by_off(author_off)?);
        }
        Ok(())
    }
}

///dependencies' info
#[derive(Debug, PartialEq)]
pub struct DepInfo {
    pub name: String,
    pub ver_req: String,
    pub src: SrcTypePath,
    pub src_platform: String,
    ///only dump dependency that can be written to crate dependency table section
    pub dump: bool,
}

impl Default for DepInfo {
    fn default() -> Self {
        Self {
            name: "".to_string(),
            ver_req: "default".to_string(),
            src: SrcTypePath::CratesIo,
            src_platform: "default".to_string(),
            dump: true,
        }
    }
}

impl DepInfo {
    pub fn new(
        name: String,
        ver_req: String,
        src: SrcTypePath,
        src_platform: String,
        dump: bool,
    ) -> Self {
        Self {
            name,
            ver_req,
            src,
            src_platform,
            dump,
        }
    }

    pub fn write_to_dep_table_entry(&self, dte: &mut DepTableEntry, str_table: &mut StringTable) {
        dte.dep_name = str_table.insert_str(self.name.clone());
        dte.dep_verreq = str_table.insert_str(self.ver_req.clone());
        dte.dep_srctype = self.src.as_u8();
        match &self.src {
            SrcTypePath::CratesIo => {
                dte.dep_srcpath = str_table.insert_str("".to_string());
            }
            SrcTypePath::Git(str) => {
                dte.dep_srcpath = str_table.insert_str(str.clone());
            }
            SrcTypePath::Url(str) => {
                dte.dep_srcpath = str_table.insert_str(str.clone());
            }
            SrcTypePath::Registry(str) => {
                dte.dep_srcpath = str_table.insert_str(str.clone());
            }
            SrcTypePath::P2p(str) => {
                dte.dep_srcpath = str_table.insert_str(str.clone());
            }
        }
        dte.dep_platform = str_table.insert_str(self.src_platform.to_string());
    }

    pub fn read_from_dep_table_entry(&mut self, dte: &DepTableEntry, str_table: &StringTable) -> Result<()> {
        self.dump = true;
        self.name = str_table.str_by_off(&dte.dep_name)?;
        self.ver_req = str_table.str_by_off(&dte.dep_verreq)?;
        let path = str_table.str_by_off(&dte.dep_srcpath)?;
        self.src = SrcTypePath::from_u8_with_path(dte.dep_srctype, path)?;
        self.src_platform = str_table.str_by_off(&dte.dep_platform)?;
        Ok(())
    }
}

///dependencies' src type and path
#[derive(Debug, PartialEq)]
pub enum SrcTypePath {
    CratesIo,
    Git(String),
    Url(String),
    Registry(String),
    P2p(String),
}

impl SrcTypePath {
    /// 获取依赖源类型的数值表示
    pub fn as_u8(&self) -> u8 {
        match self {
            SrcTypePath::CratesIo => 0,
            SrcTypePath::Git(_) => 1,
            SrcTypePath::Url(_) => 2,
            SrcTypePath::Registry(_) => 3,
            SrcTypePath::P2p(_) => 4,
        }
    }

    /// 从数值创建依赖源类型（需要路径字符串）
    pub fn from_u8_with_path(value: u8, path: String) -> Result<Self> {
        match value {
            0 => Ok(SrcTypePath::CratesIo),
            1 => Ok(SrcTypePath::Git(path)),
            2 => Ok(SrcTypePath::Url(path)),
            3 => Ok(SrcTypePath::Registry(path)),
            4 => Ok(SrcTypePath::P2p(path)),
            _ => Err(CrateSpecError::ParseError(format!("无效的依赖源类型: {}", value))),
        }
    }
}

/// StringTable is a hash map to store the string and its offset.
/// It can be used to store and get the string by its offset.
/// When storing, every string(byte array) starts with its length(4 bytes).
///
/// Every time we insert a new string, we have to add its length( plus 4 bytes) to the total bytes.
pub struct StringTable {
    str2off: HashMap<String, u32>,
    off2str: HashMap<u32, String>,
    total_bytes: u32,
}

impl Default for StringTable {
    fn default() -> Self {
        Self::new()
    }
}

impl StringTable {
    pub fn new() -> Self {
        let mut new_str_table = Self {
            str2off: Default::default(),
            off2str: Default::default(),
            total_bytes: 0,
        };
        new_str_table.insert_str("".to_string());
        new_str_table
    }

    // insert string to string table and return the offset of the new string.
    pub fn insert_str(&mut self, st: String) -> u32 {
        if let Some(&offset) = self.str2off.get(&st) {
            offset
        } else {
            let st_len = st.as_bytes().len() as u32;
            let ret_val = self.total_bytes;
            self.str2off.insert(st.clone(), self.total_bytes);
            self.off2str.insert(self.total_bytes, st.clone());
            self.total_bytes += STRING_LENGTH_PREFIX_BYTES as u32 + st_len;
            ret_val
        }
    }

    pub fn contains_str(&self, st: &String) -> bool {
        self.str2off.contains_key(st)
    }

    pub fn off_by_str(&self, st: &String) -> Result<u32> {
        self.str2off.get(st)
            .copied()
            .ok_or_else(|| CrateSpecError::Other(format!("字符串表中找不到字符串: {}", st)))
    }

    pub fn str_by_off(&self, off: &u32) -> Result<String> {
        self.off2str.get(off)
            .cloned()
            .ok_or_else(|| CrateSpecError::Other(format!("字符串表中找不到偏移量: {}", off)))
    }

    ///dump string table to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut offs: Vec<_> = self.off2str.keys().cloned().collect();
        offs.sort();
        let mut bytes = vec![];
        for off in offs {
            //FIXME we use little endian
            if let Some(st) = self.off2str.get(&off) {
                let st_bytes = st.bytes().collect::<Vec<u8>>();
                bytes.extend((st_bytes.len() as u32).to_le_bytes());
                bytes.extend(st_bytes);
            }
        }
        bytes
    }

    ///parse string table from bytes
    pub fn read_bytes(&mut self, bytes: &[u8]) -> Result<()> {
        let mut i = 0;
        while i < bytes.len() {
            if i + STRING_LENGTH_PREFIX_BYTES > bytes.len() {
                return Err(CrateSpecError::DecodeError("字符串表数据不完整".to_string()));
            }
            let mut len_bytes: [u8; STRING_LENGTH_PREFIX_BYTES] = [0; STRING_LENGTH_PREFIX_BYTES];
            len_bytes.copy_from_slice(bytes[i..i + STRING_LENGTH_PREFIX_BYTES].as_ref());
            let len = u32::from_le_bytes(len_bytes) as usize;
            if i + STRING_LENGTH_PREFIX_BYTES + len > bytes.len() {
                return Err(CrateSpecError::DecodeError("字符串表数据不完整".to_string()));
            }
            let st = String::from_utf8(bytes[i + STRING_LENGTH_PREFIX_BYTES..i + STRING_LENGTH_PREFIX_BYTES + len].to_vec())
                .map_err(|e| CrateSpecError::DecodeError(format!("UTF-8 解码失败: {}", e)))?;
            self.str2off.insert(st.clone(), i as u32);
            self.off2str.insert(i as u32, st);
            i += STRING_LENGTH_PREFIX_BYTES + len;
            self.total_bytes = i as u32;
        }
        Ok(())
    }
}

#[derive(Debug, PartialEq)]
pub struct CrateBinary {
    //FIXME this maybe change to for fast read
    pub bytes: Vec<u8>,
}

impl Default for CrateBinary {
    fn default() -> Self {
        Self::new()
    }
}

impl CrateBinary {
    pub fn new() -> Self {
        Self { bytes: vec![] }
    }

    pub fn set_bin(&mut self, bytes: Vec<u8>) {
        self.bytes = bytes;
    }

    pub fn write_to_crate_binary_section(&self, cbs: &mut CrateBinarySection) {
        cbs.bin.arr = self.bytes.to_vec();
    }

    pub fn read_from_crate_biary_section(&mut self, cbs: &CrateBinarySection) {
        self.bytes = cbs.bin.arr.to_vec();
    }
}

#[derive(Debug, PartialEq)]
pub struct SigInfo {
    pub typ: u32,
    pub size: usize,
    pub bin: Vec<u8>,
    pub pkcs: PKCS,
    pub pub_key: Option<String>, // 用于网络签名（兼容性字段，实际数据从 NetworkSignature 中提取）
}

impl Default for SigInfo {
    fn default() -> Self {
        Self::new()
    }
}

impl SigInfo {
    pub fn new() -> Self {
        SigInfo {
            typ: 0,
            size: 0,
            bin: vec![],
            pkcs: PKCS::new(),
            pub_key: None,
        }
    }

    pub fn read_from_sig_structure_section(&mut self, sig: &SigStructureSection) -> Result<()> {
        self.typ = sig.sigstruct_type as u32;
        self.size = sig.sigstruct_size as usize;
        
        // 如果是网络签名，反序列化 NetworkSignature
        if self.typ == SIGTYPE::NETWORK.as_u32() {
            match bincode::decode_from_slice::<NetworkSignature, _>(
                &sig.sigstruct_sig.arr,
                bincode::config::standard(),
            ) {
                Ok((network_sig, _)) => {
                    self.bin = sig.sigstruct_sig.arr.clone();
                    self.pub_key = Some(network_sig.pub_key.clone());
                }
                Err(e) => {
                    return Err(CrateSpecError::DecodeError(format!("无法反序列化网络签名: {}", e)));
                }
            }
        } else {
            // 本地签名，直接复制
            self.bin = sig.sigstruct_sig.arr.clone();
        }
        Ok(())
    }

    pub fn write_to_sig_structure_section(&self, sig: &mut SigStructureSection) {
        sig.sigstruct_type = self.typ as Type;
        sig.sigstruct_size = self.size as Size;
        
        // 如果是网络签名，bin 应该已经包含序列化的 NetworkSignature
        // 否则直接使用 bin
        sig.sigstruct_sig = RawArrayType::from_vec(self.bin.clone());
    }
}
