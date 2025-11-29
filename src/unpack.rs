use crate_spec::utils::context::PackageContext;
use crate_spec::utils::pkcs::PKCS;
use crate_spec::{Result, CrateSpecError};
use std::fs;
use std::path::PathBuf;
use std::str::FromStr;

struct Unpacking {
    file_path: PathBuf,
    cas_path: Vec<String>,
}

impl Unpacking {
    pub fn new(path: &str) -> Result<Self> {
        Ok(Unpacking {
            file_path: PathBuf::from_str(path)
                .map_err(|e| CrateSpecError::ValidationError(format!("无效的路径: {}", e)))?,
            cas_path: Vec::new(),
        })
    }

    pub fn add_ca_from_file(&mut self, path: &str) -> Result<()> {
        let path_buf = PathBuf::from_str(path)
            .map_err(|e| CrateSpecError::ValidationError(format!("无效的 CA 路径: {}", e)))?;
        let file_path = fs::canonicalize(&path_buf)
            .map_err(|_e| CrateSpecError::FileNotFound(path_buf.clone()))?;
        let file_path_str = file_path.to_str()
            .ok_or_else(|| CrateSpecError::Other("无法将路径转换为字符串".to_string()))?;
        self.cas_path.push(file_path_str.to_string());
        Ok(())
    }

    pub fn unpack_context(self) -> Result<PackageContext> {
        let mut package_context_new = PackageContext::new();
        package_context_new.set_root_cas_bin(PKCS::root_ca_bins(self.cas_path)?);
        let bin = fs::read(&self.file_path)
            .map_err(|_e| CrateSpecError::FileNotFound(self.file_path.clone()))?;
        let (_crate_package_new, _str_table) =
            package_context_new.decode_from_crate_package(bin.as_slice())
                .map_err(|e| CrateSpecError::DecodeError(e.to_string()))?;
        Ok(package_context_new)
    }
}

pub fn unpack_context(file_path: &str, cas_path: Vec<String>) -> Result<PackageContext> {
    let mut unpack = Unpacking::new(file_path)?;
    for ca_path in cas_path {
        unpack.add_ca_from_file(&ca_path)?;
    }
    unpack.unpack_context()
}

#[test]
fn test_unpack() {
    use crate::pack::pack_context;
    use crate_spec::utils::context::SIGTYPE;
    let mut pack_context = pack_context("../crate-spec");
    fn sign() -> PKCS {
        let mut pkcs1 = PKCS::new();
        pkcs1.load_from_file_writer(
            "test/cert.pem".to_string(),
            "test/key.pem".to_string(),
            ["test/root-ca.pem".to_string()].to_vec(),
        );
        pkcs1
    }
    pack_context.add_sig(sign(), SIGTYPE::CRATEBIN);

    let (_, _, bin) = pack_context.encode_to_crate_package();
    fs::write(PathBuf::from_str("test/crate-spec.cra").unwrap(), bin).unwrap();

    let pack_context_decode =
        unpack_context("test/crate-spec.cra", vec!["test/root-ca.pem".to_string()]);

    assert_eq!(pack_context_decode.pack_info, pack_context.pack_info);
    assert_eq!(pack_context_decode.dep_infos, pack_context.dep_infos);
    assert_eq!(pack_context_decode.crate_binary, pack_context.crate_binary);
}
