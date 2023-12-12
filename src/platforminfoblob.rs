#![allow(non_camel_case_types)]

use std::mem;
use std::u16;

use cosmwasm_std::{ensure_eq, StdError, StdResult};
use itertools::Itertools;
use sha2::{Digest, Sha256};
use crate::intelstructs::ClaimStruct;

const SGX_CPUSVN_SIZE: usize = 16;
const PSVN_SIZE: usize = 18; // sizeof(psvn_t)
const PSDA_SVN_SIZE: usize = 4;
const ISVSVN_SIZE: usize = 2;
const SGX_PLATFORM_INFO_SIZE: usize = 101;

const QE_EPID_GROUP_REVOKED: u8 = 0x01;
const PERF_REKEY_FOR_QE_EPID_GROUP_AVAILABLE: u8 = 0x02;
const QE_EPID_GROUP_OUT_OF_DATE: u8 = 0x04;

const QUOTE_CPUSVN_OUT_OF_DATE: u16 = 0x0001;
const QUOTE_ISVSVN_QE_OUT_OF_DATE: u16 = 0x0002;
const QUOTE_ISVSVN_PCE_OUT_OF_DATE: u16 = 0x0004;
const PLATFORM_CONFIGURATION_NEEDED: u16 = 0x0008;

const PSE_ISVSVN_OUT_OF_DATE: u16 = 0x0001;
const EPID_GROUP_ID_BY_PS_HW_GID_REVOKED: u16 = 0x0002;
const SVN_FROM_PS_HW_SEC_INFO_OUT_OF_DATE: u16 = 0x0004;
const SIGRL_VER_FROM_PS_HW_SIG_RLVER_OUT_OF_DATE: u16 = 0x0008;
const PRIVRL_VER_FROM_PS_HW_PRV_KEY_RLVER_OUT_OF_DATE: u16 = 0x0010;

pub type sgx_isv_svn_t = u16; // 2 bytes
pub type tcb_psvn_t = [u8; PSVN_SIZE];
pub type psda_svn_t = [u8; PSDA_SVN_SIZE];
pub type pse_isvsvn_t = [u8; ISVSVN_SIZE];

#[derive(Copy, Clone, Debug)]
#[repr(packed)]
struct sgx_cpu_svn_t {
    // 16 bytes
    pub svn: [u8; SGX_CPUSVN_SIZE],
}

#[derive(Copy, Clone, Debug)]
#[repr(packed)]
struct psvn_t {
    // 16 + 2
    pub cpu_svn: sgx_cpu_svn_t,
    pub isv_svn: sgx_isv_svn_t,
}

#[derive(Copy, Clone, Debug)]
#[repr(packed)]
pub struct sgx_ec256_signature_t {
    pub gx: [u8; 32],
    pub gy: [u8; 32],
}

#[derive(Copy, Clone, Debug)]
#[repr(packed)]
pub struct platform_info_blob {
    pub sgx_epid_group_flags: u8,
    pub sgx_tcb_evaluation_flags: u16,
    pub pse_evaluation_flags: u16,
    pub latest_equivalent_tcb_psvn: tcb_psvn_t,
    pub latest_pse_isvsvn: pse_isvsvn_t,
    pub latest_psda_svn: psda_svn_t,
    pub xeid: u32,
    pub gid: u32,
    pub signature: sgx_ec256_signature_t,
}

#[repr(packed)]
struct platform_info {
    #[allow(unused)]
    pub platform_info: [u8; SGX_PLATFORM_INFO_SIZE],
}

/// Takes in a hex string and ensures that it is 210 bytes in length and that all the characters are in the alphanumeric alphabet.
/// This is so that we can do funny platforminfoblob to struct conversion
fn input_is_ok(argv1: &str) -> bool {
    if argv1.len() != 210 {
        return false;
    }
    for c in argv1.chars() {
        if !c.is_alphanumeric() {
            return false;
        }
    }
    true
}


/// We take in a platform info blob hex string and convert it to a struct
pub fn convert_platform_info_hex(blob_hex: &str) -> StdResult<platform_info_blob> {
    return if input_is_ok(&blob_hex) {
        let from_hex = hex::decode(blob_hex).unwrap();
        println!("{:?}", from_hex);
        let blob_slice = from_hex.as_slice();

        convert_platform_info_blob(blob_slice)
    } else {
        Err(StdError::generic_err("The passed in hex for the PlatformInfoBlob was not only alphanumeric characters."))
    };
}

/// We take in a platform info blob as bytes and convert it to the struct
pub fn convert_platform_info_blob(blob: &[u8]) -> StdResult<platform_info_blob> {
    // Lets make sure that the blob length is 105 bytes long...
    ensure_eq!(blob.len(), 105 as usize, StdError::generic_err("The passed in PlatformInfoBlob is not of the correct length."));

    // Chop off the TSV header from the blob
    let pib_vec = blob[4..].to_vec();
    // Allocate a new array that is the length of the blob minus header
    let mut pib_array: [u8; 101] = [0; 101];
    // Take the entire vec and put it into the pib array
    pib_array.clone_from_slice(&pib_vec[..]);
    // I'm sorry Rustaceans... UNSAFE MEMORY TIME
    let pib: platform_info_blob = unsafe { mem::transmute(pib_array) };

    // Return the converted pib
    Ok(pib)
}

/// Given an Intel attestation Quote Body, we extract the payload from it to compare with a user submitted ClaimStruct.
pub fn get_payload_from_quote_body(quote_body: &[u8]) -> Vec<u8> {
    const PAYLOAD_OFFSET: usize = 368;
    const PAYLOAD_SIZE: usize = 64;

    let payload = &quote_body[PAYLOAD_OFFSET..PAYLOAD_OFFSET + PAYLOAD_SIZE];

    let payload_vec = Vec::from(payload);
    let spliced_vec = payload_vec.split_at(32).0;

    Vec::from(spliced_vec)
}

/// Given a ClaimStruct we convert it to a string, then we hash it so that it becomes the hash that is in the payload part of an Intel attestation.
pub fn convert_claim_struct_to_payload(claim_struct: ClaimStruct) -> Vec<u8> {
    let claim_as_json = serde_json::to_string(&claim_struct).unwrap().replace("\\", "");
    let claim_json_bytes = claim_as_json.as_bytes();

    let mut hasher = Sha256::default();
    hasher.update(claim_json_bytes);

    let sha256d_claim = &hasher.finalize()[..];

    Vec::from(sha256d_claim)
}


#[cfg(test)]
mod tests {
    use cosmwasm_std::{Binary, CanonicalAddr};
    use sha2::{Sha256, Digest};
    use serde::{Deserialize, Serialize};
    use crate::platforminfoblob::{convert_platform_info_blob, convert_platform_info_hex};

    #[test]
    fn test_convert_platform_info_blob() {
        let pib_bytes: &[u8] = &[21, 2, 0, 101, 0, 0, 8, 0, 0, 20, 20, 2, 4, 1, 128, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 13, 0, 0, 12, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 12, 176, 101, 176, 195, 160, 94, 254, 249, 118, 88, 149, 160, 59, 227, 248, 158, 208, 255, 91, 101, 76, 32, 231, 137, 173, 195, 208, 218, 219, 11, 188, 229, 125, 172, 202, 106, 135, 130, 141, 202, 140, 159, 201, 152, 209, 87, 15, 51, 8, 210, 151, 37, 221, 16, 217, 203, 134, 4, 15, 161, 138, 165, 13, 87, 89];

        let result = convert_platform_info_blob(pib_bytes);

        match result {
            Ok(pib) => {
                println!("{:?}", pib);
            }
            Err(_) => {}
        }

    }

    #[test]
    fn test_convert_platform_info_blob_hex() {
        let pib_hex = "150200650000080000141402040180070000000000000000000D00000C000000020000000000000CB065B0C3A05EFEF9765895A03BE3F89ED0FF5B654C20E789ADC3D0DADB0BBCE57DACCA6A87828DCA8C9FC998D1570F3308D29725DD10D9CB86040FA18AA50D5759";

        let result = convert_platform_info_hex(pib_hex);

        match result {
            Ok(pib) => {
                println!("{:?}", pib)
            }
            Err(_) => {}
        }
    }

    #[test]
    fn verify_isvQuoteBodyPayload() {
        let ias_response = r#"{"report":{"id":"200423264892184291776794534127952959503","timestamp":"2023-11-23T11:47:05.757595","version":4,"epidPseudonym":"+CUyIi74LPqS6M0NF7YrSxLqPdX3MKs6D6LIPqRG/ZEB4WmxZVvxAJwdwg/0m9cYnUUQguLnJotthX645lAogfJgO8Xg5/91lSegwyUKvHmKgtjOHX/YTbVe/wmgWiBdaL+KmarY0Je459Px/FqGLWLsAF7egPAJRd1Xn88Znrs=","advisoryURL":"https://security-center.intel.com","advisoryIDs":["INTEL-SA-00161","INTEL-SA-00219","INTEL-SA-00289","INTEL-SA-00334","INTEL-SA-00615"],"isvEnclaveQuoteStatus":"CONFIGURATION_AND_SW_HARDENING_NEEDED","platformInfoBlob":"150200650000080000141402040180070000000000000000000D00000C000000020000000000000CB07FA713992F17617F506072BA90D3794110D036E2293096E6BF758122D4E6BB68EE3F69B49BA232441025B331F3FA6E6AD1E70E5D8892E5F6565E5C9FCE9B2A24","isvEnclaveQuoteBody":"AgABALAMAAAPAA8AAAAAAFHK9aSLRQ1iSu/jKG0xSJQAAAAAAAAAAAAAAAAAAAAAFBQCBwGAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABQAAAAAAAAAHAAAAAAAAAOPC8qW4QNieBprK/8rbZRDvhmpz06nuVxAO1fhkbuS7AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAc8uUpEUEPvz8ZkFapjVh5WlWaLoAJM/f80T0EhGInHAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAC9zI5dTO9V43CN3I5/OaESDnWs8hiIOaCM/QJA3Uk5oQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},"reportsig":"VEd3XgpDOEeRzHpKDx61yBUr4t74Z/kQztmOFM4nkaF+muCZe2KoMd1men4R6fYJh4U1DHnrI0U/zym0N4g6olLBfQ1otxb67LV7N1ekSLQtaJw+iQxNfkrqzNSnle3eKi08GAWVIrMRFC0UooCMuUyZoIGXBsjLZ/Jq1dldus2LUBGM5KHhxhAUbbxAdrcc6NO211S3DRAAYkQYkoHMgLZwWm73TS9LLCT/8pFvkiTUXbHyHpVhnbGB9jnkMd6y22iFQrIiQ+LZKcHCuvD5I07oPQqCezCq/rMMCR/6WAcumapLScNm5zndIeWnN8KE+8EG698eCw3GTONiXoE4hw=="}"#;

        #[derive(Serialize, Deserialize, Clone)]
        pub struct reportBody {
            pub id: String,
            pub timestamp: String,
            pub version: u64,
            pub epidPseudonym: Binary,
            pub advisoryURL: String,
            pub advisoryIDs: Vec<String>,
            pub isvEnclaveQuoteStatus: String,
            pub platformInfoBlob: String,
            pub isvEnclaveQuoteBody: Binary
        }

        #[derive(Serialize, Deserialize, Clone)]
        pub struct IASReport {
            pub report: reportBody,
            pub reportsig: Binary
        }

        let report: IASReport = serde_json::from_str(ias_response).unwrap();

        let quote_body_binary = report.report.isvEnclaveQuoteBody;
        let quote_body_slice = quote_body_binary.0;

        fn get_payload_from_quote_body(quote_body: &[u8]) -> Vec<u8> {
            const PAYLOAD_OFFSET: usize = 368;
            const PAYLOAD_SIZE: usize = 64;

            let payload = &quote_body[PAYLOAD_OFFSET..PAYLOAD_OFFSET + PAYLOAD_SIZE];

            let payload_vec = Vec::from(payload);
            let spliced_vec = payload_vec.split_at(32).0;

            Vec::from(spliced_vec)
        }

        const QUOTE_BODY_LENGTH: usize = 432;
        const MRENCLAVE_OFFSET: usize = 112;
        const MRSIGNER_OFFSET: usize = 176;
        const PAYLOAD_OFFSET: usize = 368;
        const PAYLOAD_SIZE: usize = 64;


        // Lets make sure that the quote body is the correct length
        assert_eq! {quote_body_slice.len(), QUOTE_BODY_LENGTH}

        // Lets extract the MRENCLAVE
        let MRENCLAVE = &quote_body_slice[MRENCLAVE_OFFSET..MRENCLAVE_OFFSET + 32];

        let mrsigner = &quote_body_slice[MRSIGNER_OFFSET..MRSIGNER_OFFSET + 32];

        let payload = &quote_body_slice[PAYLOAD_OFFSET..PAYLOAD_OFFSET + PAYLOAD_SIZE];

        #[derive(Serialize, Deserialize, Clone)]
        struct claim_struct {
            address: Vec<u8>,
            message: String
        }

        let claim = claim_struct {
            address: Vec::from([31, 3, 24, 28, 4, 10, 7, 8, 19, 25, 4, 12, 13, 22, 1, 12, 28, 24, 30, 9, 12, 8, 26, 7, 5, 28, 26, 25, 6, 1, 24, 15]),
            message: "Hello world!".to_string(),
        };

        let claim_as_json = serde_json::to_string(&claim).unwrap().replace("\\", "");
        let claim_json_bytes = claim_as_json.as_bytes();

        println!("{:?}", claim_json_bytes);

        let mut hasher = Sha256::default();
        hasher.update(claim_json_bytes);

        let sha256d_claim = &hasher.finalize()[..];

        let payload_vec = Vec::from(payload);
        let spliced_vec = payload_vec.split_at(32).0;

        println!("Payload {:?} | Sha256'd Claim {:?}", spliced_vec, sha256d_claim);

        assert_eq!(spliced_vec, sha256d_claim);

    }
}
