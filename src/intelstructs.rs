use cosmwasm_std::Binary;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use hex_literal::hex;
use num_bigint::BigUint;

pub static INTEL_ROOT_MODULUS: &[u8] = &hex!("9F3C647EB5773CBB512D2732C0D7415EBB55A0FA9EDE2E649199E6821DB910D53177370977466A6A5E4786CCD2DDEBD4149D6A2F6325529DD10CC98737B0779C1A07E29C47A1AE004948476C489F45A5A15D7AC8ECC6ACC645ADB43D87679DF59C093BC5A2E9696C5478541B979E754B573914BE55D32FF4C09DDF27219934CD990527B3F92ED78FBF29246ABECB71240EF39C2D7107B447545A7FFB10EB060A68A98580219E36910952683892D6A5E2A80803193E407531404E36B315623799AA825074409754A2DFE8F5AFD5FE631E1FC2AF3808906F28A790D9DD9FE060939B125790C5805D037DF56A99531B96DE69DE33ED226CC1207D1042B5C9AB7F404FC711C0FE4769FB9578B1DC0EC469EA1A25E0FF9914886EF2699B235BB4847DD6FF40B606E6170793C2FB98B314587F9CFD257362DFEAB10B3BD2D97673A1A4BD44C453AAF47FC1F2D3D0F384F74A06F89C089F0DA6CDB7FCEEE8C9821A8E54F25C0416D18C46839A5F8012FBDD3DC74D256279ADC2C0D55AFF6F0622425D1B");

pub static INTEL_ROOT_EXPONENT: &[u8] = &hex!("010001");

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, JsonSchema)]
pub struct ReportBody {
    pub id: String,
    pub timestamp: String,
    pub version: u64,
    #[serde(rename="epidPseudonym")]
    pub epid_pseudonym: Binary,
    #[serde(rename="advisoryURL")]
    pub advisory_url: String,
    #[serde(rename="advisoryIDs")]
    pub advisory_ids: Vec<String>,
    #[serde(rename="isvEnclaveQuoteStatus")]
    pub isv_enclave_quote_status: String,
    #[serde(rename="platformInfoBlob")]
    pub platform_info_blob: String,
    #[serde(rename="isvEnclaveQuoteBody")]
    pub isv_enclave_quote_body: String
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, JsonSchema)]
pub struct IASReport {
    pub report: ReportBody,
    #[serde(rename="reportsig")]
    pub report_sig: String
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, JsonSchema)]
pub struct ClaimStruct {
    address: Vec<u8>,
    message: String
}

/// Given an RSA signature and the signer's exponent + modulus we recover the digest that was signed by the signature.
pub fn recover_signature_digest(signature: &[u8], exponent: &[u8], modulus: &[u8]) -> Vec<u8> {
    let sig_as_bignum_be = BigUint::from_bytes_be(signature);
    let intel_modulus_be = BigUint::from_bytes_be(modulus);
    let intel_exponent_be = BigUint::from_bytes_be(exponent);

    let digest_be = sig_as_bignum_be.modpow(&intel_exponent_be, &intel_modulus_be);

    digest_be.to_bytes_be()
}
