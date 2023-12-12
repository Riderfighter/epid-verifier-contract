use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::{Addr, Uint256};
use crate::intelstructs::{ClaimStruct, IASReport};
use crate::state::{DonationInfo, RewardInfo};

#[cw_serde]
pub struct InstantiateMsg {
    pub(crate) total_reward_shares: Uint256
}

#[cw_serde]
pub enum ExecuteMsg {
    /// For claimants to grab their reward from the pot
    ClaimGEID {
        // The report that is generated by an enclave, ClaimStruct is encoded in the payload
        report: IASReport,
        // We'll verify the IASReport and the ClaimStruct together to aware the reward
        to_claim: ClaimStruct,
    },
    /// For a donor to add money to the pot to claim from
    DonateToPot {

    }
}

#[cw_serde]
pub enum QueryMsg {
    FetchDonors {
        /// The page we wish to paginate from
        page: u64,
        /// The size of the page we're paginating by
        page_size: u64
    },
    FetchClaimants {
        /// The page we wish to paginate from
        page: u64,
        /// The size of the page we're paginating by
        page_size: u64
    },
    FetchSeenGuids {
        /// The page we wish to paginate from
        page: u64,
        /// The size of the page we're paginating by
        page_size: u64
    }
}


#[cw_serde]
pub struct FetchDonorsResponse {
    pub donors: Vec<(Addr, DonationInfo)>
}

#[cw_serde]
pub struct FetchRewardedResponse {
    pub rewarded: Vec<(Addr, RewardInfo)>
}

#[cw_serde]
pub struct FetchSeenGroupIds {
    pub rewarded: Vec<u32>
}