use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, CanonicalAddr, Decimal256, StdResult, Storage, Uint256};
use cw_storage_plus::{Item, Map};


pub static REWARD_POT: Item<RewardPot> = Item::new("reward_pot");
pub static REWARDED: Map<Vec<u8>, RewardInfo> = Map::new("rewardees");

pub static DONATIONS: Map<Vec<u8>, DonationInfo> = Map::new("donations");

/// Maps a group id back to the person who claimed from the reward pot using it. Group ID => Claimant Address
pub static SEEN_GROUP_IDS: Map<Vec<u8>, Vec<u8>> = Map::new("seen_group_ids");

#[cw_serde]
pub struct GEID_CLAIM {
    address: Addr,
    claim_message: String,
}

#[cw_serde]
pub struct RewardInfo {
    /// Amount of reward shares that this claimant has
    pub(crate) reward_shares: Decimal256,
    /// The unix timestamp of when this claimant claimed
    pub(crate) claim_time: u64
}

#[cw_serde]
pub struct RewardPot {
    /// The number of reward units that this reward contract contains.
    pub(crate) total_reward_units: Uint256,
    /// The total amount of GEIDs that have claimed from the contract
    pub(crate) GEIDs: Uint256,
    /// Total amount of donations available to claim from
    pub(crate) pot_of_rewards: Uint256
}

#[cw_serde]
pub struct DonationInfo {
    /// The amount of funds that a certain user has donated
    pub(crate) donation_size: Uint256,
    /// The timestamp(unix timestamp) of the last donation
    pub(crate) last_donation: u64
}

impl RewardPot {
    /// The base reward units given out. For each GEID submitted, we make the amount of reward units
    /// you get less and less. This gives the incentive for people to compete by submitting their unique
    /// GEID faster.
    // pub fn reward_units(&self) -> Decimal256 {
    //     Decimal256::one() / self.GEIDs
    // }
    //
    // /// Returns the multiplier to apply to amount of reward units we're paying.
    // /// The reward units are multiplied by the amount of time that has passed between claims, divided
    // /// by the amount of weeks that have passed. The more weeks that have passed the higher the multiplier.
    // pub fn reward_multiplier(&self, current_time: u64) -> Decimal256 {
    //     let last_claim_decimal = Decimal256::from_ratio(self.last_claim, 1u128);
    //     let current_claim_decimal = Decimal256::from_ratio(current_time, 1u128);
    //     let one_week_decimal = Decimal256::from_ratio(604800u128, 1u128);
    //
    //     // Should yield a multiplier based on the number of weeks that has passed
    //     (current_claim_decimal - last_claim_decimal) / one_week_decimal
    // }
    //
    // /// Returns the amount of reward units the next claimant will get given the current time.
    // /// The amount returned is the amount of reward units(1/GEIDs) multiplied by the reward multiplier.
    // pub fn next_claim_reward_units(&self, current_time: u64) -> Decimal256 {
    //     let number_of_reward_units = self.reward_units();
    //     let reward_multiplier = self.reward_multiplier(current_time);
    //
    //     number_of_reward_units * reward_multiplier
    // }

    /// A Patron of the GEID gave a donation and we're adding it to the pot! The way this works is that we take the donor's address + amount + donation time
    /// and add them to the leaderboard!
    pub fn add_donation(&mut self, storage: &mut dyn Storage, donor: CanonicalAddr, amount: Uint256, donation_time: u64) -> StdResult<()> {
        // Let's see if the donor is an existing one. If they've already donated, we'll grab the record.
        // Otherwise we are going to create a new one to save.
        let mut donation_record = match DONATIONS.load(storage, Vec::from(donor.as_slice())) {
            Ok(record) => {
                record
            }
            Err(_) => {
                DonationInfo {
                    donation_size: Uint256::zero(),
                    last_donation: 0,
                }
            }
        };

        // Increase the amount of rewards in the pot
        self.pot_of_rewards += amount;

        // Increase the donation size by the amount donated
        donation_record.donation_size += amount;
        // Set the last donation time to the one that was given
        donation_record.last_donation = donation_time;

        // Save the donation record inside of the Keymap
        DONATIONS.save(storage, Vec::from(donor.as_slice()), &donation_record).unwrap();

        // Tell the world we're happy of the result ^-^
        Ok(())
    }

    /// Returns the amount of rewards that a claimant is able to get from the reward pot.
    pub fn claimable_share_of_pot(&self, reward_info: RewardInfo) -> Uint256 {
        let user_shares = reward_info.reward_shares;
        let user_share_of_rewards = user_shares / self.total_reward_units;

        let user_rewards_from_pot = self.pot_of_rewards * user_share_of_rewards;

        return user_rewards_from_pot
    }

    /// A claimant would like to claim their reward from the pot! Since they were kind enough to provide a GEID we've never
    /// seen before lets reward them.
    pub fn claim_rewards(&mut self, storage: &mut dyn Storage, claimant: CanonicalAddr, claim_time: u64) -> Uint256 {
        let claimant = match REWARDED.load(storage, Vec::from(claimant.as_slice())) {
            Ok(reward_info) => {
                reward_info
            }
            Err(_) => {
                let reward_info = RewardInfo {
                    reward_shares: Decimal256::from_ratio(1u128, 1u128),
                    claim_time,
                };
                // Save the new claimants reward info since we've never seen them before
                REWARDED.save(storage, Vec::from(claimant.as_slice()), &reward_info).unwrap();
                // return the newly created RewardInfo
                reward_info
            }
        };
        // the amount of rewards that the user should be able to claim from the pot
        let amount_to_reward = self.claimable_share_of_pot(claimant);

        amount_to_reward
    }
}

#[cfg(test)]
mod tests {
    use cosmwasm_std::testing::mock_dependencies;
    use cosmwasm_std::{CanonicalAddr, Decimal256, Uint256};
    use crate::state::RewardPot;

    #[test]
    fn test_add_donation() {
        let mock_deps = mock_dependencies();
        let mut storage = mock_deps.storage;
        let mut reward_pot = RewardPot {
            total_reward_units: Default::default(),
            GEIDs: Uint256::zero(),
            pot_of_rewards: Uint256::zero(),
        };

        let donor = CanonicalAddr::from([72, 101, 108, 108, 111, 32, 119, 111, 114, 108, 100, 33]);
        let donation_time: u64 = 475200;

        reward_pot.add_donation(&mut storage, donor, Uint256::from(10u128), donation_time).unwrap();

        assert_eq!(reward_pot.pot_of_rewards, Uint256::from(10u128))
    }
}