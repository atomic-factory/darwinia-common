// --- substrate ---
use frame_support::{assert_err, assert_ok, traits::Currency};
// --- darwinia ---
use crate::{mock::*, RawEvent};

#[test]
fn swap_and_burn_should_work() {
	new_test_ext().execute_with(|| {
		System::set_block_number(1);

		let mut total_mapped_ring = CrabIssuing::total_mapped_ring();

		for account in 1..=5 {
			assert_eq!(Ring::free_balance(&account), account as Balance * 100);
			assert_ok!(CrabIssuing::swap_and_burn_to_genesis(
				Origin::signed(account),
				account as Balance * 100
			));

			total_mapped_ring -= account as Balance;

			assert_eq!(CrabIssuing::total_mapped_ring(), total_mapped_ring);

			assert_eq!(
				crab_issuing_events(),
				[Event::crab_issuing(RawEvent::SwapAndBurnToGenesis(
					account,
					account as Balance * 100,
					account as Balance
				))]
			);
		}
	});
}

#[test]
fn amount_too_low_should_failed() {
	new_test_ext().execute_with(|| {
		for amount in 0..=99 {
			assert_err!(
				CrabIssuing::swap_and_burn_to_genesis(Origin::signed(1), amount),
				CrabIssuingError::SwapAmountTL
			);
		}
	});
}

#[test]
fn insufficient_ring_should_fail() {
	new_test_ext().execute_with(|| {
		assert_eq!(Ring::free_balance(&1), 100);
		assert_ok!(CrabIssuing::swap_and_burn_to_genesis(
			Origin::signed(1),
			100
		));
		assert_err!(
			CrabIssuing::swap_and_burn_to_genesis(Origin::signed(1), 100),
			RingError::InsufficientBalance
		);
	});
}

#[test]
fn backed_ring_insufficient_should_fail() {
	new_test_ext().execute_with(|| {
		let _ = Ring::deposit_creating(&100, 450_000);
		assert_eq!(Ring::free_balance(&100), 450_000);
		assert_eq!(CrabIssuing::total_mapped_ring(), 4_000);

		assert_err!(
			CrabIssuing::swap_and_burn_to_genesis(Origin::signed(100), 450_000),
			CrabIssuingError::BackedRingIS
		);
	});
}
