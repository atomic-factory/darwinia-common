// --- substrate ---
use frame_support::weights::{constants::BlockExecutionWeight, DispatchClass, Weight};
use pallet_election_provider_multi_phase::{weights::SubstrateWeight, Config};
use sp_runtime::transaction_validity::TransactionPriority;
// --- darwinia ---
use crate::*;

sp_npos_elections::generate_solution_type!(
	#[compact]
	pub struct NposCompactSolution16::<u32, u16, sp_runtime::PerU16>(16)
	// -------------------- ^^ <NominatorIndex, ValidatorIndex, Accuracy>
);

frame_support::parameter_types! {
	// phase durations. 1/4 of the last session for each.
	pub const SignedPhase: u32 = BLOCKS_PER_SESSION / 4;
	pub const UnsignedPhase: u32 = BLOCKS_PER_SESSION / 4;

	// fallback: no need to do on-chain phragmen initially.
	pub const Fallback: pallet_election_provider_multi_phase::FallbackStrategy =
		pallet_election_provider_multi_phase::FallbackStrategy::OnChain;

	pub SolutionImprovementThreshold: Perbill = Perbill::from_rational(1u32, 10_000);

	// miner configs
	pub const StakingUnsignedPriority: TransactionPriority = TransactionPriority::max_value() / 2;
	pub const MultiPhaseUnsignedPriority: TransactionPriority = StakingUnsignedPriority::get() - 1u64;
	pub const MinerMaxIterations: u32 = 10;
	pub MinerMaxWeight: Weight = RuntimeBlockWeights::get()
		.get(DispatchClass::Normal)
		.max_extrinsic.expect("Normal extrinsics have a weight limit configured; qed")
		.saturating_sub(BlockExecutionWeight::get());
}

impl Config for Runtime {
	type Event = Event;
	type Currency = Balances;
	type SignedPhase = SignedPhase;
	type UnsignedPhase = UnsignedPhase;
	type SolutionImprovementThreshold = SolutionImprovementThreshold;
	type MinerMaxIterations = MinerMaxIterations;
	type MinerMaxWeight = MinerMaxWeight;
	type MinerTxPriority = MultiPhaseUnsignedPriority;
	type DataProvider = Staking;
	type OnChainAccuracy = Perbill;
	type CompactSolution = NposCompactSolution16;
	type Fallback = Fallback;
	type WeightInfo = SubstrateWeight<Runtime>;
	type BenchmarkingConfig = ();
}
