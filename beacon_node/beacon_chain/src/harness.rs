use crate::{
    builder::BeaconChainBuilder, eth1_chain::CachingEth1Backend, events::NullEventHandler,
    migrate::NullMigrator, BeaconChain,
};
use genesis::interop_genesis_state;
use lazy_static::lazy_static;
use serde_derive::{Deserialize, Serialize};
use sloggers::{null::NullLoggerBuilder, Build};
use slot_clock::{SlotClock, TestingSlotClock};
use std::sync::Arc;
use std::time::Duration;
use store::{config::StoreConfig, HotColdDB, MemoryStore};
use tempfile::{tempdir, TempDir};
use types::test_utils::generate_deterministic_keypairs;
use types::*;

// 4th September 2019
pub const HARNESS_GENESIS_TIME: u64 = 1_567_552_690;
// This parameter is required by a builder but not used because we use the `TestingSlotClock`.
pub const HARNESS_SLOT_TIME: Duration = Duration::from_secs(1);
pub const INITIAL_VALIDATOR_COUNT: usize = 64;

lazy_static! {
    pub static ref KEYPAIRS: Vec<Keypair> =
        generate_deterministic_keypairs(INITIAL_VALIDATOR_COUNT);
}

type E = MinimalEthSpec;
pub type Witness = crate::builder::Witness<
    // BlockingMigrator<E, MemoryStore<E>, MemoryStore<E>>,
    NullMigrator,
    TestingSlotClock,
    CachingEth1Backend<E>,
    E,
    NullEventHandler<E>,
    MemoryStore<E>,
    MemoryStore<E>,
>;

/// An event occuring on a single chain.
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub enum ChainEvent {
    ProduceBlock,
    SkipSlot,
    // NewSkipFork,
}

/// All the events occuring during a single slot, for each chain.
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SlotEvent {
    chain_events: Vec<ChainEvent>,
}

impl PartialEq for SlotEvent {
    fn eq(&self, other: &Self) -> bool {
        self.chain_events.iter().eq(other.chain_events.iter())
    }
}

/// All the events occuring during an execution.
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Execution {
    slot_events: Vec<SlotEvent>,
}

impl PartialEq for Execution {
    fn eq(&self, other: &Self) -> bool {
        self.slot_events.iter().eq(other.slot_events.iter())
    }
}

impl Execution {
    pub fn is_well_formed(&self) -> bool {
        if self.slot_events.is_empty() {
            return false;
        }

        let mut max_num_forks = 1;
        for slot_event in &self.slot_events {
            if slot_event.chain_events.is_empty() || slot_event.chain_events.len() != max_num_forks
            {
                return false;
            }
            /*
            max_num_forks += slot_event
                .chain_events
                .iter()
                .filter(|ev| ev == ChainEvent::NewSkipFork)
                .count();
            */
        }
        true
    }
}

pub struct Harness {
    /// Hash of the block at the head of each chain.
    pub forks: Vec<Hash256>,
    pub chain: BeaconChain<Witness>,
    pub data_dir: TempDir,
}

impl Harness {
    pub fn new() -> Self {
        let data_dir = tempdir().expect("should create temporary data_dir");
        let mut spec = E::default_spec();

        spec.target_aggregators_per_committee = 1 << 32;

        let log = NullLoggerBuilder.build().expect("logger should build");
        let store =
            HotColdDB::open_ephemeral(StoreConfig::default(), spec.clone(), log.clone()).unwrap();
        let chain = BeaconChainBuilder::new(MinimalEthSpec)
            .logger(log)
            .custom_spec(spec.clone())
            .store(Arc::new(store))
            .store_migrator(NullMigrator)
            .data_dir(data_dir.path().to_path_buf())
            .genesis_state(
                interop_genesis_state::<E>(&KEYPAIRS, HARNESS_GENESIS_TIME, &spec)
                    .expect("should generate interop state"),
            )
            .expect("should build state using recent genesis")
            .dummy_eth1_backend()
            .expect("should build dummy backend")
            .null_event_handler()
            .testing_slot_clock(HARNESS_SLOT_TIME)
            .expect("should configure testing slot clock")
            .build()
            .expect("should build");

        let forks = vec![chain.head_info().unwrap().block_root];

        Self {
            forks,
            chain,
            data_dir,
        }
    }

    // Fuzz target, don't crash!
    pub fn apply_execution(&mut self, exec: Execution) {
        if !exec.is_well_formed() {
            return;
        }
        // Go to slot 1
        self.chain.slot_clock.advance_slot();

        for slot_event in exec.slot_events {
            let slot = self.chain.slot_clock.now().unwrap();
            self.apply_slot_event(slot, slot_event);
            self.chain.slot_clock.advance_slot();
        }
    }

    fn apply_slot_event(&mut self, slot: Slot, slot_event: SlotEvent) {
        for (chain_id, chain_event) in slot_event.chain_events.into_iter().enumerate() {
            // TODO: remove this unwrap
            self.apply_chain_event(slot, chain_id, chain_event).unwrap();
        }
    }

    fn apply_chain_event(
        &mut self,
        slot: Slot,
        chain_id: usize,
        chain_event: ChainEvent,
    ) -> Option<()> {
        use ChainEvent::*;

        match chain_event {
            SkipSlot => Some(()),
            ProduceBlock => {
                let parent_block_root = &self.forks[chain_id];
                let parent_block = self.chain.get_block(parent_block_root).unwrap()?;
                let parent_state = self
                    .chain
                    .get_state(&parent_block.state_root(), Some(parent_block.slot()))
                    .unwrap()
                    .unwrap();

                // TODO: deal with long skips
                let proposer_idx = parent_state
                    .get_beacon_proposer_index(slot, self.spec())
                    .unwrap();
                let randao_reveal = self.randao_reveal(proposer_idx, slot, &parent_state);

                let (block, state) = self
                    .chain
                    .produce_block_on_state(parent_state, slot, randao_reveal)
                    .unwrap();
                let signed_block = block.sign(
                    &KEYPAIRS[proposer_idx].sk,
                    &state.fork,
                    state.genesis_validators_root,
                    self.spec(),
                );

                let block_root = self.chain.process_block(signed_block).unwrap();
                self.forks[chain_id] = block_root;
                Some(())
            } // NewSkipFork => Some(()),
        }
    }

    fn spec(&self) -> &ChainSpec {
        &self.chain.spec
    }

    fn randao_reveal(&self, validator_idx: usize, slot: Slot, state: &BeaconState<E>) -> Signature {
        let epoch = slot.epoch(E::slots_per_epoch());
        let domain = self.spec().get_domain(
            epoch,
            Domain::Randao,
            &state.fork,
            state.genesis_validators_root,
        );
        let message = epoch.signing_root(domain);
        Signature::new(message.as_bytes(), &KEYPAIRS[validator_idx].sk)
    }
}

// Manual executions
impl Execution {
    pub fn linear_chain(num_slots: usize) -> Self {
        Execution {
            slot_events: vec![
                SlotEvent {
                    chain_events: vec![ChainEvent::ProduceBlock]
                };
                num_slots
            ],
        }
    }

    pub fn hop_skip_jump(hop: usize, skip: usize, jump: usize) -> Self {
        let mut slot_events = vec![];
        slot_events.extend(vec![
            SlotEvent {
                chain_events: vec![ChainEvent::ProduceBlock],
            };
            hop
        ]);
        slot_events.extend(vec![
            SlotEvent {
                chain_events: vec![ChainEvent::SkipSlot],
            };
            skip
        ]);
        slot_events.extend(vec![
            SlotEvent {
                chain_events: vec![ChainEvent::ProduceBlock],
            };
            jump
        ]);
        Execution { slot_events }
    }
}

#[cfg(test)]
mod manual_execution {
    use super::*;
    use bincode::serialize_into;
    use std::fs::{create_dir_all, File};
    use std::path::Path;

    const OUTPUT_DIR: &str = "fuzz/manual_corpus";

    fn write_to_file(filename: &str, exec: &Execution) {
        create_dir_all(OUTPUT_DIR).unwrap();
        let mut f = File::create(Path::new(OUTPUT_DIR).join(filename)).unwrap();
        serialize_into(&mut f, exec).unwrap();
    }

    fn exec_test(name: &str, exec: Execution) {
        let mut harness = Harness::new();
        write_to_file(name, &exec);
        harness.apply_execution(exec);
    }

    #[test]
    fn linear_chain_1() {
        exec_test(
            "linear_chain_1.bin",
            Execution::linear_chain(1 * E::slots_per_epoch() as usize),
        );
    }

    #[test]
    fn linear_chain_4() {
        exec_test(
            "linear_chain_4.bin",
            Execution::linear_chain(4 * E::slots_per_epoch() as usize),
        );
    }

    #[test]
    fn linear_chain_5() {
        exec_test(
            "linear_chain_5.bin",
            Execution::linear_chain(5 * E::slots_per_epoch() as usize),
        );
    }

    #[test]
    fn hsj_0_2_3() {
        let slots_per_epoch = E::slots_per_epoch() as usize;
        exec_test(
            "hsj_0_2_3.bin",
            Execution::hop_skip_jump(0, 2 * slots_per_epoch, 3 * slots_per_epoch),
        );
    }

    #[test]
    fn hsj_2_1_2() {
        let slots_per_epoch = E::slots_per_epoch() as usize;
        exec_test(
            "hsj_2_1_2.bin",
            Execution::hop_skip_jump(
                2 * slots_per_epoch,
                1 * slots_per_epoch,
                2 * slots_per_epoch,
            ),
        );
    }
}
