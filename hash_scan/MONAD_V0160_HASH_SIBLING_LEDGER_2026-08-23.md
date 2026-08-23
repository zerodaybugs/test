# Monad v0.16.0 deterministic-hash sibling ledger

**Decision:** `RESEARCH_ONLY_SIBLINGS_REQUIRE_DYNAMIC_COLLISION_AND_FULLNODE_IMPACT_GATE`

- Public-known exact root-cause rows killed: **26**
- Distinct sibling static rows: **137**
- Submission-ready: **no**

## Public known root cause

`category-labs/monad#2462` is an explicit prior-public fix. The same key types, maps, and per-process seeding remedy are FINAL KILL.

## Promotion boundary

A sibling requires a different key type and map, attacker-controlled valid input, reproducible collision set, superlinear production-path cost, full-node progress impact below one-third Byzantine stake, a narrow distinct fix, and public duplicate clearance. A textual map/hasher hit is not a vulnerability.

- `category/core/bytes_test.cpp:204` — `// Hashing — std::hash, ankerl, boost`
- `category/core/bytes_test.cpp:211` — `EXPECT_EQ(std::hash<bytes32_t>{}(a), std::hash<bytes32_t>{}(b));`
- `category/core/bytes_test.cpp:219` — `EXPECT_NE(std::hash<bytes32_t>{}(a), std::hash<bytes32_t>{}(b));`
- `category/core/bytes_test.cpp:225` — `auto const std_h = std::hash<bytes32_t>{}(val);`
- `category/core/bytes_test.cpp:233` — `auto const std_h = std::hash<bytes32_t>{}(val);`
- `category/core/address_test.cpp:200` — `// Hashing — std::hash, ankerl, boost`
- `category/core/address_test.cpp:207` — `EXPECT_EQ(std::hash<Address>{}(a), std::hash<Address>{}(b));`
- `category/core/address_test.cpp:227` — `auto const std_h = std::hash<Address>{}(val);`
- `category/core/address_test.cpp:235` — `auto const std_h = std::hash<Address>{}(val);`
- `category/vm/compiler/transactional_unordered_map.hpp:27` — `typename K, typename V, typename Hash = std::hash<K>,`
- `category/vm/compiler/ir/x86/emitter.cpp:293` — `return std::hash<uint16_t>{}(d);`
- `category/vm/compiler/ir/x86/emitter.cpp:298` — `return std::hash<uint32_t>{}(d);`
- `category/vm/compiler/ir/x86/emitter.cpp:305` — `h ^= std::hash<uint64_t>{}(d);`
- `category/vm/fuzzing/generator/choice.hpp:109` — `typename T, typename Hash = std::hash<T>,`
- `category/execution/ethereum/state2/test/test_state.cpp:2168` — `uint64_t proposal_seed = 0;`
- `category/rpc/chain_context_buffer.cpp:57` — `ankerl::unordered_dense::segmented_set<Address> const &`
- `category/rpc/chain_context_buffer.hpp:60` — `ankerl::unordered_dense::segmented_set<Address> const &get() const;`
- `category/rpc/chain_context_buffer.hpp:63` — `std::array<ankerl::unordered_dense::segmented_set<Address>, K>`
- `category/rpc/monad_executor_test.cpp:2595` — `ankerl::unordered_dense::segmented_set<Address> const`
- `category/rpc/monad_executor_test.cpp:2597` — `ankerl::unordered_dense::segmented_set<Address> const`
- `category/rpc/monad_executor_test.cpp:2599` — `ankerl::unordered_dense::segmented_set<Address> const`
- `category/vm/memory_pool.cpp:81` — `std::unordered_set<Node *> nodes;`
- `category/core/bytes_test.cpp:226` — `auto const ankerl_h = ankerl::unordered_dense::hash<bytes32_t>{}(val);`
- `category/core/address_test.cpp:210` — `TEST(Address, std_hash_distinguishes_in_unordered_set)`
- `category/core/address_test.cpp:215` — `std::unordered_set<Address> values;`
- `category/core/address_test.cpp:228` — `auto const ankerl_h = ankerl::unordered_dense::hash<Address>{}(val);`
- `category/core/address_test.cpp:240` — `TEST(Address, usable_in_unordered_set)`
- `category/core/address_test.cpp:242` — `std::unordered_set<Address> set;`
- `category/statesync/statesync_client_context.hpp:66` — `ankerl::unordered_dense::segmented_set<monad::bytes32_t> seen_code;`
- `category/mpt/find_request_sender.hpp:47` — `using AsyncInflightNodes = ankerl::unordered_dense::segmented_map<`
- `category/vm/compiler/transactional_unordered_map.hpp:37` — `using Map = std::unordered_map<K, V, Hash, KeyEqual>;`
- `category/vm/utils/lru_weight_cache.hpp:309` — `std::unordered_set<Key> keys;`
- `category/vm/compiler/ir/basic_blocks.hpp:280` — `std::unordered_map<byte_offset, block_id> const &jump_dests() const`
- `category/vm/compiler/ir/basic_blocks.hpp:285` — `std::unordered_map<byte_offset, block_id> &jump_dests()`
- `category/vm/compiler/ir/basic_blocks.hpp:303` — `std::unordered_map<byte_offset, block_id> jump_dests_;`
- `category/vm/compiler/ir/x86/emitter.hpp:82` — `std::unordered_map<Data, int32_t, DataHash> offmap;`
- `category/vm/fuzzing/generator/choice.hpp:168` — `std::unordered_map<T, size_t, Hash, Equal> map_;`
- `category/vm/utils/evm-as/kernel-builder.hpp:503` — `std::unordered_map<std::string, size_t> address_store{};`
- `category/execution/runloop/runloop_monad.cpp:76` — `ankerl::unordered_dense::segmented_set<Address> senders_and_authorities;`
- `category/execution/runloop/runloop_monad.cpp:80` — `ankerl::unordered_dense::segmented_map<bytes32_t, BlockCacheEntry>;`
- `category/execution/runloop/runloop_monad.cpp:86` — `static ankerl::unordered_dense::segmented_set<Address>`
- `category/execution/runloop/runloop_interface_monad.cpp:74` — `using AccountOverrideMap = std::unordered_map<Address, AccountOverride>;`
- `category/execution/runloop/runloop_monad_ethblocks.cpp:126` — `ankerl::unordered_dense::segmented_set<Address> const`
- `category/execution/runloop/runloop_monad_ethblocks.cpp:128` — `ankerl::unordered_dense::segmented_set<Address> const`
- `category/execution/runloop/runloop_monad_ethblocks.cpp:130` — `ankerl::unordered_dense::segmented_set<Address>`
- `category/execution/runloop/runloop_monad_ethblocks.cpp:335` — `ankerl::unordered_dense::segmented_set<Address>`
- `category/execution/runloop/runloop_monad_ethblocks.cpp:337` — `ankerl::unordered_dense::segmented_set<Address>`
- `category/execution/runloop/runloop_monad_ethblocks.cpp:354` — `ankerl::unordered_dense::segmented_set<Address> parent_set;`
- `category/execution/runloop/runloop_monad_ethblocks.cpp:385` — `ankerl::unordered_dense::segmented_set<Address> grandparent_set;`
- `category/execution/runloop/runloop_monad_ethblocks.cpp:422` — `ankerl::unordered_dense::segmented_set<Address> senders_and_authorities;`
- `category/execution/monad/reserve_balance.hpp:44` — `using FailedSet = ankerl::unordered_dense::segmented_set<Address>;`
- `category/execution/monad/chain/monad_chain.hpp:46` — `ankerl::unordered_dense::segmented_set<Address> const`
- `category/execution/monad/chain/monad_chain.hpp:48` — `ankerl::unordered_dense::segmented_set<Address> const`
- `category/execution/monad/chain/monad_chain.hpp:50` — `ankerl::unordered_dense::segmented_set<Address> const`
- `category/execution/monad/chain/monad_chain.hpp:70` — `ankerl::unordered_dense::segmented_set<Address> combine_senders_and_authorities(`
- `category/execution/monad/chain/monad_chain.cpp:40` — `static ankerl::unordered_dense::segmented_set<Address> const`
- `category/execution/monad/chain/monad_chain.cpp:82` — `ankerl::unordered_dense::segmented_set<Address> combine_senders_and_authorities(`
- `category/execution/monad/chain/monad_chain.cpp:86` — `ankerl::unordered_dense::segmented_set<Address> senders_and_authorities;`
- `category/execution/monad/reserve_balance/reserve_balance_contract_test.cpp:102` — `ankerl::unordered_dense::segmented_set<Address> const`
- `category/execution/monad/reserve_balance/reserve_balance_contract_test.cpp:104` — `ankerl::unordered_dense::segmented_set<Address> const`
- `category/execution/monad/reserve_balance/reserve_balance_contract_test.cpp:106` — `ankerl::unordered_dense::segmented_set<Address> const`
- `category/execution/monad/reserve_balance/reserve_balance_contract_test.cpp:312` — `ankerl::unordered_dense::segmented_set<Address>`
- `category/execution/monad/reserve_balance/reserve_balance_contract_test.cpp:314` — `ankerl::unordered_dense::segmented_set<Address>`
- `category/execution/monad/reserve_balance/reserve_balance_contract_test.cpp:316` — `ankerl::unordered_dense::segmented_set<Address> const`
- `category/execution/monad/reserve_balance/reserve_balance_contract_test.cpp:605` — `ankerl::unordered_dense::segmented_set<Address> const`
- `category/execution/monad/reserve_balance/reserve_balance_contract_test.cpp:607` — `ankerl::unordered_dense::segmented_set<Address> const`
- `category/execution/monad/reserve_balance/reserve_balance_contract_test.cpp:609` — `ankerl::unordered_dense::segmented_set<Address> const`
- `category/execution/monad/staking/fuzzer/staking_contract_machine.hpp:60` — `std::unordered_map<uint64_t, Address> val_id_to_signer_;`
- `category/execution/monad/staking/fuzzer/staking_contract_model.hpp:77` — `std::unordered_map<uint64_t, std::unordered_set<Address>>;`
- `category/execution/monad/staking/fuzzer/staking_contract_model.hpp:82` — `std::tuple<uint64_t, Address>, std::unordered_set<uint8_t>,`
- `category/execution/monad/staking/fuzzer/staking_contract_machine.cpp:537` — `std::unordered_map<uint64_t, std::unordered_set<Address>> del_sets;`
- `category/execution/monad/staking/fuzzer/staking_contract_machine.cpp:547` — `std::unordered_map<Address, std::unordered_set<uint64_t>> val_sets;`
- `category/execution/ethereum/state2/block_state.hpp:38` — `using SelfDestructStorageReads = ankerl::unordered_dense::segmented_map<`
- `category/execution/ethereum/state2/block_state.hpp:39` — `Address, ankerl::unordered_dense::segmented_set<bytes32_t>>;`
- `category/execution/ethereum/state2/block_state.cpp:196` — `ankerl::unordered_dense::segmented_set<bytes32_t> code_hashes;`
- `category/execution/ethereum/state2/proposal_post_state.hpp:37` — `ankerl::unordered_dense::segmented_map<Address, std::optional<Account>>;`
- `category/execution/ethereum/state2/proposal_post_state.hpp:45` — `using StoragePostState = ankerl::unordered_dense::segmented_map<`
- `category/execution/ethereum/trace/state_tracer_test.cpp:2216` — `ankerl::unordered_dense::segmented_set<Address> const empty_neighbours;`
- `category/execution/ethereum/trace/state_tracer_test.cpp:2219` — `ankerl::unordered_dense::segmented_set<Address> senders_and_authorities;`
- `category/execution/ethereum/trace/state_tracer.hpp:40` — `using Map = ankerl::unordered_dense::segmented_map<Key, Elem>;`
- `category/execution/ethereum/trace/state_tracer.hpp:43` — `using Set = ankerl::unordered_dense::set<Key>;`
- `category/execution/ethereum/test/test_monad_chain.cpp:252` — `ankerl::unordered_dense::segmented_set<Address>`
- `category/execution/ethereum/test/test_monad_chain.cpp:257` — `ankerl::unordered_dense::segmented_set<Address>`
- `category/execution/ethereum/test/test_monad_chain.cpp:262` — `ankerl::unordered_dense::segmented_set<Address> const`
- `category/execution/ethereum/test/test_monad_chain.cpp:427` — `ankerl::unordered_dense::segmented_set<Address> const`
- `category/execution/ethereum/test/test_monad_chain.cpp:429` — `ankerl::unordered_dense::segmented_set<Address>`
- `category/execution/ethereum/test/test_monad_chain.cpp:434` — `ankerl::unordered_dense::segmented_set<Address> senders_and_authorities;`
- `category/execution/ethereum/test/test_monad_chain.cpp:559` — `ankerl::unordered_dense::segmented_set<Address> const`
- `category/execution/ethereum/test/test_monad_chain.cpp:561` — `ankerl::unordered_dense::segmented_set<Address> const`
- `category/execution/ethereum/test/test_monad_chain.cpp:566` — `ankerl::unordered_dense::segmented_set<Address> const`
- `category/execution/ethereum/test/test_monad_chain.cpp:583` — `ankerl::unordered_dense::segmented_set<Address> const`
- `category/execution/ethereum/test/test_monad_chain.cpp:585` — `ankerl::unordered_dense::segmented_set<Address> const`
- `category/execution/ethereum/test/test_monad_chain.cpp:590` — `ankerl::unordered_dense::segmented_set<Address> const`
- `category/execution/ethereum/test/test_monad_chain.cpp:638` — `ankerl::unordered_dense::segmented_set<Address> const`
- `category/execution/ethereum/test/test_monad_chain.cpp:640` — `ankerl::unordered_dense::segmented_set<Address> const`
- `category/execution/ethereum/test/test_monad_chain.cpp:644` — `ankerl::unordered_dense::segmented_set<Address> senders_and_authorities;`
- `category/execution/ethereum/test/test_monad_chain.cpp:717` — `ankerl::unordered_dense::segmented_set<Address> const`
- `category/execution/ethereum/test/test_monad_chain.cpp:719` — `ankerl::unordered_dense::segmented_set<Address> const`
- `category/execution/ethereum/test/test_monad_chain.cpp:723` — `ankerl::unordered_dense::segmented_set<Address> senders_and_authorities;`
- `category/execution/ethereum/test/test_monad_chain.cpp:788` — `ankerl::unordered_dense::segmented_set<Address> const`
