#!/usr/bin/env python3
from pathlib import Path
import argparse


def render_fuzzer(original: str, revision: str) -> str:
    page = "true" if revision == "MONAD_TEN" else "false"
    s = original
    s = s.replace(
        "#include <category/execution/ethereum/chain/ethereum_mainnet.hpp>",
        "#include <category/execution/monad/chain/monad_mainnet.hpp>\n"
        "#include <category/vm/evm/monad/revision.h>\n"
        "#include <category/vm/evm/traits.hpp>",
        1,
    )
    marker = "using monad::vm::compiler::native::CompilerConfig;\n"
    insert = marker + (
        f"\nstatic constexpr monad_revision MONAD_FUZZ_REVISION = {revision};\n"
        f"static constexpr bool MONAD_FUZZ_PAGE_ENCODED = {page};\n"
    )
    if marker not in s:
        raise SystemExit("compiler config marker missing")
    s = s.replace(marker, insert, 1)
    s = s.replace(
        "monad::test::TestState<false> test_state = {};",
        "monad::test::TestState<MONAD_FUZZ_PAGE_ENCODED> test_state = {};",
        1,
    )
    s = s.replace("EthereumMainnet const chain{};", "MonadMainnet const chain{};", 1)
    old = (
        "    MONAD_ASSERT(rev == MONAD_ETH_OSAKA); // TODO switch to monad revisions\n"
        "    using traits = EvmTraits<MONAD_ETH_OSAKA>;"
    )
    new = (
        "    MONAD_ASSERT(rev == MonadTraits<MONAD_FUZZ_REVISION>::evm_rev());\n"
        "    using traits = MonadTraits<MONAD_FUZZ_REVISION>;"
    )
    if old not in s:
        raise SystemExit("transition marker missing")
    s = s.replace(old, new, 1)

    start = s.index("    auto evmone_vm = evmc::VM(evmc_create_evmone());")
    end = s.index("    auto monad_state = [&] {", start)
    s = s[:start] + (
        "    auto evmone_state =\n"
        "        std::make_shared<FuzzerTestState>(vm::VM::InterpreterOnly);\n\n"
    ) + s[end:]

    old_config = "            s->vm.set_compiler_config(create_compiler_config(engine));"
    new_config = (
        "            if (std::getenv(\"MONAD_FUZZ_NO_HOOK\") != nullptr) {\n"
        "                s->vm.set_compiler_config(CompilerConfig{\n"
        "                    .runtime_debug_trace =\n"
        "                        vm::utils::is_compiler_runtime_debug_trace_enabled,\n"
        "                    .max_code_size_offset =\n"
        "                        vm::interpreter::code_size_t::max(),\n"
        "                    .post_instruction_emit_hook = {},\n"
        "                });\n"
        "            }\n"
        "            else {\n"
        "                s->vm.set_compiler_config(create_compiler_config(engine));\n"
        "            }"
    )
    if old_config not in s:
        raise SystemExit("compiler setup marker missing")
    s = s.replace(old_config, new_config, 1)

    diag = r'''
static std::vector<uint8_t> monad_diag_contract;
static std::vector<uint8_t> monad_diag_input;
static evmc_message monad_diag_message{};
static BlockHeader monad_diag_header{};
static uint64_t monad_diag_seed{};
static int64_t monad_diag_iteration{-1};
static int64_t monad_diag_message_index{-1};

static void monad_diag_hex(uint8_t const *data, size_t size)
{
    static constexpr char h[] = "0123456789abcdef";
    for (size_t i = 0; i < size; ++i) {
        std::fputc(h[data[i] >> 4], stderr);
        std::fputc(h[data[i] & 0x0f], stderr);
    }
}

static void monad_diag_address(evmc_address const &a)
{
    monad_diag_hex(a.bytes, sizeof(a.bytes));
}

void monad_fuzz_dump_context()
{
    std::fprintf(stderr,
        "DIAG_CONTEXT seed=%llu iteration=%lld message=%lld kind=%d flags=%u depth=%d gas=%lld block=%llu timestamp=%llu contract_size=%zu input_size=%zu\\n",
        static_cast<unsigned long long>(monad_diag_seed),
        static_cast<long long>(monad_diag_iteration),
        static_cast<long long>(monad_diag_message_index),
        static_cast<int>(monad_diag_message.kind),
        static_cast<unsigned>(monad_diag_message.flags),
        static_cast<int>(monad_diag_message.depth),
        static_cast<long long>(monad_diag_message.gas),
        static_cast<unsigned long long>(monad_diag_header.number),
        static_cast<unsigned long long>(monad_diag_header.timestamp),
        monad_diag_contract.size(), monad_diag_input.size());
    std::fputs("DIAG_SENDER=", stderr);
    monad_diag_address(monad_diag_message.sender);
    std::fputs("\\nDIAG_RECIPIENT=", stderr);
    monad_diag_address(monad_diag_message.recipient);
    std::fputs("\\nDIAG_CODE_ADDRESS=", stderr);
    monad_diag_address(monad_diag_message.code_address);
    std::fputs("\\nDIAG_VALUE=", stderr);
    monad_diag_hex(monad_diag_message.value.bytes, sizeof(monad_diag_message.value.bytes));
    std::fputs("\\nDIAG_CONTRACT=", stderr);
    monad_diag_hex(monad_diag_contract.data(), monad_diag_contract.size());
    std::fputs("\\nDIAG_INPUT=", stderr);
    monad_diag_hex(monad_diag_input.data(), monad_diag_input.size());
    std::fputs("\\nDIAG_CONTEXT_END\\n", stderr);
    std::fflush(stderr);
}
'''
    insertion_point = s.index("struct FuzzerTestState")
    s = s[:insertion_point] + diag + "\n" + s[insertion_point:]

    old_run = (
        "static void do_run(\n"
        "    monad::vm::MemoryPool &memory_pool, std::size_t const run_index,\n"
        "    arguments const &args)\n"
        "{\n"
        "    auto const rev = args.revision;"
    )
    if old_run not in s:
        raise SystemExit("do_run marker missing")
    s = s.replace(old_run, old_run + "\n    monad_diag_seed = args.seed;", 1)

    loop_marker = "    for (auto i = 0; i < args.iterations_per_run; ++i) {\n        TimeoutWaitThread timeout_wait_thread;"
    if loop_marker not in s:
        raise SystemExit("iteration marker missing")
    s = s.replace(
        loop_marker,
        "    for (auto i = 0; i < args.iterations_per_run; ++i) {\n"
        "        monad_diag_iteration = i;\n"
        "        TimeoutWaitThread timeout_wait_thread;",
        1,
    )

    deploy_marker = (
        "            auto const a = deploy_contracts(\n"
        "                evmone_state, monad_state, contract, block_counter.next());"
    )
    if deploy_marker not in s:
        raise SystemExit("deploy marker missing")
    s = s.replace(
        deploy_marker,
        "            monad_diag_contract.assign(contract.begin(), contract.end());\n" + deploy_marker,
        1,
    )

    msg_marker = "        for (auto j = 0u; j < args.messages; ++j) {\n            auto msg_memory = memory_pool.alloc_ref();"
    if msg_marker not in s:
        raise SystemExit("message-loop marker missing")
    s = s.replace(
        msg_marker,
        "        for (auto j = 0u; j < args.messages; ++j) {\n"
        "            monad_diag_message_index = static_cast<int64_t>(j);\n"
        "            auto msg_memory = memory_pool.alloc_ref();",
        1,
    )

    header_marker = (
        "            auto const block_header =\n"
        "                generate_block_header(engine, block_counter.next());"
    )
    if header_marker not in s:
        raise SystemExit("block-header marker missing")
    s = s.replace(
        header_marker,
        "            monad_diag_message = *msg;\n"
        "            monad_diag_input.assign(msg->input_data, msg->input_data + msg->input_size);\n"
        + header_marker
        + "\n            monad_diag_header = block_header;",
        1,
    )
    return s


def patch_assertions(s: str) -> str:
    s = s.replace(
        "#include <algorithm>\n",
        "#include <algorithm>\n#include <cstdio>\n#include <cstdlib>\n",
        1,
    )
    marker = "namespace monad::vm::fuzzing\n{\n"
    if marker not in s:
        raise SystemExit("assertions namespace marker missing")
    s = s.replace("namespace monad::vm::fuzzing\n", "extern void monad_fuzz_dump_context();\n\nnamespace monad::vm::fuzzing\n", 1)
    helper = r'''
    static void diag_address(char const *label, Address const &a)
    {
        static constexpr char h[] = "0123456789abcdef";
        std::fputs(label, stderr);
        for (auto const b : a.bytes) {
            std::fputc(h[b >> 4], stderr);
            std::fputc(h[b & 0x0f], stderr);
        }
        std::fputc('\n', stderr);
    }

    static void diag_account(char const *prefix, Address const &k, AccountState const &as)
    {
        diag_address(prefix, k);
        std::fprintf(stderr,
            "DIAG_ACCOUNT has=%d nonce=%llu storage=%zu transient=%zu touched=%d destructed=%d\\n",
            as.has_account() ? 1 : 0,
            static_cast<unsigned long long>(as.get_nonce()),
            as.storage_.size(), as.transient_storage_.size(),
            as.is_touched() ? 1 : 0,
            as.is_destructed() ? 1 : 0);
    }

    [[noreturn]] static void diag_abort(State &a, State &b)
    {
        std::fprintf(stderr, "DIAG_STATE_MAP_SIZE interpreter=%zu compiler=%zu\\n",
            a.current().size(), b.current().size());
        for (auto const &[k, v] : a.current()) {
            if (b.current().find(k) == b.current().end()) {
                diag_account("DIAG_ONLY_INTERPRETER=", k, v.recent());
            }
        }
        for (auto const &[k, v] : b.current()) {
            if (a.current().find(k) == a.current().end()) {
                diag_account("DIAG_ONLY_COMPILER=", k, v.recent());
            }
        }
        ::monad_fuzz_dump_context();
        std::fflush(stderr);
        std::abort();
    }

'''
    s = s.replace(marker, marker + helper, 1)
    old = "        MONAD_ASSERT(a.current().size() == b.current().size());"
    if s.count(old) != 1:
        raise SystemExit(f"state-size assertion count={s.count(old)}")
    s = s.replace(old, "        if (a.current().size() != b.current().size()) { diag_abort(a, b); }", 1)
    return s


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    src = Path(args.source)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    fuzzer = (src / "test/vm/fuzzer/fuzzer.cpp").read_text()
    assertions_path = src / "test/vm/fuzzer/assertions.cpp"
    assertions = assertions_path.read_text()
    (out / "fuzzer.MONAD_NINE.cpp").write_text(render_fuzzer(fuzzer, "MONAD_NINE"))
    (out / "fuzzer.MONAD_TEN.cpp").write_text(render_fuzzer(fuzzer, "MONAD_TEN"))
    assertions_path.write_text(patch_assertions(assertions))


if __name__ == "__main__":
    main()
