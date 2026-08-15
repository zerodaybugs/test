#!/usr/bin/env python3
from pathlib import Path

path = Path("src/aave-core/tests/aave-logic/liquidation_logic_tests.move")
source = path.read_text()
function_name = "fun test_liquidation_when_has_no_collateral_left_and_user_has_borrowing_any"
function_start = source.index(function_name)
next_test = source.find("\n    #[", function_start + 1)
function_end = len(source) if next_test < 0 else next_test
prefix = source[:function_start]
body = source[function_start:function_end]
suffix = source[function_end:]

before_anchor = (
    "        let (\n"
    "            _, u1_current_variable_debt_before, _, _, _\n"
    "        ) =\n"
    "            pool_data_provider::get_user_reserve_data(\n"
    "                underlying_u1_token_address, borrower_address\n"
    "            );\n"
)
before_insert = before_anchor + (
    "\n"
    "        let (\n"
    "            _, u0_current_variable_debt_before, _, _, _\n"
    "        ) =\n"
    "            pool_data_provider::get_user_reserve_data(\n"
    "                underlying_u0_token_address, borrower_address\n"
    "            );\n"
    "        let u0_deficit_before =\n"
    "            pool::get_reserve_deficit(\n"
    "                pool::get_reserve_data(underlying_u0_token_address)\n"
    "            );\n"
    "        let u1_deficit_before =\n"
    "            pool::get_reserve_deficit(\n"
    "                pool::get_reserve_data(underlying_u1_token_address)\n"
    "            );\n"
    "        let liquidator_u1_balance_before =\n"
    "            (mock_underlying_token_factory::balance_of(\n"
    "                liquidator_address, underlying_u1_token_address\n"
    "            ) as u256);\n"
)
if body.count(before_anchor) != 1:
    raise RuntimeError("before-anchor mismatch")
body = body.replace(before_anchor, before_insert, 1)

after_anchor = (
    "        let (\n"
    "            _, u1_current_variable_debt_after, _, _, _\n"
    "        ) =\n"
    "            pool_data_provider::get_user_reserve_data(\n"
    "                underlying_u1_token_address, borrower_address\n"
    "            );\n"
)
after_insert = after_anchor + (
    "\n"
    "        let (\n"
    "            _, u0_current_variable_debt_after, _, _, _\n"
    "        ) =\n"
    "            pool_data_provider::get_user_reserve_data(\n"
    "                underlying_u0_token_address, borrower_address\n"
    "            );\n"
    "        let u0_deficit_after =\n"
    "            pool::get_reserve_deficit(\n"
    "                pool::get_reserve_data(underlying_u0_token_address)\n"
    "            );\n"
    "        let u1_deficit_after =\n"
    "            pool::get_reserve_deficit(\n"
    "                pool::get_reserve_data(underlying_u1_token_address)\n"
    "            );\n"
    "        let liquidator_u1_balance_after =\n"
    "            (mock_underlying_token_factory::balance_of(\n"
    "                liquidator_address, underlying_u1_token_address\n"
    "            ) as u256);\n"
    "        let actual_u1_debt_paid =\n"
    "            liquidator_u1_balance_before - liquidator_u1_balance_after;\n"
    "        let final_user_config = pool::get_user_configuration(borrower_address);\n"
)
if body.count(after_anchor) != 1:
    raise RuntimeError("after-anchor mismatch")
body = body.replace(after_anchor, after_insert, 1)

final_anchor = (
    "        assert!(u1_current_variable_debt_after == 0, TEST_SUCCESS);\n"
    "        assert!(u2_current_variable_debt_before == 0, TEST_SUCCESS);\n"
)
final_insert = (
    "        assert!(u1_current_variable_debt_after == 0, TEST_SUCCESS);\n"
    "        assert!(u0_current_variable_debt_after == 0, TEST_SUCCESS);\n"
    "        assert!(actual_u1_debt_paid <= u1_current_variable_debt_before, TEST_SUCCESS);\n"
    "        assert!(\n"
    "            u1_deficit_after\n"
    "                == u1_deficit_before\n"
    "                    + ((u1_current_variable_debt_before - actual_u1_debt_paid) as u128),\n"
    "            TEST_SUCCESS\n"
    "        );\n"
    "        assert!(\n"
    "            u0_deficit_after\n"
    "                == u0_deficit_before + (u0_current_variable_debt_before as u128),\n"
    "            TEST_SUCCESS\n"
    "        );\n"
    "        assert!(!user_config::is_borrowing_any(&final_user_config), TEST_SUCCESS);\n"
    "        assert!(u2_current_variable_debt_before == 0, TEST_SUCCESS);\n"
)
if body.count(final_anchor) != 1:
    raise RuntimeError("final-anchor mismatch")
body = body.replace(final_anchor, final_insert, 1)
path.write_text(prefix + body + suffix)
