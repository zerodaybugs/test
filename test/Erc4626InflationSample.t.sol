// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

// =============================================================================
// PUBLIC SAMPLE: ERC-4626 inflation / donation-attack + share-conservation harness.
// =============================================================================
//
// This is a sanitized, standalone sample from a negative-control-validated
// invariant test library. It demonstrates ONE thing: how a harness proves it
// can actually detect an accounting bug, instead of just printing "tests pass".
//
// THE METHODOLOGY (negative control):
//   - A VULNERABLE reference vault, deliberately built to be exploitable, must
//     FAIL the invariant. If it does not fail, the harness is blind and the
//     "pass" on real code is worthless.
//   - A DEFENDED reference vault, built correctly, must PASS the same invariant
//     under the same attack. If it fails, the invariant is too strict (a false
//     positive generator).
//   - Only when the vulnerable ref FAILS and the defended ref PASSES is the
//     harness proven to detect THIS bug class as signal, not noise.
//
// HOW A REAL ENGAGEMENT USES THIS:
//   Swap the DefendedVault reference for the real target vault behind the IVault
//   adapter (or fork-deploy it), then run the same invariant. A normal depositor
//   receiving 0 shares, or a profitable deposit->redeem round-trip, is a shrunk,
//   executable counterexample -> a candidate finding.
//
// PUBLIC PRECEDENT (why this bug class matters):
//   The ERC-4626 "first-depositor / donation inflation" attack is well documented:
//   deposit 1 wei to mint 1 share, then donate underlying directly to the vault so
//   totalAssets() inflates without minting shares; the next real depositor's share
//   amount rounds down to 0 and their deposit is captured. The enabler is always
//   the same: totalAssets() reads the raw asset balance AND some path increases
//   that balance without minting shares, with no virtual-offset / minimum-shares
//   guard. OpenZeppelin's virtual shares/assets offset is the standard mitigation
//   and is what the DefendedVault below implements.
//
// This sample uses only forge-std. No external dependencies, no client data.

import "forge-std/Test.sol";

/// Minimal ERC20 (test double; not production-safe by design).
contract MockERC20 {
    string public name;
    uint8 public decimals;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    uint256 public totalSupply;

    constructor(string memory n, uint8 d) {
        name = n;
        decimals = d;
    }

    function mint(address to, uint256 a) external {
        balanceOf[to] += a;
        totalSupply += a;
    }

    function approve(address s, uint256 a) external returns (bool) {
        allowance[msg.sender][s] = a;
        return true;
    }

    function transfer(address to, uint256 a) external returns (bool) {
        _t(msg.sender, to, a);
        return true;
    }

    function transferFrom(address f, address to, uint256 a) external returns (bool) {
        uint256 al = allowance[f][msg.sender];
        if (al != type(uint256).max) allowance[f][msg.sender] = al - a;
        _t(f, to, a);
        return true;
    }

    function _t(address f, address to, uint256 a) internal {
        balanceOf[f] -= a;
        balanceOf[to] += a;
    }
}

/// The adapter the harness targets. In a real engagement the target vault is
/// driven through this interface (or fork-deployed and called directly).
interface IVault {
    function deposit(uint256 assets, address receiver) external returns (uint256 shares);
    function redeem(uint256 shares, address receiver, address owner) external returns (uint256 assets);
    function totalAssets() external view returns (uint256);
    function totalSupply() external view returns (uint256);
    function balanceOf(address) external view returns (uint256);
    function convertToShares(uint256) external view returns (uint256);
    function convertToAssets(uint256) external view returns (uint256);
}

/// VULNERABLE reference: totalAssets() == asset.balanceOf(this), no virtual
/// offset. A direct token transfer to the vault inflates the price-per-share.
/// This contract exists ONLY to prove the harness can catch the bug.
contract VulnerableVault is IVault {
    MockERC20 public asset;
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;

    constructor(MockERC20 a) {
        asset = a;
    }

    function totalAssets() public view returns (uint256) {
        return asset.balanceOf(address(this)); // donation-inflatable
    }

    function convertToShares(uint256 assets) public view returns (uint256) {
        uint256 ts = totalSupply;
        uint256 ta = totalAssets();
        return (ts == 0 || ta == 0) ? assets : (assets * ts) / ta; // round down, no offset
    }

    function convertToAssets(uint256 shares) public view returns (uint256) {
        uint256 ts = totalSupply;
        return ts == 0 ? shares : (shares * totalAssets()) / ts;
    }

    function deposit(uint256 assets, address receiver) external returns (uint256 shares) {
        shares = convertToShares(assets);
        asset.transferFrom(msg.sender, address(this), assets);
        balanceOf[receiver] += shares;
        totalSupply += shares;
    }

    function redeem(uint256 shares, address receiver, address owner) external returns (uint256 assets) {
        assets = convertToAssets(shares);
        balanceOf[owner] -= shares;
        totalSupply -= shares;
        asset.transfer(receiver, assets);
    }
}

/// DEFENDED reference: OpenZeppelin-style virtual shares/assets offset
/// (decimals offset = 6 -> +1e6 virtual shares, +1 virtual asset). This is a
/// correct mitigation; the SAME attack must NOT round the victim to 0 shares.
contract DefendedVault is IVault {
    MockERC20 public asset;
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;
    uint256 constant OFFSET = 1e6; // virtual shares/assets

    constructor(MockERC20 a) {
        asset = a;
    }

    function totalAssets() public view returns (uint256) {
        return asset.balanceOf(address(this));
    }

    function convertToShares(uint256 assets) public view returns (uint256) {
        return (assets * (totalSupply + OFFSET)) / (totalAssets() + 1);
    }

    function convertToAssets(uint256 shares) public view returns (uint256) {
        return (shares * (totalAssets() + 1)) / (totalSupply + OFFSET);
    }

    function deposit(uint256 assets, address receiver) external returns (uint256 shares) {
        shares = convertToShares(assets);
        asset.transferFrom(msg.sender, address(this), assets);
        balanceOf[receiver] += shares;
        totalSupply += shares;
    }

    function redeem(uint256 shares, address receiver, address owner) external returns (uint256 assets) {
        assets = convertToAssets(shares);
        balanceOf[owner] -= shares;
        totalSupply -= shares;
        asset.transfer(receiver, assets);
    }
}

contract Erc4626InflationSample is Test {
    MockERC20 usdc;
    address attacker = address(0xA11CE);
    address victim = address(0x1C71);

    function setUp() public {
        usdc = new MockERC20("USDC", 6);
        usdc.mint(attacker, 2_000e6);
        usdc.mint(victim, 1_000e6);
    }

    /// The inflation attack, parameterized over any IVault:
    /// deposit 1 wei -> donate to inflate totalAssets -> victim's shares round to 0.
    function _runAttack(IVault vault) internal returns (uint256 victimShares) {
        vm.startPrank(attacker);
        usdc.approve(address(vault), type(uint256).max);
        vault.deposit(1, attacker); // 1 wei -> 1 share
        usdc.transfer(address(vault), 1_000e6); // DONATION: inflate totalAssets, mint no shares
        vm.stopPrank();

        vm.startPrank(victim);
        usdc.approve(address(vault), type(uint256).max);
        victimShares = vault.deposit(500e6, victim); // rounds to 0 on the vulnerable vault
        vm.stopPrank();
    }

    /// NEGATIVE CONTROL: the VULNERABLE vault MUST be exploitable.
    /// If this ever passes (victim shares > 0), the harness has gone blind and
    /// every "green" result on real code is meaningless.
    function test_negControl_vulnerableVaultIsExploitable() public {
        VulnerableVault v = new VulnerableVault(usdc);
        uint256 vs = _runAttack(v);
        assertEq(vs, 0, "negative-control: vulnerable vault should round victim shares to 0 (attack works)");
    }

    /// THE INVARIANT (this is what you run against the REAL vault):
    /// a normal depositor must NEVER receive 0 shares.
    function test_invariant_defendedVaultResistsInflation() public {
        DefendedVault v = new DefendedVault(usdc);
        uint256 vs = _runAttack(v);
        assertGt(vs, 0, "victim received 0 shares -> INFLATION/DONATION ATTACK");
    }

    /// SHARE-CONSERVATION (fuzz): no deposit-then-redeem round-trip profit on the
    /// defended vault. A profitable round-trip means the vault leaks value.
    function testFuzz_noRoundTripProfit(uint256 amt) public {
        DefendedVault v = new DefendedVault(usdc);
        vm.startPrank(attacker);
        usdc.approve(address(v), type(uint256).max);
        v.deposit(1000e6, attacker);
        vm.stopPrank();

        amt = bound(amt, 1e6, 500e6);
        usdc.mint(victim, amt);

        vm.startPrank(victim);
        usdc.approve(address(v), type(uint256).max);
        uint256 balBefore = usdc.balanceOf(victim);
        uint256 sh = v.deposit(amt, victim);
        uint256 got = v.redeem(sh, victim, victim);
        vm.stopPrank();

        assertLe(got, amt, "round-trip returned more than deposited (vault drain)");
        assertLe(usdc.balanceOf(victim), balBefore, "victim net-positive on round-trip (value leak)");
    }
}
