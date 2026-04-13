# 2021 DeFi Security Incidents

DeFi's explosive growth brought a surge of flash loan attacks, oracle manipulation, and K-invariant bypasses across BSC and Ethereum. This year saw 34 incidents as protocols like PancakeBunny, Rari Capital, and Cream Finance were exploited.

**Total incidents: 34**

---

## Top Vulnerability Types

| Type | Count |
|------|-------|
| yDAI CurvePoolImbalance | 1 |
| Network UnauthorizedMint | 1 |
| FlashLoan ReInit | 1 |
| Finance KInvariantMismatch | 1 |
| Protocol SpotBalanceLPCalc | 1 |
| AlpacaVault WorkReetrancy | 1 |
| FlashLoan OracleManipulation | 1 |
| ERC20 Reentrancy | 1 |
| BUSD DepositWithdrawLoop | 1 |
| FlashLoan AddBNB Manipulation | 1 |

---

## Incident List

| Date | Protocol | Vulnerability Type | Report |
|------|----------|--------------------|--------|
| 2021-02-04 | Yearn | yDAI CurvePoolImbalance | [2021-02-04_Yearn_yDAI_CurvePoolImbalance.md](./2021-02-04_Yearn_yDAI_CurvePoolImbalance.md) |
| 2021-03-07 | PAID | Network UnauthorizedMint | [2021-03-07_PAID_Network_UnauthorizedMint.md](./2021-03-07_PAID_Network_UnauthorizedMint.md) |
| 2021-03-09 | DODO | FlashLoan ReInit | [2021-03-09_DODO_FlashLoan_ReInit.md](./2021-03-09_DODO_FlashLoan_ReInit.md) |
| 2021-04-28 | Uranium | Finance KInvariantMismatch | [2021-04-28_Uranium_Finance_KInvariantMismatch.md](./2021-04-28_Uranium_Finance_KInvariantMismatch.md) |
| 2021-05-02 | Spartan | Protocol SpotBalanceLPCalc | [2021-05-02_Spartan_Protocol_SpotBalanceLPCalc.md](./2021-05-02_Spartan_Protocol_SpotBalanceLPCalc.md) |
| 2021-05-05 | ValueDeFi | AlpacaVault WorkReetrancy | [2021-05-05_ValueDeFi_AlpacaVault_WorkReetrancy.md](./2021-05-05_ValueDeFi_AlpacaVault_WorkReetrancy.md) |
| 2021-05-06 | PancakeBunny | FlashLoan OracleManipulation | [2021-05-06_PancakeBunny_FlashLoan_OracleManipulation.md](./2021-05-06_PancakeBunny_FlashLoan_OracleManipulation.md) |
| 2021-05-08 | RariCapital | ERC20 Reentrancy | [2021-05-08_RariCapital_ERC20_Reentrancy.md](./2021-05-08_RariCapital_ERC20_Reentrancy.md) |
| 2021-05-16 | bEarn | BUSD DepositWithdrawLoop | [2021-05-16_bEarn_BUSD_DepositWithdrawLoop.md](./2021-05-16_bEarn_BUSD_DepositWithdrawLoop.md) |
| 2021-05-21 | JulSwap | FlashLoan AddBNB Manipulation | [2021-05-21_JulSwap_FlashLoan_AddBNB_Manipulation.md](./2021-05-21_JulSwap_FlashLoan_AddBNB_Manipulation.md) |
| 2021-05-28 | BurgerSwap | Reentrancy StaleReserves | [2021-05-28_BurgerSwap_Reentrancy_StaleReserves.md](./2021-05-28_BurgerSwap_Reentrancy_StaleReserves.md) |
| 2021-06-02 | PancakeHunny | BalanceOf MintManipulation | [2021-06-02_PancakeHunny_BalanceOf_MintManipulation.md](./2021-06-02_PancakeHunny_BalanceOf_MintManipulation.md) |
| 2021-06-21 | ElevenFinance | EmergencyBurn NoWithdraw | [2021-06-21_ElevenFinance_EmergencyBurn_NoWithdraw.md](./2021-06-21_ElevenFinance_EmergencyBurn_NoWithdraw.md) |
| 2021-06-23 | 88mph | UnprotectedInit | [2021-06-23_88mph_UnprotectedInit.md](./2021-06-23_88mph_UnprotectedInit.md) |
| 2021-06-26 | xWin | SlippageControl Bypass | [2021-06-26_xWin_SlippageControl_Bypass.md](./2021-06-26_xWin_SlippageControl_Bypass.md) |
| 2021-06-28 | SafeDollar | SDO FlashSwapReward | [2021-06-28_SafeDollar_SDO_FlashSwapReward.md](./2021-06-28_SafeDollar_SDO_FlashSwapReward.md) |
| 2021-07-10 | Chainswap | ETH SignatureReuse | [2021-07-10_Chainswap_ETH_SignatureReuse.md](./2021-07-10_Chainswap_ETH_SignatureReuse.md) |
| 2021-07-20 | Levyathan | PrivateKeyLeak MintOwnership | [2021-07-20_Levyathan_PrivateKeyLeak_MintOwnership.md](./2021-07-20_Levyathan_PrivateKeyLeak_MintOwnership.md) |
| 2021-08-10 | PolyNetwork | CrossChain AccessControl | [2021-08-10_PolyNetwork_CrossChain_AccessControl.md](./2021-08-10_PolyNetwork_CrossChain_AccessControl.md) |
| 2021-08-16 | XSURGE | Sell Reentrancy | [2021-08-16_XSURGE_Sell_Reentrancy.md](./2021-08-16_XSURGE_Sell_Reentrancy.md) |
| 2021-08-27 | WaultFinance | WUSD PriceManipulation | [2021-08-27_WaultFinance_WUSD_PriceManipulation.md](./2021-08-27_WaultFinance_WUSD_PriceManipulation.md) |
| 2021-09-04 | DaoMaker | UnprotectedInit EmergencyExit | [2021-09-04_DaoMaker_UnprotectedInit_EmergencyExit.md](./2021-09-04_DaoMaker_UnprotectedInit_EmergencyExit.md) |
| 2021-09-14 | NowSwap | DutchAuction BatchReentrancy | [2021-09-14_NowSwap_DutchAuction_BatchReentrancy.md](./2021-09-14_NowSwap_DutchAuction_BatchReentrancy.md) |
| 2021-09-17 | SushiMiso | DutchAuction AccessControl | [2021-09-17_SushiMiso_DutchAuction_AccessControl.md](./2021-09-17_SushiMiso_DutchAuction_AccessControl.md) |
| 2021-09-21 | Nimbus | KInvariant 1000vs10000 | [2021-09-21_Nimbus_KInvariant_1000vs10000.md](./2021-09-21_Nimbus_KInvariant_1000vs10000.md) |
| 2021-09-27 | ZABU | FlashSwap FarmReward Drain | [2021-09-27_ZABU_FlashSwap_FarmReward_Drain.md](./2021-09-27_ZABU_FlashSwap_FarmReward_Drain.md) |
| 2021-10-15 | IndexedFinance | ReweightManipulation | [2021-10-15_IndexedFinance_ReweightManipulation.md](./2021-10-15_IndexedFinance_ReweightManipulation.md) |
| 2021-10-27 | Cream | Finance2 OracleManipulation RecursiveBorrow | [2021-10-27_Cream_Finance2_OracleManipulation_RecursiveBorrow.md](./2021-10-27_Cream_Finance2_OracleManipulation_RecursiveBorrow.md) |
| 2021-11-04 | Ploutoz | DOP FlashLoan OracleManipulation | [2021-11-04_Ploutoz_DOP_FlashLoan_OracleManipulation.md](./2021-11-04_Ploutoz_DOP_FlashLoan_OracleManipulation.md) |
| 2021-11-30 | MonoSwap | SelfSwap PriceManipulation | [2021-11-30_MonoSwap_SelfSwap_PriceManipulation.md](./2021-11-30_MonoSwap_SelfSwap_PriceManipulation.md) |
| 2021-11-30 | MonoX | SwapPriceManipulation | [2021-11-30_MonoX_SwapPriceManipulation.md](./2021-11-30_MonoX_SwapPriceManipulation.md) |
| 2021-12-18 | Grim | Finance Reentrancy DepositFor | [2021-12-18_Grim_Finance_Reentrancy_DepositFor.md](./2021-12-18_Grim_Finance_Reentrancy_DepositFor.md) |
| 2021-12-21 | NerveBridge | MetaSwap PriceManipulation | [2021-12-21_NerveBridge_MetaSwap_PriceManipulation.md](./2021-12-21_NerveBridge_MetaSwap_PriceManipulation.md) |
| 2021-12-21 | Visor | Finance DepositUnprotected | [2021-12-21_Visor_Finance_DepositUnprotected.md](./2021-12-21_Visor_Finance_DepositUnprotected.md) |

---

[← Back to main index](../README.md)
