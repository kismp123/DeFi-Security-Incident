# 2022 DeFi Security Incidents

The year of bridge hacks and cross-chain exploits. Ronin ($625M), Wormhole ($320M), and Nomad ($190M) were among the largest DeFi losses in history. Signature replay and oracle manipulation also dominated.

**Total incidents: 135**

---

## Top Vulnerability Types

| Type | Count |
|------|-------|
| SkimSyncPriceManipulation | 2 |
| OracleManipulationBorrow | 2 |
| SkimReserveManipulation | 2 |
| StakingRewardManipulation | 2 |
| PermitSignatureReplay | 1 |
| DepositZeroAddressWhitelist | 1 |
| BridgeNativeTokenConfusion | 1 |
| NFTBurnAccessControl | 1 |
| GovernanceAttack | 1 |
| BurnFromPriceManipulation | 1 |

---

## Incident List

| Date | Protocol | Vulnerability Type | Report |
|------|----------|--------------------|--------|
| 2022-01-18 | Anyswap | PermitSignatureReplay | [2022-01-18_Anyswap_PermitSignatureReplay.md](./2022-01-18_Anyswap_PermitSignatureReplay.md) |
| 2022-01-28 | Qubit | DepositZeroAddressWhitelist | [2022-01-28_Qubit_DepositZeroAddressWhitelist.md](./2022-01-28_Qubit_DepositZeroAddressWhitelist.md) |
| 2022-02-06 | Meter | BridgeNativeTokenConfusion | [2022-02-06_Meter_BridgeNativeTokenConfusion.md](./2022-02-06_Meter_BridgeNativeTokenConfusion.md) |
| 2022-02-14 | Sandbox | NFTBurnAccessControl | [2022-02-14_Sandbox_NFTBurnAccessControl.md](./2022-02-14_Sandbox_NFTBurnAccessControl.md) |
| 2022-02-17 | BuildFinance | GovernanceAttack | [2022-02-17_BuildFinance_GovernanceAttack.md](./2022-02-17_BuildFinance_GovernanceAttack.md) |
| 2022-02-18 | TecraSpace | BurnFromPriceManipulation | [2022-02-18_TecraSpace_BurnFromPriceManipulation.md](./2022-02-18_TecraSpace_BurnFromPriceManipulation.md) |
| 2022-03-01 | Bacon | ERC1820ReentrancyFlashLoan | [2022-03-01_Bacon_ERC1820ReentrancyFlashLoan.md](./2022-03-01_Bacon_ERC1820ReentrancyFlashLoan.md) |
| 2022-03-03 | TreasureDAO | MarketplaceBuyItemFree | [2022-03-03_TreasureDAO_MarketplaceBuyItemFree.md](./2022-03-03_TreasureDAO_MarketplaceBuyItemFree.md) |
| 2022-03-06 | BaconProtocol | Reentrancy | [2022-03-06_BaconProtocol_Reentrancy.md](./2022-03-06_BaconProtocol_Reentrancy.md) |
| 2022-03-09 | Fantasm | DecimalErrorMinting | [2022-03-09_Fantasm_DecimalErrorMinting.md](./2022-03-09_Fantasm_DecimalErrorMinting.md) |
| 2022-03-13 | Paraluni | ReentrancyDepositLP | [2022-03-13_Paraluni_ReentrancyDepositLP.md](./2022-03-13_Paraluni_ReentrancyDepositLP.md) |
| 2022-03-14 | CompoundTUSD | SweepTokenUnauthorized | [2022-03-14_CompoundTUSD_SweepTokenUnauthorized.md](./2022-03-14_CompoundTUSD_SweepTokenUnauthorized.md) |
| 2022-03-15 | Agave | ERC667ReentrancyLending | [2022-03-15_Agave_ERC667ReentrancyLending.md](./2022-03-15_Agave_ERC667ReentrancyLending.md) |
| 2022-03-15 | HundredFinance | ERC677ReentrancyLending | [2022-03-15_HundredFinance_ERC677ReentrancyLending.md](./2022-03-15_HundredFinance_ERC677ReentrancyLending.md) |
| 2022-03-17 | Umbrella | StakingUnderflowDrain | [2022-03-17_Umbrella_StakingUnderflowDrain.md](./2022-03-17_Umbrella_StakingUnderflowDrain.md) |
| 2022-03-19 | RedactedCartel | TransferFromApprovalBug | [2022-03-19_RedactedCartel_TransferFromApprovalBug.md](./2022-03-19_RedactedCartel_TransferFromApprovalBug.md) |
| 2022-03-20 | LiFi | ArbitrarySwapCallExploit | [2022-03-20_LiFi_ArbitrarySwapCallExploit.md](./2022-03-20_LiFi_ArbitrarySwapCallExploit.md) |
| 2022-03-21 | OneRing | FlashLoanVaultPriceManipulation | [2022-03-21_OneRing_FlashLoanVaultPriceManipulation.md](./2022-03-21_OneRing_FlashLoanVaultPriceManipulation.md) |
| 2022-03-23 | Ronin | CompromisedValidatorSignatures | [2022-03-23_Ronin_CompromisedValidatorSignatures.md](./2022-03-23_Ronin_CompromisedValidatorSignatures.md) |
| 2022-03-27 | Revest | FNFTReentrancyMint | [2022-03-27_Revest_FNFTReentrancyMint.md](./2022-03-27_Revest_FNFTReentrancyMint.md) |
| 2022-03-28 | Auctus | ArbitraryCallTransferFrom | [2022-03-28_Auctus_ArbitraryCallTransferFrom.md](./2022-03-28_Auctus_ArbitraryCallTransferFrom.md) |
| 2022-04-03 | GymNetwork | MigrationExploit | [2022-04-03_GymNetwork_MigrationExploit.md](./2022-04-03_GymNetwork_MigrationExploit.md) |
| 2022-04-09 | Wdoge | SkimSyncPriceManipulation | [2022-04-09_Wdoge_SkimSyncPriceManipulation.md](./2022-04-09_Wdoge_SkimSyncPriceManipulation.md) |
| 2022-04-12 | ElephantMoney | FlashLoanMintRedeemArbitrage | [2022-04-12_ElephantMoney_FlashLoanMintRedeemArbitrage.md](./2022-04-12_ElephantMoney_FlashLoanMintRedeemArbitrage.md) |
| 2022-04-15 | Rikkei | OracleManipulationBorrow | [2022-04-15_Rikkei_OracleManipulationBorrow.md](./2022-04-15_Rikkei_OracleManipulationBorrow.md) |
| 2022-04-17 | Beanstalk | GovernanceFlashLoan | [2022-04-17_Beanstalk_GovernanceFlashLoan.md](./2022-04-17_Beanstalk_GovernanceFlashLoan.md) |
| 2022-04-19 | CFToken | PublicTransferDrain | [2022-04-19_CFToken_PublicTransferDrain.md](./2022-04-19_CFToken_PublicTransferDrain.md) |
| 2022-04-21 | Zeed | SkimRewardManipulation | [2022-04-21_Zeed_SkimRewardManipulation.md](./2022-04-21_Zeed_SkimRewardManipulation.md) |
| 2022-04-22 | AkutarNFT | RefundDoSFundsLocked | [2022-04-22_AkutarNFT_RefundDoSFundsLocked.md](./2022-04-22_AkutarNFT_RefundDoSFundsLocked.md) |
| 2022-04-28 | DeusFinance | OracleManipulationBorrow | [2022-04-28_DeusFinance_OracleManipulationBorrow.md](./2022-04-28_DeusFinance_OracleManipulationBorrow.md) |
| 2022-04-28 | Deus | OracleManipulation | [2022-04-28_Deus_OracleManipulation.md](./2022-04-28_Deus_OracleManipulation.md) |
| 2022-04-30 | GymNetwork1 | LiquidityMigrationExploit | [2022-04-30_GymNetwork1_LiquidityMigrationExploit.md](./2022-04-30_GymNetwork1_LiquidityMigrationExploit.md) |
| 2022-04-30 | Rari | ERC20ReentrancyCompound | [2022-04-30_Rari_ERC20ReentrancyCompound.md](./2022-04-30_Rari_ERC20ReentrancyCompound.md) |
| 2022-04-30 | Saddle | StableSwapArbitrage | [2022-04-30_Saddle_StableSwapArbitrage.md](./2022-04-30_Saddle_StableSwapArbitrage.md) |
| 2022-05-01 | BAYC | ApeCoinAirdropFlashLoan | [2022-05-01_BAYC_ApeCoinAirdropFlashLoan.md](./2022-05-01_BAYC_ApeCoinAirdropFlashLoan.md) |
| 2022-05-08 | FortressLoans | OraclePriceGovernanceAttack | [2022-05-08_FortressLoans_OraclePriceGovernanceAttack.md](./2022-05-08_FortressLoans_OraclePriceGovernanceAttack.md) |
| 2022-05-20 | Novo | TransferFromLPDrain | [2022-05-20_Novo_TransferFromLPDrain.md](./2022-05-20_Novo_TransferFromLPDrain.md) |
| 2022-05-26 | HackDao | SkimSyncPriceManipulation | [2022-05-26_HackDao_SkimSyncPriceManipulation.md](./2022-05-26_HackDao_SkimSyncPriceManipulation.md) |
| 2022-06-08 | Snood | TransferFromSyncDrain | [2022-06-08_Snood_TransferFromSyncDrain.md](./2022-06-08_Snood_TransferFromSyncDrain.md) |
| 2022-06-09 | Optimism | WintermuteVanityAddress | [2022-06-09_Optimism_WintermuteVanityAddress.md](./2022-06-09_Optimism_WintermuteVanityAddress.md) |
| 2022-06-15 | Discover | PledgeinFlashLoan | [2022-06-15_Discover_PledgeinFlashLoan.md](./2022-06-15_Discover_PledgeinFlashLoan.md) |
| 2022-06-16 | InverseFinance | CurveOracleManipulation | [2022-06-16_InverseFinance_CurveOracleManipulation.md](./2022-06-16_InverseFinance_CurveOracleManipulation.md) |
| 2022-06-23 | Harmony | CompromisedMultisig | [2022-06-23_Harmony_CompromisedMultisig.md](./2022-06-23_Harmony_CompromisedMultisig.md) |
| 2022-06-24 | HarmonyBridge | MultisigKeyCompromise | [2022-06-24_HarmonyBridge_MultisigKeyCompromise.md](./2022-06-24_HarmonyBridge_MultisigKeyCompromise.md) |
| 2022-06-26 | XCarnival | NFTPledgeReentrancy | [2022-06-26_XCarnival_NFTPledgeReentrancy.md](./2022-06-26_XCarnival_NFTPledgeReentrancy.md) |
| 2022-06-29 | GymNetwork2 | DepositWithdrawExploit | [2022-06-29_GymNetwork2_DepositWithdrawExploit.md](./2022-06-29_GymNetwork2_DepositWithdrawExploit.md) |
| 2022-07-10 | FlippazOne | AccessControl | [2022-07-10_FlippazOne_AccessControl.md](./2022-07-10_FlippazOne_AccessControl.md) |
| 2022-07-21 | Quixotic | SignatureBypass | [2022-07-21_Quixotic_SignatureBypass.md](./2022-07-21_Quixotic_SignatureBypass.md) |
| 2022-07-23 | Audius | GovernanceManipulation | [2022-07-23_Audius_GovernanceManipulation.md](./2022-07-23_Audius_GovernanceManipulation.md) |
| 2022-07-25 | LPC | FeeTokenSelfTransfer | [2022-07-25_LPC_FeeTokenSelfTransfer.md](./2022-07-25_LPC_FeeTokenSelfTransfer.md) |
| 2022-07-28 | Omni | NFTFlashLoanReentrancy | [2022-07-28_Omni_NFTFlashLoanReentrancy.md](./2022-07-28_Omni_NFTFlashLoanReentrancy.md) |
| 2022-07-28 | SpaceGodzilla | PriceManipulation | [2022-07-28_SpaceGodzilla_PriceManipulation.md](./2022-07-28_SpaceGodzilla_PriceManipulation.md) |
| 2022-07-LPC | FlashLoanSelfTransfer |  | [2022-07-LPC_FlashLoanSelfTransfer.md](./2022-07-LPC_FlashLoanSelfTransfer.md) |
| 2022-08-01 | NomadBridge | MessageVerification | [2022-08-01_NomadBridge_MessageVerification.md](./2022-08-01_NomadBridge_MessageVerification.md) |
| 2022-08-07 | EGDFinance | PriceOracleManipulation | [2022-08-07_EGDFinance_PriceOracleManipulation.md](./2022-08-07_EGDFinance_PriceOracleManipulation.md) |
| 2022-08-07 | EGD | Finance OracleManipulation | [2022-08-07_EGD_Finance_OracleManipulation.md](./2022-08-07_EGD_Finance_OracleManipulation.md) |
| 2022-08-09 | ANCH | FlashLoanSkimManipulation | [2022-08-09_ANCH_FlashLoanSkimManipulation.md](./2022-08-09_ANCH_FlashLoanSkimManipulation.md) |
| 2022-08-13 | ReaperFarm | MissingOwnerCheck | [2022-08-13_ReaperFarm_MissingOwnerCheck.md](./2022-08-13_ReaperFarm_MissingOwnerCheck.md) |
| 2022-08-26 | DDC | FeeHandlerAccessControl | [2022-08-26_DDC_FeeHandlerAccessControl.md](./2022-08-26_DDC_FeeHandlerAccessControl.md) |
| 2022-08 | Circle | MakerCDP FlashLoan | [2022-08_Circle_MakerCDP_FlashLoan.md](./2022-08_Circle_MakerCDP_FlashLoan.md) |
| 2022-08 | EtnProduct | NFTMintExploit | [2022-08_EtnProduct_NFTMintExploit.md](./2022-08_EtnProduct_NFTMintExploit.md) |
| 2022-08 | LuckyTiger | WeakRandomness | [2022-08_LuckyTiger_WeakRandomness.md](./2022-08_LuckyTiger_WeakRandomness.md) |
| 2022-08 | Qixi | FlashSwapManipulation | [2022-08_Qixi_FlashSwapManipulation.md](./2022-08_Qixi_FlashSwapManipulation.md) |
| 2022-08 | XST | SkimReserveManipulation | [2022-08_XST_SkimReserveManipulation.md](./2022-08_XST_SkimReserveManipulation.md) |
| 2022-09 | BNB48MEVBot | UnprotectedCallback | [2022-09_BNB48MEVBot_UnprotectedCallback.md](./2022-09_BNB48MEVBot_UnprotectedCallback.md) |
| 2022-09 | BXH | StakingFlashLoan | [2022-09_BXH_StakingFlashLoan.md](./2022-09_BXH_StakingFlashLoan.md) |
| 2022-09 | BadGuysbyRPF | MissingAmountCheck | [2022-09_BadGuysbyRPF_MissingAmountCheck.md](./2022-09_BadGuysbyRPF_MissingAmountCheck.md) |
| 2022-09 | DPC | StakingRewardManipulation | [2022-09_DPC_StakingRewardManipulation.md](./2022-09_DPC_StakingRewardManipulation.md) |
| 2022-09 | MEVbadc0de | DyDxArbitraryCall | [2022-09_MEVbadc0de_DyDxArbitraryCall.md](./2022-09_MEVbadc0de_DyDxArbitraryCall.md) |
| 2022-09 | NXUSD | FlashLoanOracleManipulation | [2022-09_NXUSD_FlashLoanOracleManipulation.md](./2022-09_NXUSD_FlashLoanOracleManipulation.md) |
| 2022-09 | NewFreeDAO | FlashLoanRewardDrain | [2022-09_NewFreeDAO_FlashLoanRewardDrain.md](./2022-09_NewFreeDAO_FlashLoanRewardDrain.md) |
| 2022-09 | RADT | SyncPriceManipulation | [2022-09_RADT_SyncPriceManipulation.md](./2022-09_RADT_SyncPriceManipulation.md) |
| 2022-09 | ROI | OwnershipTakeover | [2022-09_ROI_OwnershipTakeover.md](./2022-09_ROI_OwnershipTakeover.md) |
| 2022-09 | Shadowfi | BurnReserveManipulation | [2022-09_Shadowfi_BurnReserveManipulation.md](./2022-09_Shadowfi_BurnReserveManipulation.md) |
| 2022-09 | THB | GameRewardReentrancy | [2022-09_THB_GameRewardReentrancy.md](./2022-09_THB_GameRewardReentrancy.md) |
| 2022-09 | Yyds | FlashSwapWithdrawDrain | [2022-09_Yyds_FlashSwapWithdrawDrain.md](./2022-09_Yyds_FlashSwapWithdrawDrain.md) |
| 2022-09 | ZoomproFinance | FakePairManipulation | [2022-09_ZoomproFinance_FakePairManipulation.md](./2022-09_ZoomproFinance_FakePairManipulation.md) |
| 2022-10-18 | Market | ReadOnlyReentrancy | [2022-10-18_Market_ReadOnlyReentrancy.md](./2022-10-18_Market_ReadOnlyReentrancy.md) |
| 2022-10-21 | OlympusDAO | BondRedeemBypass | [2022-10-21_OlympusDAO_BondRedeemBypass.md](./2022-10-21_OlympusDAO_BondRedeemBypass.md) |
| 2022-10-27 | TeamFinance | MigrateSqrtPrice | [2022-10-27_TeamFinance_MigrateSqrtPrice.md](./2022-10-27_TeamFinance_MigrateSqrtPrice.md) |
| 2022-10 | ATK | FlashSwapClaimManipulation | [2022-10_ATK_FlashSwapClaimManipulation.md](./2022-10_ATK_FlashSwapClaimManipulation.md) |
| 2022-10 | BEGO | SignatureBypassMinting | [2022-10_BEGO_SignatureBypassMinting.md](./2022-10_BEGO_SignatureBypassMinting.md) |
| 2022-10 | BabySwap | FakeFactoryRewardDrain | [2022-10_BabySwap_FakeFactoryRewardDrain.md](./2022-10_BabySwap_FakeFactoryRewardDrain.md) |
| 2022-10 | Carrot | TransRewardOwnerTakeover | [2022-10_Carrot_TransRewardOwnerTakeover.md](./2022-10_Carrot_TransRewardOwnerTakeover.md) |
| 2022-10 | EFLeverVault | FlashLoanVaultManipulation | [2022-10_EFLeverVault_FlashLoanVaultManipulation.md](./2022-10_EFLeverVault_FlashLoanVaultManipulation.md) |
| 2022-10 | HEALTH | ZeroTransferBurnDrain | [2022-10_HEALTH_ZeroTransferBurnDrain.md](./2022-10_HEALTH_ZeroTransferBurnDrain.md) |
| 2022-10 | HPAY | FakeTokenStakingDrain | [2022-10_HPAY_FakeTokenStakingDrain.md](./2022-10_HPAY_FakeTokenStakingDrain.md) |
| 2022-10 | INUKO | BondFlashLoanOracleManipulation | [2022-10_INUKO_BondFlashLoanOracleManipulation.md](./2022-10_INUKO_BondFlashLoanOracleManipulation.md) |
| 2022-10 | MEVa47b | BalancerArbitraryCall | [2022-10_MEVa47b_BalancerArbitraryCall.md](./2022-10_MEVa47b_BalancerArbitraryCall.md) |
| 2022-10 | MulticallWithoutCheck | ArbitraryTransfer | [2022-10_MulticallWithoutCheck_ArbitraryTransfer.md](./2022-10_MulticallWithoutCheck_ArbitraryTransfer.md) |
| 2022-10 | N00d | ERC777ReentrancyFlashLoan | [2022-10_N00d_ERC777ReentrancyFlashLoan.md](./2022-10_N00d_ERC777ReentrancyFlashLoan.md) |
| 2022-10 | PLTD | SkimFlashLoan | [2022-10_PLTD_SkimFlashLoan.md](./2022-10_PLTD_SkimFlashLoan.md) |
| 2022-10 | RES | ThisAToBManipulation | [2022-10_RES_ThisAToBManipulation.md](./2022-10_RES_ThisAToBManipulation.md) |
| 2022-10 | RL | AirdropMultiContractDrain | [2022-10_RL_AirdropMultiContractDrain.md](./2022-10_RL_AirdropMultiContractDrain.md) |
| 2022-10 | RabbyWallet | SwapRouterArbitraryCall | [2022-10_RabbyWallet_SwapRouterArbitraryCall.md](./2022-10_RabbyWallet_SwapRouterArbitraryCall.md) |
| 2022-10 | Templedao | MigrateStakeAccessControl | [2022-10_Templedao_MigrateStakeAccessControl.md](./2022-10_Templedao_MigrateStakeAccessControl.md) |
| 2022-10 | TransitSwap | TransferFromOwnerBypass | [2022-10_TransitSwap_TransferFromOwnerBypass.md](./2022-10_TransitSwap_TransferFromOwnerBypass.md) |
| 2022-10 | ULME | BuyMinerAllowanceDrain | [2022-10_ULME_BuyMinerAllowanceDrain.md](./2022-10_ULME_BuyMinerAllowanceDrain.md) |
| 2022-10 | Uerii | MintAccessControl | [2022-10_Uerii_MintAccessControl.md](./2022-10_Uerii_MintAccessControl.md) |
| 2022-10 | VTF | UpdateUserBalanceCreate2Drain | [2022-10_VTF_UpdateUserBalanceCreate2Drain.md](./2022-10_VTF_UpdateUserBalanceCreate2Drain.md) |
| 2022-10 | XaveFinance | GovernanceDAOModuleAttack | [2022-10_XaveFinance_GovernanceDAOModuleAttack.md](./2022-10_XaveFinance_GovernanceDAOModuleAttack.md) |
| 2022-11-15 | SheepFarm2 | RegisterRewardExploit | [2022-11-15_SheepFarm2_RegisterRewardExploit.md](./2022-11-15_SheepFarm2_RegisterRewardExploit.md) |
| 2022-11 | AUR | NodePoolAccessControl | [2022-11_AUR_NodePoolAccessControl.md](./2022-11_AUR_NodePoolAccessControl.md) |
| 2022-11 | Annex | FakeTokenLiquidation | [2022-11_Annex_FakeTokenLiquidation.md](./2022-11_Annex_FakeTokenLiquidation.md) |
| 2022-11 | BDEX | ConvertDustManipulation | [2022-11_BDEX_ConvertDustManipulation.md](./2022-11_BDEX_ConvertDustManipulation.md) |
| 2022-11 | BrahTOPG | ZapInArbitraryCall | [2022-11_BrahTOPG_ZapInArbitraryCall.md](./2022-11_BrahTOPG_ZapInArbitraryCall.md) |
| 2022-11 | DFX | FlashDepositReentrancy | [2022-11_DFX_FlashDepositReentrancy.md](./2022-11_DFX_FlashDepositReentrancy.md) |
| 2022-11 | Kashi | InvalidSignatureApproval | [2022-11_Kashi_InvalidSignatureApproval.md](./2022-11_Kashi_InvalidSignatureApproval.md) |
| 2022-11 | MBC | ZZSH SwapLiquifyManipulation | [2022-11_MBC_ZZSH_SwapLiquifyManipulation.md](./2022-11_MBC_ZZSH_SwapLiquifyManipulation.md) |
| 2022-11 | MEV | 0ad8 ArbitraryCallAllowanceDrain | [2022-11_MEV_0ad8_ArbitraryCallAllowanceDrain.md](./2022-11_MEV_0ad8_ArbitraryCallAllowanceDrain.md) |
| 2022-11 | MooCAKECTX | HarvestFlashLoanManipulation | [2022-11_MooCAKECTX_HarvestFlashLoanManipulation.md](./2022-11_MooCAKECTX_HarvestFlashLoanManipulation.md) |
| 2022-11 | NUM | MultichainPermitBypass | [2022-11_NUM_MultichainPermitBypass.md](./2022-11_NUM_MultichainPermitBypass.md) |
| 2022-11 | Polynomial | SwapDepositArbitraryCall | [2022-11_Polynomial_SwapDepositArbitraryCall.md](./2022-11_Polynomial_SwapDepositArbitraryCall.md) |
| 2022-11 | SDAO | StakeRewardManipulation | [2022-11_SDAO_StakeRewardManipulation.md](./2022-11_SDAO_StakeRewardManipulation.md) |
| 2022-11 | SEAMAN | FlashLoanPriceManipulation | [2022-11_SEAMAN_FlashLoanPriceManipulation.md](./2022-11_SEAMAN_FlashLoanPriceManipulation.md) |
| 2022-11 | SheepFarm | RegisterLogicError | [2022-11_SheepFarm_RegisterLogicError.md](./2022-11_SheepFarm_RegisterLogicError.md) |
| 2022-11 | UEarnPool | TeamRewardCreate2Drain | [2022-11_UEarnPool_TeamRewardCreate2Drain.md](./2022-11_UEarnPool_TeamRewardCreate2Drain.md) |
| 2022-12 | AES | DistributeFeeSkimManipulation | [2022-12_AES_DistributeFeeSkimManipulation.md](./2022-12_AES_DistributeFeeSkimManipulation.md) |
| 2022-12 | APC | SwapPriceManipulation | [2022-12_APC_SwapPriceManipulation.md](./2022-12_APC_SwapPriceManipulation.md) |
| 2022-12 | BBOX | TransferHelperDrain | [2022-12_BBOX_TransferHelperDrain.md](./2022-12_BBOX_TransferHelperDrain.md) |
| 2022-12 | BGLD | MigrateSkimManipulation | [2022-12_BGLD_MigrateSkimManipulation.md](./2022-12_BGLD_MigrateSkimManipulation.md) |
| 2022-12 | DFS | SkimReserveManipulation | [2022-12_DFS_SkimReserveManipulation.md](./2022-12_DFS_SkimReserveManipulation.md) |
| 2022-12 | Defrost | LSW DepositRedeemManipulation | [2022-12_Defrost_LSW_DepositRedeemManipulation.md](./2022-12_Defrost_LSW_DepositRedeemManipulation.md) |
| 2022-12 | ElasticSwap | LiquidityManipulation | [2022-12_ElasticSwap_LiquidityManipulation.md](./2022-12_ElasticSwap_LiquidityManipulation.md) |
| 2022-12 | FPR | SetAdminAccessControl | [2022-12_FPR_SetAdminAccessControl.md](./2022-12_FPR_SetAdminAccessControl.md) |
| 2022-12 | JAY | BuyJayReentrancy | [2022-12_JAY_BuyJayReentrancy.md](./2022-12_JAY_BuyJayReentrancy.md) |
| 2022-12 | Lodestar | GLP PriceManipulation | [2022-12_Lodestar_GLP_PriceManipulation.md](./2022-12_Lodestar_GLP_PriceManipulation.md) |
| 2022-12 | MEVbot | 0x28d9 FlashLoanCallback | [2022-12_MEVbot_0x28d9_FlashLoanCallback.md](./2022-12_MEVbot_0x28d9_FlashLoanCallback.md) |
| 2022-12 | MUMUG | BondFlashLoanManipulation | [2022-12_MUMUG_BondFlashLoanManipulation.md](./2022-12_MUMUG_BondFlashLoanManipulation.md) |
| 2022-12 | Nmbplatform | StakingRewardManipulation | [2022-12_Nmbplatform_StakingRewardManipulation.md](./2022-12_Nmbplatform_StakingRewardManipulation.md) |
| 2022-12 | NovaExchange | RewardHoldersAccessControl | [2022-12_NovaExchange_RewardHoldersAccessControl.md](./2022-12_NovaExchange_RewardHoldersAccessControl.md) |
| 2022-12 | Overnight | USDPlusPlatypusManipulation | [2022-12_Overnight_USDPlusPlatypusManipulation.md](./2022-12_Overnight_USDPlusPlatypusManipulation.md) |
| 2022-12 | RFB | FeeOnTransferSwapManipulation | [2022-12_RFB_FeeOnTransferSwapManipulation.md](./2022-12_RFB_FeeOnTransferSwapManipulation.md) |
| 2022-12 | Rubic | RouterCallNativeArbitraryCall | [2022-12_Rubic_RouterCallNativeArbitraryCall.md](./2022-12_Rubic_RouterCallNativeArbitraryCall.md) |
| 2022-12 | TIFI | DepositBorrowReserveManipulation | [2022-12_TIFI_DepositBorrowReserveManipulation.md](./2022-12_TIFI_DepositBorrowReserveManipulation.md) |

---

[← Back to main index](../README.md)
