package com.tangem.feature.wallet.presentation.wallet.state2

import com.tangem.core.ui.event.consumedEvent
import com.tangem.domain.wallets.models.UserWalletId
import com.tangem.feature.wallet.presentation.wallet.state.components.WalletTopBarConfig
import com.tangem.feature.wallet.presentation.wallet.state2.transformers.WalletScreenStateTransformer
import kotlinx.collections.immutable.persistentListOf
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.update
import javax.inject.Inject
import javax.inject.Singleton

/**
 * @author Andrew Khokhlov on 15/11/2023
 */
@Singleton
internal class WalletStateHolderV2 @Inject constructor() {

    val uiState: StateFlow<WalletScreenState> get() = mutableUiState
    val value: WalletScreenState get() = uiState.value
    private val mutableUiState: MutableStateFlow<WalletScreenState> = MutableStateFlow(value = getInitialState())

    fun update(function: (WalletScreenState) -> WalletScreenState) {
        mutableUiState.update(function = function).also {
            // with(value) {
            //     (wallets[selectedWalletIndex] as? WalletState.SingleCurrency.Content)?.txHistoryState as?
            //         TxHistoryState.
            // }
            // Timber.e()
        }
    }

    fun update(transformer: WalletScreenStateTransformer) {
        mutableUiState.update(function = transformer::transform)
    }

    fun getSelectedWallet(): WalletState {
        return with(value) { wallets[selectedWalletIndex] }
    }

    fun getSelectedWalletId(): UserWalletId {
        return with(value) { wallets[selectedWalletIndex].walletCardState.id }
    }

    private fun getInitialState(): WalletScreenState {
        return WalletScreenState(
            onBackClick = {},
            topBarConfig = WalletTopBarConfig(onDetailsClick = {}),
            selectedWalletIndex = NOT_INITIALIZED_WALLET_INDEX,
            wallets = persistentListOf(),
            onWalletChange = {},
            event = consumedEvent(),
            isHidingMode = false,
        )
    }
}
