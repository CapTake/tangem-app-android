package com.tangem.features.send.impl.presentation.state.fields

import com.tangem.common.ui.amountScreen.converters.MaxEnterAmountConverter
import com.tangem.common.ui.amountScreen.converters.field.AmountFieldSetMaxAmountTransformer
import com.tangem.common.ui.amountScreen.models.EnterAmountBoundary
import com.tangem.domain.tokens.model.CryptoCurrencyStatus
import com.tangem.features.send.impl.presentation.state.SendUiState
import com.tangem.features.send.impl.presentation.state.StateRouter
import com.tangem.utils.Provider
import com.tangem.utils.converter.Converter
import com.tangem.utils.isNullOrZero

internal class SendAmountFieldMaxAmountConverter(
    private val stateRouterProvider: Provider<StateRouter>,
    private val currentStateProvider: Provider<SendUiState>,
    private val cryptoCurrencyStatusProvider: Provider<CryptoCurrencyStatus>,
    private val minimumTransactionAmountProvider: Provider<EnterAmountBoundary?>,
) : Converter<Unit, SendUiState> {

    private val maxEnterAmountConverter = MaxEnterAmountConverter()

    override fun convert(value: Unit): SendUiState {
        val state = currentStateProvider()
        val cryptoCurrencyStatus = cryptoCurrencyStatusProvider()
        val isEditState = stateRouterProvider().isEditState
        val amountState = state.getAmountState(isEditState) ?: return state

        val decimalCryptoValue = cryptoCurrencyStatus.value.amount
        if (decimalCryptoValue.isNullOrZero()) return state

        val maxEnterAmount = maxEnterAmountConverter.convert(cryptoCurrencyStatus)
        val minimumTransactionAmount = minimumTransactionAmountProvider()

        return state.copyWrapped(
            isEditState = isEditState,
            sendState = state.sendState?.copy(reduceAmountBy = null),
            amountState = AmountFieldSetMaxAmountTransformer(
                cryptoCurrencyStatus = cryptoCurrencyStatus,
                maxAmount = maxEnterAmount,
                minAmount = minimumTransactionAmount,
            ).transform(amountState),
        )
    }
}
