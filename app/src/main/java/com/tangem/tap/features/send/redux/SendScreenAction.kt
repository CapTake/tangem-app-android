package com.tangem.tap.features.send.redux

import com.tangem.blockchain.common.Amount
import com.tangem.tap.common.redux.ErrorAction
import com.tangem.tap.common.redux.ToastNotificationAction
import com.tangem.tap.domain.TapError
import com.tangem.tap.features.send.redux.states.FeeType
import com.tangem.tap.features.send.redux.states.MainCurrencyType
import com.tangem.tap.features.send.redux.states.SendButtonState
import com.tangem.wallet.R
import org.rekotlin.Action
import java.math.BigDecimal

/**
 * Created by Anton Zhilenkov on 31/08/2020.
 */
interface SendScreenAction : Action
interface SendScreenActionUi : SendScreenAction

object ReleaseSendState : Action

data class PrepareSendScreen(
        val coinAmount: Amount?,
        val tokenAmount: Amount? = null
) : SendScreenAction

// Address or PayId
sealed class AddressPayIdActionUi : SendScreenActionUi {
    data class ChangeAddressOrPayId(val data: String) : AddressPayIdActionUi()
    data class SetTruncateHandler(val handler: (String) -> String) : AddressPayIdActionUi()
    data class TruncateOrRestore(val truncate: Boolean) : AddressPayIdActionUi()
}

sealed class AddressPayIdVerifyAction : SendScreenAction {
    enum class Error {
        IS_NOT_PAY_ID,
        PAY_ID_UNSUPPORTED_BY_BLOCKCHAIN,
        PAY_ID_NOT_REGISTERED,
        PAY_ID_REQUEST_FAILED,
        ADDRESS_INVALID_OR_UNSUPPORTED_BY_BLOCKCHAIN,
        ADDRESS_SAME_AS_WALLET
    }

    data class VerifyClipboard(val data: String?) : AddressPayIdVerifyAction()
    data class ChangePasteBtnEnableState(val isEnabled: Boolean) : AddressPayIdVerifyAction()

    sealed class PayIdVerification : AddressPayIdVerifyAction() {
        data class SetError(val payId: String, val error: Error) : PayIdVerification()
        data class SetPayIdWalletAddress(val payId: String, val payIdWalletAddress: String) : PayIdVerification()
    }

    sealed class AddressVerification : AddressPayIdVerifyAction() {
        data class SetError(val address: String, val error: Error) : AddressVerification()
        data class SetWalletAddress(val address: String) : AddressVerification()
    }
}

// Amount to send
sealed class AmountActionUi : SendScreenActionUi {
    data class HandleUserInput(val proposedAmount: String) : AmountActionUi()
    object CheckAmountToSend : AmountActionUi()
    object SetMaxAmount : AmountActionUi()
    data class SetMainCurrency(val mainCurrency: MainCurrencyType) : AmountActionUi()
    object ToggleMainCurrency : AmountActionUi()
}

sealed class AmountAction : SendScreenAction {
    data class SetAmount(val amount: BigDecimal, val isUserInput: Boolean) : AmountAction()
    data class SetAmountError(val error: TapError?) : AmountAction()
}

// Fee
sealed class FeeActionUi : SendScreenActionUi {
    object ToggleControlsVisibility : FeeActionUi()
    data class ChangeSelectedFee(val feeType: FeeType) : FeeActionUi()
    class ChangeIncludeFee(val isIncluded: Boolean) : FeeActionUi()
}

sealed class FeeAction : SendScreenAction {
    enum class Error {
        ADDRESS_OR_AMOUNT_IS_EMPTY,
        REQUEST_FAILED
    }

    object RequestFee : FeeAction()
    sealed class FeeCalculation : FeeAction() {
        data class SetFeeResult(val fee: List<Amount>) : FeeCalculation()
        data class SetFeeError(val error: Error) : FeeCalculation()
    }

    data class ChangeLayoutVisibility(
            val main: Boolean? = null,
            val controls: Boolean? = null,
            val chipGroup: Boolean? = null,
    ) : FeeAction()
}

sealed class ReceiptAction : SendScreenAction {
    object RefreshReceipt : ReceiptAction()
}

sealed class SendActionUi : SendScreenActionUi {
    object SendAmountToRecipient : SendScreenActionUi
}

sealed class SendAction : SendScreenAction {

    data class ChangeSendButtonState(val state: SendButtonState) : SendAction()
    object SendSuccess : SendAction(), ToastNotificationAction {
        override val messageResource: Int = R.string.send_transaction_complete
    }

    data class SendError(override val error: TapError) : SendAction(), ErrorAction
}