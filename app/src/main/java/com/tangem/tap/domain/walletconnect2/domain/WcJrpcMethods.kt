package com.tangem.tap.domain.walletconnect2.domain

import com.squareup.moshi.JsonAdapter
import com.squareup.moshi.JsonClass
import com.squareup.moshi.Moshi
import com.squareup.moshi.Types
import com.tangem.datasource.di.SdkMoshi
import com.tangem.tap.domain.walletconnect2.domain.models.SignMessageData
import com.tangem.tap.domain.walletconnect2.domain.models.binance.WCBinanceTxConfirmParam
import com.tangem.tap.domain.walletconnect2.domain.models.binance.WcBinanceCancelOrder
import com.tangem.tap.domain.walletconnect2.domain.models.binance.WcBinanceTradeOrder
import com.tangem.tap.domain.walletconnect2.domain.models.binance.WcBinanceTransferOrder
import com.tangem.tap.domain.walletconnect2.domain.models.solana.SolanaSignMessage
import com.tangem.tap.domain.walletconnect2.domain.models.solana.SolanaTransactionRequest
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.json.Json
import timber.log.Timber
import javax.inject.Inject
import javax.inject.Singleton

enum class WcJrpcMethods(val code: String) {

    ETH_SIGN("eth_sign"),
    ETH_PERSONAL_SIGN("personal_sign"),
    ETH_SIGN_TYPE_DATA("eth_signTypedData"),
    ETH_SIGN_TYPE_DATA_V4("eth_signTypedData_v4"),
    ETH_SIGN_TRANSACTION("eth_signTransaction"),
    ETH_SEND_TRANSACTION("eth_sendTransaction"),

    BNB_SIGN("bnb_sign"),
    BNB_TRANSACTION_CONFIRM("bnb_tx_confirmation"),
    SIGN_TRANSACTION("trust_signTransaction"),

    POLKADOT_SIGN_TX("polkadot_signTransaction"),
    POLKADOT_SIGN_MESSAGE("polkadot_signMessage"),

    TRON_SIGN_TX("tron_signTransaction"),
    TRON_SIGN_MESSAGE("tron_signMessage"),

    SOLANA_SIGN_TX("solana_signTransaction"),
    SOLANA_SIGN_MESSAGE("solana_signMessage"),
    ;

    companion object {
        fun fromCode(code: String): WcJrpcMethods? = values().firstOrNull { it.code == code }
    }
}

@JsonClass(generateAdapter = true)
data class WCSignTransaction(
    val network: Int,
    val transaction: String,
) : WcRequestData

@JsonClass(generateAdapter = true)
data class WcEthereumSignMessage(
    val raw: List<String>,
    val type: WCSignType,
) : WcRequestData {
    enum class WCSignType {
        MESSAGE, PERSONAL_MESSAGE, TYPED_MESSAGE, SOLANA_MESSAGE, POLKADOT_MESSAGE, TRON_MESSAGE
    }

    /**
     * Raw parameters will always be the message and the address. Depending on the WCSignType,
     * those parameters can be swapped as description below:
     *
     *  - MESSAGE: `[address, data ]`
     *  - TYPED_MESSAGE: `[address, data]`
     *  - PERSONAL_MESSAGE: `[data, address]`
     *
     *  reference: https://docs.walletconnect.org/json-rpc/ethereum#eth_signtypeddata
     */
    val data
        get() = when (type) {
            WCSignType.PERSONAL_MESSAGE -> raw[0]
            else -> raw[1]
        }

    val address
        get() = when (type) {
            WCSignType.PERSONAL_MESSAGE -> raw[1]
            else -> raw[0]
        }
}

@JsonClass(generateAdapter = true)
data class WcEthereumTransaction(
    val from: String,
    val to: String?,
    val nonce: String?,
    val gasPrice: String?,
    val maxFeePerGas: String?,
    val maxPriorityFeePerGas: String?,
    val gas: String?,
    val gasLimit: String?,
    val value: String?,
    val data: String,
) : WcRequestData

interface WcRequestData

data class WcCustomRequestData(val data: String) : WcRequestData

sealed class WcRequest(open val data: WcRequestData) {
    data class EthSign(override val data: WcEthereumSignMessage) : WcRequest(data)
    data class EthSignTransaction(override val data: WcEthereumTransaction) : WcRequest(data)
    data class EthSendTransaction(override val data: WcEthereumTransaction) : WcRequest(data)
    data class BnbTrade(override val data: WcBinanceTradeOrder) : WcRequest(data)
    data class BnbCancel(override val data: WcBinanceCancelOrder) : WcRequest(data)
    data class BnbTransfer(override val data: WcBinanceTransferOrder) : WcRequest(data)
    data class BnbTxConfirm(override val data: WCBinanceTxConfirmParam) : WcRequest(data)
    data class SignTransaction(override val data: WCSignTransaction) : WcRequest(data)
    data class CustomRequest(override val data: WcCustomRequestData) : WcRequest(data)
    data class SolanaSignRequest(override val data: SolanaTransactionRequest) : WcRequest(data)
}

@Singleton
class WcJrpcRequestsDeserializer @Inject constructor(@SdkMoshi private val moshi: Moshi) {

    private val json = Json { ignoreUnknownKeys = true }

    @Suppress("ComplexMethod", "LongMethod")
    fun deserialize(method: String, params: String): WcRequest {
        val customRequest = WcRequest.CustomRequest(WcCustomRequestData(params))
        val wcMethod: WcJrpcMethods = WcJrpcMethods.fromCode(method) ?: return customRequest

        return when (wcMethod) {
            WcJrpcMethods.ETH_SIGN_TRANSACTION -> {
                val deserializedParams = moshi.adapter<List<WcEthereumTransaction>>(
                    Types.newParameterizedType(List::class.java, WcEthereumTransaction::class.java),
                ).fromJsonFirstOrNull(params) ?: return customRequest
                WcRequest.EthSignTransaction(data = deserializedParams)
            }
            WcJrpcMethods.ETH_SEND_TRANSACTION -> {
                val deserializedParams = moshi.adapter<List<WcEthereumTransaction>>(
                    Types.newParameterizedType(List::class.java, WcEthereumTransaction::class.java),
                ).fromJsonFirstOrNull(params) ?: return customRequest
                WcRequest.EthSendTransaction(data = deserializedParams)
            }
            WcJrpcMethods.ETH_SIGN -> {
                val deserializedParams = moshi.adapter<List<String>>(
                    Types.newParameterizedType(List::class.java, String::class.java),
                ).fromJsonOrNull(params) ?: return customRequest
                val data = WcEthereumSignMessage(
                    raw = deserializedParams,
                    type = WcEthereumSignMessage.WCSignType.MESSAGE,
                )
                WcRequest.EthSign(data = data)
            }
            WcJrpcMethods.ETH_PERSONAL_SIGN -> {
                val deserializedParams = moshi.adapter<List<String>>(
                    Types.newParameterizedType(List::class.java, String::class.java),
                ).fromJsonOrNull(params) ?: return customRequest
                val data = WcEthereumSignMessage(
                    raw = deserializedParams,
                    type = WcEthereumSignMessage.WCSignType.PERSONAL_MESSAGE,
                )
                WcRequest.EthSign(data = data)
            }
            WcJrpcMethods.ETH_SIGN_TYPE_DATA, WcJrpcMethods.ETH_SIGN_TYPE_DATA_V4 -> {
                val deserializedParams = listOf(
                    params.substring(params.indexOf("\"") + 1, params.indexOf("\"", startIndex = 2)),
                    params.substring(params.indexOfFirst { it == '{' }, params.indexOfLast { it == '}' } + 1),
                )
                val data = WcEthereumSignMessage(
                    deserializedParams,
                    WcEthereumSignMessage.WCSignType.TYPED_MESSAGE,
                )
                Timber.d("TypedData params: $deserializedParams")
                WcRequest.EthSign(data)
            }
            WcJrpcMethods.BNB_SIGN -> {
                return deserializeBnb(moshi, params) ?: customRequest
            }
            WcJrpcMethods.BNB_TRANSACTION_CONFIRM -> {
                val deserializedParams = moshi.adapter<List<WCBinanceTxConfirmParam>>(
                    Types.newParameterizedType(List::class.java, WCBinanceTxConfirmParam::class.java),
                ).fromJsonFirstOrNull(params) ?: return customRequest
                WcRequest.BnbTxConfirm(data = deserializedParams)
            }
            WcJrpcMethods.SIGN_TRANSACTION -> {
                val deserializedParams = moshi.adapter<List<WCSignTransaction>>(
                    Types.newParameterizedType(List::class.java, WCSignTransaction::class.java),
                ).fromJsonFirstOrNull(params) ?: return customRequest
                WcRequest.SignTransaction(data = deserializedParams)
            }
            WcJrpcMethods.POLKADOT_SIGN_TX -> TODO()
            WcJrpcMethods.POLKADOT_SIGN_MESSAGE -> {
                val signMessage = Json.decodeFromStringOrNull<SignMessageData>(params) ?: return customRequest
                val data = WcEthereumSignMessage(
                    raw = listOf(signMessage.address, signMessage.message),
                    type = WcEthereumSignMessage.WCSignType.POLKADOT_MESSAGE,
                )
                WcRequest.EthSign(data = data)
            }
            WcJrpcMethods.TRON_SIGN_TX -> TODO()
            WcJrpcMethods.TRON_SIGN_MESSAGE -> {
                val signMessage = Json.decodeFromStringOrNull<SignMessageData>(params) ?: return customRequest
                val data = WcEthereumSignMessage(
                    raw = listOf(signMessage.address, signMessage.message),
                    type = WcEthereumSignMessage.WCSignType.TRON_MESSAGE,
                )
                WcRequest.EthSign(data = data)
            }
            WcJrpcMethods.SOLANA_SIGN_TX -> {
                val tx = json.decodeFromStringOrNull<SolanaTransactionRequest>(params) ?: return customRequest
                WcRequest.SolanaSignRequest(data = tx)
            }
            WcJrpcMethods.SOLANA_SIGN_MESSAGE -> {
                val signMessage = Json.decodeFromStringOrNull<SolanaSignMessage>(params) ?: return customRequest
                val data = WcEthereumSignMessage(
                    raw = listOf(signMessage.pubkey, signMessage.message),
                    type = WcEthereumSignMessage.WCSignType.SOLANA_MESSAGE,
                )
                WcRequest.EthSign(data = data)
            }
        }
    }

    private fun deserializeBnb(moshi: Moshi, params: String): WcRequest? {
        val cancelOrder = moshi.adapter<List<WcBinanceCancelOrder>>(
            Types.newParameterizedType(List::class.java, WcBinanceCancelOrder::class.java),
        ).fromJsonFirstOrNull(params)
        if (cancelOrder != null) return WcRequest.BnbCancel(cancelOrder)

        val tradeOrder = moshi.adapter<List<WcBinanceTradeOrder>>(
            Types.newParameterizedType(List::class.java, WcBinanceTradeOrder::class.java),
        ).fromJsonFirstOrNull(params)
        if (tradeOrder != null) return WcRequest.BnbTrade(tradeOrder)

        val transferOrder = moshi.adapter<List<WcBinanceTransferOrder>>(
            Types.newParameterizedType(List::class.java, WcBinanceTransferOrder::class.java),
        ).fromJsonFirstOrNull(params)
        if (transferOrder != null) return WcRequest.BnbTransfer(transferOrder)

        return null
    }

    private fun <T> JsonAdapter<T>.fromJsonOrNull(data: String): T? {
        return try {
            this.fromJson(data)
        } catch (e: Exception) {
            Timber.e(e.message)
            null
        }
    }

    private inline fun <reified T> Json.decodeFromStringOrNull(data: String): T? {
        return try {
            this.decodeFromString<T>(data)
        } catch (e: Exception) {
            Timber.e(e.message)
            null
        }
    }

    private fun <T> JsonAdapter<List<T>>.fromJsonFirstOrNull(data: String): T? {
        return try {
            this.fromJson(data)?.firstOrNull()
        } catch (e: Exception) {
            Timber.e(e.message)
            null
        }
    }
}
