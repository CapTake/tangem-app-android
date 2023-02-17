package com.tangem.tap.features.onboarding.products.wallet.saltPay

import org.spongycastle.util.encoders.Base64.toBase64String

/**
 * Created by Anton Zhilenkov on 13.10.2022.
 */
data class SaltPayConfig(
    val sprinklrAppID: String,
    val kycProvider: KYCProvider,
    val credentials: Credentials,
) {
    companion object {
        fun stub(): SaltPayConfig {
            return SaltPayConfig(
                sprinklrAppID = "",
                kycProvider = KYCProvider("", "", "", ""),
                credentials = Credentials("", ""),
            )
        }
    }
}

data class KYCProvider(
    val baseUrl: String,
    val externalIdParameterKey: String,
    val sidParameterKey: String,
    val sidValue: String,
)

data class Credentials(
    val user: String,
    val password: String,
) {
    val token: String by lazy { "Basic ${toBase64String("$user:$password".toByteArray())}" }
}
