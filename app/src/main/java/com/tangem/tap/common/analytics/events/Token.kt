package com.tangem.tap.common.analytics.events

import com.tangem.core.analytics.models.AnalyticsEvent
import com.tangem.core.analytics.models.AnalyticsParam.Key.TOKEN_PARAM
import com.tangem.core.analytics.models.EventValue

/**
 * Created by Anton Zhilenkov on 28.09.2022.
 */
sealed class Token(
    category: String,
    event: String,
    params: Map<String, EventValue> = mapOf(),
    error: Throwable? = null,
) : AnalyticsEvent(category, event, params, error) {

    sealed class Receive(
        event: String,
        params: Map<String, EventValue> = mapOf(),
    ) : Token("Token / Receive", event, params) {

        class ScreenOpened(
            val token: String,
        ) : Receive(
            event = "Receive Screen Opened",
            params = mapOf(TOKEN_PARAM to token.asStringValue()),
        )
        class ButtonCopyAddress : Receive("Button - Copy Address")
        class ButtonShareAddress : Receive("Button - Share Address")
    }

    sealed class Topup(
        event: String,
        params: Map<String, EventValue> = mapOf(),
    ) : Token("Token / Topup", event, params) {

        class ScreenOpened : Topup("Top Up Screen Opened")
        class P2PScreenOpened : Topup("P2P Screen Opened")
    }

    sealed class Withdraw(
        event: String,
        params: Map<String, EventValue> = mapOf(),
    ) : Token("Token / Withdraw", event, params) {

        class ScreenOpened : Withdraw("Withdraw Screen Opened")
    }
}
