package com.tangem.tap.common.analytics.events

import com.tangem.core.analytics.models.AnalyticsEvent
import com.tangem.core.analytics.models.EventValue

/**
 * Created by Anton Zhilenkov on 28.09.2022.
 */
sealed class MainScreen(
    event: String,
    params: Map<String, EventValue> = mapOf(),
) : AnalyticsEvent("Main Screen", event, params) {

    class ScreenOpened : MainScreen("Screen opened")
    class ButtonScanCard : MainScreen("Button - Scan Card")

    class EnableBiometrics(state: AnalyticsParam.OnOffState) : MainScreen(
        event = "Enable Biometric",
        params = mapOf("State" to state.value.asStringValue()),
    )

    class NoticeRateAppButton(result: AnalyticsParam.RateApp) : MainScreen(
        event = "Notice - Rate The App Button Tapped",
        params = mapOf("Result" to result.value.asStringValue()),
    )
}
