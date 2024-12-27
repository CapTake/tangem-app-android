package com.tangem.domain.redux

interface StateDialog {

    data object NfcFeatureIsUnavailable : StateDialog

    data class ScanFailsDialog(val source: ScanFailsSource, val onTryAgain: (() -> Unit)? = null) : StateDialog

    data class CardOfflineAttestationFailed(val onRequestSupportClick: () -> Unit) : StateDialog

    enum class ScanFailsSource {
        MAIN, SIGN_IN, SETTINGS, INTRO;
    }
}
