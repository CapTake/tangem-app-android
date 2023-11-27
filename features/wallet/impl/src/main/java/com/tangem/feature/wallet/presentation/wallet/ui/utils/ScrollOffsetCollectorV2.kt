package com.tangem.feature.wallet.presentation.wallet.ui.utils

import androidx.compose.foundation.lazy.LazyListItemInfo
import androidx.compose.foundation.lazy.LazyListState
import kotlinx.coroutines.flow.FlowCollector
import kotlin.math.abs

/**
 * Flow collector for scroll items tracking.
 * If first visible item offset is greater than half item size, then change selected wallet index.
 * If last visible item offset is greater than half item size, then change selected wallet index.
 *
 * @property lazyListState     lazy list state
 * @property walletsListConfig wallets list config
 * @property isAutoScroll      check if last scrolling is auto scroll
 *
 * @author Andrew Khokhlov on 01/07/2023
 */
internal class ScrollOffsetCollectorV2(
    private val lazyListState: LazyListState,
    selectedWalletIndex: Int,
    private val onWalletChange2: (Int) -> Unit,
) : FlowCollector<List<LazyListItemInfo>> {

    private val LazyListItemInfo.halfItemSize
        get() = size.div(other = 2)

    private var currentIndex = selectedWalletIndex

    override suspend fun emit(value: List<LazyListItemInfo>) {
        if (!lazyListState.isScrollInProgress || value.size <= 1) return

        val firstItem = value.firstOrNull() ?: return
        val lastItem = value.lastOrNull() ?: return

        if (abs(firstItem.offset) > firstItem.halfItemSize) {
            onWalletChange(newIndex = firstItem.index + 1)
        } else if (abs(lastItem.offset) > lastItem.halfItemSize) {
            onWalletChange(newIndex = lastItem.index - 1)
        }
    }

    private fun onWalletChange(newIndex: Int) {
        if (currentIndex != newIndex) {
            currentIndex = newIndex
            onWalletChange2(newIndex)
        }
    }
}
