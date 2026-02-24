# STOProtocol-16k-PoC

**Chain:** BSC

**Date:** February 24, 2025

**Attacker:** `0x8E6149b4a6AB28Db7d4b1E8261bD71364307FCFD`

**Profit:** 26.57 BNB (~$16,100 USD)

**Root cause:** Logic error permit deflationary sell-burn drains AMM reserves mid-swap

| Contract | Address |
|----------|---------|
| STO Token | [`0xFE33EB082B2374ecd9Fb550f833DB88CaD8d084B`](https://bscscan.com/address/0xFE33EB082B2374ecd9Fb550f833DB88CaD8d084B) |
| PancakePair (WBNB/STO) | [`0x7c404aD6149BC69e07eCd534B9F4243Ef289bD00`](https://bscscan.com/address/0x7c404aD6149BC69e07eCd534B9F4243Ef289bD00) |
| PancakeRouter v2 | [`0x10ED43C718714eb63d5aA57B78B54704E256024E`](https://bscscan.com/address/0x10ED43C718714eb63d5aA57B78B54704E256024E) |
| Moolah Flash Loan Pool | [`0x8F73b65B4caAf64FBA2aF91cC5D4a2A1318E5D8C`](https://bscscan.com/address/0x8F73b65B4caAf64FBA2aF91cC5D4a2A1318E5D8C) |
| LP Dividend Contract | [`0x52614E1e257F0C2fEe904B54161Ed2C22D28D2d6`](https://bscscan.com/address/0x52614E1e257F0C2fEe904B54161Ed2C22D28D2d6) |
| Whitelisted Helper | [`0x4CC42A6131B5F75739C694423bbe62110A446fea`](https://bscscan.com/address/0x4CC42A6131B5F75739C694423bbe62110A446fea) |

---

## Summary

STO Protocol is a deflationary BEP-20 token on BSC with the following features:

- **Total supply:** 10,000,000 STO, deflationary down to 10,000 STO
- **6% buy/sell tax** sent to an ecosystem wallet
- **Sell burn:** after each sell, the post-tax tokens (`afterTax`) are queued in `pendingBurnFromSell` and burned from the PancakeSwap pair on the **next** sell
- **Daily burn:** 3% of pair balance burned every 24h (half to LP dividends, half to dead address)
- **Whitelist-only liquidity addition**, open buying/selling (when enabled)
- **Auto-buy threshold:** buying is automatically enabled when pair WBNB reaches 2,000 BNB via `initializeLiquidity`

---

## Root cause

The root cause `_executePendingSellBurn()`

```solidity
function _executePendingSellBurn() private {
    uint256 pairBalance = balanceOf(pancakePair);
    uint256 toBurn = pendingBurnFromSell;

    uint256 minReserve = 1000 * 1e18;
    if (pairBalance > toBurn + minReserve) {
        pendingBurnFromSell = 0;
        super._update(pancakePair, DEAD, toBurn);   // [1] Burns STO FROM pair
        IPancakePair(pancakePair).sync();            // [2] Resets reserves DOWN
    }
}
```

**Directly removes STO tokens from the PancakeSwap pair balance** via `super._update(pair, DEAD, toBurn)` — bypassing the pair own accounting
**Calls `sync()`** to force the pair internal reserves to match the new (lower) token balances

`_executePendingSellBurn()` is invoked inside the `_update()` transfer hook, which runs at the **beginning** of every sell (transfer to pair)

```solidity
if (to == pancakePair) {
    // *** BURN HAPPENS HERE — BEFORE new tokens arrive ***
    if (pendingBurnFromSell > 0) {
        _executePendingSellBurn();  // burns from pair + sync()
    }

    uint256 tax = amount * TAX_RATE / BASIS_POINTS;  // 6%
    uint256 afterTax = amount - tax;

    super._update(from, ecosystemWallet, tax);
    super._update(from, to, afterTax);     // new tokens arrive AFTER burn

    if (!burningStopped && burnEnabled) {
        pendingBurnFromSell += afterTax;   // queued for next sell
    }
}
```

## Invariant Violation

PancakeSwap AMM relies on the constant-product invariant **K = reserve0 * reserve1**, reserves should only change through `swap()`, `mint()`, `burn()`, or `skim()` all of which maintain K or adjust it predictably

`_executePendingSellBurn()` violates this by:

1. Destroying STO tokens directly from the pair balance (reducing `balance1`)
2. Calling `sync()` to write this reduced balance into `reserve1`
3. **Without removing any WBNB** — so K drops to `reserve0 * new_lower_reserve1`

When the sell's `afterTax` STO then arrives in the pair, and the attacker calls `pair.swap()`, the pair sees:
- `stoIn = actualBalance - reserve1` (a large input relative to the burned-down reserve)
- WBNB output is calculated against the **reduced K**, yielding more WBNB than a normal constant-K sell

Each cycle **permanently reduces K** because STO is burned to DEAD without corresponding WBNB removal, the attacker repeats this to drain all WBNB.

---

## Pre-Attack State (Block 82,890,985)

| Parameter | Value |
|-----------|-------|
| Pair WBNB reserve | 26.611 BNB |
| Pair STO reserve | 7,901,582 STO |
| pendingBurnFromSell | 0 |
| buyEnabled | **false** |
| sellEnabled | true |
| burnEnabled | true |
| autoBuyThreshold | 2,000 BNB |
| Moolah WBNB available | 360,894 WBNB |

**`buyEnabled` was false**, only whitelisted addresses could buy STO from the pair, the attacker needed to first enable buying via the `autoBuyThreshold` mechanism.

---

## Attack Flow

The attacker deployed two contracts: a factory (`0x8E6149`) which created the main exploit contract (`0xc2b361`). The entire attack executed atomically in a single transaction.

// Moolah flashloan

```
Moolah.flashLoan(WBNB, 360,894 WBNB)
```

<img width="1141" height="229" alt="image" src="https://github.com/user-attachments/assets/f6e28c4c-9022-46d0-8b6c-a741d1d6a6e4" />


Flash loan of 360,894 WBNB (~$220M at the time) from Moolah lending protocol.

// Obtain Initial STO Tokens

`buyEnabled = false` means direct buying is blocked, the attacker leveraged a **pre-existing whitelisted ecosystem contract** at `0x4CC42A6` which, when called with BNB, buys STO and adds liquidity, because this contract is in the STO whitelist, it bypasses the buy restriction:

```
STO._update: isWhitelisted[0x4CC42A6] == true → bypass all restrictions
```

1. Send 0.1 BNB to whitelisted helper `0x4CC42A6`
2. Helper buys ~8,905 STO via PancakeRouter (whitelisted bypass)
3. Helper adds liquidity → LP tokens sent to attacker
4. Attacker claims LP dividends from `0x52614E` → receives ~461 STO
5. Attacker removes liquidity → gets WBNB back (STO burned to DEAD per protocol design)

**Net result:** Attacker has ~461 STO + recovered WBNB.

// Enable Buying

The `initializeLiquidity()` function at STO.sol:373-397 has an auto-enable mechanism:

```solidity
if (!buyEnabled && autoBuyThreshold > 0) {
    uint256 pairWBNB = IERC20(WBNB).balanceOf(pancakePair);
    if (pairWBNB >= autoBuyThreshold) {     // 2,000 BNB threshold
        buyEnabled = true;
        sellEnabled = true;
    }
}
```

The attacker:

1. **Sends 1,973 WBNB directly to the pair** (no swap — just a raw transfer)
2. **Calls `STO.initializeLiquidity{value: 1 wei}(461 STO)`**
   - The `lockSwap` modifier sets `inSwap = true` → all transfers bypass restrictions
   - Router's `addLiquidityETH` calls `pair.mint()` which accounts for the excess 1,973 WBNB
   - **After mint, pair WBNB balance ≈ 2,000 BNB ≥ `autoBuyThreshold`**
   - **`buyEnabled` is set to `true`**

<img width="1199" height="224" alt="image" src="https://github.com/user-attachments/assets/af708142-85a9-4722-83b4-ff4615484fcb" />

// Massive Buy

With buying now enabled, the attacker swaps ~358,921 WBNB for STO through PancakeRouter `0x10ED43C718714eb63d5aA57B78B54704E256024E`

```
Router.swapExactTokensForTokensSupportingFeeOnTransferTokens(
    358,921 WBNB → STO
)
```

| | Before | After |
|---|--------|-------|
| Pair WBNB | ~2,000 BNB | ~360,921 BNB |
| Pair STO | ~7,892,677 STO | ~43,845 STO |
| Attacker STO | ~0 | ~7,377,902 STO (after 6% buy tax) |

The pair now holds nearly all the flash-loaned WBNB and very little STO. This is the setup for the drain.

// Drain loop (45 Cycles)

The attacker executes **45 sell cycles**, each cycle has two steps

// Sell STO to Pair

```solidity
STO.transfer(pair, 184,459 STO)
```

Inside `STO._update()` (to == pair):

1. **`_executePendingSellBurn()`** fires (from cycle 2 onward):
   - Burns 173,391 STO from pair → pair STO drops from 217,236 to 43,845
   - Calls `pair.sync()` → **reserves updated to (WBNB, 43,845 STO)**
2. **6% tax** (11,067 STO) sent to ecosystem wallet
3. **afterTax** (173,391 STO) transferred to pair → pair STO: 43,845 + 173,391 = **217,236**
4. **`pendingBurnFromSell += 173,391`** → queued for next cycle

<img width="1179" height="262" alt="image" src="https://github.com/user-attachments/assets/1b6ec7d5-2d86-477f-87f2-cc90ab466f5f" />

// Extract WBNB via Swap

```solidity
pair.swap(wbnbOut, 0, attacker, "")
```

<img width="1179" height="200" alt="image" src="https://github.com/user-attachments/assets/1c7e2fe1-9fc9-4abd-af5e-1bc6b47d9025" />

The Pair reserves were synced to `(WBNB, 43,845)` by the burn, but the actual STO balance is `217,236`, the pair sees `stoIn = 217,236 - 43,845 = 173,391` as new input and computes WBNB output using the AMM formula against the **reduced reserves**.

// Reserve Evolution (across cycles)

| Cycle | WBNB Reserve (post-sync) | STO Reserve (post-sync) | WBNB Extracted |
|-------|:------------------------:|:-----------------------:|:--------------:|
| 1 | 360,921 | 43,845 | 285,637 |
| 2 | 75,283 | 43,845 | 33,833 |
| 3 | 41,450 | 43,845 | 18,628 |
| 4 | 22,822 | 43,845 | 10,256 |
| 5 | 12,565 | 43,845 | 5,647 |
| 6 | 6,918 | 43,845 | 3,109 |
| 7 | 3,809 | 43,845 | 1,711 |
| ... | _(exponential decay)_ | 43,845 | ... |
| 45 | ~0.000006 | 43,845 | ~0.000005 |

STO reserve resets to the same **43,845 STO** every cycle (burn removes 173,391, then sell adds 173,391 back), only WBNB decreases, exponentially, the compounding drain extracts 79.8% of remaining WBNB per cycle.

// Repay and Profit

After the drain loop, the attacker holds ~360,921 WBNB (extracted from pair), moolah pulls 360,894 WBNB via `transferFrom`.

| | Amount |
|---|--------|
| Flash loan repaid | 360,894.644 WBNB |
| WBNB remaining (profit) | **26.571 WBNB** |
| Pair WBNB remaining | 0.000000000000000001 WBNB |

The attacker unwrapped the profit to BNB and sent it to EOA `0x622DDba7`.

---

### Output

```
============ PRE-ATTACK STATE
  Pair WBNB reserve: 26.611271941212387188
  Pair STO reserve:  7901582.908873299214809729
  pendingBurnFromSell: 0.000000000000000000
  buyEnabled: 0
  sellEnabled: 1
  burnEnabled: 1
============ POST-ATTACK STATE
  Pair WBNB reserve: 0.000000000000000001
  Pair STO reserve:  43845.297773049838847186
  Exploit WBNB bal:  26.571271941212387187
============ RESULTS
  WBNB drained from pair: 26.611271941212387187
  Net profit (WBNB+BNB):  26.571271941212387187
============ EXPLOIT SUCCESS
```

---
