Fixed

- **A fresh tip enables tx relay before scripthash materialize finishes.** Regtest `generate` runs while startup is still packing the scripthash index, so `getblocktemplate` saw a nonempty pool with relay off and returned `-10`. Connecting a block that leaves IBD turns relay on after the template hold drops, and latches a feefilter refresh for the tip-follow loop. `-blocksonly` stays quiet. Class A tail backfill keeps scanning creates that land during that same window, and the `getblockstats` harness waits until Esplora binds.
