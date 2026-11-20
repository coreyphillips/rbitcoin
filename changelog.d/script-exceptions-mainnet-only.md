Fixed

- **The mainnet BIP16 and taproot exception blocks are exceptions on
  mainnet only,** as in Core's `script_flag_exceptions`. No block of
  another network has either hash, so no verdict changes (#1778).
