Fixed

- **The signet solution check skips only the genesis block.** It skipped
  any block whose previous hash is zero; Core skips the genesis block by
  its hash. No block other than genesis reaches the check with a zero
  previous hash, since it has no parent, so no verdict changes (#1776).
