# Unreleased

* Add `prepared_key_cache` feature: `verify_bls_signature` caches the
  most recently used public keys in their prepared form, cache hits
  reduce instructions per verification by ~22%. Needs `std`.
* `prepared_key_cache_statistics` reports that cache's size, hits and misses.

# 0.6 - 2024-08-09

* Gate use of `rand` behind feature "rand"

# 0.5 - 2024-07-17

* Bump `ic_bls12_381` dependency to 0.10

# 0.4 - 2024-07-17

* Yanked
* Bump `sha2` dependency to 0.10

# 0.3 - 2024-05-06

* Add `alloc` feature to support no-alloc environments.
* Switch to using `ic_bls12_381` to take advantage of reduced stack
  usage during final exponentiation.
* Upgrade various dependencies.

# 0.2 - 2023-05-10

* Add support for key types
* Add suppot for signature generation
* Add GH Actions CI setup

# 0.1 - 2022-09-22

* Initial release. Just supports BLS signature verification.
