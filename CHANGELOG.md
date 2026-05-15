# Changelog

## [0.3.1](https://github.com/usetero/policy-zig/compare/v0.3.0...v0.3.1) (2026-05-15)


### Bug Fixes

* registry shouldn't need the accessors ([#57](https://github.com/usetero/policy-zig/issues/57)) ([16dd81d](https://github.com/usetero/policy-zig/commit/16dd81d7dcb4415a5994bef91222ae5a1c89aeff))

## [0.3.0](https://github.com/usetero/policy-zig/compare/v0.2.0...v0.3.0) (2026-05-13)


### Features

* support regex replacements in redactions ([#55](https://github.com/usetero/policy-zig/issues/55)) ([e5fddf6](https://github.com/usetero/policy-zig/commit/e5fddf63800c667eb7a1f6ae3bc80cd64a9fed37))

## [0.2.0](https://github.com/usetero/policy-zig/compare/v0.1.17...v0.2.0) (2026-04-06)


### Features

* add support for arbitrary rate limit windows ([#53](https://github.com/usetero/policy-zig/issues/53)) ([e7b8a81](https://github.com/usetero/policy-zig/commit/e7b8a81c3fae5c3a1c531bfc75b21cac58bbbbf6))

## [0.1.17](https://github.com/usetero/policy-zig/compare/v0.1.16...v0.1.17) (2026-03-04)


### Bug Fixes

* minor perf improvement ([#47](https://github.com/usetero/policy-zig/issues/47)) ([2be0d3a](https://github.com/usetero/policy-zig/commit/2be0d3a51ab5705fd13426a73a8f8bf860bd4fab))

## [0.1.16](https://github.com/usetero/policy-zig/compare/v0.1.15...v0.1.16) (2026-02-25)


### Bug Fixes

* bump protobuf dep to latest ([#42](https://github.com/usetero/policy-zig/issues/42)) ([106a8a4](https://github.com/usetero/policy-zig/commit/106a8a4fea535edb78e03a6bd5c7007213745f6d))

## [0.1.15](https://github.com/usetero/policy-zig/compare/v0.1.14...v0.1.15) (2026-02-25)


### Bug Fixes

* bump dep again ([#40](https://github.com/usetero/policy-zig/issues/40)) ([4e02746](https://github.com/usetero/policy-zig/commit/4e02746feb2d590765459d9c0b5ed332a9bab679))

## [0.1.14](https://github.com/usetero/policy-zig/compare/v0.1.13...v0.1.14) (2026-02-25)


### Bug Fixes

* support hex properly ([#38](https://github.com/usetero/policy-zig/issues/38)) ([74ba61d](https://github.com/usetero/policy-zig/commit/74ba61da04d4059948c28a51fbb901f1f56bc12b))

## [0.1.13](https://github.com/usetero/policy-zig/compare/v0.1.12...v0.1.13) (2026-02-23)


### Bug Fixes

* policies should work alphanumerically ([#36](https://github.com/usetero/policy-zig/issues/36)) ([f12504b](https://github.com/usetero/policy-zig/commit/f12504b96bafc547e9a7690bbad00dd755929453))
* sampling logic wasnt hashing right ([#32](https://github.com/usetero/policy-zig/issues/32)) ([1ee791c](https://github.com/usetero/policy-zig/commit/1ee791c552b8319061906893fbe07f976bd151a8))
* upsert default is false ([#37](https://github.com/usetero/policy-zig/issues/37)) ([08ee378](https://github.com/usetero/policy-zig/commit/08ee3783c401534d70c863046431f4301b6f82e6))
* zig runner reports incorrect stats for mixed signal policy ([#34](https://github.com/usetero/policy-zig/issues/34)) ([f75a791](https://github.com/usetero/policy-zig/commit/f75a7919ed06e956575823875860b953b1ec8c88))
* zig should follow spec for recording misses ([#35](https://github.com/usetero/policy-zig/issues/35)) ([a7fabb0](https://github.com/usetero/policy-zig/commit/a7fabb0c682f6d2b91752d6601eac9e1b6714988))

## [0.1.12](https://github.com/usetero/policy-zig/compare/v0.1.11...v0.1.12) (2026-02-20)


### Bug Fixes

* support shorthand and schema urls and versions ([#30](https://github.com/usetero/policy-zig/issues/30)) ([aa5f5ac](https://github.com/usetero/policy-zig/commit/aa5f5acc4b69ef051053b78e90086bdee133c39d))

## [0.1.11](https://github.com/usetero/policy-zig/compare/v0.1.10...v0.1.11) (2026-02-20)


### Bug Fixes

* probabilistic sampling off spec ([#27](https://github.com/usetero/policy-zig/issues/27)) ([f494423](https://github.com/usetero/policy-zig/commit/f494423065dd8edcd7ce8c4d8bbfecea52b4f1a1))

## [0.1.10](https://github.com/usetero/policy-zig/compare/v0.1.9...v0.1.10) (2026-02-19)


### Bug Fixes

* tracing should use probabilistic sampler ([#25](https://github.com/usetero/policy-zig/issues/25)) ([14224ce](https://github.com/usetero/policy-zig/commit/14224cecbf4447d1c3fa5b53e32f77cb5a7004c0))

## [0.1.9](https://github.com/usetero/policy-zig/compare/v0.1.8...v0.1.9) (2026-02-18)


### Bug Fixes

* record hit correctly ([#23](https://github.com/usetero/policy-zig/issues/23)) ([7546e29](https://github.com/usetero/policy-zig/commit/7546e2910eb60125caa1829f4f971985fee9058b))

## [0.1.8](https://github.com/usetero/policy-zig/compare/v0.1.7...v0.1.8) (2026-02-18)


### Bug Fixes

* accept null matchers ([#21](https://github.com/usetero/policy-zig/issues/21)) ([03a3ca0](https://github.com/usetero/policy-zig/commit/03a3ca059d0329239880e012d5883b75c5717600))

## [0.1.7](https://github.com/usetero/policy-zig/compare/v0.1.6...v0.1.7) (2026-02-16)


### Bug Fixes

* better approach for providers ([#19](https://github.com/usetero/policy-zig/issues/19)) ([eb20494](https://github.com/usetero/policy-zig/commit/eb20494a6a98bc29b1d59b84bafee328b76b3fd0))

## [0.1.6](https://github.com/usetero/policy-zig/compare/v0.1.5...v0.1.6) (2026-02-16)


### Bug Fixes

* return file listener, fix metric_type and aggregation producing ([#17](https://github.com/usetero/policy-zig/issues/17)) ([1f260d5](https://github.com/usetero/policy-zig/commit/1f260d573608343abbb12f28f264b3843c15f5e4))

## [0.1.5](https://github.com/usetero/policy-zig/compare/v0.1.4...v0.1.5) (2026-02-16)


### Bug Fixes

* support all the fields ([#15](https://github.com/usetero/policy-zig/issues/15)) ([5ae7568](https://github.com/usetero/policy-zig/commit/5ae75684cc5c3eb74e9d696008fee73b4681e9c9))

## [0.1.4](https://github.com/usetero/policy-zig/compare/v0.1.3...v0.1.4) (2026-02-13)


### Bug Fixes

* use different reset method ([#13](https://github.com/usetero/policy-zig/issues/13)) ([0aa5d10](https://github.com/usetero/policy-zig/commit/0aa5d100452cea685c7107479ab84e4e876160dc))

## [0.1.3](https://github.com/usetero/policy-zig/compare/v0.1.2...v0.1.3) (2026-02-12)


### Bug Fixes

* expose otel protos ([#11](https://github.com/usetero/policy-zig/issues/11)) ([e5e1c11](https://github.com/usetero/policy-zig/commit/e5e1c11b277e6691fc5dec539a90fb354214a77d))

## [0.1.2](https://github.com/usetero/policy-zig/compare/v0.1.1...v0.1.2) (2026-02-12)


### Bug Fixes

* expose it ([#9](https://github.com/usetero/policy-zig/issues/9)) ([19c822a](https://github.com/usetero/policy-zig/commit/19c822a83855048b1c5dc265986078544310ad6e))

## [0.1.1](https://github.com/usetero/policy-zig/compare/v0.1.0...v0.1.1) (2026-02-12)


### Bug Fixes

* more pub ([#7](https://github.com/usetero/policy-zig/issues/7)) ([526bc3a](https://github.com/usetero/policy-zig/commit/526bc3acf0f229573ddea54623323493d67c7f58))

## [0.1.0](https://github.com/usetero/policy-zig/compare/v0.0.1...v0.1.0) (2026-02-12)


### Features

* publish all protos ([#5](https://github.com/usetero/policy-zig/issues/5)) ([8b72a20](https://github.com/usetero/policy-zig/commit/8b72a202e168409c3f213a135532f14f96bac08a))

## 0.0.1 (2026-02-12)


### Features

* split edge code and policy zig code into separate libraries ([#1](https://github.com/usetero/policy-zig/issues/1)) ([f750d02](https://github.com/usetero/policy-zig/commit/f750d024ae8e963545419440b4cbb207a00af9cf))
