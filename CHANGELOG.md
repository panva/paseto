# Changelog

All notable changes to this project will be documented in this file. See [standard-version](https://github.com/conventional-changelog/standard-version) for commit guidelines.

## [2.1.1](https://github.com/panva/paseto/compare/v2.1.0...v2.1.1) (2021-04-06)


### Performance

* improve base64url encoding when native is available ([385689e](https://github.com/panva/paseto/commit/385689ef54390e9f8cbb72af21cac6350e996f72))
* use native sign/verify non-blocking callback when available ([995b278](https://github.com/panva/paseto/commit/995b2780556f4843c655117205d7454f9086eef4))

## [2.1.0](https://github.com/panva/paseto/compare/v2.0.0...v2.1.0) (2021-02-24)


### Features

* allow arbitrary payloads ([#15](https://github.com/panva/paseto/issues/15)) ([7869f25](https://github.com/panva/paseto/commit/7869f2516dc745228e9bfd7351f3df62710813b0)), closes [#14](https://github.com/panva/paseto/issues/14)

## [2.0.0](https://github.com/panva/paseto/compare/v1.0.8...v2.0.0) (2021-02-23)


### ⚠ BREAKING CHANGES

* removed v2.local encrypt, decrypt, and key generation
* requires Node.js version ^12.19.0 || >=14.15.0

### Features

* removed the libsodium dependency ([0fe5de6](https://github.com/panva/paseto/commit/0fe5de69925ed2c98e1d6527da9a3ac961349145))

## [1.0.8](https://github.com/panva/paseto/compare/v1.0.7...v1.0.8) (2020-11-19)

## [1.0.7](https://github.com/panva/paseto/compare/v1.0.6...v1.0.7) (2020-07-09)


### Performance Improvements

* omit serializing KeyObjects when Node.js >= 14.5.0 is used ([3d5c148](https://github.com/panva/paseto/commit/3d5c1487df714a0bf62a4fc5f89d280a8c649f09))



## [1.0.6](https://github.com/panva/paseto/compare/v1.0.5...v1.0.6) (2020-04-21)


### Performance Improvements

* faster V1 encrypt/decrypt by grouping the crypto worker operations ([dbbdfa6](https://github.com/panva/paseto/commit/dbbdfa631a5afe1fa4790d681e382bb2ad44d46c))
* removed regexp checking for base64url padding and charset ([f113782](https://github.com/panva/paseto/commit/f113782092d56cb122a94556e8b5214f3cc361b4))



## [1.0.5](https://github.com/panva/paseto/compare/v1.0.4...v1.0.5) (2019-12-26)



## [1.0.4](https://github.com/panva/paseto/compare/v1.0.3...v1.0.4) (2019-11-14)



## [1.0.3](https://github.com/panva/paseto/compare/v1.0.2...v1.0.3) (2019-10-21)


### Bug Fixes

* **typescript:** actually bundle the types with a package release ([5f4e961](https://github.com/panva/paseto/commit/5f4e961f954e6181c79abf20f5b69d2cfd675a33))

## [1.0.2](https://github.com/panva/paseto/compare/v1.0.1...v1.0.2) (2019-10-18)


### Bug Fixes

* symmetric keys are 32 bytes, not 256 (error message was wrong) ([d223704](https://github.com/panva/paseto/commit/d223704))



## [1.0.1](https://github.com/panva/paseto/compare/v1.0.0...v1.0.1) (2019-09-30)


### Bug Fixes

* **typescript:** move ts files around and fix missing DecodeResult ([c797404](https://github.com/panva/paseto/commit/c797404))



## [1.0.0](https://github.com/panva/paseto/compare/v0.9.1...v1.0.0) (2019-09-27)



## 0.9.1 (2019-07-02)


### Features

* implement v1 and v2 ([c11a3ff](https://github.com/panva/paseto/commit/c11a3ff))
