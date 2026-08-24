# Upstream test vectors

These files are copied from
[`paseto-standard/test-vectors`](https://github.com/paseto-standard/test-vectors) at revision
`32d7406591eb022f9eff88abb84106dd9d42c0f2`.

The upstream `LICENSE` and `README.md` are included unchanged in this directory. The `PASERK`
subdirectory contains every k1 through k4 JSON vector available at that revision. The built-in
runtime suite exercises `k3.seal`; private reference implementations exercise `k1.seal`, `k2.seal`,
and `k4.seal`, whose required primitives are not all exposed by Web Cryptography.
