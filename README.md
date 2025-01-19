# go secp256k1

a golang binding for bitcoin [libsecp256k1](https://github.com/bitcoin-core/secp256k1).

## usage

you can get this library using:

```sh
go get github.com/kehiy/go-secp256k1
```

### examples and benchmarks

you can check [examples](./example/) and [benchmarks](./benchmark/).

## todo

todo list:

- [ ] removing the usage of C.secp356k1_context from go api.
- [ ] supporting key generation.(?)
- [ ] supporting sign32/taghash(?) method.
- [ ] writing tests.
- [ ] writing examples.
- [ ] writing benchmarks.
- [ ] adding godoc documents.
- [ ] adding security check linter and workflows.

## license and contribution

this library is unlicensed and open to contributions.
