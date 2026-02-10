.PHONY: build release clean check test fix install uninstall

build:
	cargo build

run:
	cargo run -q -- $(ARGS)

release:
	cargo build --release

install:
	cargo install --path cli

uninstall:
	cargo uninstall purl

clean:
	cargo clean

test:
	cargo test

check:
	cargo fmt --check
	cargo clippy -- -D warnings
	cargo test
	cargo build

fmt:
	cargo fmt
	cargo clippy --fix --allow-dirty --allow-staged
