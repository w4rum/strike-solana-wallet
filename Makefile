build:
	cargo build-bpf

deploy_and_test: build
	solana program deploy ./target/deploy/strike_wallet.so
