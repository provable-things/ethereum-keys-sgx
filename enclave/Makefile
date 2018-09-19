Rust_Enclave_Name := libenclave.a
Rust_Enclave_Files := $(wildcard src/*.rs)
Rust_Target_Path := $(CURDIR)/../../../xargo
Rust_Enclave_Profile := debug

ifeq ($Rust_Enclave_Profile, release)
    Cargo_Flags := --release
endif


.PHONY: all

all: $(Rust_Enclave_Name)

$(Rust_Enclave_Name): $(Rust_Enclave_Files)
ifeq ($(XARGO_SGX), 1)
	RUST_TARGET_PATH=$(Rust_Target_Path) xargo build --target x86_64-unknown-linux-sgx $(Cargo_Flags)
	cp ./target/x86_64-unknown-linux-sgx/$(Rust_Enclave_Profile)/libsecp256k1_examples.a ../lib/libenclave.a
else
	cargo build -v $(Cargo_Flags)
	cp ./target/$(Rust_Enclave_Profile)/libsecp256k1_examples.a ../lib/libenclave.a
endif
