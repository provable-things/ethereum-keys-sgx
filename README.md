# __A Pure Rust Implementation of an Elliptic Curve Keypair Generator in an Intel SGX Enclave__

## __:black_nib: Notes:__

&nbsp;

More specifically, an Secp256k1 key pair generator & message signer where both the enclave _and_ the app are written in pure Rust. Made possible by the fantastic Rust SGX Software Developer Kit by Baidux Labs:
https://github.com/baidu/rust-sgx-sdk

## __:page_with_curl: Instructions:__

&nbsp;

**1)** Coming soon.

## Notes whilst WIPPING:

Have to use non-stable version.

sudo docker run -v ~/oraclize/sgx/rust-sgx-sdk:/root/sgx -ti baiduxlab/sgx-rust

Rebuild the tool chain too per instructions:

rustup default nightly-2018-08-25-x86_64-unknown-linux-gnu
then:
rustup component add rust-src

Then in the ~/sgx/samplecode/secp256k1-enclave-rust inside the docker: 
make clean

Then:
make

Then:
cd bin && ./sgx-enclave-ec-keygen

Can also run make file targets separately when making changes to either app or enc. via:
make enclave
make app

Here's some stuff about the edl file:
https://software.intel.com/en-us/documentation/intel-sgx-web-based-training/the-enclave-definition-language

Here's some stuff about the Makefile syntax:
https://www3.nd.edu/~zxu2/acms60212-40212/Makefile.pdf
