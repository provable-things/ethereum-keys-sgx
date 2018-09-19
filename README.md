Have to use non-stable version.
sudo docker run -v ~/oraclize/sgx/rust-sgx-sdk:/root/sgx -ti baiduxlab/sgx-rust
Update the tool chain too per instructions:
rustup default nightly-2018-08-25-x86_64-unknown-linux-gnu
then:
rustup component add rust-src
Then in the root of the keygen: 
make clean
Then:
make
Then:
cd bin && ./app

stuff about the edl file
  2 https://software.intel.com/en-us/documentation/intel-sgx-web-based-training/the-enclave-definition-language

