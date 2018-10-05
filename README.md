# __A Pure Rust Implementation of an Elliptic Curve Keypair Generator in an Intel SGX Enclave__

## __:black_nib: Notes:__

More specifically, an Secp256k1 key pair generator & message signer where both the enclave _and_ the app are written in pure Rust. Made possible by the fantastic Rust SGX Software Developer Kit by Baidux Labs:
https://github.com/baidu/rust-sgx-sdk

&nbsp;

## __:page_with_curl: Instructions:__

_SIMULATION MODE:_
_**`❍ sgx-nuc@~$ sudo docker run -v ~/oraclize/sgx/rust-sgx-sdk:/root/sgx -ti baiduxlab/sgx-rust`**_

_REAL MODE:_
_**`❍ sgx-nuc@~$ sudo docker run -v ~/oraclize/sgx/rust-sgx-sdk:/root/sgx -ti --device /dev/isgx baiduxlab/sgx-rust`**_

Rebuild the tool chain too per instructions:

<!-- 
_**`❍ sgx-nuc-docker@~# rustup default nightly-2018-08-25-x86_64-unknown-linux-gnu`**_
-->

_**`❍ sgx-nuc-docker@~# rustup default nightly-2018-08-25-x86_64-unknown-linux-gnu`**_

_**`❍ sgx-nuc-docker@~# rustup component add rust-src`**_

_REAL MODE ONLY:_ 
_**`❍ sgx-nuc-docker@~# /opt/intel/sgxpsw/aesm/aesm_service &`**_

Then in the `~/sgx/samplecode/secp256k1-enclave-rust` inside the docker, first ensure the desired mode is set correctly inside the `Makefile`.  Next, set the environment variable inside the docker to the desired mode:

_**`❍ sgx-nuc-docker@~/sgx/samplecode/secp256k1-enclave-rust# export SGX_MODE=HW`**_

Then build the project:

_**`❍ sgx-nuc-docker@~/sgx/samplecode/secp256k1-enclave-rust# make clean`**_

_**`❍ sgx-nuc-docker@~/sgx/samplecode/secp256k1-enclave-rust# make`**_

And finally run it:

_**`❍ sgx-nuc-docker@~/sgx/samplecode/secp256k1-enclave-rust# cd bin && ./ethkeysgx`**_

Can also run make file targets separately when making changes to either app or enc. via:
`make enclave` or `make app` etc.

&nbsp;

## __:clipboard: To Do List:__

:white_check_mark: Refactor to lib crate.

:white_check_mark: Test on real nuc in HW mode.

:black_square_button: Make CLI with Docopt.

:black_square_button: Abstract out generic enclave funcs (mem. allocing etc)

:black_square_button: Separate the app from the SDK repo enclave to make it lean and mean.

:black_square_button: Add transaction signing.

:black_square_button: Make a stand alone binary for D/L.

:black_square_button: Add a monotonic counter to the key accesses.

:black_square_button: Add a monotonic counter to tx signing events.


&nbsp;

## __:books: Resources:__

[__❍__ Here's some stuff about the __EDL__ file](https://software.intel.com/en-us/documentation/intel-sgx-web-based-training/the-enclave-definition-language)

[__❍__ Here's some stuff about the Makefile syntax:](https://www3.nd.edu/~zxu2/acms60212-40212/Makefile.pdf)
