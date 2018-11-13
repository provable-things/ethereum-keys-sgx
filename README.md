# __A Pure Rust Implementation of an Elliptic Curve Keypair Generator in an Intel SGX Enclave__

## __:black_nib: Notes:__

More specifically, an Secp256k1 key-pair generator & message/transaction signer where both the enclave _and_ the app are written in pure Rust. Made possible by the fantastic Rust SGX Software Developer Kit by Baidux Labs:
https://github.com/baidu/rust-sgx-sdk

__Update #4:__ This fork can import private keys! (Master still cannot, for obvious reasons!)

__Update #3:__ Now with full transaction sending capabilities!

__Update #2:__ Now with full transaction-signing capabilities!

__Update #1:__ Now with replay-attack protection!

&nbsp;

## __:page_with_curl: CLI Usage:__

<!-- Can I link to the actual usage file here so it updates on changes? -->

```
    Intel SGX Ethereum Key Management CLI.

        Copyright: 2018 Oraclize.it
        Questions: greg@oraclize.it

    Usage:  ethkey_sgx                                              [-h | --help]
            ethkey_sgx import <secret>                              [--keyfile=<path>]
            ethkey_sgx generate                                     [--keyfile=<path>]
            ethkey_sgx show public                                  [--keyfile=<path>]
            ethkey_sgx show secret                                  [--keyfile=<path>]
            ethkey_sgx show address                                 [--keyfile=<path>] 
            ethkey_sgx destroy                                      [--keyfile=<path>]
            ethkey_sgx show nonce                                   [--keyfile=<path>] [--chainid=<uint>] 
            ethkey_sgx sign msg <message>                           [--keyfile=<path>] [-n | --noprefix]
            ethkey_sgx verify <address> <message> <signature>       [--keyfile=<path>] [-n | --noprefix]
            ethkey_sgx sendtx      [--to=<address>] [--value=<Wei>] [--keyfile=<path>] [--gaslimit=<uint>] [--gasprice=<Wei>] [--nonce=<uint>] [--data=<string>] [--chainid=<uint>]
            ethkey_sgx sign tx     [--to=<address>] [--value=<Wei>] [--keyfile=<path>] [--gaslimit=<uint>] [--gasprice=<Wei>] [--nonce=<uint>] [--data=<string>] [--chainid=<uint>]


    Commands:
        generate            ❍ Generates an secp256k1 keypair inside an SGX enclave, encrypts
                            them & saves to disk as either ./encrypted_keypair.txt in the
                            current directory, or at the passed in path.

        show secret         ❍ Log the private key from the given encrypted keypair to the console.

        import secret       ❍ Import a secret & encrypt via the enclave  & save it to a given path,
                            or the default path: `./encrypted_keypair`)

        show nonce          ❍ Retrieves the current nonce of the keypair in a given keyfile, for
                            the network specified via the chain ID parameter:
                                1  = Ethereum Main-Net (default)
                                3  = Ropsten Test-Net
                                4  = Rinkeby Test-Net
                                42 = Kovan Test-Net

        sign tx             ❍ Signs a transaction with the given parameters and returns the raw 
                            data ready for broadcasting to the ethereum network. If no nonce is
                            supplied, the tool will attempt to discover the nonce of the given
                            keypair for the network the transaction is destined for. See below
                            for the parameter defaults.

        sendtx              ❍ Signs a transaction per the above instructions, then sends the 
                            transaction to an Infura node for broadcasting to the chosen network.
                            Returns the transactions hash if successful.

        sign msg            ❍ Signs a passed in message using key pair provided, otherwise uses
                            default keypair if it exists. Defaults to using the ethereum message
                            prefix and ∴ signatures are ECRecoverable.

       verify               ❍ Verify a given address signed a given message with a given signature. 

       destroy              ❍ Destroys a given key file's monotonic counters, rendering the keyfile
                            unusable, before erasing the encrypted keyfile itself. Use with caution!

    Options:
        -h, --help          ❍ Show this usage message.

        --keyfile=<path>    ❍ Path to desired encrypted keyfile [default: ./encrypted_keypair]

        --to=<address>      ❍ Destination address of transaction [default: ]

        --value=<Wei>       ❍ Amount of ether to send with transaction in Wei [default: 0]

        --gaslimit=<uint>   ❍ Amount of gas to send with transaction [default: 210000]

        --gasprice=<Wei>    ❍ Gas price for transaction in Wei [default: 20000000000]

        --chainid=<uint>    ❍ ID of desired chain for transaction [default: 1]

        --nonce=<uint>      ❍ Nonce of transaction in Wei [default:  -1]

        --data=<string>     ❍ Additional data to send with transaction [default:  ]

        -n, --noprefix      ❍ Does not add the ethereum message prefix when signing or verifying 
                            a signed message. Messages signed with no prefix are NOT ECRecoverable!   
```
&nbsp;

## __:wrench: Build it Yourself:__


__❍ Pull requisite files:__

_Pull the Rust SGX SDK Docker image_

_**`❍ sgx-nuc@~$ docker pull baiduxlab/sgx-rust`**_

_Clone this Repo_

_**`❍ sgx-nuc@~$ git clone https://gitlab.com/gskapka/secp256k1-enclave-rust.git`**_

&nbsp;

__**❍ Prepare the Docker Container:**__

If using __SIMULATION__ mode:

_**`❍ sgx-nuc@~$ sudo docker run -v /path/to/secp256k1-enclave-rust:/root/keygen -ti baiduxlab/sgx-rust`**_

Else if using __HARDWARE__ mode:

_**`❍ sgx-nuc@~$ sudo docker run -v/path/to/secp256k1-enclave-rust:/root/keygen -ti --device /dev/isgx baiduxlab/sgx-rust`**_

Rebuild the tool chain:

_**`❍ sgx-nuc-docker@~# rustup default nightly-2018-10-01-x86_64-unknown-linux-gnu`**_

Add required components:

_**`❍ sgx-nuc-docker@~# rustup component add rust-src`**_

Finally, if using __HARDWARE__ mode, import the service:_

_**`❍ sgx-nuc-docker@~# /opt/intel/libsgx-enclave-common/aesm/aesm_service &`**_

&nbsp;

__❍ Prepare the keygen:__

In the `❍ sgx-nuc-docker@~/keygen` directory inside the docker, first ensure the desired mode (__SW__ or __HW__) is set correctly inside the `Makefile`:

```javascript
    // ... Beginning of file ...

    ######## SGX SDK Settings ########

    SGX_SDK ?= /opt/intel/sgxsdk
    SGX_MODE ?= HW                // <-- This option. HW for Hardware or SW for software.
    SGX_ARCH ?= x64

    // ... Remainder of file ...
```

Next, set the environment variable inside the docker to the desired mode:

_**`❍ sgx-nuc-docker@~/keygen# export SGX_MODE=HW`**_

Then build the project:

_**`❍ sgx-nuc-docker@~/keygen# make`**_

And finally run it to see the usage notes:

_**`❍ sgx-nuc-docker@~/keygen# cd bin && ./ethkey_sgx`**_

&nbsp;

## __:clipboard: To Do List:__

:white_check_mark: Refactor to lib crate.

:white_check_mark: Make CLI with Docopt.

:black_square_button: Remotely attest!

:black_square_button: Save key files as their corresponding address names!

:black_square_button: Add more tests!

:white_check_mark: Make ECRecoverable sigs.

:black_square_button: Stream to the enc. to allow file encryption.

:black_square_button: Add rudimentary password protection.

:black_square_button: Use mister enclave instead of mister signer!

:black_square_button: Make threaded to have vanity addresses (can limit tried?)

:white_check_mark: Abstract out generic enclave funcs (mem. allocing etc)

:white_check_mark: Separate the app from the SDK repo enclave to make it lean and mean.

:white_check_mark: Add transaction signing.

:black_square_button: Make a stand alone binary for D/L.

:black_square_button: Make a getter for enclave measurement.

:black_square_button: Remove `show public` since it's useless.

:black_square_button: Remove ability to show private key for prod. usage.

:black_square_button: Make a nonce getter.

:white_check_mark: Add a monotonic counter to the key accesses.

:white_check_mark: Add a monotonic counter to tx signing events.

:white_check_mark: Add SGX time checks to stop replay attacks.

&nbsp;

## __:books: Resources:__

[__❍__ Here's some stuff about the __EDL__ file](https://software.intel.com/en-us/documentation/intel-sgx-web-based-training/the-enclave-definition-language)

[__❍__ Here's some stuff about the Makefile syntax:](https://www3.nd.edu/~zxu2/acms60212-40212/Makefile.pdf)
