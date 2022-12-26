

[![logo](assets/tangram_white.png?raw=true "Tangrm")](https://tangram.network)


[![Build Tangram node](https://github.com/tangramproject/tangram/workflows/build%20tangram%20node/badge.svg)](https://github.com/tangramproject/tangram/commits/master/)
[![GitHub release](https://img.shields.io/github/release/tangramproject/tangram.svg)](https://GitHub.com/tangramproject/tangram/releases/)

### Hardware Requirements

|                 | Relay                                                                            | Staking                                                          |
|-----------------|----------------------------------------------------------------------------------|------------------------------------------------------------------|
| System          | Windows 10<br/>Ubuntu 18.04/22.04<br/>CentOS 8/9<br/>AlmaLinux 9</br>macOS 11/12 | Windows 10<br/>Ubuntu 18.04/22.04<br/>CentOS 8/9<br/>AlmaLinux 9</br>macOS 11/12 |
| CPU             | Dual core                                                                        | Quad core                                                        |
| Memory          | 1G/4G                                                                            | 2G/8G                                                            |
| Hard Disk       | 25G SSD hard drive                                                               | 50G SSD hard drive                                               | 

**NB - The hardware requirements may change.**

## Installation

### Linux and macOS
- [Install .NET For Linux](https://dotnet.microsoft.com/en-us/download?initial-os=linux)
- [Install .NET For macOS](https://dotnet.microsoft.com/en-us/download?initial-os=macOS)

For quick installation on Linux and macOS, execute the following command:

```shell
bash <(curl -sSL https://raw.githubusercontent.com/tangramproject/tangram/master/install/install.sh)
```

The following parameters can be supplied:

#### Linux Only

`install.sh --runasuser <username> --runasgroup users`
Install as the current logged in user

`install.sh --upgrade --runasuser <username> --runasgroup users` Upgrades the node

#### Linux and macOS

`--help`
Display help
  
`--config-skip`
Do not run configuration wizard

`--no-service`
Do not install node as a service

`--noninteractive`
Assume default answers without user interaction.

`--uninstall`
Uninstall node

For example:

```shell
bash <(curl -sSL https://raw.githubusercontent.com/tangramproject/tangram/master/install/install.sh) --uninstall
```

### Windows

-   [Install .NET For Windows](https://dotnet.microsoft.com/en-us/download?initial-os=windows)
-   For some versions of Windows, you may need to install [Visual C++ Redistributable](https://docs.microsoft.com/en-us/cpp/windows/latest-supported-vc-redist).

For quick installation, download the latest zip file [**here**](https://github.com/tangramproject/tangram/releases)


## What is Tangram
Tangram is a revolutionary cryptocurrency that transforms the way we transact. It's fast, fee-less, private and fungible, making it an ideal choice for blockchain transactions. The Tangram network uses a state-of-the-art Pure-Proof-Of-Stake (PPoS) consensus algorithm that is secure, energy-efficient, and decentralized.

Incorporating advanced cryptographic protocols like Bulletproofs, stealth addresses and RingCT for transaction mixing, Tangram guarantees that users can keep their identity and financial activities completely private.  Plus, its lightning-fast transaction speeds and zero fees make it the perfect choice for everyday payments.  

Tangram's PPoS consensus algorithm is specifically designed to ensure a fair distribution of rewards.  Whether it's a small stake or a large one, Tangram ensures that the rewards are distributed fairly to those who put their precious time and effort into staking.

## Security Warning
Tangram is the first release with consensus and should be treated as an experiment! There are no guarantees and we can expect flaws. Use it at your own risk.

## Whitepaper
If you’re interested, you can use the [Whitepaper](https://github.com/cypher-network/whitepaper) as a reference.


## Who can participate in Tangram
If you wish to run a node, experiment and support the release by finding bugs or even getting yourself accustomed to the intricacies of what Tangram is about, this is the release is for you! This is the perfect time to start getting to know Tangram and the inner mechanics of its technologies and protocols.

If you wish to participate in the release of Tangram, you can claim $XTGM through any of the channels (we recommend Discord, [**here**](https://discord.gg/6DT3yFhXCB)).

## Contribution and Support
If you have questions that need answering or a little more detail, feel free to get in touch through any of Tangram’s channels and our community members and managers can point you in the right direction.
If you'd like to contribute to Tangram Cypher (Node code), please know we're currently accepting issues, forks, fixes, commits and pull requests so that maintainers can review and merge into the main code base. If you wish to submit more complex changes, please check up with the core devs first on [Discord Channel](https://discord.gg/6DT3yFhXCB) to ensure the changes get early feedback which can make both your efforts more effective, and review quick and simple.

Licence
-------
For licence information see the file [LICENCE](LICENSE)
