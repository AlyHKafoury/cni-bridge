# Kubernetes Bridge Rust CNI Plugin

This is an experimental Kubernetes CNI plugin written in Rust. It provides a bridge network for Kubernetes pods.

## Features

* Supports the following CNI commands:
    * `ADD`
    * `DEL`
    * `CHECK`
* Uses the host-local IPAM plugin for IP address allocation.
* Supports the following options:
    * `name` - The name of the network.
    * `type` - The type of network. (Default: `bridge`)
    * `bridge` - The name of the bridge device. (Default: `cni0`)
    * `ip` - The IP address of the bridge device. (Default: `10.65.0.1`)
    * `netmask` - The netmask of the bridge device. (Default: `255.255.255.0`)
    * `gateway` - The gateway IP address. (Default: `10.65.0.1`)

## How to use

* Copy the files to their crosponding nodes.
  * `10-rust_bridge-master.conf`
  * `10-rust_bridge-node01.conf`
  * `10-rust_bridge-node02.conf`
* Build the rust code using `cargo build`.
* Copy the binary using the following command `cp ./target/debug/cni-bridge /opt/cni/bin/`.
* A Workaround for cross-node container communication is to run the following scripts on thier respective nodes keep in mind to replace the nodes ips and network devices in the bash files.
  * `setup_node01.sh`
  * `setup_node02.sh`

## Limitations

* Only 2 workers and 1 master is the currently supported setup.
* Workaround for cross-node container communication.