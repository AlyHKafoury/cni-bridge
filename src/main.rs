use futures::TryStreamExt;
use interfaces::Interface;
use log::{info, warn, LevelFilter};
use nix::sched;
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_json::{Result, json};
use simple_logging::log_to_file;
use std::fmt::format;
use std::net::Ipv4Addr;
use std::{io, result, thread};

use std::fs::{self, File};
use std::io::{Error, ErrorKind, Write};
use std::os::unix::prelude::*;
use std::path::Path;
use std::process::{Command, Stdio};

use ipnetwork::{IpNetwork, Ipv4Network};
use netns_rs::{get_from_current_thread, NetNs};
use sha2::{Digest, Sha512};

#[derive(Serialize, Deserialize, Debug)]
struct CniInput {
    bridge: String,
    #[serde(alias = "cniVersion")]
    cni_version: String,
    #[serde(alias = "ipMasq")]
    ip_masq: bool,
    ipam: Ipam,
    #[serde(alias = "isGateway")]
    is_gateway: bool,
    name: String,
    #[serde(alias = "type")]
    cni_type: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct Ipam {
    routes: Vec<Route>,
    subnet: String,
    #[serde(alias = "type")]
    ipam_type: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct Route {
    dst: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct IpamOut {
    ips: Vec<IP4>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct IP4 {
    address: String,
    gateway: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct RestultIP {
    address: String,
    gateway: String,
    interface: usize,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct ResultInterface {
    name: String,
    mac: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    sandbox: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct ResultDNS {
    nameservers: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct JsonResult {
    ips: Vec<RestultIP>,
    routes: Vec<Route>,
    interfaces: Vec<ResultInterface>,
    dns: ResultDNS,
}

const CNI_PATH: &str = "/opt/cni/bin";

fn exec_ipam(input: &str, ipam_type: &str) -> String {
    let exec_path = format!("{}/{}", CNI_PATH, ipam_type);

    let mut ipam_proc = Command::new(&exec_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();

    ipam_proc
        .stdin
        .as_mut()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();

    let output = ipam_proc.wait_with_output().unwrap();
    String::from_utf8_lossy(&output.stdout).to_string()
}

async fn attach_ip_interface(handle: &rtnetlink::Handle, ifname: &str, ip: IpNetwork) {
    let mut links = handle.link().get().match_name(ifname.to_owned()).execute();
    match links.try_next().await {
        Ok(Some(link)) => {
            match handle
                .address()
                .add(link.header.index, ip.ip(), ip.prefix())
                .execute()
                .await
            {
                Ok(_) => (),
                Err(rtnetlink::Error::NetlinkError(err)) => {
                    if err.code != -17 {
                        panic!("error adding ip to interface, {}, {}", ifname, err)
                    }
                }
                Err(err) => panic!("error adding ip to interface, {}, {}", ifname, err),
            }
        }
        Ok(None) => panic!("cannot attach IP, interface not found"),
        Err(err) => panic!("cannot attach IP : {}, {}", ifname, err),
    }
}

async fn set_link_up(handle: &rtnetlink::Handle, ifname: &str) {
    let mut links = handle.link().get().match_name(ifname.to_owned()).execute();
    match links.try_next().await {
        Ok(Some(link)) => {
            handle
                .link()
                .set(link.header.index)
                .up()
                .execute()
                .await
                .unwrap();
        }
        Ok(None) => panic!("unable to set link up, {}", ifname),
        Err(err) => panic!("unable to set link up, {}, {}", ifname, err),
    }
}

fn append_ip_tables(net_name: &str, cni_containerid: &str, ipv4: &str, subnet: &str) {
    let ip_tbl = iptables::new(false).unwrap();
    ip_tbl
        .append(
            "filter",
            "FORWARD",
            &format!("--source {} --jump ACCEPT", subnet),
        )
        .unwrap();
    ip_tbl
        .append(
            "filter",
            "FORWARD",
            &format!("--destination {} --jump ACCEPT", subnet),
        )
        .unwrap();

    let cni_chain_name = format!("{}-{}", net_name, cni_containerid);
    ip_tbl.new_chain("nat", &cni_chain_name);
    ip_tbl
        .append(
            "nat",
            &cni_chain_name,
            &format!("--jump ACCEPT --destination {}", subnet),
        )
        .unwrap();
    ip_tbl
        .append(
            "nat",
            &cni_chain_name,
            "--jump MASQUERADE ! --destination base-address.mcast.net/4",
        )
        .unwrap();
    ip_tbl
        .append(
            "nat",
            "POSTROUTING",
            &format!("--jump {} --source {}", &cni_chain_name, ipv4),
        )
        .unwrap();
}

#[tokio::main]
async fn build_bridge(bridge_name: &str, ip4: IP4) {
    let (connection, handle, _) = rtnetlink::new_connection().unwrap();
    tokio::spawn(connection);

    let mut links = handle
        .link()
        .get()
        .match_name(bridge_name.to_string())
        .execute();
    match links.try_next().await {
        Ok(Some(_)) => return,
        _ => {
            handle
                .link()
                .add()
                .bridge(bridge_name.to_owned())
                .execute()
                .await
                .unwrap();
        } // Err(err) => panic!("Cannot Build bridge interface {}, error : {}", bridge_name, err),
    }
    let mask: Vec<&str> = ip4.address.split("/").collect();
    let ip: IpNetwork = format!("{}/{}", ip4.gateway, mask[1].to_string())
        .parse()
        .unwrap();
    attach_ip_interface(&handle, bridge_name, ip).await;
    set_link_up(&handle, bridge_name).await;
}

#[tokio::main]
async fn create_veth(veth_host: &str, veth_container: &str) {
    let (connection, handle, _) = rtnetlink::new_connection().unwrap();
    tokio::spawn(connection);

    handle
        .link()
        .add()
        .veth(veth_host.to_string(), veth_container.to_string())
        .execute()
        .await
        .unwrap();

    let mut links = handle
        .link()
        .get()
        .match_name(veth_host.to_owned())
        .execute();
    match links.try_next().await {
        Ok(Some(link)) => {
            handle
                .link()
                .set(link.header.index)
                .setns_by_pid(1)
                .execute()
                .await
                .unwrap();
        }
        _ => panic!("error fetching veth_host id, {}", veth_host),
    }
}

#[tokio::main]
async fn master_veth(veth_host: &str, bridge_name: &str) {
    let (connection, handle, _) = rtnetlink::new_connection().unwrap();
    tokio::spawn(connection);

    let mut links = handle
        .link()
        .get()
        .match_name(bridge_name.to_string())
        .execute();

    let bridge_interface_index = match links.try_next().await {
        Ok(Some(link)) => link.header.index,
        _ => panic!("cannot get bridge interface id for {}", bridge_name),
    };
    let mut links = handle
        .link()
        .get()
        .match_name(veth_host.to_string())
        .execute();
    match links.try_next().await {
        Ok(Some(link)) => handle
            .link()
            .set(link.header.index)
            .master(bridge_interface_index)
            .execute()
            .await
            .unwrap(),
        _ => panic!("error fetching veth_host id, {}", veth_host),
    }

    set_link_up(&handle, veth_host).await;
}

fn get_mac(ifname: &str) -> String {
    match Interface::get_by_name(ifname) {
        Ok(Some(iface)) => {
            return iface.hardware_addr().unwrap().as_string();
        }
        _ => panic!("cannot get mac, interface not found {}", ifname),
    }
}

#[tokio::main]
async fn setup_container_if(ifname: &str, ipv4_ip: &str, ipv4_mask: &str, gw_ipv4: &str) {
    let (connection, handle, _) = rtnetlink::new_connection().unwrap();
    tokio::spawn(connection);

    set_link_up(&handle, ifname).await;

    let container_ip: IpNetwork = format!("{}/{}", ipv4_ip, ipv4_mask).parse().unwrap();
    attach_ip_interface(&handle, ifname, container_ip).await;

    let gateway_ip: Ipv4Network = gw_ipv4.to_owned().parse().unwrap();
    let dst_ip: Ipv4Network = format!("0.0.0.0/0").parse().unwrap();
    handle
        .route()
        .add()
        .v4()
        .destination_prefix(dst_ip.ip(), dst_ip.prefix())
        .gateway(gateway_ip.ip())
        .execute()
        .await
        .unwrap();
}

fn remove_ip_table(net_name: &str, cni_containerid: &str, subnet: &str) {
    let ip_tbl = iptables::new(false).unwrap();
    ip_tbl
        .delete(
            "filter",
            "FORWARD",
            &format!("--source {} --jump ACCEPT", subnet),
        );
    ip_tbl
        .delete(
            "filter",
            "FORWARD",
            &format!("--destination {} --jump ACCEPT", subnet),
        );

    let cni_chain_name = format!("{}-{}", net_name, cni_containerid);
    let list_post = ip_tbl
        .execute("nat", &format!("--list POSTROUTING --line-numbers"))
        .unwrap();
    let list_post_str = String::from_utf8_lossy(&list_post.stdout).to_string();
    let lines: Vec<&str> = list_post_str.split('\n').collect();
    for line in lines {
        if !line.contains(&cni_chain_name) {
            continue;
        }

        let items: Vec<&str> = line.split(' ').collect();
        ip_tbl.delete("nat", "POSTROUTING", items[0]).unwrap();
    }

    ip_tbl.flush_chain("nat", &cni_chain_name);
    ip_tbl.delete_chain("nat", &cni_chain_name);
}

#[tokio::main]
async fn del_if(ifname: &str) {
    let (connection, handle, _) = rtnetlink::new_connection().unwrap();
    tokio::spawn(connection);

    let mut links = handle.link().get().match_name(ifname.to_string()).execute();
    match links.try_next().await {
        Ok(Some(link)) => {
            handle
                .link()
                .del(link.header.index)
                .execute()
                .await
                .unwrap();
        }
        _ => info!("unable to delete interface: {}", ifname),
    }
}

fn main() {
    log_to_file("/tmp/rust_bridge.log", LevelFilter::Info).unwrap();
    let stdin = io::stdin();
    let mut user_input = String::new();
    stdin.read_line(&mut user_input).unwrap();
    info!("stdin : {:#?}", &user_input);
    let cni_command = envmnt::get_or("CNI_COMMAND", "Not found");
    let cni_containerid = envmnt::get_or("CNI_CONTAINERID", "Not found");
    let cni_ifname = envmnt::get_or("CNI_IFNAME", "Not found");
    let cni_netns = envmnt::get_or("CNI_NETNS", "Not found");
    info!(
        "command: {} , containerid: {} , interface name: {} , netns: {}",
        cni_command, cni_containerid, cni_ifname, cni_netns
    );
    if cni_command.as_str() == "VERSION" {
        let version_json = json!({
            "cniVersion": "1.0.0",
            "supportedVersions": [ "0.1.0", "0.2.0", "0.3.0", "0.3.1", "0.4.0", "1.0.0" ]
        }); 
        info!("{}", &version_json);
        println!("{}", &version_json);
        std::process::exit(0);
    }
    let cni_input: CniInput = serde_json::from_str(&user_input).unwrap();
    info!("stdin : {:#?}", cni_input);
    let ipam_out_string = exec_ipam(&user_input, &cni_input.ipam.ipam_type);
    let ipam_out: IpamOut = serde_json::from_str(&ipam_out_string).unwrap_or(IpamOut {
        ips: vec![IP4 {
            address: ipam_out_string.clone(),
            gateway: "".to_owned(),
        }],
    });
    info!("Ipam Out: {:#?}", ipam_out);
    let mut hash = Sha512::new();
    hash.update(cni_containerid.clone());
    let container_hash = hex::encode(hash.finalize())[..12].to_owned();
    if cni_command.as_str() == "ADD" {
        build_bridge(&cni_input.bridge, ipam_out.ips[0].clone());
        let ipv4: Vec<&str> = ipam_out.ips[0].address.split("/").collect();
        let ipv4_ip = ipv4[0].to_string();
        let ipv4_mask = ipv4[1].to_string();
        append_ip_tables(
            &cni_input.name,
            &container_hash,
            &ipv4_ip,
            &cni_input.ipam.subnet,
        );
        let veth_host = format!("veth-{}", rand::thread_rng().gen::<u32>());

        let file_handle = File::open(&cni_netns).unwrap();
        let netns_fd = file_handle.as_raw_fd();

        let thread_veth_host_name = veth_host.clone();
        let thread_cni_ifname = cni_ifname.clone();
        let handle = thread::spawn(move || {
            sched::setns(netns_fd, sched::CloneFlags::CLONE_NEWNET).unwrap();

            create_veth(&thread_veth_host_name, &thread_cni_ifname);
        });
        handle.join().unwrap();
        master_veth(&veth_host, &cni_input.bridge);
        let bridge_mac = get_mac(&cni_input.bridge);
        let host_mac = get_mac(&veth_host);

        let file_handle = File::open(&cni_netns).unwrap();
        let netns_fd = file_handle.as_raw_fd();

        let thread_gw_ipv4 = ipam_out.ips[0].gateway.clone();
        let thread_cni_ifname = cni_ifname.clone();
        let handle = thread::spawn(move || {
            sched::setns(netns_fd, sched::CloneFlags::CLONE_NEWNET).unwrap();
            setup_container_if(&thread_cni_ifname, &ipv4_ip, &ipv4_mask, &thread_gw_ipv4);
            get_mac(&thread_cni_ifname)
        });
        let container_mac = handle.join().unwrap();
        info!("{} , {}, {}", container_mac, host_mac, bridge_mac);
        let res = JsonResult {
            ips: vec![RestultIP{
                address: ipam_out.ips[0].address.clone(),
                gateway: ipam_out.ips[0].gateway.clone(),
                interface: 2,
            }],
            routes: cni_input.ipam.routes,
            interfaces: vec![
                ResultInterface{
                    name: cni_input.bridge,
                    mac: bridge_mac,
                    sandbox: "".to_owned(),
                },
                ResultInterface{
                    name: veth_host,
                    mac: host_mac,
                    sandbox: "".to_owned(),
                },
                ResultInterface{
                    name: cni_ifname.clone(),
                    mac: container_mac,
                    sandbox: cni_netns.clone(),
                },
            ],
            dns: ResultDNS { nameservers: vec!["8.8.8.8".to_owned(), "1.1.1.1".to_owned()] },
        };
        info!("{}", json!(res.clone()));
        println!("{}", json!(res));
    }
    if cni_command.as_str() == "DEL" {
        remove_ip_table(&cni_input.name, &container_hash, &cni_input.ipam.subnet);

        let file_handle = File::open(&cni_netns).unwrap();
        let netns_fd = file_handle.as_raw_fd();

        let handle = thread::spawn(move || {
            sched::setns(netns_fd, sched::CloneFlags::CLONE_NEWNET).unwrap();
            del_if(&cni_ifname);
        });
        handle.join().unwrap();
        println!("{}", ipam_out_string);
    }
    if cni_command.as_str() == "CHECK" { 
        println!("{}", ipam_out_string);
    }
}
