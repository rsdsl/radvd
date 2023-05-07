use std::io::{self, Read};
use std::net::{Ipv6Addr, SocketAddrV6};
use std::thread;
use std::time::Duration;

use ipnet::Ipv6Net;
use pnet_packet::icmpv6::ndp::{MutableRouterAdvertPacket, NdpOption, NdpOptionType, RouterAdvert};
use pnet_packet::icmpv6::{Icmpv6Code, Icmpv6Type};
use rsdsl_netlinkd::link;
use socket2::{Domain, Protocol, Socket, Type};
use thiserror::Error;

#[derive(Debug, Error)]
enum Error {
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("linkaddrs: {0}")]
    LinkAddrs(#[from] linkaddrs::Error),
    #[error("rsdsl_netlinkd: {0}")]
    RsdslNetlinkd(#[from] rsdsl_netlinkd::error::Error),
}

type Result<T> = std::result::Result<T, Error>;

fn main() -> Result<()> {
    for i in 1..=4 {
        let vlan_id = i * 10;
        let vlan_name = format!("eth0.{}", vlan_id);

        thread::spawn(move || match run(vlan_name.clone()) {
            Ok(_) => {}
            Err(e) => println!("[radvd] can't init {}: {}", vlan_name, e),
        });
    }

    run("eth0".into())?;
    Ok(())
}

fn run(link: String) -> Result<()> {
    println!("[radvd] wait for {}", link);
    link::wait_up(link.clone())?;
    thread::sleep(Duration::from_secs(1));

    println!("[radvd] init {}", link);

    let ifi = link::index(link.clone())?;

    let mut sock = Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::ICMPV6))?;

    sock.join_multicast_v6(&Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 2), ifi)?;
    sock.set_multicast_hops_v6(255)?;

    // Periodically send NDP RAs so SLAAC addresses don't expire.
    // The interval is five minutes shorter than the preferred lifetime.
    let sock2 = sock.try_clone()?;
    let link2 = link.clone();
    thread::spawn(move || loop {
        match send_ra_multicast(&sock2, &link2, ifi) {
            Ok(_) => {}
            Err(e) => println!(
                "[radvd] warning: can't send ra multicast on {}: {}",
                link2, e
            ),
        }

        thread::sleep(Duration::from_secs(1200));
    });

    let mut buf = [0; 1500];
    loop {
        let n = sock.read(&mut buf)?;
        let buf = &buf[..n];

        // Router Solicitation
        if buf[0] == 133 {
            println!("[radvd] recv nd-rs on {}", link);

            match send_ra_multicast(&sock, &link, ifi) {
                Ok(_) => {}
                Err(e) => println!(
                    "[radvd] warning: can't send ra multicast on {}: {}",
                    link, e
                ),
            }
        }
    }
}

fn send_ra_multicast(sock: &Socket, link: &str, ifi: u32) -> Result<()> {
    let all_nodes = SocketAddrV6::new(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1), 0, 0, ifi).into();
    let global = Ipv6Net::new(Ipv6Addr::new(0x2000, 0, 0, 0, 0, 0, 0, 0), 3).unwrap();

    let mut ndp_opts = Vec::new();
    let mut prefs = Vec::new();

    for prefix in linkaddrs::ipv6_addresses(link.to_owned())?
        .into_iter()
        .filter(|addr| global.contains(addr))
    {
        let mut prefix_data = [
            64,   // Prefix Length, always /64
            0xc0, // Flags: On-Link + SLAAC
            0, 0, 0x07, 0x08, // Valid Lifetime: 1800s
            0, 0, 0x05, 0xdc, // Preferred Lifetime: 1500s
            0, 0, 0, 0, // Reserved
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // Prefix (inserted later)
        ];
        prefix_data[14..].copy_from_slice(&prefix.trunc().addr().octets());

        prefs.push(prefix);

        ndp_opts.push(NdpOption {
            option_type: NdpOptionType::new(3),
            length: 4,
            data: prefix_data.to_vec(),
        });
    }

    let adv = RouterAdvert {
        icmpv6_type: Icmpv6Type::new(134),
        icmpv6_code: Icmpv6Code::new(0),
        checksum: 0,
        hop_limit: 64,
        flags: 0,
        lifetime: 1800,
        reachable_time: 0,
        retrans_time: 0,
        options: ndp_opts.clone(),
        /*NdpOption {
            option_type: NdpOptionType::new(25),
            length: 3,
            data: vec![
                0, 0, 0xff, 0xff, 0xff, 0xff, 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 1,
            ],
        },*/
        payload: vec![],
    };

    let mut buf = Vec::new();
    buf.resize(16 + (32 * ndp_opts.len()), 0);

    let mut pkt = MutableRouterAdvertPacket::new(&mut buf).unwrap();
    pkt.populate(&adv);

    sock.send_to(&buf, &all_nodes)?;

    let prefixes = prefs
        .into_iter()
        .map(|prefix| format!("{}", prefix))
        .reduce(|acc, prefix| acc + &prefix)
        .unwrap_or(String::from("::/64"));

    println!("[radvd] send multicast nd-ra {} on {}", prefixes, link);
    Ok(())
}
