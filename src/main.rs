use std::io;
use std::mem::MaybeUninit;
use std::net::{Ipv6Addr, SocketAddrV6};
use std::thread;
use std::time::Duration;

use ipnet::Ipv6Net;
use pnet_packet::icmpv6::ndp::{MutableRouterAdvertPacket, NdpOption, NdpOptionType, RouterAdvert};
use pnet_packet::icmpv6::{Icmpv6Code, Icmpv6Type};
use rsdsl_netlinklib::blocking::link;
use signal_hook::{consts::SIGUSR1, iterator::Signals};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use thiserror::Error;

#[derive(Debug, Error)]
enum Error {
    #[error("sockaddr is not an ipv6 address")]
    SockAddrNotIpv6,

    #[error("io: {0}")]
    Io(#[from] io::Error),

    #[error("linkaddrs: {0}")]
    LinkAddrs(#[from] linkaddrs::Error),
    #[error("netlinklib error: {0}")]
    Netlinklib(#[from] rsdsl_netlinklib::Error),
}

type Result<T> = std::result::Result<T, Error>;

const LINK_LOCAL: Ipv6Addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);

fn main() -> Result<()> {
    for i in 1..=4 {
        let vlan_id = i * 10;
        let vlan_name = format!("eth0.{}", vlan_id);

        thread::spawn(move || run_supervised(vlan_name));
    }

    run_supervised("eth0".into());
}

fn run_supervised(link: String) -> ! {
    loop {
        match run(link.clone()) {
            Ok(_) => {}
            Err(e) => println!("[warn] error on {}: {}", link, e),
        }
    }
}

fn run(link: String) -> Result<()> {
    println!("[info] wait for {}", link);
    link::wait_up(link.clone())?;
    thread::sleep(Duration::from_secs(1));

    println!("init {}", link);

    let ifi = link::index(link.clone())?;

    let sock = Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::ICMPV6))?;

    sock.join_multicast_v6(&Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 2), ifi)?;
    sock.set_multicast_hops_v6(255)?;

    // Periodically send NDP RAs so SLAAC addresses don't expire.
    // The interval is five minutes shorter than the preferred lifetime.
    let sock2 = sock.try_clone()?;
    let link2 = link.clone();
    thread::spawn(move || loop {
        match send_ra_multicast(&sock2, link2.clone(), ifi) {
            Ok(_) => {}
            Err(e) => println!("[warn] multicast ra {}: {}", link2, e),
        }

        thread::sleep(Duration::from_secs(120));
    });

    // Send NDP RAs when SIGUSR1 is received.
    // This updates the prefixes whenever netlinkd informs us of a change.
    let sock2 = sock.try_clone()?;
    let link2 = link.clone();
    thread::spawn(move || match Signals::new([SIGUSR1]) {
        Ok(mut signals) => {
            for _ in signals.forever() {
                match send_ra_multicast(&sock2, link2.clone(), ifi) {
                    Ok(_) => {}
                    Err(e) => println!("[warn] sig multicast ra {}: {}", link2, e),
                }
            }
        }
        Err(e) => println!("[warn] no signal handling on {}: {}", link2, e),
    });

    loop {
        let mut buf = [MaybeUninit::new(0); 1500];
        let (n, raddr) = sock.recv_from(&mut buf)?;

        // See unstable `MaybeUninit::slice_assume_init_ref`.
        let buf = unsafe { &*(&buf as *const [MaybeUninit<u8>] as *const [u8]) };

        let buf = &buf[..n];

        // Router Solicitation
        if buf[0] == 133 {
            println!("[info] recv rs {}", link);

            match send_ra_unicast(&sock, link.clone(), &raddr) {
                Ok(_) => {}
                Err(e) => println!(
                    "[warn] unicast ra {} to {}: {}",
                    link,
                    raddr.as_socket_ipv6().ok_or(Error::SockAddrNotIpv6)?.ip(),
                    e
                ),
            }
        }
    }
}

fn create_ra_pkt(link: String) -> Result<(Vec<u8>, Vec<Ipv6Net>)> {
    let global = Ipv6Net::new(Ipv6Addr::new(0x2000, 0, 0, 0, 0, 0, 0, 0), 3).unwrap();

    let mut rdnss_data = [
        0, 0, // Reserved
        0, 0, 0x07, 0x08, // Lifetime: 1800s
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // DNS1 (inserted later)
    ];
    rdnss_data[6..].copy_from_slice(&LINK_LOCAL.octets());

    let mut ndp_opts = vec![NdpOption {
        option_type: NdpOptionType::new(25),
        length: 3,
        data: rdnss_data.to_vec(),
    }];
    let mut prefixes = Vec::new();

    for prefix in linkaddrs::ipv6_addresses(link)?
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

        prefixes.push(prefix);

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
        payload: vec![],
    };

    let mut buf = Vec::new();
    buf.resize(16 + 24 + 32 * (ndp_opts.len() - 1), 0);

    let mut pkt = MutableRouterAdvertPacket::new(&mut buf).unwrap();
    pkt.populate(&adv);

    Ok((buf, prefixes))
}

fn send_ra_multicast(sock: &Socket, link: String, ifi: u32) -> Result<()> {
    let all_nodes = SocketAddrV6::new(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1), 0, 0, ifi).into();

    let (pkt, pkt_prefixes) = create_ra_pkt(link.clone())?;
    sock.send_to(&pkt, &all_nodes)?;

    let prefixes = pkt_prefixes
        .into_iter()
        .map(|prefix| format!("{}", prefix))
        .reduce(|acc, prefix| acc + ", " + &prefix)
        .unwrap_or(String::from("::/64"));

    println!("[info] multicast ra {} net {}", link, prefixes);
    Ok(())
}

fn send_ra_unicast(sock: &Socket, link: String, raddr: &SockAddr) -> Result<()> {
    let (pkt, pkt_prefixes) = create_ra_pkt(link.clone())?;
    sock.send_to(&pkt, raddr)?;

    let prefixes = pkt_prefixes
        .into_iter()
        .map(|prefix| format!("{}", prefix))
        .reduce(|acc, prefix| acc + ", " + &prefix)
        .unwrap_or(String::from("::/64"));

    println!(
        "[info] unicast ra {} to {} net {}",
        link,
        raddr.as_socket_ipv6().ok_or(Error::SockAddrNotIpv6)?.ip(),
        prefixes
    );
    Ok(())
}
