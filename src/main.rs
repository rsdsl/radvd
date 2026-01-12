use std::io;
use std::mem::MaybeUninit;
use std::net::{IpAddr, Ipv6Addr, SocketAddrV6};
use std::thread;
use std::time::Duration;

use pnet_packet::icmpv6::ndp::{MutableRouterAdvertPacket, NdpOption, NdpOptionType, RouterAdvert};
use pnet_packet::icmpv6::{Icmpv6Code, Icmpv6Type};
use rsdsl_netlinklib::blocking::Connection;
use signal_hook::{consts::SIGUSR1, iterator::Signals};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use thiserror::Error;

const PI_PREFIX: u128 = 0x200106780b2400000000000000000000;
const PI_MASK: u128 = 0xffffffffffff00000000000000000000;

#[derive(Debug, Error)]
enum Error {
    #[error("sockaddr is not an ipv6 address")]
    SockAddrNotIpv6,

    #[error("io: {0}")]
    Io(#[from] io::Error),

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
            Err(e) => eprintln!("[warn] error on {}: {}", link, e),
        }
    }
}

fn run(link: String) -> Result<()> {
    let conn = Connection::new()?;

    eprintln!("[info] wait for {}", link);
    conn.link_wait_up(link.clone())?;
    thread::sleep(Duration::from_secs(1));

    eprintln!("[info] init {}", link);

    let ifi = conn.link_index(link.clone())?;

    let sock = Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::ICMPV6))?;

    sock.bind_device(Some(link.as_bytes()))?;

    sock.join_multicast_v6(&Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 2), ifi)?;

    sock.set_multicast_hops_v6(255)?;
    sock.set_unicast_hops_v6(255)?;

    // Periodically send NDP RAs so SLAAC addresses don't expire.
    // The interval is five minutes shorter than the preferred lifetime.
    let sock2 = sock.try_clone()?;
    let link2 = link.clone();
    thread::spawn(move || loop {
        match send_ra_multicast(&sock2, link2.clone(), ifi) {
            Ok(_) => {}
            Err(e) => eprintln!("[warn] multicast ra {}: {}", link2, e),
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
                    Err(e) => eprintln!("[warn] sig multicast ra {}: {}", link2, e),
                }
            }
        }
        Err(e) => eprintln!("[warn] no signal handling on {}: {}", link2, e),
    });

    loop {
        let mut buf = [MaybeUninit::new(0); 1500];
        let (n, raddr) = sock.recv_from(&mut buf)?;

        // See unstable `MaybeUninit::slice_assume_init_ref`.
        let buf = unsafe { &*(&buf as *const [MaybeUninit<u8>] as *const [u8]) };

        let buf = &buf[..n];

        // Router Solicitation
        if buf[0] == 133 {
            eprintln!("[info] recv rs {}", link);

            match send_ra_unicast(&sock, link.clone(), &raddr) {
                Ok(_) => {}
                Err(e) => eprintln!(
                    "[warn] unicast ra {} to {}: {}",
                    link,
                    raddr.as_socket_ipv6().ok_or(Error::SockAddrNotIpv6)?.ip(),
                    e
                ),
            }
        }
    }
}

fn create_ra_pkt(link: String) -> Result<(Vec<u8>, Vec<Ipv6Addr>)> {
    let conn = Connection::new()?;

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

    let ipv6_addrs = conn.address_get(link)?.into_iter().filter_map(|addr| {
        if let IpAddr::V6(v6) = addr {
            Some(v6)
        } else {
            None
        }
    });

    for prefix in ipv6_addrs.filter(should_advertise) {
        let mut prefix_data = [
            64,   // Prefix Length, always /64
            0xc0, // Flags: On-Link + SLAAC
            0, 0, 0x07, 0x08, // Valid Lifetime: 1800s
            0, 0, 0x05, 0xdc, // Preferred Lifetime: 1500s
            0, 0, 0, 0, // Reserved
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // Prefix (inserted later)
        ];
        prefix_data[14..].copy_from_slice(&prefix.octets());

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

    let mut buf = vec![0; 16 + 24 + 32 * (ndp_opts.len() - 1)];

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
        .map(|prefix| format!("{}/64", prefix))
        .reduce(|acc, prefix| acc + ", " + &prefix)
        .unwrap_or(String::from("::/64"));

    eprintln!("[info] multicast ra {} net {}", link, prefixes);
    Ok(())
}

fn send_ra_unicast(sock: &Socket, link: String, raddr: &SockAddr) -> Result<()> {
    let (pkt, pkt_prefixes) = create_ra_pkt(link.clone())?;
    sock.send_to(&pkt, raddr)?;

    let prefixes = pkt_prefixes
        .into_iter()
        .map(|prefix| format!("{}/64", prefix))
        .reduce(|acc, prefix| acc + ", " + &prefix)
        .unwrap_or(String::from("::/64"));

    eprintln!(
        "[info] unicast ra {} to {} net {}",
        link,
        raddr.as_socket_ipv6().ok_or(Error::SockAddrNotIpv6)?.ip(),
        prefixes
    );
    Ok(())
}

/// Checks whether an IPv6 address is part of the `2000::/3` network.
fn is_gua(addr: &Ipv6Addr) -> bool {
    let first_octet_trunc = addr.octets()[0] & 0xe0;
    first_octet_trunc == 0x20
}

/// Checks whether an IPv6 address is part of the `fc00::/7` network.
fn is_ula(addr: &Ipv6Addr) -> bool {
    // Stable implementation of [`Ipv6Addr::is_unique_local`].
    // Tracking issue: https://github.com/rust-lang/rust/issues/27709 for
    (addr.segments()[0] & 0xfe00) == 0xfc00
}

/// Checks whether an IPv6 address is part of the network's PI prefix.
fn is_pi(addr: &Ipv6Addr) -> bool {
    addr.to_bits() & PI_MASK == PI_PREFIX
}

/// Checks whether an IPv6 subnet address should be advertised.
fn should_advertise(addr: &Ipv6Addr) -> bool {
    (is_gua(addr) || is_ula(addr)) && !is_pi(addr)
}
