use std::io::{self, Read};
use std::net::{Ipv6Addr, SocketAddrV6};

use pnet_packet::icmpv6::ndp::{MutableRouterAdvertPacket, NdpOption, NdpOptionType, RouterAdvert};
use pnet_packet::icmpv6::{Icmpv6Code, Icmpv6Type};
use rsdsl_netlinkd::error::Result;
use rsdsl_netlinkd::link;
use socket2::{Domain, Protocol, Socket, Type};

fn main() -> Result<()> {
    run("eth0".into())?;
    Ok(())
}

fn run(link: String) -> Result<()> {
    println!("[radvd] init {}", link);

    let ifi = link::index(link.clone())?;

    let mut sock = Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::ICMPV6))?;

    sock.join_multicast_v6(&Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 2), ifi)?;
    sock.set_multicast_hops_v6(255)?;

    send_ra_multicast(&sock, &link, ifi)?;

    let mut buf = [0; 1500];
    loop {
        let n = sock.read(&mut buf)?;
        let buf = &buf[..n];

        // Router Solicitation
        if buf[0] == 133 {
            println!("[radvd] recv nd-rs on {}", link);
            send_ra_multicast(&sock, &link, ifi)?;
        }
    }
}

fn send_ra_multicast(sock: &Socket, link: &str, ifi: u32) -> io::Result<()> {
    let all_nodes = SocketAddrV6::new(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1), 0, 0, ifi).into();

    let adv = RouterAdvert {
        icmpv6_type: Icmpv6Type::new(134),
        icmpv6_code: Icmpv6Code::new(0),
        checksum: 0,
        hop_limit: 64,
        flags: 0,
        lifetime: 1800,
        reachable_time: 0,
        retrans_time: 0,
        options: vec![
            NdpOption {
                option_type: NdpOptionType::new(3),
                length: 4,
                data: vec![
                    64, 0b11000000, 0, 0, 0, 30, 0, 0, 0, 20, 0, 0, 0, 0, 0x20, 0x01, 0xab, 0xab,
                    0xab, 0xbe, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                ],
            },
            /*NdpOption {
                option_type: NdpOptionType::new(25),
                length: 3,
                data: vec![
                    0, 0, 0xff, 0xff, 0xff, 0xff, 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 1,
                ],
            },*/
        ],
        payload: vec![],
    };

    let mut buf = [0; 16 + 32];
    let mut pkt = MutableRouterAdvertPacket::new(&mut buf).unwrap();
    pkt.populate(&adv);

    sock.send_to(&buf, &all_nodes)?;

    println!("[radvd] send multicast nd-ra ::/64 on {}", link);
    Ok(())
}
