UDP Broadcast Relay for Linux / FreeBSD / pfSense / OPNsense
============================================================
( For Opensense a plugin is already available )

This program listens for packets on a specified UDP broadcast port. When
a packet is received, it sends that packet to all specified interfaces
but the one it came from as though it originated from the original
sender.

The primary purpose of this is to allow devices or game servers on separated
local networks (Ethernet, WLAN, VLAN) that use udp broadcasts to find each
other to do so.

INSTALL
-------

    make
    cp udpbroadcastrelay /some/where

USAGE
-----

```
./udpbroadcastrelay \
    -id id \
    --port <udp-port> \
    --dev eth0 --dev eth1
    [--dev ethx...] \
    [--blockid id...] \
    [--blockcidr network-prefix/size] \
    [--allowcidr network-prefix/size] \
    [--msearch action[,search-term]] \   
    [--multicast 224.0.0.251] \
    [-s <spoof_source_ip>]
    [-t|--ttl-id] [-d] [-f]
    [-h|--help]
```

- udpbroadcastrelay must be run as root to be able to create a raw
  socket (necessary) to send packets as though they originated from the
  original sender.
- `id` must be unique number between instances with range 1 - 63. This is
  used to set the DSCP of outgoing packets to determine if a packet is an
  echo and should be discarded.
- `blockid` can be used to drop packets received from other instances of
  udpbroadcastrelay using the specified ID value.
- `--blockcidr` can be used to block packets from a range of IP source
  addresses, given in CIDR notation. This option can be specified multiple
  times to block more than one range. Where multiple overlapping CIDRs are
  specified with the `--blockcidr` and `--allowcidr` options the most
  specific match (longest prefix) will take effect.
- `--allowcidr` can be used to only allow packets from a range of IP source
  addresses, given in CIDR notation. This option can be specified multiple
  times to allow more than one range. Once this option is specified the
  default behaviour for packets which does not any CIDRs changes from
  Allow to Block.
- `udp-port` Destination udp port to listen to. Range 1 - 65535.
  Example values for common services are given below.
- `-dev <ethx>` specifies the name of an interface to receive and
  transmit packets on. This option needs to be specified at least twice
  for 2 separate interfaces otherwise this tool won't actually do
  anything!
- The tool can listen for and relay packets using multicast groups
  with
  `--multicast <group address>`.
- The source address for all packets can be modified with `-s <ip>`. This
  is unusual.
- A special source ip of `-s 1.1.1.1` can be used to set the source ip of the relayed packet
  to the ip address of the relay destiantion interface. Additionally, the source UDP port for the destination interface is set to the
  same as the original packet's destination port. `-s 1.1.1.2` does the same but leaves
  the UDP ports unchanged. These values are notably required to cater
  for the Chromecast system.
- Special SSDP processing can be turned on using the `--msearch` option.
  By default SSDP M-SEARCH packets are treated the same as any other
  packet. The `action` parameter changes this default:
  - `block`:  drop the M-SEARCH packet.
  - `fwd`:    forward the M-SEARCH packet like a regular packet (and the
  `-s` into account).
  - `proxy`:  create a local proxy for M-SEARCH requests. Set the M-SEARCH UDP source to the IP of the relay's destination network
   interface before relaying.
   Addtionally, the UDP source port is updated to a port that is tracked by
   the proxy for relaying responses back to the correct requesting host.
   Received responses are sent back to original requester with no processing. 
   i.e. the requester will receive an SSDP reponse with a LOCATION referencing
   a host on the other network.
  - `dial`:   perform full DIAL protocol processing on M-SEARCH request.
  Create proxies for M-SEARCH (same as `proxy`), Locator and REST services. Use this for
  Youtube app on Smart TVs. 
  
  When a `search-term` is also specified the given action will only apply
  to M-SEARCH packets containing this specific search term. `--msearch`
  can be specified multiple times to add more search terms. The value of `-s`
  affects normal and M-SEARCH packets with the forward action.
  
  The old `-s 1.1.1.3` option should be replaced with `--msearch dial`.
  
- The original version of this tool marked the TTL of outgoing relayed
  packets to detect echos and preserved DSCP. This original behavior can
  be restored by setting the [-t|--ttl-id] parameter.
- `-d` will enable debugging output. Specify `-d` twice for extra debugging info
- `-f` will fork the application to the background and create a pid file
  at /var/run/udpbroadcastrelay_ID.pid
- `-h|--help` Display a detailed help dialog.

EXAMPLE
-------

#### mDNS / Multicast DNS (Chromecast Discovery + Bonjour + More)
`./udpbroadcastrelay --id 1 --port 5353 --dev eth0 --dev eth1 --multicast 224.0.0.251 -s 1.1.1.1`

(Chromecast requires broadcasts to originate from an address on its subnet)

#### mDNS example which allows messages from hosts on 192.168.1.0/24 and 192.168.20.0/24 subnets but blocks host 192.168.20.20
`./udpbroadcastrelay --id 1 --port 5353 --dev eth0 --dev eth1 --multicast 224.0.0.251 -s 1.1.1.1 --allowcidr 192.168.1.0/24 --allowcidr 192.168.20.0/24 --blockcidr 192.168.20.20/32`

This will prevent relaying broadcast/multicast packets from host 192.168.20.20. It will not stop any unicast traffic from this host.
 
#### SSDP (Roku Discovery, DLNA Media, Sonos, UPnP + More)
`./udpbroadcastrelay --id 1 --port 1900 --dev eth0 --dev eth1 --multicast 239.255.255.250`

#### Youtube Application on Smart TV
`./udpbroadcastrelay --id 1 --dev eth0 --dev eth1 --port 1900 --multicast 239.255.255.250 -s 1.1.1.2 --msearch dial`

#### Youtube Application on Smart TV along with DLNA media playback
`./udpbroadcastrelay --id 1 --dev eth0 --dev eth1 --port 1900 --multicast 239.255.255.250 -s 1.1.1.2 --msearch proxy,urn:schemas-upnp-org:device:MediaServer:1 --msearch dial`

#### Lifx Bulb Discovery
`./udpbroadcastrelay --id 1 --port 56700 --dev eth0 --dev eth1`

#### Broadlink IR Emitter Discovery
`./udpbroadcastrelay --id 1 --port 80 --dev eth0 --dev eth1`

#### Warcraft 3 Server Discovery
`./udpbroadcastrelay --id 1 --port 6112 --dev eth0 --dev eth1`

#### Windows Network Neighborhood Discovery
 NetBIOS Name Service (137), SMB Browser (138) and SSDP (1900).
 Windows Network Discovery across networks relies on relaying
 these three protocols all at once.
 To requires that three separate instances of udpbroadcastrelay
 run simultaneously so in this example we execute the command
 with the "-f" parameter in order to run the tool in the
 background.
`./udpbroadcastrelay --id 1 --port 137 --dev eth0 --dev eth1 -f`
`./udpbroadcastrelay --id 2 --port 138 --dev eth0 --dev eth1 -f`
`./udpbroadcastrelay --id 3 --port 1900 --dev eth0 --dev eth1 --multicast 239.255.255.250 -f`

#### Syncthing Discovery
`./udpbroadcastrelay --id 1 --port 21027 --dev eth0 --dev eth1`

#### Raknet Discovery (Minecraft)
`./udpbroadcastrelay --id 1 --port 19132 --dev eth0 --dev eth1`

Note about firewall rules
---

If you are running udpbroadcastrelay on a router, it can be an easy
way to relay broadcasts between VLANs. However, beware that these broadcasts
will not establish a RELATED firewall relationship between the source and
destination addresses.

This means if you have strict firewall rules, the recipient may not be able
to respond to the broadcaster. For instance, the SSDP protocol involves
sending a broadcast packet to port 1900 to discover devices on the network.
The devices then respond to the broadcast with a unicast packet back to the
original sender. You will need to make sure that your firewall rules allow
these response packets to make it back to the original sender.


Recent changes
--------------

- Added --blockcidr and --allowcidr options
- Print interface names instead of numbers in packet information messages
- Removed the `-s 1.1.1.3` option and replaced it with a more general `--msearch`
  option, which allows finer control (see USAGE section)
- Updated the expiry time for M-SEARCH, Locator and REST proxies.
- Fixed build information not being printed when `-d` is specififed
- Introduced a second level of debug info, activated by specifying `-d` twice

Please note: Maintenance of this project is on a 'when I have a moment' basis, and that may be several months.
