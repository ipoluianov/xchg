# xchg
xchg - Lightweight tool for PrP communication.

PrP (Peer-Router-Peer) - communication between peers through a layer of routers. Direct communication between peers is often a tricky thing. XCHG is a lightweight tool to establish communication between peers using private or public xchg-networks.

# xchg is
- a Protocol with Peer-to-Peer encryption (AES-256/RSA-2048)
- an open source XCHG Router (golang)
- public network of routers
- authentication(P2P) is built into the protocol
- SDK for multiple programming languages
- an ability to create your own network of routers for your services

## router role
- accepts peer-connections via TCP
- checks whether an address belongs to a peer
- tells which peers are connected
- translate calls between peers

## server role
- maintains connections to the subnet corresponding to its address
- verifies your address with your private key
- accepts and fulfills requests from peers

## client role
- maintains a connection to the router hosting the destination peer
- verifies your address with your private key
- sends requests to the destination peer through the router
