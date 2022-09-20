# 0x00 - Ping Request
    00 00 00 00 00 00 00 00

## Behavior of Router
responds with frame 0x01

## Behavior of Node
responds with frame 0x01

---

# 0x01 - Ping Response
    01 00 00 00 00 00 00 00

## Behavior of Router
no action

## Behavior of Node
no action

---

# 0x02 - Nonce Request
    02 00 00 00 00 00 00 00

## Behavior of Router
sends frame 0x03

## Behavior of Node
no action

---

# 0x03 - Nonce Response
    03 00 00 00 00 00 00 00 nonce[8:24]

## Behavior of Router
no action

## Behavior of Node
sends frame 0x04

---

# 0x04 - Declare Routing Data for Native Address
    04 00 00 00 00 00 00 00 [nonce[8:24]] [salt[24:32]] [sign[32:288]] [pkLen[288:292]] [pk[292:292+pkLen]] [data[292+pkLen:]]

## Behavior of Router
- check Nonce
- check SHA256(nonce+salt) - PoW
- check signature (SHA256(nonce+salt), pk)
- add the data to the block linked to the address

## Behavior of Node
no action

---

# 0x05 - Declare Routing Data for Native Address - Response
    05 CC 00 00 00 00 00 00

## Description
### Values of CC
    00 = SUCCESS
    01 = ERROR

## Behavior of Router
no action

## Behavior of Node
no action

---

# 0x06 - Get Data for Native Address 
    06 00 00 00 00 00 00 00 [native address]

## Behavior of Router
no action

## Behavior of Node
no action    

---

# 0x07 - Get Data for Native Address Response
    07 00 00 00 00 00 00 00 [native address] 3D('=') [data]

## Behavior of Router
no action

## Behavior of Node
no action

---

# 0x08 - Resolve Custom Address
    08 00 00 00 00 00 00 00 [address]

## Behavior of Router
sends frame 0x09

## Behavior of Node
no action

---

# 0x09 - Resolve Custom Address
    09 00 00 00 00 00 00 00 [address] 3D('=') [native address]

## Behavior of Router
no action

## Behavior of Node
no action

---

# 0x10 - Call
# 0x11 - Response

# 0x20 - LAN ARP Request
# 0x21 - LAN ARP Response
# 0x22 - Get Public Key Request
# 0x23 - Get Public Key Response
