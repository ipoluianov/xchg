package xchg

const (
	HeaderSize = 32
)

const (
	FrameInit1 = byte(0x01) // 1 -> 2: [addr1]
	FrameInit2 = byte(0x02) // 2 -> 1: [addr2]
	FrameInit3 = byte(0x03) // 2 -> 1: [enc(secret2, addr1)] // client, prove it is you
	FrameInit4 = byte(0x04) // 1 -> 2: [enc(secret2, addr2)] // it is me, client
	FrameInit5 = byte(0x05) // 1 -> 2: [enc(secret1, addr2)] // xchg,prove it is you
	FrameInit6 = byte(0x06) // 2 -> 1: [enc(secret1, addr1)] // it is me, xchg

	FrameResolveAddress  = byte(0x10) // 1 -> 2: [addr3]
	FrameResolvedAddress = byte(0x11) // 2 -> 1: [eid3]

	FrameCall     = byte(0x20) // 1 -> 2: [eid3][call_frame] --- 2 -> 3: [call_frame]
	FrameResponse = byte(0x21) // 3 -> 2: [response_frame] --- 2 -> 1: [response_frame]
	FrameError    = byte(0xFF)
)
