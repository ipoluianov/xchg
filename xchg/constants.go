package xchg

const (
	HeaderSize = 32
)

const (
	FuncPing           = byte(0x00)
	FuncResolveAddress = byte(0x01)
	FuncCall           = byte(0x02)
	FuncSend           = byte(0x03)
	FuncDeclareAddr    = byte(0x04)
	FuncConfirmAddr    = byte(0x05)
	FuncResponse       = byte(0x06)
)

const (
	FrameCodeSuccess = byte(0x00)
	FrameCodeError   = byte(0xFF)
)
