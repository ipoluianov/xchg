package core

type Statistics struct {
	Core  CoreStat  `json:"core"`
	Info  InfoStat  `json:"info"`
	Ping  PingStat  `json:"ping"`
	Init1 Init1Stat `json:"init1"`
	Init2 Init2Stat `json:"init2"`
	Pull  PullStat  `json:"pull"`
	Call  CallStat  `json:"call"`
	Put   PutStat   `json:"put"`
}
