package app

import (
	"crypto/rsa"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/ipoluianov/gomisc/crypt_tools"
	"github.com/ipoluianov/gomisc/logger"
	"github.com/ipoluianov/xchg/xchg"
	"github.com/ipoluianov/xchg/xchg_localtest"
	"github.com/ipoluianov/xchg/xchg_network"
	"github.com/ipoluianov/xchg/xchg_router"
	"github.com/kardianos/osext"
	"github.com/kardianos/service"
)

var ServiceName string
var ServiceDisplayName string
var ServiceDescription string
var ServiceRunFunc func() error
var ServiceStopFunc func()

func SetAppPath() {
	exePath, _ := osext.ExecutableFolder()
	err := os.Chdir(exePath)
	if err != nil {
		return
	}
}

func init() {
	SetAppPath()
}

func TryService() bool {
	serviceFlagPtr := flag.Bool("service", false, "Run as service")
	installFlagPtr := flag.Bool("install", false, "Install service")
	uninstallFlagPtr := flag.Bool("uninstall", false, "Uninstall service")
	startFlagPtr := flag.Bool("start", false, "Start service")
	stopFlagPtr := flag.Bool("stop", false, "Stop service")
	selftestFlagPtr := flag.Bool("selftest", false, "Self test")
	simpleServerFlagPtr := flag.Bool("simple-server", false, "Simple Server")
	simpleClientFlagPtr := flag.Bool("simple-client", false, "Simple Client")

	flag.Parse()

	if *serviceFlagPtr {
		runService()
		return true
	}

	if *installFlagPtr {
		InstallService()
		return true
	}

	if *uninstallFlagPtr {
		UninstallService()
		return true
	}

	if *startFlagPtr {
		StartService()
		return true
	}

	if *stopFlagPtr {
		StopService()
		return true
	}

	if *selftestFlagPtr {
		xchg_localtest.SelfTest()
		return true
	}

	if *simpleClientFlagPtr {
		xchg_localtest.SimpleClient()
		return true
	}

	if *simpleServerFlagPtr {
		xchg_localtest.SimpleServer()
		return true
	}

	return false
}

func NewSvcConfig() *service.Config {
	var SvcConfig = &service.Config{
		Name:        ServiceName,
		DisplayName: ServiceDisplayName,
		Description: ServiceDescription,
	}
	SvcConfig.Arguments = append(SvcConfig.Arguments, "-service")
	return SvcConfig
}

func InstallService() {
	fmt.Println("Service installing")
	prg := &program{}
	s, err := service.New(prg, NewSvcConfig())
	if err != nil {
		log.Fatal(err)
	}
	err = s.Install()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Service installed")
}

func UninstallService() {
	fmt.Println("Service uninstalling")
	prg := &program{}
	s, err := service.New(prg, NewSvcConfig())
	if err != nil {
		log.Fatal(err)
	}
	err = s.Uninstall()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Service uninstalled")
}

func StartService() {
	fmt.Println("Service starting")
	prg := &program{}
	s, err := service.New(prg, NewSvcConfig())
	if err != nil {
		log.Fatal(err)
	}
	err = s.Start()
	if err != nil {
		log.Fatal(err)
	} else {
		fmt.Println("Service started")
	}
}

func StopService() {
	fmt.Println("Service stopping")
	prg := &program{}
	s, err := service.New(prg, NewSvcConfig())
	if err != nil {
		log.Fatal(err)
	}
	err = s.Stop()
	if err != nil {
		log.Fatal(err)
		return
	} else {
		fmt.Println("Service stopped")
	}
}

func runService() {
	prg := &program{}
	s, err := service.New(prg, NewSvcConfig())
	if err != nil {
		log.Fatal(err)
	}
	err = s.Run()
	if err != nil {
		logger.Error(err)
	}
}

type program struct{}

func (p *program) Start(_ service.Service) error {
	return ServiceRunFunc()
}

func (p *program) Stop(_ service.Service) error {
	ServiceStopFunc()
	return nil
}

/////////////////////////////
var srv *xchg_router.RouterServer
var router *xchg_router.Router

func Start() error {
	logger.Println("[i]", "App::Start", "begin")
	TuneFDs()

	conf, err := xchg_router.LoadConfigFromFile(logger.CurrentExePath() + "/" + "config.json")
	if err != nil {
		logger.Println("[i]", "App::Start", "xchg_router.LoadConfigFromFile error:", err)
		return err
	}

	network := xchg_network.NewNetworkFromFileOrCreate(logger.CurrentExePath() + "/" + "network.json")

	var privateKey *rsa.PrivateKey
	privateKey, err = LoadKeys()
	if err != nil {
		logger.Println("[i]", "App::Start", "LoadKeys() error:", err)
		return err
	}

	router = xchg_router.NewRouter(privateKey, conf, network)
	router.Start()

	logger.Println("[i]", "App::Start", "end")

	return nil
}

func LoadKeys() (privateKey *rsa.PrivateKey, err error) {

	privateKeyFile := logger.CurrentExePath() + "/" + "/private_key.pem"
	publicKeyFile := logger.CurrentExePath() + "/" + "/public_key.pem"
	addressFile := logger.CurrentExePath() + "/" + "/address.txt"

	_, err = os.Stat(privateKeyFile)
	if os.IsNotExist(err) {
		privateKey, err = crypt_tools.GenerateRSAKey()
		if err != nil {
			return
		}
		err = ioutil.WriteFile(privateKeyFile, []byte(crypt_tools.RSAPrivateKeyToPem(privateKey)), 0666)
		if err != nil {
			return
		}
		err = ioutil.WriteFile(publicKeyFile, []byte(crypt_tools.RSAPublicKeyToPem(&privateKey.PublicKey)), 0666)
		if err != nil {
			return
		}
		logger.Println("Key saved to file")
	} else {
		var bs []byte
		bs, err = ioutil.ReadFile(privateKeyFile)
		if err != nil {
			return
		}
		privateKey, err = crypt_tools.RSAPrivateKeyFromPem(string(bs))
		if err != nil {
			return
		}
		logger.Println("Key loaded from file")
	}

	address := xchg.AddressForPublicKey(&privateKey.PublicKey)
	err = ioutil.WriteFile(addressFile, []byte(address), 0666)
	//c.serverPrivateKey32 = base32.StdEncoding.EncodeToString([]byte(crypt_tools.RSAPrivateKeyToDer(privateKey)))
	logger.Println("ADDRESS:", address)
	return
}

func Stop() {
	srv.Stop()
}

func RunConsole() {
	logger.Println("[i]", "App::RunConsole", "begin")
	err := Start()
	if err != nil {
		logger.Println("[ERROR]", "App::RunConsole", "Start error:", err)
		return
	}
	_, _ = fmt.Scanln()
	logger.Println("[i]", "App::RunConsole", "end")
}

func RunAsServiceF() error {
	return Start()
}

func StopServiceF() {
	Stop()
}
