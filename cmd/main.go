package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/grahamgilbert/crypt/pkg/checkin"
	"github.com/grahamgilbert/crypt/pkg/postinstall"
	"github.com/grahamgilbert/crypt/pkg/pref"
	"github.com/grahamgilbert/crypt/pkg/utils"
)

var version = "development" // nolint:gochecknoglobals

func main() {

	install := flag.Bool("install", false, "Install the AuthDB mechanisms")
	uninstall := flag.Bool("uninstall", false, "Uninstall the AuthDB mechanisms")
	versionFlag := flag.Bool("version", false, "print the version")
	flag.Parse()

	p := pref.New()
	r := utils.NewRunner()
	if *versionFlag {
		fmt.Println(version)
		os.Exit(0)
	}
	if *install {
		err := postinstall.Run(r, true)
		if err != nil {
			log.Println(err)
			os.Exit(1)
		}
	} else if *uninstall {
		err := postinstall.Run(r, false)
		if err != nil {
			log.Println(err)
			os.Exit(1)
		}
	} else {
		err := checkin.RunEscrow(r, p)
		if err != nil {
			log.Println(err)
			os.Exit(1)
		}
	}

	os.Exit(0)
}
