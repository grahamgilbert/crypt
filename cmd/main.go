package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/grahamgilbert/crypt/pkg/authmechs"
	"github.com/grahamgilbert/crypt/pkg/checkin"
	"github.com/grahamgilbert/crypt/pkg/pref"
	"github.com/grahamgilbert/crypt/pkg/utils"
)

var version = "development" // nolint:gochecknoglobals

func main() {

	if os.Geteuid() != 0 {
		fmt.Println("Crypt must be run as root!")
		os.Exit(1)
	}

	install := flag.Bool("install", false, "Install the AuthDB mechanisms")
	uninstall := flag.Bool("uninstall", false, "Uninstall the AuthDB mechanisms")
	checkMechs := flag.Bool("check-auth-mechs", false, "Check the AuthDB mechanisms. Returns 0 if all are present, 1 if not.")
	versionFlag := flag.Bool("version", false, "print the version")
	flag.Parse()

	p := pref.New()
	r := utils.NewRunner()
	if *versionFlag {
		fmt.Println(version)
		os.Exit(0)
	}
	if *install {
		err := authmechs.Run(r, true)
		if err != nil {
			log.Println(err)
			os.Exit(1)
		}
	} else if *uninstall {
		err := authmechs.Run(r, false)
		if err != nil {
			log.Println(err)
			os.Exit(1)
		}
	} else if *checkMechs {
		err := authmechs.Check(r)
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
