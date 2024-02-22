package main

import (
	"log"
	"os"

	"github.com/grahamgilbert/crypt/pkg/checkin"
	"github.com/grahamgilbert/crypt/pkg/pref"
	"github.com/grahamgilbert/crypt/pkg/utils"
)

func main() {

	p := pref.New()
	r := utils.NewRunner()

	err := checkin.RunEscrow(r, p)
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}
	os.Exit(0)
}
