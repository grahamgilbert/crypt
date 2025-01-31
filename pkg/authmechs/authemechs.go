package authmechs

import (
	"errors"
	"fmt"
	"log"
	"os"
	"reflect"

	"github.com/grahamgilbert/crypt/pkg/utils"
	"github.com/groob/plist"
)

var (
	fv2Mechs         = []string{"Crypt:Check,privileged"}
	fv2MechsToRemove = []string{"Crypt:Check,privileged", "Crypt:CryptGUI", "Crypt:Enablement,privileged"}
	fv2IndexMech     = "loginwindow:done"
	fv2IndexOffset   = 0
)

type AuthDB struct {
	Class      string   `plist:"class"`
	Comment    string   `plist:"comment"`
	Created    float64  `plist:"created"`
	Modified   float64  `plist:"modified"`
	Shared     bool     `plist:"shared"`
	Tries      int      `plist:"tries"`
	Version    int      `plist:"version"`
	Mechanisms []string `plist:"mechanisms"`
}

func removeMechsInDB(db AuthDB, mechList []string) AuthDB {
	for i := len(db.Mechanisms) - 1; i >= 0; i-- {
		for _, mechToRemove := range mechList {
			if db.Mechanisms[i] == mechToRemove {
				db.Mechanisms = append(db.Mechanisms[:i], db.Mechanisms[i+1:]...)
				break
			}
		}
	}

	return db
}

func checkMechsInDB(db AuthDB, mechList []string, indexMech string, indexOffset int) bool {
	insertIndex := indexOf(db.Mechanisms, indexMech) - len(mechList) // start from the position before the indexMech

	// Check if the position is valid
	if insertIndex < 0 || insertIndex+len(mechList) > len(db.Mechanisms) {
		fmt.Println("Invalid index")
		return false
	}

	// Compare the corresponding elements of the two slices
	return reflect.DeepEqual(db.Mechanisms[insertIndex:insertIndex+len(mechList)], mechList)
}

func setMechsInDB(db AuthDB, mechList []string, indexMech string, indexOffset int, add bool) AuthDB {
	db = removeMechsInDB(db, fv2MechsToRemove)

	if add {
		insertIndex := indexOf(db.Mechanisms, indexMech) + indexOffset
		db.Mechanisms = insertMechsAtPosition(db.Mechanisms, mechList, insertIndex)
	}

	return db
}

func insertMechsAtPosition(mechanisms []string, mechsToInsert []string, pos int) []string {
	if pos < 0 || pos > len(mechanisms) {
		return mechanisms
	}

	// Separate the original slice into two at the position where we want to insert
	firstPart := make([]string, len(mechanisms[:pos]))
	copy(firstPart, mechanisms[:pos])
	secondPart := mechanisms[pos:]
	// Append the new mechanisms to the first part
	newFirstPart := append(firstPart, mechsToInsert...)

	// Append the second part of the original slice to complete the insertion
	result := append(newFirstPart, secondPart...)

	return result
}

func indexOf(slice []string, item string) int {
	for i, v := range slice {
		if v == item {
			return i
		}
	}
	return -1
}

func getAuthDb(r utils.Runner) (AuthDB, error) {
	securityConsoleOut, err := r.Runner.RunCmd("/usr/bin/security", "authorizationdb", "read", "system.login.console")
	if err != nil {
		return AuthDB{}, err
	}

	var d AuthDB
	err = plist.Unmarshal(securityConsoleOut, &d)
	if err != nil {
		return AuthDB{}, err
	}

	return d, nil
}

func editAuthDB(r utils.Runner, add bool) error {
	d, err := getAuthDb(r)
	if err != nil {
		return err
	}

	d = setMechsInDB(d, fv2Mechs, fv2IndexMech, fv2IndexOffset, add)
	data, err := plist.Marshal(d)
	if err != nil {
		return err
	}

	_, err = r.Runner.RunCmdWithStdin("/usr/bin/security", string(data), "authorizationdb", "write", "system.login.console")
	if err != nil {
		return err
	}

	return nil
}

func checkRoot() error {
	if os.Geteuid() != 0 {
		return errors.New("only root can run this tool")
	}

	return nil
}

func Check(r utils.Runner) error {
	err := checkRoot()
	if err != nil {
		return err
	}

	d, err := getAuthDb(r)
	if err != nil {
		return err
	}

	if !checkMechsInDB(d, fv2Mechs, fv2IndexMech, fv2IndexOffset) {
		return errors.New("mechanisms are not set correctly")
	}

	return nil
}

func Run(r utils.Runner, add bool) error {
	err := checkRoot()
	if err != nil {
		return err
	}

	return editAuthDB(r, add)
}

func Ensure(r utils.Runner) error {
	d, err := getAuthDb(r)
	if err != nil {
		return err
	}

	if checkMechsInDB(d, fv2Mechs, fv2IndexMech, fv2IndexOffset) {
		return nil
	}

	log.Println("Mechanisms are not set correctly, adding to AuthDB")

	return editAuthDB(r, true)
}
