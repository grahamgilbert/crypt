package postinstall

import (
	"errors"
	"os"

	"github.com/grahamgilbert/crypt/pkg/utils"
	"github.com/groob/plist"
)

var (
	fv2Mechs       = []string{"Crypt:Check,privileged", "Crypt:CryptGUI", "Crypt:Enablement,privileged"}
	fv2IndexMech   = "loginwindow:done"
	fv2IndexOffset = 0
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
			}
		}
	}

	return db
}

func setMechsInDB(db AuthDB, mechList []string, indexMech string, indexOffset int, add bool) AuthDB {
	db = removeMechsInDB(db, mechList)

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

func editAuthDB(r utils.Runner, add bool) error {
	securityConsoleOut, err := r.Runner.RunCmd("/usr/bin/security", "authorizationdb", "read", "system.login.console")
	if err != nil {
		return err
	}

	var d AuthDB
	err = plist.Unmarshal(securityConsoleOut, &d)
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

func Run(r utils.Runner, add bool) error {
	err := checkRoot()
	if err != nil {
		return err
	}
	err = editAuthDB(r, add)
	if err != nil {
		return err
	}

	return nil
}
