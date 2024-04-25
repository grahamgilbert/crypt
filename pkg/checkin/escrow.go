package checkin

import (
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/grahamgilbert/crypt/pkg/authmechs"
	"github.com/grahamgilbert/crypt/pkg/pref"
	"github.com/grahamgilbert/crypt/pkg/utils"
	"github.com/groob/plist"
	"github.com/hashicorp/go-version"
	"github.com/pkg/errors"
)

type CryptData struct {
	SerialNumber  string    `plist:"SerialNumber"`
	RecoveryKey   string    `plist:"RecoveryKey"`
	EnabledUser   string    `plist:"EnabledUser"`
	LastRun       time.Time `plist:"last_run"`
	EscrowSuccess bool      `plist:"escrow_success"`
	HardwareUUID  string    `plist:"HardwareUUID"`
	EnabledDate   string    `plist:"EnabledDate"`
}

func RunEscrow(r utils.Runner, p pref.PrefInterface) error {
	plistPath, err := p.GetString("OutputPath")
	if err != nil {
		return errors.Wrap(err, "failed to get output path")
	}

	rotateUsedKey, err := p.GetBool("RotateUsedKey")
	if err != nil {
		return errors.Wrap(err, "failed to get rotate used key preference")
	}

	validateKey, err := p.GetBool("ValidateKey")
	if err != nil {
		return errors.Wrap(err, "failed to get validate key preference")
	}

	removePlist, err := p.GetBool("RemovePlist")
	if err != nil {
		return errors.Wrap(err, "failed to get remove plist preference")
	}

	manageAuthMechs, err := p.GetBool("ManageAuthMechs")
	if err != nil {
		return errors.Wrap(err, "failed to get manage auth mechs preference")
	}

	if manageAuthMechs {
		err := authmechs.Ensure(r)
		if err != nil {
			return errors.Wrap(err, "failed to ensure auth mechs")
		}
	}

	if rotateUsedKey && validateKey && !removePlist {
		err := rotateInvalidKey(plistPath, r, p)
		if err != nil {
			return errors.Wrap(err, "rotateInvalidKey")
		}
		// TODO: Post run command
	}

	// Return nil if plist does not exist
	_, err = os.Stat(plistPath)
	if os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return errors.Wrap(err, "failed to check if plist exists")
	}

	cryptData, err := parsePlist(plistPath)
	if err != nil {
		return errors.Wrap(err, "failed to parse plist")
	}

	if cryptData.EnabledUser == "" {
		cryptData.EnabledUser, err = utils.GetConsoleUser()
		if err != nil {
			return errors.Wrap(err, "failed to get enabled user")
		}
	}

	if userShouldBeSkipped(cryptData.EnabledUser) || cryptData.EnabledUser == "" {
		cryptData.EnabledUser, err = getEnabledUser(p, r)
		if err != nil {
			return errors.Wrap(err, "failed to get enabled user")
		}
	}

	escrowRequired, err := escrowRequired(cryptData, p)
	if err != nil {
		return errors.Wrap(err, "failed to check if escrow is required")
	}

	if !escrowRequired {
		log.Printf("Escrow not required")
		return nil
	}

	err = escrowKey(cryptData, r, p)
	if err != nil {
		return errors.Wrap(err, "escrowKey")
	}

	cryptData.LastRun = time.Now()
	cryptData.EscrowSuccess = true

	err = writePlist(cryptData, plistPath)
	if err != nil {
		return errors.Wrap(err, "failed to write plist")
	}

	if removePlist {
		err = os.Remove(plistPath)
		if err != nil {
			return errors.Wrap(err, "failed to remove plist")
		}
	}

	return nil
}

func escrowRequired(cryptData CryptData, p pref.PrefInterface) (bool, error) {
	if cryptData.LastRun.IsZero() {
		return true, nil
	}

	escrowInterval, err := p.GetInt("KeyEscrowInterval")
	if err != nil {
		return false, errors.Wrap(err, "failed to get escrow interval")
	}

	now := time.Now()
	nowMinusInterval := now.Add(-time.Duration(escrowInterval) * time.Hour)

	if cryptData.LastRun.After(nowMinusInterval) {
		log.Printf("We escrowed less than %d hour(s) ago. Skipping...\n", escrowInterval)
		return false, nil
	}

	return true, nil
}

func userShouldBeSkipped(user string) bool {
	skipUsers := []string{"root", "_mbsetupuser"}
	return utils.StringInSlice(user, skipUsers)
}

func parsePlist(plistPath string) (CryptData, error) {
	var cryptData CryptData
	plistBytes, err := os.ReadFile(plistPath)
	if err != nil {
		return cryptData, errors.Wrap(err, "failed to read plist file")
	}

	err = plist.Unmarshal(plistBytes, &cryptData)
	if err != nil {
		return cryptData, errors.Wrap(err, "failed to unmarshal plist")
	}

	return cryptData, nil
}

func writePlist(cryptData CryptData, plistPath string) error {
	plistBytes, err := plist.Marshal(cryptData)
	if err != nil {
		return errors.Wrap(err, "failed to marshal plist")
	}

	err = os.WriteFile(plistPath, plistBytes, 0644)
	if err != nil {
		return errors.Wrap(err, "failed to write plist")
	}

	return nil
}

// rotateInvalidKey will send the key (if present) for validation. If validation fails,
// it will remove the plist so the key can be regenerated at next login.
// Due to the bug that restricts the number of validations before reboot
// in versions of macOS prior to 10.12.5, this will only run there.
func rotateInvalidKey(plistPath string, r utils.Runner, p pref.PrefInterface) error {
	_, err := utils.GetConsoleUser()
	if err != nil {
		// a work aroud for https://github.com/grahamgilbert/crypt/issues/68
		return nil
	}

	macOSVersion, err := utils.GetOSVersion(r.Runner)
	if err != nil {
		return errors.Wrap(err, "failed to get macOS version")
	}

	macOSVersionParsed, err := version.NewVersion(macOSVersion)
	if err != nil {
		return errors.Wrap(err, "failed to parse macOS version")
	}

	if macOSVersionParsed.LessThan(version.Must(version.NewVersion("10.12.5"))) {
		return nil
	}

	_, err = os.Stat(plistPath)
	if os.IsNotExist(err) {
		return nil
	}

	recoveryKey, err := getRecoveryKey(plistPath)
	if err != nil {
		return errors.Wrap(err, "failed to get recovery key")
	}

	keyValid, err := validateRecoveryKey(recoveryKey, r)
	if err != nil {
		return errors.Wrap(err, "validateRecoveryKey")
	}

	if !keyValid {
		err := os.Remove(plistPath)
		if err != nil {
			return errors.Wrap(err, "os.remove plistPath")
		}
	}

	err = postRunCommand(r, p)
	if err != nil {
		return errors.Wrap(err, "postRunCommand")
	}

	return nil
}

func validateRecoveryKey(recoveryKey string, r utils.Runner) (bool, error) {
	type Key struct {
		Password string
	}
	key := Key{Password: recoveryKey}
	inputPlist, err := plist.Marshal(key)
	if err != nil {
		return false, err
	}

	stdoutData, err := r.Runner.RunCmdWithStdin(
		"/usr/bin/fdesetup",
		string(inputPlist),
		"validaterecovery",
		"-inputplist",
	)
	if err != nil {
		if strings.TrimSpace(string(stdoutData)) == "false" {
			return false, nil
		}
		return false, err
	}

	if strings.TrimSpace(string(stdoutData)) == "true" {
		return true, nil
	} else {
		log.Println("Recovery Key could not be validated.")
		log.Printf("Failed with Error: %s", stdoutData)
		return false, errors.New("Recovery Key validation failed")
	}
}

func getEnabledUser(p pref.PrefInterface, r utils.Runner) (string, error) {
	skipUsers, err := p.GetArray("SkipUsers")
	if err != nil {
		return "", errors.Wrap(err, "failed to get skip users")
	}
	fdeUsers, err := r.Runner.RunCmd("/usr/bin/fdesetup", "list")
	if err != nil {
		return "", errors.Wrap(err, "failed to get fdeUsers")
	}

	fdeUsersSlice := strings.Split(strings.TrimSpace(string(fdeUsers)), "\n")
	for _, user := range fdeUsersSlice {
		// split on comma and take the first element
		user = strings.Split(user, ",")[0]
		if !utils.StringInSlice(user, skipUsers) {
			return strings.TrimSpace(user), nil
		}
	}

	return "", nil
}

func buildData(cryptData CryptData, runner utils.Runner) (string, error) {
	computerName, err := utils.GetComputerName(runner)
	if err != nil {
		return "", errors.Wrap(err, "failed to get computer name")
	}

	data := url.Values{}
	data.Set("serial", cryptData.SerialNumber)
	data.Set("recovery_password", cryptData.RecoveryKey)
	data.Set("username", cryptData.EnabledUser)
	data.Set("macname", computerName)
	return data.Encode(), nil
}

func buildCheckinURL(p pref.PrefInterface) (string, error) {
	serverURL, err := p.GetString("ServerURL")
	if err != nil {
		return "", errors.Wrap(err, "failed to get server URL")
	}
	if !strings.HasSuffix(serverURL, "/") {
		serverURL = serverURL + "/"
	}
	return serverURL + "checkin/", nil
}

func runCurl(configFile string, r utils.Runner, p pref.PrefInterface) (string, error) {
	// --fail: Fail silently (no output at all) on server errors.
	// --silent: Silent mode. Don't show progress meter or error messages.
	// --show-error: When used with silent, it makes curl show an error message
	// if it fails.
	// --location: This option will make curl redo the request on the new
	// location if the server responds with a 3xx code.
	// --config: Specify which config file to read curl arguments from.
	// The config file is a text file in which command line arguments can be
	// written which then will be used as if they were written on the actual
	// command line.
	cmd := "/usr/bin/curl"
	args := []string{"--fail", "--silent", "--show-error", "--location"}
	additionalCurlOpts, err := p.GetArray("AdditionalCurlOpts")
	if err != nil {
		return "", errors.Wrap(err, "failed to get additional curl options")
	}
	if additionalCurlOpts != nil {
		args = append(args, additionalCurlOpts...)
	}
	args = append(args, "--config", "-")
	out, err := r.Runner.RunCmdWithStdin(cmd, configFile, args...)
	if err != nil {
		theErr := fmt.Errorf("stdout: %s err: %s", out, err)
		return "", errors.Wrap(theErr, "failed to run curl")
	}
	return string(out), nil
}

func escrowKey(plist CryptData, r utils.Runner, p pref.PrefInterface) error {
	log.Println("Attempting to Escrow Key...")
	// serverURL, err := p.GetString("ServerURL")
	// if err != nil {
	// 	return errors.Wrap(err, "failed to get server URL")
	// }
	theURL, err := buildCheckinURL(p)
	if err != nil {
		return errors.Wrap(err, "failed to build checkin URL")
	}
	data, err := buildData(plist, r)
	if err != nil {
		return errors.Wrap(err, "failed to build data")
	}
	configFile := utils.BuildCurlConfigFile(map[string]string{"url": theURL, "data": data})
	output, err := runCurl(configFile, r, p)
	if err != nil {
		return errors.Wrap(err, "failed to run curl")
	}
	log.Println("Key escrow successful.")

	err = serverInitiatedRotation(output, r, p)
	if err != nil {
		return errors.Wrap(err, "serverInitiatedRotation")
	}
	return nil
}

func serverInitiatedRotation(output string, r utils.Runner, p pref.PrefInterface) error {
	var rotation struct {
		RotationRequired bool `json:"rotation_required"`
	}
	err := json.Unmarshal([]byte(output), &rotation)
	if err != nil {
		return errors.Wrap(err, "failed to unmarshal output")
	}
	rotateUsedKey, err := p.GetBool("RotateUsedKey")
	if err != nil {
		return errors.Wrap(err, "failed to get rotate used key preference")
	}

	removePlist, err := p.GetBool("RemovePlist")
	if err != nil {
		return errors.Wrap(err, "failed to get remove plist preference")
	}
	if !rotateUsedKey || removePlist {
		return nil
	}

	outputPath, err := p.GetString("OutputPath")
	if err != nil {
		return errors.Wrap(err, "failed to get output path preference")
	}
	_, err = os.Stat(outputPath)
	if os.IsNotExist(err) {
		return nil
	}

	if rotation.RotationRequired {
		log.Println("Removing output plist for rotation at next login.")
		err = os.Remove(outputPath)
		if err != nil {
			log.Println("Failed to remove output plist:", err)
		}
	}

	err = postRunCommand(r, p)
	if err != nil {
		return errors.Wrap(err, "postRunCommand")
	}

	return nil
}

func postRunCommand(r utils.Runner, p pref.PrefInterface) error {
	var command string
	var err error

	postRunCommand, err := p.Get("PostRunCommand")
	if err != nil {
		return errors.Wrap(err, "failed to get post run command")
	}

	switch v := postRunCommand.(type) {
	case string:
		command = v
	case []string:
		command = strings.Join(v, " ")
	default:
		return errors.New("PostRunCommand is neither a string nor an array of strings")
	}

	outputPlist, err := p.GetString("OutputPath")
	if err != nil {
		return errors.Wrap(err, "failed to get output path")
	}

	if command != "" {
		_, err := os.Stat(outputPlist)
		if os.IsNotExist(err) {
			log.Println("Running post run command...")
			_, err = r.Runner.RunCmd(command, outputPlist)
			if err != nil {
				return errors.Wrap(err, "failed to run post run command")
			}
			log.Println("Post run command successful.")
		}
	}

	return nil
}

func getRecoveryKey(keyLocation string) (string, error) {
	type keyPlist struct {
		RecoveryKey string `plist:"RecoveryKey"`
	}

	// Read file to bytes
	plistBytes, err := os.ReadFile(keyLocation)
	if err != nil {
		return "", errors.Wrap(err, "failed to read plist file")
	}

	// Unmarshal bytes to struct
	var key keyPlist
	err = plist.Unmarshal(plistBytes, &key)
	if err != nil {
		return "", errors.Wrap(err, "failed to unmarshal plist")
	}

	return key.RecoveryKey, nil
}
