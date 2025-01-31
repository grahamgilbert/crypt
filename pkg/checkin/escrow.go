package checkin

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/googleapis/enterprise-certificate-proxy/darwin"
	"github.com/grahamgilbert/crypt/pkg/authmechs"
	"github.com/grahamgilbert/crypt/pkg/pref"
	"github.com/grahamgilbert/crypt/pkg/utils"
	"github.com/groob/plist"
	"github.com/hashicorp/go-version"
	"github.com/korylprince/macserial"
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

// RunEscrow manages the process of escrowing a FileVault recovery key to a server.
// Parameters:
//   - r: Runner interface for executing system commands
//   - p: PrefInterface for accessing configuration preferences
//
// Returns:
//   - error: Any error encountered during the escrow process
func RunEscrow(r utils.Runner, p pref.PrefInterface) error {
	// Get preferences early
	useKeychain, err := p.GetBool("StoreRecoveryKeyInKeychain")
	if err != nil {
		return errors.Wrap(err, "failed to get StoreRecoveryKeyInKeychain preference")
	}

	manageAuthMechs, err := p.GetBool("ManageAuthMechs")
	if err != nil {
		return errors.Wrap(err, "failed to get manage auth mechs preference")
	}

	if manageAuthMechs {
		if err := authmechs.Ensure(r); err != nil {
			return errors.Wrap(err, "failed to ensure auth mechs")
		}
	}

	removePlist, err := p.GetBool("RemovePlist")
	if err != nil {
		return errors.Wrap(err, "failed to get remove plist preference")
	}

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

	if rotateUsedKey && validateKey && !removePlist {
		log.Println("Checking that current key is valid.")
		if err := rotateInvalidKey(plistPath, r, p); err != nil {
			return errors.Wrap(err, "rotateInvalidKey")
		}
	}

	var cryptData CryptData

	if useKeychain {
		log.Println("Configured to use keychain for recovery key storage.")
		recoveryKey, err := utils.GetSecret()
		if err != nil {
			return errors.Wrap(err, "failed to get recovery key from keychain.")
		}

		// create our cryptData from current system information since we don't have it in the plist
		cryptData, err = buildCryptData(p, r)
		if err != nil {
			return errors.Wrap(err, "failed to build crypt data")
		}
		cryptData.RecoveryKey = recoveryKey
	} else {
		// Not using keychain, gather the cryptData from the plist on disk.
		// Check if plist exists
		if _, err := os.Stat(plistPath); os.IsNotExist(err) {
			return nil
		} else if err != nil {
			return errors.Wrap(err, "failed to check if plist exists")
		}

		cryptData, err = parsePlist(plistPath)
		if err != nil {
			return errors.Wrap(err, "failed to parse plist")
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

	// Handle escrow
	var keyRotated bool
	mTLScommonName, err := p.GetString("CommonNameForEscrow")
	if err != nil {
		return errors.Wrap(err, "failed to get mTLS common name for escrow")
	}

	if mTLScommonName != "" {
		// we will use mTLS for escrow, as well as native go http client
		keyRotated, err = escrowWithMTLS(cryptData, r, p, mTLScommonName)
	} else {
		// escrow using curl if mTLS is not configured
		keyRotated, err = escrowKey(cryptData, r, p)
	}
	if err != nil {
		return errors.Wrap(err, "escrow operation failed")
	}

	// if using the keychain and the key wasn't rotated, update the preference last escrow date and return
	if useKeychain && !keyRotated {
		// write the last escrow date to preferences if using keychain.
		p.SetDate("LastEscrow", time.Now())
		return nil
	}

	// Handle plist operations if not using keychain
	if !keyRotated {
		cryptData.LastRun = time.Now()
		cryptData.EscrowSuccess = true
		if err := writePlist(cryptData, plistPath); err != nil {
			return errors.Wrap(err, "failed to write plist")
		}
	}

	if removePlist {
		if err := os.Remove(plistPath); err != nil {
			return errors.Wrap(err, "failed to remove plist")
		}
	}

	return nil
}

// buildCryptData constructs a CryptData structure with current system information.
// Parameters:
//   - p: PrefInterface for accessing configuration preferences
//   - r: Runner interface for executing system commands
//
// Returns:
//   - CryptData: Populated structure with system information
//   - error: Any error encountered during data collection
func buildCryptData(p pref.PrefInterface, r utils.Runner) (CryptData, error) {
	var cryptData CryptData
	var err error

	// Get serial number
	cryptData.SerialNumber, err = macserial.Get()
	if err != nil {
		return CryptData{}, errors.Wrap(err, "failed to get serial number")
	}

	// Get enabled user
	cryptData.EnabledUser, err = utils.GetConsoleUser()
	if err != nil {
		return CryptData{}, errors.Wrap(err, "failed to get enabled user")
	}

	// Handle skipped users
	if userShouldBeSkipped(cryptData.EnabledUser) || cryptData.EnabledUser == "" {
		cryptData.EnabledUser, err = getEnabledUser(p, r)
		if err != nil {
			return CryptData{}, errors.Wrap(err, "failed to get enabled user")
		}
	}

	// Get last run time
	lastRun, err := p.GetDate("LastEscrow")
	if err != nil {
		return CryptData{}, errors.Wrap(err, "failed to get last escrow date")
	}
	if lastRun != (time.Time{}) {
		cryptData.LastRun = lastRun
	}

	return cryptData, nil
}

// escrowRequired determines if a key needs to be escrowed based on the last escrow
// time and the configured escrow interval.
// Parameters:
//   - cryptData: CryptData containing the last escrow time
//   - p: PrefInterface for accessing configuration preferences
//
// Returns:
//   - bool: True if escrow is required, false otherwise
//   - error: Any error encountered during the check
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

// userShouldBeSkipped checks if a given username is in the list of users that
// should be skipped during the escrow process.
// Parameters:
//   - user: String containing the username to check
//
// Returns:
//   - bool: True if user should be skipped, false otherwise
func userShouldBeSkipped(user string) bool {
	skipUsers := []string{"root", "_mbsetupuser"}
	return utils.StringInSlice(user, skipUsers)
}

// parsePlist reads and unmarshals a property list file into a CryptData structure.
// Parameters:
//   - plistPath: String path to the plist file
//
// Returns:
//   - CryptData: Unmarshaled data structure
//   - error: Any error encountered during parsing
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

// writePlist marshals CryptData into a property list format and writes it to the
// specified file path.
// Parameters:
//   - cryptData: CryptData to be written
//   - plistPath: String path where the plist should be written
//
// Returns:
//   - error: Any error encountered during writing
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

// rotateInvalidKey validates the current recovery key and removes the plist if
// validation fails, allowing key regeneration at next login.
// Parameters:
//   - plistPath: String path to the plist file
//   - r: Runner interface for executing system commands
//   - p: PrefInterface for accessing configuration preferences
//
// Returns:
//   - error: Any error encountered during rotation
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
		log.Println("Version is less than 10.12.5, skipping key validation.")
		return nil
	}

	useKeychain, err := p.GetBool("StoreRecoveryKeyInKeychain")
	if err != nil {
		return errors.Wrap(err, "failed to get StoreRecoveryKeyInKeychain preference")
	}

	_, err = os.Stat(plistPath)
	if !useKeychain && os.IsNotExist(err) {
		return nil
	}

	recoveryKey, err := getRecoveryKey(plistPath, p)
	if err != nil {
		return errors.Wrap(err, "failed to get recovery key")
	}

	keyValid, err := validateRecoveryKey(recoveryKey, r)
	if err != nil {
		return errors.Wrap(err, "validateRecoveryKey")
	}

	if keyValid {
		return nil
	}

	err = removeInvalidKey(plistPath, useKeychain)
	if err != nil {
		return err
	}

	err = postRunCommand(r, p)
	if err != nil {
		return errors.Wrap(err, "postRunCommand")
	}

	return errors.New("Removed invalid key")
}

// removeInvalidKey removes an invalid key either from the keychain or from a specified plist file.
// If usingKeychain is true, it attempts to delete the key from the keychain using utils.DeleteSecret().
// If usingKeychain is false, it attempts to remove the key from the specified plist file path.
//
// Parameters:
// - plistPath: The path to the plist file from which the key should be removed if not using the keychain.
// - usingKeychain: A boolean indicating whether to remove the key from the keychain (true) or from the plist file (false).
//
// Returns:
// - An error if the key removal operation fails, otherwise nil.
func removeInvalidKey(plistPath string, usingKeychain bool) error {
	var err error
	if usingKeychain {
		log.Println("Removing invalid recovery key from keychain.")
		err = utils.DeleteSecret()
		if err != nil {
			return errors.Wrap(err, "failed to delete recovery key from keychain")
		}
		return nil
	}

	log.Printf("Removing invalid key at path: %s\n", plistPath)
	err = os.Remove(plistPath)
	if err != nil {
		return errors.Wrap(err, "os.remove plistPath")
	}

	return nil
}

// validateRecoveryKey checks if a given recovery key is valid by testing it
// against the system's FileVault configuration.
// Parameters:
//   - recoveryKey: String containing the recovery key to validate
//   - r: Runner interface for executing system commands
//
// Returns:
//   - bool: True if key is valid, false otherwise
//   - error: Any error encountered during validation
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

// getEnabledUser retrieves the first enabled FileVault user that isn't in the
// skip users list.
// Parameters:
//   - p: PrefInterface for accessing configuration preferences
//   - r: Runner interface for executing system commands
//
// Returns:
//   - string: Username of the first valid enabled user
//   - error: Any error encountered during the search
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

// buildData constructs the form data for the escrow request.
// Parameters:
//   - cryptData: CryptData containing the information to be sent
//   - runner: Runner interface for executing system commands
//
// Returns:
//   - string: Encoded form data
//   - error: Any error encountered during construction
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

// buildCheckinURL constructs the complete URL for the escrow check-in endpoint.
// Parameters:
//   - p: PrefInterface for accessing configuration preferences
//
// Returns:
//   - string: Complete checkin URL
//   - error: Any error encountered during URL construction
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

// runCurl executes a curl command with the specified configuration.
// Parameters:
//   - configFile: String containing curl configuration
//   - r: Runner interface for executing system commands
//   - p: PrefInterface for accessing configuration preferences
//
// Returns:
//   - string: Command output
//   - error: Any error encountered during execution
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
		log.Println("Additional curl options found.. Adding to curl command")
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

// escrowKey attempts to escrow a key by sending data to a server URL built from preferences.
// It logs the process and handles errors appropriately.
//
// Parameters:
//   - plist: CryptData containing the data to be sent.
//   - r: utils.Runner to execute commands.
//   - p: pref.PrefInterface to retrieve preferences.
//
// Returns:
//   - bool: indicating if the key rotation was initiated by the server.
//   - error: if any error occurs during the process.
func escrowKey(plist CryptData, r utils.Runner, p pref.PrefInterface) (bool, error) {
	log.Println("Attempting to Escrow Key...")
	// serverURL, err := p.GetString("ServerURL")
	// if err != nil {
	// 	return errors.Wrap(err, "failed to get server URL")
	// }
	theURL, err := buildCheckinURL(p)
	if err != nil {
		return false, errors.Wrap(err, "failed to build checkin URL")
	}

	data, err := buildData(plist, r)
	if err != nil {
		return false, errors.Wrap(err, "failed to build data")
	}
	configFile := utils.BuildCurlConfigFile(map[string]string{"url": theURL, "data": data})
	output, err := runCurl(configFile, r, p)
	if err != nil {
		return false, errors.Wrap(err, "failed to run curl")
	}

	log.Println("Key escrow successful.")

	keyRotated, err := serverInitiatedRotation(output, r, p)
	if err != nil {
		return false, errors.Wrap(err, "serverInitiatedRotation")
	}
	return keyRotated, nil
}

// serverInitiatedRotation processes the server's response for key rotation.
// Parameters:
//   - output: String containing server response
//   - r: Runner interface for executing system commands
//   - p: PrefInterface for accessing configuration preferences
//
// Returns:
//   - bool: Whether rotation was completed
//   - error: Any error encountered during rotation
func serverInitiatedRotation(output string, r utils.Runner, p pref.PrefInterface) (bool, error) {
	var rotation struct {
		RotationRequired bool `json:"rotation_required"`
	}

	rotationCompleted := false
	err := json.Unmarshal([]byte(output), &rotation)
	if err != nil {
		return rotationCompleted, errors.Wrap(err, "failed to unmarshal output")
	}
	rotateUsedKey, err := p.GetBool("RotateUsedKey")
	if err != nil {
		return rotationCompleted, errors.Wrap(err, "failed to get rotate used key preference")
	}

	removePlist, err := p.GetBool("RemovePlist")
	if err != nil {
		return rotationCompleted, errors.Wrap(err, "failed to get remove plist preference")
	}
	if !rotateUsedKey || removePlist {
		return rotationCompleted, nil
	}

	useKeychain, err := p.GetBool("StoreRecoveryKeyInKeychain")
	if err != nil {
		return rotationCompleted, nil
	}

	outputPath, err := p.GetString("OutputPath")
	if err != nil {
		return rotationCompleted, errors.Wrap(err, "failed to get output path preference")
	}

	if !useKeychain {
		_, err = os.Stat(outputPath)
		if os.IsNotExist(err) {
			return rotationCompleted, nil
		}
	}

	if rotation.RotationRequired {
		log.Println("Found server initiated key rotation. Removing used/invalid key.")
		err = removeInvalidKey(outputPath, useKeychain)
		if err != nil {
			return rotationCompleted, errors.Wrap(err, "failed to remove invalid key")
		}
		rotationCompleted = true
	}

	err = postRunCommand(r, p)
	if err != nil {
		return rotationCompleted, errors.Wrap(err, "postRunCommand")
	}

	return rotationCompleted, nil
}

// getCommand retrieves and formats the post-run command from preferences.
// Parameters:
//   - p: PrefInterface for accessing configuration preferences
//
// Returns:
//   - string: Formatted command string
//   - error: Any error encountered during retrieval
func getCommand(p pref.PrefInterface) (string, error) {
	var command string

	postRunCommand, err := p.Get("PostRunCommand")
	if err != nil {
		return "", errors.Wrap(err, "failed to get post run command")
	}

	switch v := postRunCommand.(type) {
	case string:
		command = v
	case []string:
		command = strings.Join(v, " ")
	case nil:
		return "", nil
	default:
		return "", errors.New("PostRunCommand is neither a string nor an array of strings")
	}

	return command, nil
}

// postRunCommand executes a configured command after the escrow process.
// Parameters:
//   - r: Runner interface for executing system commands
//   - p: PrefInterface for accessing configuration preferences
//
// Returns:
//   - error: Any error encountered during command execution
func postRunCommand(r utils.Runner, p pref.PrefInterface) error {
	command, err := getCommand(p)
	if err != nil {
		return err
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

// getRecoveryKey retrieves the recovery key from either the keychain or a plist file based on the user's preference.
//
// Parameters:
//   - keyLocation: The file path to the plist file containing the recovery key.
//   - p: An implementation of the PrefInterface used to get user preferences.
//
// Returns:
//   - A string containing the recovery key.
//   - An error if there is any issue retrieving the recovery key.
//
// The function first checks the user preference "StoreRecoveryKeyInKeychain" to determine where to retrieve the recovery key from.
// If the preference is set to true, it attempts to get the recovery key from the keychain using utils.GetSecret().
// If the keychain retrieval fails or the key is empty, an error is returned.
// If the preference is set to false, it reads the recovery key from the specified plist file.
// If reading the plist file or unmarshalling its contents fails, an error is returned.
func getRecoveryKey(keyLocation string, p pref.PrefInterface) (string, error) {
	useKeychain, err := p.GetBool("StoreRecoveryKeyInKeychain")
	if err != nil {
		return "", errors.Wrap(err, "failed to get StoreRecoveryKeyInKeychain preference")
	}

	if useKeychain {
		log.Println("Using keychain to get recovery key.")
		keychainRecoveryKey, err := utils.GetSecret()
		if err != nil {
			return "", errors.Wrap(err, "failed to get recovery key from keychain")
		}

		// if the recovery key isn't found in the keychain it will return an empty string
		// check if the recovery key is empty and return an error if it is
		if keychainRecoveryKey == "" {
			return "", errors.New("recovery key is empty")
		}
		log.Println("Found recovery key in keychain.")
		return keychainRecoveryKey, nil
	}

	// if we are not using the keychain, we will read the recovery key from the plist
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

// escrowWithMTLS attempts to escrow a key using mTLS (mutual TLS) authentication.
// It builds the check-in URL, constructs the form data, creates an HTTP POST request,
// and sends it using an mTLS client. The function checks the response status and
// processes the response body to determine if the key escrow was successful.
//
// Parameters:
//   - plist: CryptData containing the data to be sent.
//   - r: utils.Runner interface for executing commands.
//   - p: pref.PrefInterface for accessing preferences.
//
// Returns:
//   - bool: Indicates if the key was rotated as part of the escrow process.
//   - error: Any error encountered during the process.
func escrowWithMTLS(plist CryptData, r utils.Runner, p pref.PrefInterface, commonName string) (bool, error) {
	log.Println("Attempting to Escrow Key...")

	theURL, err := buildCheckinURL(p)
	if err != nil {
		return false, errors.Wrap(err, "failed to build checkin URL")
	}

	// Build form data
	data, err := buildData(plist, r)
	if err != nil {
		return false, errors.Wrap(err, "failed to build data")
	}

	body, err := sendRequest(theURL, data, commonName)
	if err != nil {
		return false, errors.Wrap(err, "failed to send request")
	}

	log.Println("Key escrow successful.")

	keyRotated, err := serverInitiatedRotation(string(body), r, p)
	if err != nil {
		return false, errors.Wrap(err, "serverInitiatedRotation")
	}

	return keyRotated, nil
}

// sendRequest sends an HTTP POST request to the specified URL with the given data
// and uses mTLS (mutual TLS) for authentication with the provided common name.
// It returns the response body as a byte slice or an error if the request fails.
//
// Parameters:
//   - url: The URL to send the request to.
//   - data: The data to include in the request body.
//   - commonName: The common name used to retrieve the secure key from the keychain.
//
// Returns:
//   - []byte: The response body from the server.
//   - error: An error if the request fails or the server returns a non-200 status.
func sendRequest(url string, data string, commonName string) ([]byte, error) {
	// Create request
	req, err := http.NewRequest(
		"POST",
		url,
		strings.NewReader(data),
	)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create request")
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Get the secure key from the keychain
	log.Println("Using mTLS for escrow with common name: ", commonName)
	secureKey, err := darwin.NewSecureKey(commonName)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get secure key from keychain")
	}
	defer secureKey.Close() // Make sure to close the secure key when done

	// Get the certificate chain
	certChain := secureKey.CertificateChain()
	if len(certChain) == 0 {
		return nil, errors.New("no certificates found in chain")
	}

	// Create TLS config with the secure key and certificates
	tlsConfig := &tls.Config{
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return &tls.Certificate{
				Certificate: certChain,
				PrivateKey:  secureKey,
			}, nil
		},
	}

	// Create transport with the TLS config
	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	client := &http.Client{Transport: transport}

	// Execute request
	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "failed to execute request")
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read response")
	}

	// Check response status
	if resp.StatusCode != http.StatusOK {
		return nil, errors.Errorf("server returned non-200 status: %d, body: %s",
			resp.StatusCode, string(body))
	}
	return body, nil
}
