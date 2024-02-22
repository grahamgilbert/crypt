package pref

/*
#cgo CFLAGS: -x objective-c
#cgo LDFLAGS: -framework CoreFoundation
#include <CoreFoundation/CoreFoundation.h>

CFPropertyListRef GetPreference(CFStringRef key, CFStringRef applicationID) {
	CFPropertyListRef value = CFPreferencesCopyAppValue(key, applicationID);
	return value;
}



CFBooleanRef getTrue() {
    return kCFBooleanTrue;
}

CFBooleanRef getFalse() {
    return kCFBooleanFalse;
}

CFStringRef CFStringCreateWithCString(CFAllocatorRef alloc, const char *cStr, CFStringEncoding encoding) {
    return CFStringCreateWithCString(alloc, cStr, encoding);
}

Boolean Go_CFStringGetCString(CFStringRef str, char *buffer, CFIndex bufferSize, CFStringEncoding encoding) {
    return CFStringGetCString(str, buffer, bufferSize, encoding);
}
*/
import "C"
import (
	"fmt"
	"os/user"
	"unsafe"

	"github.com/pkg/errors"
)

const BundleID = "com.grahamgilbert.crypt"

var defaultPrefs = map[string]interface{}{
	"RemovePlist":        true,
	"RotateUsedKey":      true,
	"OutputPath":         "/private/var/root/crypt_output.plist",
	"ValidateKey":        true,
	"KeyEscrowInterval":  1,
	"AdditionalCurlOpts": []string{},
}

func (p *Pref) Get(prefName string) (interface{}, error) {
	cPrefName := C.CFStringCreateWithCStringNoCopy(
		C.kCFAllocatorDefault,
		C.CString(prefName),
		C.kCFStringEncodingUTF8,
		C.kCFAllocatorDefault,
	)
	defer C.CFRelease(C.CFTypeRef(cPrefName))

	cBundleID := C.CFStringCreateWithCStringNoCopy(
		C.kCFAllocatorDefault,
		C.CString(BundleID),
		C.kCFStringEncodingUTF8,
		C.kCFAllocatorDefault,
	)
	defer C.CFRelease(C.CFTypeRef(cBundleID))

	prefValue := C.GetPreference(cPrefName, cBundleID)
	if unsafe.Pointer(prefValue) == nil {
		defaultValue, ok := defaultPrefs[prefName]
		if !ok {
			return nil, nil
		}
		err := p.Set(prefName, defaultValue)
		if err != nil {
			return nil, errors.Wrap(err, "failed to set default preference")
		}
		return defaultValue, nil
	}

	// Handle different types of preferences
	switch C.CFGetTypeID(prefValue) {
	case C.CFStringGetTypeID():
		var buffer [1024]C.char
		success := C.CFStringGetCString(
			C.CFStringRef(prefValue),
			&buffer[0],
			C.CFIndex(len(buffer)),
			C.kCFStringEncodingUTF8,
		)
		if success == C.false {
			return "", fmt.Errorf("failed to convert value to string")
		}
		return C.GoString(&buffer[0]), nil
	case C.CFBooleanGetTypeID():
		return C.CFBooleanGetValue(C.CFBooleanRef(prefValue)) != 0, nil
	case C.CFNumberGetTypeID():
		var num int
		C.CFNumberGetValue(C.CFNumberRef(prefValue), C.kCFNumberIntType, unsafe.Pointer(&num))
		return num, nil
	case C.CFArrayGetTypeID():
		length := C.CFArrayGetCount(C.CFArrayRef(prefValue))
		array := make([]string, length)
		for i := 0; i < int(length); i++ {
			value := C.CFArrayGetValueAtIndex(C.CFArrayRef(prefValue), C.CFIndex(i))
			if C.CFGetTypeID(C.CFTypeRef(value)) != C.CFStringGetTypeID() {
				return nil, fmt.Errorf("array contains non-string value")
			}
			var buffer [1024]C.char
			success := C.Go_CFStringGetCString(
				C.CFStringRef(value),
				&buffer[0],
				C.CFIndex(len(buffer)),
				C.kCFStringEncodingUTF8,
			)
			if success != C.true {
				return nil, fmt.Errorf("failed to convert value to string")
			}
			array[i] = C.GoString(&buffer[0])
		}
		return array, nil
	default:
		return nil, fmt.Errorf("unsupported preference type for %s", prefName)
	}
}

func isRoot() (bool, error) {
	currentUser, err := user.Current()
	if err != nil {
		return false, err
	}

	if currentUser.Uid == "0" {
		return true, nil
	}
	return false, nil
}

// Set sets the value of a preference
// Why use defaults over cgo? It's simpler, and more reliable.
func (p *Pref) Set(prefName string, prefValue interface{}) error {
	isRoot, err := isRoot()
	if err != nil {
		return errors.Wrap(err, "failed to determine if running as root")
	}
	cmd := "/usr/bin/defaults"
	var path string
	if isRoot {
		path = fmt.Sprintf("/Library/Preferences/%s", BundleID)
	} else {
		path = BundleID
	}

	args := []string{"write", path, prefName}
	switch v := prefValue.(type) {
	case string:
		args = append(args, prefValue.(string))
	case bool:
		if v {
			args = append(args, "-bool", "true")
		} else {
			args = append(args, "-bool", "false")
		}
	case int:
		args = append(args, "-int", fmt.Sprintf("%d", prefValue))
	case []string:
		args = append(args, "-array")
		for _, s := range prefValue.([]string) {
			args = append(args, s)
		}
	default:
		return fmt.Errorf("unsupported preference type for %s", prefName)
	}

	_, err = p.Runner.RunCmd(cmd, args...)
	if err != nil {
		return errors.Wrap(err, "failed to set preference")
	}

	return nil
}
