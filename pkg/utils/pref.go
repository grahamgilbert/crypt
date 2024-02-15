//go:build darwin
// +build darwin

package utils

/*
#cgo CFLAGS: -x objective-c
#cgo LDFLAGS: -framework CoreFoundation
#include <CoreFoundation/CoreFoundation.h>

CFPropertyListRef GetPreference(CFStringRef key, CFStringRef applicationID) {
	CFPropertyListRef value = CFPreferencesCopyAppValue(key, applicationID);
	return value;
}

bool SetPreference(CFStringRef key, CFPropertyListRef value, CFStringRef applicationID) {
    CFPreferencesSetAppValue(key, value, applicationID);
    return CFPreferencesAppSynchronize(applicationID);
}

CFBooleanRef getTrue() {
    return kCFBooleanTrue;
}

CFBooleanRef getFalse() {
    return kCFBooleanFalse;
}
*/
import "C"
import (
	"fmt"
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

func Pref(prefName string) (interface{}, error) {
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
			return nil, fmt.Errorf(
				"preference %s not found and no default value provided",
				prefName,
			)
		}
		err := SetPref(prefName, defaultValue)
		if err != nil {
			return nil, errors.Wrap(err, "failed to set default preference")
		}
		return defaultValue, nil
	}

	// Handle different types of preferences
	switch C.CFGetTypeID(prefValue) {
	case C.CFStringGetTypeID():
		return C.GoString(
			C.CFStringGetCStringPtr(C.CFStringRef(prefValue), C.kCFStringEncodingUTF8),
		), nil
	case C.CFBooleanGetTypeID():
		return C.CFBooleanGetValue(C.CFBooleanRef(prefValue)) != 0, nil
	case C.CFNumberGetTypeID():
		var num int
		C.CFNumberGetValue(C.CFNumberRef(prefValue), C.kCFNumberIntType, unsafe.Pointer(&num))
		return num, nil
	case C.CFArrayGetTypeID():
		length := C.CFArrayGetCount(C.CFArrayRef(prefValue))
		array := make([]interface{}, length)
		for i := 0; i < int(length); i++ {
			value := C.CFArrayGetValueAtIndex(C.CFArrayRef(prefValue), C.CFIndex(i))
			// TODO: Handle different types of values in the array
			array[i] = C.GoString(
				C.CFStringGetCStringPtr(C.CFStringRef(value), C.kCFStringEncodingUTF8),
			)
		}
		return array, nil
	default:
		return nil, fmt.Errorf("Unsupported preference type for %s", prefName)
	}
}

func SetPref(prefName string, prefValue interface{}) error {
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

	var cPrefValue C.CFPropertyListRef
	switch v := prefValue.(type) {
	case string:
		cPrefValue = C.CFPropertyListRef(C.CFStringCreateWithCStringNoCopy(C.kCFAllocatorDefault, C.CString(v), C.kCFStringEncodingUTF8, C.kCFAllocatorDefault))
	case bool:
		if v {
			cPrefValue = C.CFPropertyListRef(C.getTrue())
		} else {
			cPrefValue = C.CFPropertyListRef(C.getFalse())
		}
	case int:
		cPrefValue = C.CFPropertyListRef(C.CFNumberCreate(C.kCFAllocatorDefault, C.kCFNumberIntType, unsafe.Pointer(&v)))
	default:
		return fmt.Errorf("unsupported preference type for %s", prefName)
	}
	defer C.CFRelease(C.CFTypeRef(cPrefValue))

	if C.SetPreference(cPrefName, cPrefValue, cBundleID) == false {
		return fmt.Errorf("failed to set preference %s", prefName)
	}

	return nil
}
