//go:build darwin
// +build darwin

package utils

/*
#cgo LDFLAGS: -framework CoreFoundation -framework Security
#include <stdlib.h>
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <CoreServices/CoreServices.h>
*/
import "C"
import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"unsafe"
)

const service = "com.grahamgilbert.crypt.recovery"

var serviceStringRef = stringToCFString(service)
var mu sync.Mutex

// AddSecret will add a secret to the keychain. This secret can be retrieved by this application without any user authorization.
func AddSecret(secret string) error {
	secret = strings.TrimSpace(secret)
	if secret == "" {
		return errors.New("secret cannot be empty")
	}

	mu.Lock()
	defer mu.Unlock()

	query := C.CFDictionaryCreateMutable(
		C.kCFAllocatorDefault,
		0,
		&C.kCFTypeDictionaryKeyCallBacks,
		&C.kCFTypeDictionaryValueCallBacks, //nolint:gocritic // dubSubExpr false positive
	)
	defer C.CFRelease(C.CFTypeRef(query))

	data := C.CFDataCreate(C.kCFAllocatorDefault, (*C.UInt8)(&[]byte(secret)[0]), C.CFIndex(len(secret)))
	defer C.CFRelease(C.CFTypeRef(data))

	C.CFDictionaryAddValue(query, unsafe.Pointer(C.kSecClass), unsafe.Pointer(C.kSecClassGenericPassword))
	C.CFDictionaryAddValue(query, unsafe.Pointer(C.kSecAttrService), unsafe.Pointer(serviceStringRef))
	C.CFDictionaryAddValue(query, unsafe.Pointer(C.kSecValueData), unsafe.Pointer(data))

	status := C.SecItemAdd(C.CFDictionaryRef(query), nil)
	if status != C.errSecSuccess {
		return fmt.Errorf("failed to add %v to keychain: %v", service, status)
	}
	return nil
}

// GetSecret retrieves a secret from the macOS keychain.
// It creates a query dictionary to search for a generic password item with a specific label.
// If the item is found, it returns the secret as a string.
// If the item is not found, it returns an empty string.
// If an error occurs during the retrieval, it returns an error.
//
// Returns:
//   - string: The secret retrieved from the keychain, or an empty string if not found.
//   - error: An error if the retrieval fails, or nil if successful.
func GetSecret() (string, error) {
	mu.Lock()
	defer mu.Unlock()

	query := C.CFDictionaryCreateMutable(
		C.kCFAllocatorDefault,
		0,
		&C.kCFTypeDictionaryKeyCallBacks,
		&C.kCFTypeDictionaryValueCallBacks, //nolint:gocritic // dubSubExpr false positive
	)
	defer C.CFRelease(C.CFTypeRef(query))

	C.CFDictionaryAddValue(query, unsafe.Pointer(C.kSecClass), unsafe.Pointer(C.kSecClassGenericPassword))
	C.CFDictionaryAddValue(query, unsafe.Pointer(C.kSecReturnData), unsafe.Pointer(C.kCFBooleanTrue))
	C.CFDictionaryAddValue(query, unsafe.Pointer(C.kSecMatchLimit), unsafe.Pointer(C.kSecMatchLimitOne))
	C.CFDictionaryAddValue(query, unsafe.Pointer(C.kSecAttrLabel), unsafe.Pointer(serviceStringRef))

	var data C.CFTypeRef
	status := C.SecItemCopyMatching(C.CFDictionaryRef(query), &data) //nolint:gocritic // dubSubExpr false positive
	if status != C.errSecSuccess {
		if status == C.errSecItemNotFound {
			return "", fmt.Errorf("could not find %v in keychain", service)
		}
		return "", fmt.Errorf("failed to retrieve %v from keychain: %v", service, status)
	}
	defer C.CFRelease(data)

	secret := C.CFDataGetBytePtr(C.CFDataRef(data))
	return C.GoString((*C.char)(unsafe.Pointer(secret))), nil
}

// deleteSecret will delete a secret from the keychain.
func DeleteSecret() error {
	mu.Lock()
	defer mu.Unlock()

	query := C.CFDictionaryCreateMutable(
		C.kCFAllocatorDefault,
		0,
		&C.kCFTypeDictionaryKeyCallBacks,
		&C.kCFTypeDictionaryValueCallBacks, //nolint:gocritic // dubSubExpr false positive
	)
	defer C.CFRelease(C.CFTypeRef(query))

	C.CFDictionaryAddValue(query, unsafe.Pointer(C.kSecClass), unsafe.Pointer(C.kSecClassGenericPassword))
	C.CFDictionaryAddValue(query, unsafe.Pointer(C.kSecMatchLimit), unsafe.Pointer(C.kSecMatchLimitOne))
	C.CFDictionaryAddValue(query, unsafe.Pointer(C.kSecAttrLabel), unsafe.Pointer(serviceStringRef))

	status := C.SecItemDelete(C.CFDictionaryRef(query))
	if status != C.errSecSuccess {
		return fmt.Errorf("failed to delete %v from keychain: %v", service, status)
	}
	return nil
}

// stringToCFString will return a CFStringRef
func stringToCFString(s string) C.CFStringRef {
	bytes := []byte(s)
	ptr := (*C.UInt8)(&bytes[0])
	return C.CFStringCreateWithBytes(C.kCFAllocatorDefault, ptr, C.CFIndex(len(bytes)), C.kCFStringEncodingUTF8, C.false)
}

// releaseCFString will release memory allocated for a CFStringRef
func releaseCFString(s C.CFStringRef) {
	C.CFRelease(C.CFTypeRef(s))
}
