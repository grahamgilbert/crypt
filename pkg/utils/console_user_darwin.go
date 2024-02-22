//go:build darwin
// +build darwin

package utils

/*
#cgo LDFLAGS: -framework SystemConfiguration
#include <SystemConfiguration/SystemConfiguration.h>

const char *getConsoleUser() {
	CFStringRef cfUser;
	CFStringEncoding cfEncoding = kCFStringEncodingUTF8;
	cfUser = SCDynamicStoreCopyConsoleUser(NULL, NULL, NULL);
	if (cfUser == NULL) {
		return NULL;
	}
	CFIndex length = CFStringGetLength(cfUser);
	CFIndex maxSize = CFStringGetMaximumSizeForEncoding(length, cfEncoding) + 1;
	char *buffer = (char *)malloc(maxSize);
	if (CFStringGetCString(cfUser, buffer, maxSize, cfEncoding)) {
		return buffer;
	}
	return NULL;
}
*/
import "C"
import (
	"fmt"
	"unsafe"
)

// GetConsoleUser returns the current console user
func GetConsoleUser() (string, error) {
	user := C.getConsoleUser()
	if user == nil {
		return "", fmt.Errorf("could not get console user")
	}

	out := C.GoString(user)
	C.free(unsafe.Pointer(user))

	return out, nil

}
