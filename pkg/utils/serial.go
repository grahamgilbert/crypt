package utils

/*
#cgo LDFLAGS: -framework CoreFoundation -framework IOKit
#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>

void getSerialNumber(char *serialNumberBuf, int serialNumberBufLen)
{
  CFMutableDictionaryRef matching = IOServiceMatching("IOPlatformExpertDevice");
  io_service_t service = IOServiceGetMatchingService(kIOMainPortDefault, matching);

  CFStringRef serialNumber = IORegistryEntryCreateCFProperty(service,
    CFSTR("IOPlatformSerialNumber"), kCFAllocatorDefault, 0);

  if (serialNumber) {
    CFStringGetCString(serialNumber, serialNumberBuf, serialNumberBufLen, kCFStringEncodingUTF8);
  }

  IOObjectRelease(service);
}
*/
import "C"
import (
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/sys/unix"
)

var (
	value string
	once  sync.Once
)

// Get returns the serial number of the machine. The value is cached after the first call.
func GetSerial() string {
	once.Do(func() {
		// Serial numbers are between 8 and 14 characters long, leave some room just in case
		var serialBuf [65]byte

		C.getSerialNumber(
			(*C.char)(unsafe.Pointer(&serialBuf[0])),
			C.int(len(serialBuf)),
		)

		value = strings.ToValidUTF8(unix.ByteSliceToString(serialBuf[:]), "")
	})
	return value
}
