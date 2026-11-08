//go:build darwin

package main

import (
	"fmt"

	"github.com/ebitengine/purego"
)

const (
	systemConfigurationPath = "/System/Library/Frameworks/SystemConfiguration.framework/SystemConfiguration"
	coreFoundationPath      = "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation"
	cfStringEncodingUTF8    = 0x08000100
	cfNumberSInt32Type      = 3
	pacURLBufferSize        = 2048
)

// systemPACURL returns the URL of the automatic proxy configuration that macOS has enabled.
//
// It calls the SystemConfiguration framework without cgo, which avoids starting scutil. The
// result is empty if no PAC is enabled.
func systemPACURL() (string, error) {
	var (
		copyProxies  func(store uintptr) uintptr
		dictGetValue func(dict, key uintptr) uintptr
		stringCreate func(alloc uintptr, cstr *byte, encoding uint32) uintptr
		numberGet    func(number uintptr, kind int, out *int32) bool
		stringGetC   func(str uintptr, buf *byte, size int, encoding uint32) bool
		release      func(object uintptr)
	)

	systemConfiguration, err := purego.Dlopen(systemConfigurationPath, purego.RTLD_NOW|purego.RTLD_GLOBAL)
	if err != nil {
		return "", fmt.Errorf("load SystemConfiguration: %w", err)
	}
	coreFoundation, err := purego.Dlopen(coreFoundationPath, purego.RTLD_NOW|purego.RTLD_GLOBAL)
	if err != nil {
		return "", fmt.Errorf("load CoreFoundation: %w", err)
	}
	purego.RegisterLibFunc(&copyProxies, systemConfiguration, "SCDynamicStoreCopyProxies")
	purego.RegisterLibFunc(&dictGetValue, coreFoundation, "CFDictionaryGetValue")
	purego.RegisterLibFunc(&stringCreate, coreFoundation, "CFStringCreateWithCString")
	purego.RegisterLibFunc(&numberGet, coreFoundation, "CFNumberGetValue")
	purego.RegisterLibFunc(&stringGetC, coreFoundation, "CFStringGetCString")
	purego.RegisterLibFunc(&release, coreFoundation, "CFRelease")

	key := func(name string) uintptr {
		cstr := append([]byte(name), 0)
		return stringCreate(0, &cstr[0], cfStringEncodingUTF8)
	}

	proxies := copyProxies(0)
	if proxies == 0 {
		return "", nil
	}
	defer release(proxies)

	enableKey := key("ProxyAutoConfigEnable")
	defer release(enableKey)
	urlKey := key("ProxyAutoConfigURLString")
	defer release(urlKey)

	var enabled int32
	if number := dictGetValue(proxies, enableKey); number != 0 {
		numberGet(number, cfNumberSInt32Type, &enabled)
	}
	str := dictGetValue(proxies, urlKey)
	if enabled != 1 || str == 0 {
		return "", nil
	}

	buf := make([]byte, pacURLBufferSize)
	if !stringGetC(str, &buf[0], len(buf), cfStringEncodingUTF8) {
		return "", fmt.Errorf("read the PAC URL: longer than %d bytes", pacURLBufferSize)
	}
	end := 0
	for end < len(buf) && buf[end] != 0 {
		end++
	}
	return string(buf[:end]), nil
}
