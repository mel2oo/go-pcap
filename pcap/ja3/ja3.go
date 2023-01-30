package ja3

// https://github.com/salesforce/ja3

import (
	"crypto/md5"
	"encoding/hex"
	"strconv"

	"github.com/mel2oo/go-pcap/gnet"
)

const (
	dashByte  = byte(45)
	commaByte = byte(44)
)

// GetJa3SHash returns the JA3 fingerprint hash of the tls client hello.
// SSLVersion,Cipher,SSLExtension,EllipticCurve,EllipticCurvePointFormat
func GetJa3Hash(clientHello gnet.TLSClientHello) string {
	byteString := make([]byte, 0)

	// Version
	byteString = strconv.AppendUint(byteString, uint64(clientHello.Version), 10)
	byteString = append(byteString, commaByte)

	// Cipher Suites
	if len(clientHello.CipherSuites) != 0 {
		for _, val := range clientHello.CipherSuites {
			byteString = strconv.AppendUint(byteString, uint64(val), 10)
			byteString = append(byteString, dashByte)
		}
		// Replace last dash with a comma
		byteString[len(byteString)-1] = commaByte
	} else {
		byteString = append(byteString, commaByte)
	}

	for i := range clientHello.Extensions {
		byteString = appendExtension(byteString, clientHello.Extensions[i])
	}

	// If dash found replace it with a comma
	if byteString[len(byteString)-1] == dashByte {
		byteString[len(byteString)-1] = commaByte
	} else {
		// else add a comma (no extension present)
		byteString = append(byteString, commaByte)
	}

	// Suppported Elliptic Curves
	if len(clientHello.SupportedCurves) > 0 {
		for _, val := range clientHello.SupportedCurves {
			byteString = strconv.AppendUint(byteString, uint64(val), 10)
			byteString = append(byteString, dashByte)
		}
		// Replace last dash with a comma
		byteString[len(byteString)-1] = commaByte
	} else {
		byteString = append(byteString, commaByte)
	}

	// Elliptic Curve Point Formats
	if len(clientHello.SupportedPoints) > 0 {
		for _, val := range clientHello.SupportedPoints {
			byteString = strconv.AppendUint(byteString, uint64(val), 10)
			byteString = append(byteString, dashByte)
		}
		// Remove last dash
		byteString = byteString[:len(byteString)-1]
	}

	h := md5.Sum(byteString)
	return hex.EncodeToString(h[:])
}

// GetJa3SHash returns the JA3 fingerprint hash of the tls server hello.
// SSLVersion,Cipher,SSLExtension
func GetJa3SHash(serverHello gnet.TLSServerHello) string {
	byteString := make([]byte, 0)

	// Version
	byteString = strconv.AppendUint(byteString, uint64(serverHello.HandshakeVersion), 10)
	byteString = append(byteString, commaByte)

	// Cipher Suite
	byteString = strconv.AppendUint(byteString, uint64(serverHello.CipherSuite), 10)
	byteString = append(byteString, commaByte)

	for i := range serverHello.Extensions {
		byteString = appendExtension(byteString, serverHello.Extensions[i])
	}

	if byteString[len(byteString)-1] == dashByte {
		byteString = byteString[:len(byteString)-1]
	}

	h := md5.Sum(byteString)
	return hex.EncodeToString(h[:])
}

func appendExtension(byteString []byte, exType uint16) []byte {
	byteString = strconv.AppendUint(byteString, uint64(exType), 10)
	byteString = append(byteString, dashByte)
	return byteString
}
