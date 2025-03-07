package main

import (
	"github.com/bogdanfinn/tls-client/profiles"
)

// Map of browser profile names to their corresponding tls-client profiles
var browserProfiles = map[string]profiles.ClientProfile{
	// Chrome profiles
	"chrome133": profiles.Chrome_133,
	"chrome124": profiles.Chrome_124,
	"chrome120": profiles.Chrome_120,
	"chrome117": profiles.Chrome_117,
	"chrome110": profiles.Chrome_110,
	"chrome107": profiles.Chrome_107,
	"chrome104": profiles.Chrome_104,

	// Firefox profiles
	"firefox117": profiles.Firefox_117,
	"firefox110": profiles.Firefox_110,
	"firefox108": profiles.Firefox_108,

	// Safari profiles - note that Safari 18.0 might not be available in the library yet
	"safari18_0": profiles.Safari_16_0, // Using 16.0 as fallback
	"safari16_0": profiles.Safari_16_0,

	// iOS Safari profiles
	"safari_ios_18_0": profiles.Safari_IOS_18_0,
	"safari_ios_17_0": profiles.Safari_IOS_17_0,
	"safari_ios_16_0": profiles.Safari_IOS_16_0,

	// Opera profiles
	"opera91": profiles.Opera_91,
	"opera90": profiles.Opera_90,

	// Default profile
	"default": profiles.Chrome_133,
}

// GetClientProfile returns the corresponding tls-client profile for a given browser name
func GetClientProfile(profileName string) profiles.ClientProfile {
	profile, exists := browserProfiles[profileName]
	if !exists {
		return browserProfiles["default"]
	}
	return profile
}
