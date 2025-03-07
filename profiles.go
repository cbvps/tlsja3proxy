package main

import (
	"github.com/bogdanfinn/tls-client/profiles"
)

// Map of browser profile names to their corresponding tls-client profiles
var browserProfiles = map[string]profiles.ClientProfile{
	"chrome133":         profiles.Chrome_133,
	"chrome124":         profiles.Chrome_124,
	"chrome120":         profiles.Chrome_120,
	"chrome117":         profiles.Chrome_117,
	"chrome110":         profiles.Chrome_110,
	"chrome107":         profiles.Chrome_107,
	"chrome104":         profiles.Chrome_104,
	"firefox117":        profiles.Firefox_117,
	"firefox110":        profiles.Firefox_110,
	"firefox108":        profiles.Firefox_108,
	"safari18_0":        profiles.Safari_16_0,
	"safari16_0":        profiles.Safari_16_0,
	"safari_ios_18_0":   profiles.Safari_IOS_18_0,
	"safari_ios_17_0":   profiles.Safari_IOS_17_0,
	"safari_ios_16_0":   profiles.Safari_IOS_16_0,
	"opera91":           profiles.Opera_91,
	"opera90":           profiles.Opera_90,
	"default":           profiles.Chrome_133,
}

// GetClientProfile returns the corresponding tls-client profile for a given browser name
func GetClientProfile(profileName string) profiles.ClientProfile {
	profile, exists := browserProfiles[profileName]
	if !exists {
		return browserProfiles["default"]
	}
	return profile
}
