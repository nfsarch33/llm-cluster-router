package main

import "testing"

// TestHelixChannelEnabledFromEnv_DefaultIsTrue asserts the
// HELIXCHANNEL_ENABLED env var defaults to true when unset
// (v18712-2 production default). This is the v18712-2 contract.
func TestHelixChannelEnabledFromEnv_DefaultIsTrue(t *testing.T) {
	t.Setenv("HELIXCHANNEL_ENABLED", "")
	if got := helixChannelEnabledFromEnv(); got != true {
		t.Errorf("HELIXCHANNEL_ENABLED='' → %t, want true", got)
	}
}

// TestHelixChannelEnabledFromEnv_TruthyValues asserts the
// canonical truthy strings enable HelixChannel.
func TestHelixChannelEnabledFromEnv_TruthyValues(t *testing.T) {
	for _, v := range []string{"true", "TRUE", "1", "yes", "YES", "on", "ON", "  true  "} {
		t.Run(v, func(t *testing.T) {
			t.Setenv("HELIXCHANNEL_ENABLED", v)
			if got := helixChannelEnabledFromEnv(); got != true {
				t.Errorf("HELIXCHANNEL_ENABLED=%q → %t, want true", v, got)
			}
		})
	}
}

// TestHelixChannelEnabledFromEnv_FalsyValues asserts the
// canonical falsy strings opt out of HelixChannel.
func TestHelixChannelEnabledFromEnv_FalsyValues(t *testing.T) {
	for _, v := range []string{"false", "FALSE", "0", "no", "NO", "off", "OFF"} {
		t.Run(v, func(t *testing.T) {
			t.Setenv("HELIXCHANNEL_ENABLED", v)
			if got := helixChannelEnabledFromEnv(); got != false {
				t.Errorf("HELIXCHANNEL_ENABLED=%q → %t, want false", v, got)
			}
		})
	}
}

// TestHelixChannelEnabledFromEnv_UnknownDefaultsTrue asserts
// unknown values default to true (HelixChannel on). Operators
// who set HELIXCHANNEL_ENABLED=garbage still get the AES/mTLS
// factory; this avoids silent regression.
func TestHelixChannelEnabledFromEnv_UnknownDefaultsTrue(t *testing.T) {
	for _, v := range []string{"garbage", "definitely-not-true"} {
		t.Run(v, func(t *testing.T) {
			t.Setenv("HELIXCHANNEL_ENABLED", v)
			if got := helixChannelEnabledFromEnv(); got != true {
				t.Errorf("HELIXCHANNEL_ENABLED=%q → %t, want true (default)", v, got)
			}
		})
	}
}
