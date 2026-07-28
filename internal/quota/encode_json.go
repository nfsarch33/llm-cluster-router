package quota

import "encoding/json"

// encodeJSON is a tiny wrapper used to keep the Detector's hot path
// allocation-free.
func encodeJSON(v interface{}) ([]byte, error) {
	return json.Marshal(v)
}
