package dtos

type ECOutput struct {
	Hints []ECOutputItem `json:"purls"`
}

type ECOutputItem struct {
	Purl       string           `json:"purl"`
	Versions   []string         `json:"versions"`
	Detections []ECDetectedItem `json:"detections"`
}

type ECDetectedItem struct {
	Id          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	URL         string `json:"URL"`
	Categoty    string `json:"category"`
	Purl        string `json:"purl"`
}
