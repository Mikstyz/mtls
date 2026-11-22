package models

type PlaybackSettings struct {
	Photo string `json:"photo"`
	Video string `json:"video"`
}

func (s PlaybackSettings) Valid() bool {
	valid := func(q string) bool { return q == "auto" || q == "original" || q == "reduced" }
	return valid(s.Photo) && valid(s.Video)
}
