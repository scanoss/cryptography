package models

type QuerySummary struct {
	PurlsFailedToParse []string
	PurlsWOInfo        []string
	PurlsNotFound      []string
}
