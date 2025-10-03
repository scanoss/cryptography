package helper

import common "github.com/scanoss/papi/api/commonv2"

const (
	ResponseMessageSuccess = "Success"
	ResponseMessageError   = "Internal error occurred"
)

type Response interface {
	DetermineResponseStatusAndHttpCode(output interface{}) (*common.StatusResponse, int)
}
