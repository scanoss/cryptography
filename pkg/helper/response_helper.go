package helper

import (
	common "github.com/scanoss/papi/api/commonv2"
	"net/http"
)

const (
	ResponseMessageSuccess = "Success"
	ResponseMessageError   = "Internal error occurred"
)

type Response interface {
	DetermineResponseStatusAndHttpCode(output interface{}) (*common.StatusResponse, int)
}

func determineStatusForSingleAction(malformed int, withOutInfo int, notFound int) (*common.StatusResponse, int) {
	response := common.StatusResponse{
		Status:  common.StatusCode_SUCCESS,
		Message: "Algorithms retrieved successfully",
	}
	httpCode := http.StatusOK

	if malformed > 0 {
		response.Status = common.StatusCode_FAILED
		httpCode = http.StatusBadRequest
		response.Message = "Bad Request"
		return &response, httpCode
	}

	if notFound > 0 {
		response.Status = common.StatusCode_FAILED
		httpCode = http.StatusNotFound
		response.Message = "not found algorithm for requested components"
		return &response, httpCode
	}

	if withOutInfo > 0 {
		response.Status = common.StatusCode_SUCCEEDED_WITH_WARNINGS
		httpCode = http.StatusOK
		response.Message = "Not found info for requested components"
		return &response, httpCode
	}

	return &response, httpCode
}

func determineStatusForBatchAction(malformed int, withOutInfo int, notFound int, total int) (*common.StatusResponse, int) {
	response := common.StatusResponse{
		Status:  common.StatusCode_SUCCESS,
		Message: "Algorithms retrieved successfully",
	}
	httpCode := http.StatusOK

	if malformed > 0 && malformed >= total {
		response.Status = common.StatusCode_FAILED
		httpCode = http.StatusBadRequest
		response.Message = "Invalid purls"
		return &response, httpCode
	}

	if notFound > 0 && notFound >= total {
		response.Status = common.StatusCode_SUCCEEDED_WITH_WARNINGS
		httpCode = http.StatusOK
		response.Message = "not found algorithm for requested components"
		return &response, httpCode
	}

	if notFound > 0 {
		response.Status = common.StatusCode_SUCCEEDED_WITH_WARNINGS
		httpCode = http.StatusOK
		response.Message = "Some components algorithms were not found"
	}

	if withOutInfo > 0 {
		response.Status = common.StatusCode_SUCCEEDED_WITH_WARNINGS
		httpCode = http.StatusOK
		response.Message = "Not found info for requested components"
		return &response, httpCode
	}

	if malformed > 0 {
		response.Status = common.StatusCode_SUCCEEDED_WITH_WARNINGS
		httpCode = http.StatusOK
		response.Message = "Some components are not valid purls"
		return &response, httpCode
	}
	return &response, httpCode
}
