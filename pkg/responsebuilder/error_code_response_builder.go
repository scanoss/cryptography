package responsebuilder

import (
	pb "github.com/scanoss/papi/api/commonv2"
	"scanoss.com/cryptography/pkg/domain"
)

func statusCodeToErrorCode(code domain.StatusCode) *pb.ErrorCode {
	switch code {
	case domain.InvalidPurl:
		return pb.ErrorCode_INVALID_PURL.Enum()
	case domain.ComponentNotFound:

		return pb.ErrorCode_COMPONENT_NOT_FOUND.Enum()
	case domain.InvalidSemver:
		return pb.ErrorCode_INVALID_SEMVER.Enum()
	case domain.ComponentWithoutInfo:
		return pb.ErrorCode_NO_INFO.Enum()
	case domain.Success:
		return nil
	default:
		return nil
	}
}
