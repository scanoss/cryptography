package httphelper

import (
	"context"
	"net/http"
	"testing"

	"go.uber.org/zap"
	"google.golang.org/grpc/metadata"
)

func Test_setHTTPCodeOnTrailer(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	sugar := logger.Sugar()

	tests := []struct {
		name string
		code int
	}{
		{
			name: "set 200 code",
			code: http.StatusOK,
		},
		{
			name: "set 400 code",
			code: http.StatusBadRequest,
		},
		{
			name: "set 404 code",
			code: http.StatusNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()

			// Mock the grpc.SetTrailer function by creating a context with metadata
			md := metadata.New(map[string]string{})
			ctx = metadata.NewOutgoingContext(ctx, md)

			// This test mainly ensures the function doesn't panic
			// and handles the trailer setting gracefully
			SetHTTPCodeOnTrailer(ctx, sugar, tt.code)
		})
	}
}
