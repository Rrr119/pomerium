package zerotrust

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/device"
	"github.com/pomerium/pomerium/pkg/grpc/session"
)

func TestVerifyDevicePolicy(t *testing.T) {
	t.Parallel()

	const (
		userID       = "user-1"
		credentialID = "credential-1"
		enrollmentID = "enrollment-1"
		deviceType   = "hardware-key"
	)

	sessionWithDevice := func() *session.Session {
		return &session.Session{
			Id:     "session-1",
			UserId: userID,
			DeviceCredentials: []*session.Session_DeviceCredential{{
				TypeId: deviceType,
				Credential: &session.Session_DeviceCredential_Id{
					Id: credentialID,
				},
			}},
		}
	}
	credential := func() *device.Credential {
		return &device.Credential{
			Id:           credentialID,
			TypeId:       deviceType,
			EnrollmentId: enrollmentID,
			UserId:       userID,
		}
	}
	enrollment := func() *device.Enrollment {
		return &device.Enrollment{
			Id:           enrollmentID,
			TypeId:       deviceType,
			CredentialId: credentialID,
			UserId:       userID,
			ApprovedBy:   "admin@example.com",
		}
	}
	requirement := DeviceRequirement{
		TypeID:   deviceType,
		Approval: ApprovalRequired,
	}

	t.Run("allows an approved device", func(t *testing.T) {
		verifier := NewDeviceVerifier(&fakeDeviceReader{
			records: map[string]proto.Message{
				credentialID: credential(),
				enrollmentID: enrollment(),
			},
		})

		verification, err := verifier.Verify(t.Context(), sessionWithDevice(), requirement)
		require.NoError(t, err)
		assert.Equal(t, credentialID, verification.Credential.GetId())
		assert.Equal(t, enrollmentID, verification.Enrollment.GetId())
	})

	t.Run("rejects an unapproved device", func(t *testing.T) {
		e := enrollment()
		e.ApprovedBy = ""
		verifier := NewDeviceVerifier(&fakeDeviceReader{
			records: map[string]proto.Message{
				credentialID: credential(),
				enrollmentID: e,
			},
		})

		_, err := verifier.Verify(t.Context(), sessionWithDevice(), requirement)
		assert.ErrorIs(t, err, ErrDeviceUnauthorized)
	})

	t.Run("rejects a missing device credential", func(t *testing.T) {
		verifier := NewDeviceVerifier(&fakeDeviceReader{})

		_, err := verifier.Verify(t.Context(), sessionWithDevice(), requirement)
		assert.ErrorIs(t, err, ErrDeviceUnauthenticated)
	})

	t.Run("rejects a device owned by another user", func(t *testing.T) {
		c := credential()
		c.UserId = "user-2"
		verifier := NewDeviceVerifier(&fakeDeviceReader{
			records: map[string]proto.Message{
				credentialID: c,
				enrollmentID: enrollment(),
			},
		})

		_, err := verifier.Verify(t.Context(), sessionWithDevice(), requirement)
		assert.ErrorIs(t, err, ErrDeviceUnauthorized)
	})

	t.Run("propagates datastore failures", func(t *testing.T) {
		verifier := NewDeviceVerifier(&fakeDeviceReader{
			err: status.Error(codes.Unavailable, "databroker unavailable"),
		})

		_, err := verifier.Verify(t.Context(), sessionWithDevice(), requirement)
		assert.Equal(t, codes.Unavailable, status.Code(err))
	})
}

type fakeDeviceReader struct {
	records map[string]proto.Message
	err     error
}

func (f *fakeDeviceReader) Get(
	_ context.Context,
	req *databroker.GetRequest,
	_ ...grpc.CallOption,
) (*databroker.GetResponse, error) {
	if f.err != nil {
		return nil, f.err
	}
	message := f.records[req.GetId()]
	if message == nil {
		return nil, status.Error(codes.NotFound, "not found")
	}
	data, err := anypb.New(message)
	if err != nil {
		return nil, err
	}
	return &databroker.GetResponse{Record: &databroker.Record{
		Type: req.GetType(),
		Id:   req.GetId(),
		Data: data,
	}}, nil
}
