package zerotrust

import (
	"context"
	"errors"
	"fmt"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/device"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpcutil"
)

var (
	// ErrNoSession indicates that a device check was attempted without a
	// session or user.
	ErrNoSession = errors.New("zero trust: no session")
	// ErrDeviceUnauthenticated indicates that no enrolled device could be
	// found for the session.
	ErrDeviceUnauthenticated = errors.New("zero trust: device unauthenticated")
	// ErrDeviceUnauthorized indicates that a device was found but did not
	// satisfy the policy.
	ErrDeviceUnauthorized = errors.New("zero trust: device unauthorized")
)

// ApprovalRequirement describes whether a device enrollment must be approved.
type ApprovalRequirement int

const (
	// ApprovalAny does not constrain the enrollment's approval state.
	ApprovalAny ApprovalRequirement = iota
	// ApprovalRequired requires an approved enrollment.
	ApprovalRequired
	// ApprovalForbidden requires an enrollment that has not been approved.
	ApprovalForbidden
)

// DeviceRequirement is a runtime device check.
type DeviceRequirement struct {
	TypeID       string
	CredentialID string
	Approval     ApprovalRequirement
}

// DeviceVerification is the credential and enrollment that satisfied a device
// requirement.
type DeviceVerification struct {
	Credential *device.Credential
	Enrollment *device.Enrollment
}

// DeviceReader is the subset of the databroker client needed for device
// verification.
type DeviceReader interface {
	Get(context.Context, *databroker.GetRequest, ...grpc.CallOption) (*databroker.GetResponse, error)
}

// DeviceVerifier checks session-bound device credentials against device
// credential and enrollment records.
type DeviceVerifier struct {
	client DeviceReader
}

// NewDeviceVerifier creates a new DeviceVerifier.
func NewDeviceVerifier(client DeviceReader) *DeviceVerifier {
	return &DeviceVerifier{client: client}
}

// Verify verifies that the session contains a device credential that exists,
// belongs to the session's user, has a matching enrollment, and meets the
// supplied requirement.
func (v *DeviceVerifier) Verify(
	ctx context.Context,
	s *session.Session,
	requirement DeviceRequirement,
) (*DeviceVerification, error) {
	if s == nil || s.GetId() == "" || s.GetUserId() == "" {
		return nil, ErrNoSession
	}

	var candidateCount int
	var lastErr error
	for _, binding := range s.GetDeviceCredentials() {
		credentialID := binding.GetId()
		if credentialID == "" {
			continue
		}
		if requirement.CredentialID != "" && requirement.CredentialID != credentialID {
			continue
		}
		if requirement.TypeID != "" &&
			binding.GetTypeId() != "" &&
			requirement.TypeID != binding.GetTypeId() {
			continue
		}
		candidateCount++

		verification, err := v.VerifyCredential(ctx, s.GetUserId(), credentialID, requirement)
		if err != nil {
			lastErr = err
			continue
		}
		return verification, nil
	}

	if lastErr != nil {
		return nil, lastErr
	}
	if candidateCount == 0 {
		return nil, fmt.Errorf("%w: no matching credential in session", ErrDeviceUnauthenticated)
	}
	return nil, ErrDeviceUnauthenticated
}

// VerifyCredential verifies a device credential independently of a session.
// It checks ownership, device type, enrollment consistency, and approval.
func (v *DeviceVerifier) VerifyCredential(
	ctx context.Context,
	userID string,
	credentialID string,
	requirement DeviceRequirement,
) (*DeviceVerification, error) {
	if userID == "" {
		return nil, ErrNoSession
	}

	credential, err := v.getCredential(ctx, credentialID)
	if err != nil {
		return nil, classifyDeviceLookupError("credential", credentialID, err)
	}
	if credential.GetUserId() != "" && credential.GetUserId() != userID {
		return nil, fmt.Errorf("%w: credential %q belongs to another user", ErrDeviceUnauthorized, credentialID)
	}
	if requirement.TypeID != "" && credential.GetTypeId() != requirement.TypeID {
		return nil, fmt.Errorf("%w: credential %q has type %q, expected %q",
			ErrDeviceUnauthorized, credentialID, credential.GetTypeId(), requirement.TypeID)
	}

	enrollment, err := v.getEnrollment(ctx, credential.GetEnrollmentId())
	if err != nil {
		return nil, classifyDeviceLookupError("enrollment", credential.GetEnrollmentId(), err)
	}
	if err := verifyEnrollment(userID, credential, enrollment, requirement.Approval); err != nil {
		return nil, err
	}

	return &DeviceVerification{
		Credential: credential,
		Enrollment: enrollment,
	}, nil
}

// VerifySession verifies every credential bound to the session.
func (v *DeviceVerifier) VerifySession(
	ctx context.Context,
	s *session.Session,
) ([]DeviceVerification, error) {
	if s == nil || s.GetId() == "" || s.GetUserId() == "" {
		return nil, ErrNoSession
	}

	verifications := make([]DeviceVerification, 0, len(s.GetDeviceCredentials()))
	for _, binding := range s.GetDeviceCredentials() {
		if binding.GetId() == "" {
			continue
		}
		verification, err := v.Verify(ctx, s, DeviceRequirement{CredentialID: binding.GetId()})
		if err != nil {
			return nil, err
		}
		verifications = append(verifications, *verification)
	}
	return verifications, nil
}

func classifyDeviceLookupError(kind, id string, err error) error {
	if status.Code(err) == codes.NotFound {
		return fmt.Errorf("%w: %s %q not found", ErrDeviceUnauthenticated, kind, id)
	}
	return fmt.Errorf("zero trust: look up device %s %q: %w", kind, id, err)
}

func (v *DeviceVerifier) getCredential(
	ctx context.Context,
	credentialID string,
) (*device.Credential, error) {
	if credentialID == "" {
		return nil, status.Error(codes.NotFound, "credential id is empty")
	}
	res, err := v.client.Get(ctx, &databroker.GetRequest{
		Type: grpcutil.GetTypeURL(new(device.Credential)),
		Id:   credentialID,
	})
	if err != nil {
		return nil, err
	}
	var credential device.Credential
	if err := res.GetRecord().GetData().UnmarshalTo(&credential); err != nil {
		return nil, err
	}
	return &credential, nil
}

func (v *DeviceVerifier) getEnrollment(
	ctx context.Context,
	enrollmentID string,
) (*device.Enrollment, error) {
	if enrollmentID == "" {
		return nil, status.Error(codes.NotFound, "enrollment id is empty")
	}
	res, err := v.client.Get(ctx, &databroker.GetRequest{
		Type: grpcutil.GetTypeURL(new(device.Enrollment)),
		Id:   enrollmentID,
	})
	if err != nil {
		return nil, err
	}
	var enrollment device.Enrollment
	if err := res.GetRecord().GetData().UnmarshalTo(&enrollment); err != nil {
		return nil, err
	}
	return &enrollment, nil
}

func verifyEnrollment(
	userID string,
	credential *device.Credential,
	enrollment *device.Enrollment,
	approval ApprovalRequirement,
) error {
	if enrollment.GetUserId() != "" && enrollment.GetUserId() != userID {
		return fmt.Errorf("%w: enrollment %q belongs to another user",
			ErrDeviceUnauthorized, enrollment.GetId())
	}
	if enrollment.GetCredentialId() != "" &&
		enrollment.GetCredentialId() != credential.GetId() {
		return fmt.Errorf("%w: enrollment %q references a different credential",
			ErrDeviceUnauthorized, enrollment.GetId())
	}
	if enrollment.GetTypeId() != "" &&
		credential.GetTypeId() != "" &&
		enrollment.GetTypeId() != credential.GetTypeId() {
		return fmt.Errorf("%w: enrollment %q references a different device type",
			ErrDeviceUnauthorized, enrollment.GetId())
	}

	switch approval {
	case ApprovalRequired:
		if enrollment.GetApprovedBy() == "" {
			return fmt.Errorf("%w: enrollment %q is not approved",
				ErrDeviceUnauthorized, enrollment.GetId())
		}
	case ApprovalForbidden:
		if enrollment.GetApprovedBy() != "" {
			return fmt.Errorf("%w: enrollment %q is approved",
				ErrDeviceUnauthorized, enrollment.GetId())
		}
	}
	return nil
}
