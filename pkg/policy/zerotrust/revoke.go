package zerotrust

import (
	"context"
	"fmt"
	"slices"
	"sort"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpcutil"
	"github.com/pomerium/pomerium/pkg/protoutil"
)

const sessionRevocationPageSize = 100

// SessionStore is the subset of the databroker client needed to find and
// revoke sessions.
type SessionStore interface {
	Query(context.Context, *databroker.QueryRequest, ...grpc.CallOption) (*databroker.QueryResponse, error)
	Put(context.Context, *databroker.PutRequest, ...grpc.CallOption) (*databroker.PutResponse, error)
}

// SessionRevoker revokes sessions by user or by a user's device credential.
type SessionRevoker struct {
	client SessionStore
}

// NewSessionRevoker creates a new SessionRevoker.
func NewSessionRevoker(client SessionStore) *SessionRevoker {
	return &SessionRevoker{client: client}
}

// RevokeSession revokes a single session.
func (r *SessionRevoker) RevokeSession(ctx context.Context, sessionID string) error {
	if sessionID == "" {
		return fmt.Errorf("zero trust: session id is required")
	}
	data := protoutil.NewAny(new(session.Session))
	_, err := r.client.Put(ctx, &databroker.PutRequest{Records: []*databroker.Record{{
		Type:      data.GetTypeUrl(),
		Id:        sessionID,
		Data:      data,
		DeletedAt: timestamppb.Now(),
	}}})
	if err != nil {
		return fmt.Errorf("zero trust: revoke session %q: %w", sessionID, err)
	}
	return nil
}

// RevokeSessionsForUser revokes every active session for a user.
func (r *SessionRevoker) RevokeSessionsForUser(
	ctx context.Context,
	userID string,
	excludeSessionIDs ...string,
) ([]string, error) {
	return r.revoke(ctx, userID, "", excludeSessionIDs...)
}

// RevokeSessionsForDevice revokes every active session for a user that is
// bound to the given device credential. Use excludeSessionIDs to keep the
// session performing the device unregistration active.
func (r *SessionRevoker) RevokeSessionsForDevice(
	ctx context.Context,
	userID string,
	deviceCredentialID string,
	excludeSessionIDs ...string,
) ([]string, error) {
	if deviceCredentialID == "" {
		return nil, fmt.Errorf("zero trust: device credential id is required")
	}

	sessionIDs, err := r.revoke(ctx, userID, deviceCredentialID, excludeSessionIDs...)
	if err != nil {
		return nil, err
	}
	return sessionIDs, nil
}

func (r *SessionRevoker) revoke(
	ctx context.Context,
	userID string,
	deviceCredentialID string,
	excludeSessionIDs ...string,
) ([]string, error) {
	if userID == "" {
		return nil, fmt.Errorf("zero trust: user id is required")
	}

	sessions, err := r.listSessionsForUser(ctx, userID)
	if err != nil {
		return nil, err
	}

	excluded := make(map[string]struct{}, len(excludeSessionIDs))
	for _, sessionID := range excludeSessionIDs {
		excluded[sessionID] = struct{}{}
	}

	var sessionIDs []string
	for _, s := range sessions {
		if _, ok := excluded[s.GetId()]; ok {
			continue
		}
		if deviceCredentialID != "" && !hasDeviceCredential(s, deviceCredentialID) {
			continue
		}
		sessionIDs = append(sessionIDs, s.GetId())
	}
	slices.Sort(sessionIDs)
	if len(sessionIDs) == 0 {
		return nil, nil
	}

	records := make([]*databroker.Record, 0, len(sessionIDs))
	for _, sessionID := range sessionIDs {
		data := protoutil.NewAny(new(session.Session))
		records = append(records, &databroker.Record{
			Type:      data.GetTypeUrl(),
			Id:        sessionID,
			Data:      data,
			DeletedAt: timestamppb.Now(),
		})
	}
	for _, req := range databroker.OptimumPutRequestsFromRecords(records) {
		if _, err := r.client.Put(ctx, req); err != nil {
			return nil, fmt.Errorf("zero trust: revoke sessions: %w", err)
		}
	}
	return sessionIDs, nil
}

func (r *SessionRevoker) listSessionsForUser(
	ctx context.Context,
	userID string,
) ([]*session.Session, error) {
	var sessions []*session.Session
	seen := make(map[string]struct{})
	var offset int64

	for {
		res, err := r.client.Query(ctx, &databroker.QueryRequest{
			Type:   grpcutil.GetTypeURL(new(session.Session)),
			Filter: userIDFilter(userID),
			Offset: offset,
			Limit:  sessionRevocationPageSize,
		})
		if status.Code(err) == codes.NotFound {
			return sessions, nil
		} else if err != nil {
			return nil, fmt.Errorf("zero trust: query sessions for user %q: %w", userID, err)
		}

		records := res.GetRecords()
		for _, record := range records {
			if record.GetDeletedAt() != nil {
				continue
			}
			if _, ok := seen[record.GetId()]; ok {
				continue
			}
			var s session.Session
			if err := record.GetData().UnmarshalTo(&s); err != nil {
				return nil, fmt.Errorf("zero trust: unmarshal session %q: %w", record.GetId(), err)
			}
			if s.GetUserId() != userID {
				continue
			}
			seen[s.GetId()] = struct{}{}
			sessions = append(sessions, &s)
		}

		offset += int64(len(records))
		if len(records) == 0 || offset >= res.GetTotalCount() {
			break
		}
	}

	sort.Slice(sessions, func(i, j int) bool {
		return sessions[i].GetId() < sessions[j].GetId()
	})
	return sessions, nil
}

func userIDFilter(userID string) *structpb.Struct {
	return &structpb.Struct{Fields: map[string]*structpb.Value{
		"user_id": structpb.NewStringValue(userID),
	}}
}

func hasDeviceCredential(s *session.Session, credentialID string) bool {
	for _, binding := range s.GetDeviceCredentials() {
		if binding.GetId() == credentialID {
			return true
		}
	}
	return false
}
