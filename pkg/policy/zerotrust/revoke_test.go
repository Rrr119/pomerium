package zerotrust

import (
	"context"
	"sort"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/session"
)

func TestSessionRevocationPolicy(t *testing.T) {
	t.Parallel()

	newStore := func() *fakeSessionStore {
		return &fakeSessionStore{sessions: map[string]*session.Session{
			"s1": sessionWithCredential("s1", "user-1", "device-1"),
			"s2": sessionWithCredential("s2", "user-1", "device-2"),
			"s3": sessionWithCredential("s3", "user-2", "device-1"),
			"s4": sessionWithCredential("s4", "user-1", "device-1"),
		}}
	}

	t.Run("revokes sessions bound to a deleted device", func(t *testing.T) {
		store := newStore()
		revoker := NewSessionRevoker(store)

		revoked, err := revoker.RevokeSessionsForDevice(
			t.Context(),
			"user-1",
			"device-1",
			"s4",
		)
		require.NoError(t, err)
		assert.Equal(t, []string{"s1"}, revoked)
		assert.Equal(t, []string{"s1"}, store.deletedIDs())
	})

	t.Run("revokes every session for a user", func(t *testing.T) {
		store := newStore()
		revoker := NewSessionRevoker(store)

		revoked, err := revoker.RevokeSessionsForUser(t.Context(), "user-1")
		require.NoError(t, err)
		assert.Equal(t, []string{"s1", "s2", "s4"}, revoked)
		assert.Equal(t, []string{"s1", "s2", "s4"}, store.deletedIDs())
	})
}

func sessionWithCredential(sessionID, userID, credentialID string) *session.Session {
	return &session.Session{
		Id:     sessionID,
		UserId: userID,
		DeviceCredentials: []*session.Session_DeviceCredential{{
			TypeId: "any",
			Credential: &session.Session_DeviceCredential_Id{
				Id: credentialID,
			},
		}},
	}
}

type fakeSessionStore struct {
	mu       sync.Mutex
	sessions map[string]*session.Session
	deleted  map[string]struct{}
}

func (f *fakeSessionStore) Query(
	_ context.Context,
	req *databroker.QueryRequest,
	_ ...grpc.CallOption,
) (*databroker.QueryResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	userID := ""
	if req.GetFilter() != nil {
		userID = req.GetFilter().GetFields()["user_id"].GetStringValue()
	}

	ids := make([]string, 0, len(f.sessions))
	for id := range f.sessions {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	var records []*databroker.Record
	for _, id := range ids {
		s := f.sessions[id]
		if userID != "" && s.GetUserId() != userID {
			continue
		}
		data, err := anypb.New(s)
		if err != nil {
			return nil, err
		}
		records = append(records, &databroker.Record{
			Type: req.GetType(),
			Id:   id,
			Data: data,
		})
	}

	total := int64(len(records))
	start := int(req.GetOffset())
	if start > len(records) {
		start = len(records)
	}
	end := len(records)
	if limit := int(req.GetLimit()); limit > 0 && start+limit < end {
		end = start + limit
	}
	return &databroker.QueryResponse{
		Records:    records[start:end],
		TotalCount: total,
	}, nil
}

func (f *fakeSessionStore) Put(
	_ context.Context,
	req *databroker.PutRequest,
	_ ...grpc.CallOption,
) (*databroker.PutResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.deleted == nil {
		f.deleted = make(map[string]struct{})
	}
	for _, record := range req.GetRecords() {
		f.deleted[record.GetId()] = struct{}{}
	}
	return &databroker.PutResponse{Records: req.GetRecords()}, nil
}

func (f *fakeSessionStore) deletedIDs() []string {
	f.mu.Lock()
	defer f.mu.Unlock()

	ids := make([]string, 0, len(f.deleted))
	for id := range f.deleted {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}
