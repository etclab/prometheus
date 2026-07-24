// Copyright The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package hermes

import (
	"encoding/base64"
	"fmt"

	"github.com/etclab/hermes/wire"
	pb "github.com/etclab/hermes/wire/pb"
	"google.golang.org/protobuf/proto"

	hindex "github.com/etclab/hermes/index"
)

// The HTTP transport reuses Hermes' own gRPC wire messages: an update is a
// marshalled pb.UpdateRequest posted as the request body, and a search query is
// a marshalled pb.SearchRequest carried base64-encoded in a request parameter
// (aggregate keys run to several kilobytes, which is why searches are POSTed
// rather than squeezed into the selector). Encoding is unpadded URL-safe base64
// so the same string is valid in a query string and in a form body.

// EncodeSearchQuery renders a search query for transport in a request
// parameter. It is the client half of DecodeSearchQuery.
func EncodeSearchQuery(q *hindex.SearchQuery) (string, error) {
	req, err := wire.SearchToProto(q)
	if err != nil {
		return "", fmt.Errorf("hermes: encoding search query: %w", err)
	}
	blob, err := proto.Marshal(req)
	if err != nil {
		return "", fmt.Errorf("hermes: marshalling search query: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(blob), nil
}

// DecodeSearchQuery parses a search query out of a request parameter.
func DecodeSearchQuery(s string) (*hindex.SearchQuery, error) {
	blob, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("hermes: decoding search query: %w", err)
	}
	var req pb.SearchRequest
	if err := proto.Unmarshal(blob, &req); err != nil {
		return nil, fmt.Errorf("hermes: unmarshalling search query: %w", err)
	}
	q, err := wire.SearchFromProto(&req)
	if err != nil {
		return nil, fmt.Errorf("hermes: building search query: %w", err)
	}
	return q, nil
}

// EncodeUpdate renders a writer's update operation as a request body. It is the
// client half of DecodeUpdate.
func EncodeUpdate(wid int, op *hindex.UpdateOp) ([]byte, error) {
	req, err := wire.UpdateToProto(wid, op)
	if err != nil {
		return nil, fmt.Errorf("hermes: encoding update: %w", err)
	}
	blob, err := proto.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("hermes: marshalling update: %w", err)
	}
	return blob, nil
}

// DecodeUpdate parses a writer id and its update operation out of a request
// body.
func DecodeUpdate(blob []byte) (int, *hindex.UpdateOp, error) {
	var req pb.UpdateRequest
	if err := proto.Unmarshal(blob, &req); err != nil {
		return 0, nil, fmt.Errorf("hermes: unmarshalling update: %w", err)
	}
	wid, op, err := wire.UpdateFromProto(&req)
	if err != nil {
		return 0, nil, fmt.Errorf("hermes: building update: %w", err)
	}
	return wid, op, nil
}
