package gnet

import "github.com/google/uuid"

// An ID that uniquely identifies a pair of uni-directional flows in a TCP
// stream. We use UUID instead of a hash of the ip/port tuple (src IP, dst IP,
// src port, dst port) because we want to uniquely identify the pair as a
// specific interaction between 2 hosts at a particular time, whereas IPs and
// ports may be reused, particularly in test setup.
type TCPBidiID uuid.UUID
