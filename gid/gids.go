package gid

import (
	"strings"

	"github.com/google/uuid"
	"github.com/pkg/errors"
)

const (
	APISpecTag            = "api"
	APIKeyTag             = "apk"
	APIMethodTag          = "mth"
	ClientTag             = "cli"
	ConnectionTag         = "cxn"
	DataCategoryTag       = "dct"
	GraphTag              = "gph"
	IdentityTag           = "idt"
	InvalidTag            = "xxx"
	LearnSessionTag       = "lrn"
	MessageTag            = "msg"
	MonitorTag            = "mtr"
	OrganizationTag       = "org"
	OutboundRequestTag    = "obr"
	ProjectTag            = "prj"
	RequestTag            = "req"
	RuleTag               = "rul"
	ScheduleTag           = "sch"
	ServiceClusterTag     = "scl"
	ServiceTag            = "svc"
	ShardAliasTag         = "sal"
	ShardTag              = "shd"
	UsageTrackingEventTag = "ute"
	UserTag               = "usr"
	WitnessTag            = "wit"
)

type tagToIDConstructor func(uuid.UUID) ID

var idConstructorMap = map[string]tagToIDConstructor{
	APISpecTag:            func(ID uuid.UUID) ID { return NewAPISpecID(ID) },
	APIKeyTag:             func(ID uuid.UUID) ID { return NewAPIKeyID(ID) },
	APIMethodTag:          func(ID uuid.UUID) ID { return NewAPIMethodID(ID) },
	ClientTag:             func(ID uuid.UUID) ID { return NewClientID(ID) },
	ConnectionTag:         func(ID uuid.UUID) ID { return NewConnectionID(ID) },
	DataCategoryTag:       func(ID uuid.UUID) ID { return NewDataCategoryID(ID) },
	IdentityTag:           func(ID uuid.UUID) ID { return NewIdentityID(ID) },
	GraphTag:              func(ID uuid.UUID) ID { return NewGraphID(ID) },
	LearnSessionTag:       func(ID uuid.UUID) ID { return NewLearnSessionID(ID) },
	MessageTag:            func(ID uuid.UUID) ID { return NewMessageID(ID) },
	MonitorTag:            func(ID uuid.UUID) ID { return NewMonitorID(ID) },
	OrganizationTag:       func(ID uuid.UUID) ID { return NewOrganizationID(ID) },
	OutboundRequestTag:    func(ID uuid.UUID) ID { return NewOutboundRequestID(ID) },
	ProjectTag:            func(ID uuid.UUID) ID { return NewProjectID(ID) },
	RequestTag:            func(ID uuid.UUID) ID { return NewRequestID(ID) },
	RuleTag:               func(ID uuid.UUID) ID { return NewRuleID(ID) },
	ScheduleTag:           func(ID uuid.UUID) ID { return NewScheduleID(ID) },
	ServiceClusterTag:     func(ID uuid.UUID) ID { return NewServiceClusterID(ID) },
	ServiceTag:            func(ID uuid.UUID) ID { return NewServiceID(ID) },
	ShardAliasTag:         func(ID uuid.UUID) ID { return NewShardAliasID(ID) },
	ShardTag:              func(ID uuid.UUID) ID { return NewShardID(ID) },
	UsageTrackingEventTag: func(ID uuid.UUID) ID { return NewUsageTrackingEventID(ID) },
	UserTag:               func(ID uuid.UUID) ID { return NewUserID(ID) },
	WitnessTag:            func(ID uuid.UUID) ID { return NewWitnessID(ID) },
}

var (
	// NOTE: These are deprecated and will be removed in a subsequent PR.
	// Use the zero (unassigned) value for any given ID instead.
	NilDataCategoryID   = NewDataCategoryID(uuid.Nil)
	NilProjectID        = NewProjectID(uuid.Nil)
	NilServiceID        = NewServiceID(uuid.Nil)
	NilServiceClusterID = NewServiceClusterID(uuid.Nil)
	NilUserID           = NewUserID(uuid.Nil)
)

func parseIDParts(str string) (string, uuid.UUID, error) {
	parts := strings.Split(str, "_")
	if len(parts) != 2 {
		return "", uuid.Nil, errors.New("invalid GID structure")
	}
	idPart, err := decodeUUID(parts[1])
	if err != nil {
		return "", uuid.Nil, errors.Wrap(err, "invalid unique id part of GID")
	}
	return parts[0], idPart, nil
}

func ParseID(str string) (ID, error) {
	tagName, uniquePart, err := parseIDParts(str)
	if err != nil {
		return nil, err
	}

	constructor := idConstructorMap[tagName]
	if constructor == nil {
		return nil, errors.Errorf("no known gid for tag %s", tagName)
	}

	return constructor(uniquePart), nil
}

func ParseIDAs(str string, destID interface{}) error {
	id, err := ParseID(str)
	if err != nil {
		return errors.Wrapf(err, "parse ID failed: %s", str)
	}
	return assignTo(id, destID)
}

// APISpecIDs
type APISpecID struct {
	baseID
}

func (APISpecID) GetType() string {
	return APISpecTag
}

func (id APISpecID) String() string {
	return String(id)
}

func NewAPISpecID(ID uuid.UUID) APISpecID {
	return APISpecID{baseID(ID)}
}

func GenerateAPISpecID() APISpecID {
	return NewAPISpecID(uuid.New())
}

func (id APISpecID) MarshalText() ([]byte, error) {
	return toText(id)
}

func (id *APISpecID) UnmarshalText(data []byte) error {
	return fromText(id, data)
}

// APIKeyIDs
type APIKeyID struct {
	baseID
}

func (APIKeyID) GetType() string {
	return APIKeyTag
}

func (id APIKeyID) String() string {
	return String(id)
}

func NewAPIKeyID(ID uuid.UUID) APIKeyID {
	return APIKeyID{baseID(ID)}
}

func GenerateAPIKeyID() APIKeyID {
	return NewAPIKeyID(uuid.New())
}

func (id APIKeyID) MarshalText() ([]byte, error) {
	return toText(id)
}

func (id *APIKeyID) UnmarshalText(data []byte) error {
	return fromText(id, data)
}

// APIMethodIDs
type APIMethodID struct {
	baseID
}

func (APIMethodID) GetType() string {
	return APIMethodTag
}

func (id APIMethodID) String() string {
	return String(id)
}

func NewAPIMethodID(ID uuid.UUID) APIMethodID {
	return APIMethodID{baseID(ID)}
}

func GenerateAPIMethodID() APIMethodID {
	return NewAPIMethodID(uuid.New())
}

func (id APIMethodID) MarshalText() ([]byte, error) {
	return toText(id)
}

func (id *APIMethodID) UnmarshalText(data []byte) error {
	return fromText(id, data)
}

// ClientIDs
// ClientID represents a unique run of the client.
type ClientID struct {
	baseID
}

func (ClientID) GetType() string {
	return ClientTag
}

func (id ClientID) String() string {
	return String(id)
}

func NewClientID(ID uuid.UUID) ClientID {
	return ClientID{baseID(ID)}
}

func GenerateClientID() ClientID {
	return NewClientID(uuid.New())
}

func (id ClientID) MarshalText() ([]byte, error) {
	return toText(id)
}

func (id *ClientID) UnmarshalText(data []byte) error {
	return fromText(id, data)
}

// ConnectionIDs represent a network connection
type ConnectionID struct {
	baseID
}

func (ConnectionID) GetType() string {
	return ConnectionTag
}

func (id ConnectionID) String() string {
	return String(id)
}

func NewConnectionID(ID uuid.UUID) ConnectionID {
	return ConnectionID{baseID(ID)}
}

func GenerateConnectionID() ConnectionID {
	return NewConnectionID(uuid.New())
}

func (id ConnectionID) MarshalText() ([]byte, error) {
	return toText(id)
}

func (id *ConnectionID) UnmarshalText(data []byte) error {
	return fromText(id, data)
}

// DataCategoryIDs
type DataCategoryID struct {
	baseID
}

func (DataCategoryID) GetType() string {
	return DataCategoryTag
}

func (id DataCategoryID) String() string {
	return String(id)
}

func NewDataCategoryID(ID uuid.UUID) DataCategoryID {
	return DataCategoryID{baseID(ID)}
}

func GenerateDataCategoryID() DataCategoryID {
	return NewDataCategoryID(uuid.New())
}

// IdentityIDs
type IdentityID struct {
	baseID
}

func (IdentityID) GetType() string {
	return IdentityTag
}

func (id IdentityID) String() string {
	return String(id)
}

func NewIdentityID(ID uuid.UUID) IdentityID {
	return IdentityID{baseID(ID)}
}

func GenerateIdentityID() IdentityID {
	return NewIdentityID(uuid.New())
}

func (id IdentityID) MarshalText() ([]byte, error) {
	return toText(id)
}

func (id *IdentityID) UnmarshalText(data []byte) error {
	return fromText(id, data)
}

// GraphIDs
type GraphID struct {
	baseID
}

func (GraphID) GetType() string {
	return GraphTag
}

func (id GraphID) String() string {
	return String(id)
}

func NewGraphID(ID uuid.UUID) GraphID {
	return GraphID{baseID(ID)}
}

func GenerateGraphID() GraphID {
	return NewGraphID(uuid.New())
}

func (id GraphID) MarshalText() ([]byte, error) {
	return toText(id)
}

func (id *GraphID) UnmarshalText(data []byte) error {
	return fromText(id, data)
}

// ServiceIDs
type ServiceID struct {
	baseID
}

func (ServiceID) GetType() string {
	return ServiceTag
}

func (id ServiceID) String() string {
	return String(id)
}

func NewServiceID(ID uuid.UUID) ServiceID {
	return ServiceID{baseID(ID)}
}

func GenerateServiceID() ServiceID {
	return NewServiceID(uuid.New())
}

func (id ServiceID) MarshalText() ([]byte, error) {
	return toText(id)
}

func (id *ServiceID) UnmarshalText(data []byte) error {
	return fromText(id, data)
}

// ScheduleIDs
type ScheduleID struct {
	baseID
}

func (ScheduleID) GetType() string {
	return ScheduleTag
}

func (id ScheduleID) String() string {
	return String(id)
}

func NewScheduleID(ID uuid.UUID) ScheduleID {
	return ScheduleID{baseID(ID)}
}

func GenerateScheduleID() ScheduleID {
	return NewScheduleID(uuid.New())
}

func (id ScheduleID) MarshalText() ([]byte, error) {
	return toText(id)
}

func (id *ScheduleID) UnmarshalText(data []byte) error {
	return fromText(id, data)
}

// ServiceClusterIDs
type ServiceClusterID struct {
	baseID
}

func (ServiceClusterID) GetType() string {
	return ServiceClusterTag
}

func (id ServiceClusterID) String() string {
	return String(id)
}

func NewServiceClusterID(ID uuid.UUID) ServiceClusterID {
	return ServiceClusterID{baseID(ID)}
}

func GenerateServiceClusterID() ServiceClusterID {
	return NewServiceClusterID(uuid.New())
}

// ShardIDs
type ShardID struct {
	baseID
}

func (ShardID) GetType() string {
	return ShardTag
}

func (id ShardID) String() string {
	return String(id)
}

func NewShardID(ID uuid.UUID) ShardID {
	return ShardID{baseID(ID)}
}

func GenerateShardID() ShardID {
	return NewShardID(uuid.New())
}

// ShardAliasIDs

type ShardAliasID struct {
	baseID
}

func (ShardAliasID) GetType() string {
	return ShardAliasTag
}

func (id ShardAliasID) String() string {
	return String(id)
}

func NewShardAliasID(ID uuid.UUID) ShardAliasID {
	return ShardAliasID{baseID(ID)}
}

func GenerateShardAliasID() ShardAliasID {
	return NewShardAliasID(uuid.New())
}

// LearnSessionIDs
type LearnSessionID struct {
	baseID
}

func (LearnSessionID) GetType() string {
	return LearnSessionTag
}

func (id LearnSessionID) String() string {
	return String(id)
}

func NewLearnSessionID(ID uuid.UUID) LearnSessionID {
	return LearnSessionID{baseID(ID)}
}

func GenerateLearnSessionID() LearnSessionID {
	return NewLearnSessionID(uuid.New())
}

func (id LearnSessionID) MarshalText() ([]byte, error) {
	return toText(id)
}

func (id *LearnSessionID) UnmarshalText(data []byte) error {
	return fromText(id, data)
}

// ProjectIDs
type ProjectID struct {
	baseID
}

func (ProjectID) GetType() string {
	return ProjectTag
}

func (id ProjectID) String() string {
	return String(id)
}

func NewProjectID(ID uuid.UUID) ProjectID {
	return ProjectID{baseID(ID)}
}

func GenerateProjectID() ProjectID {
	return NewProjectID(uuid.New())
}

// RequestIDs
type RequestID struct {
	baseID
}

func (RequestID) GetType() string {
	return RequestTag
}

func (id RequestID) String() string {
	return String(id)
}

func NewRequestID(ID uuid.UUID) RequestID {
	return RequestID{baseID(ID)}
}

func GenerateRequestID() RequestID {
	return NewRequestID(uuid.New())
}

func (id RequestID) MarshalText() ([]byte, error) {
	return toText(id)
}

func (id *RequestID) UnmarshalText(data []byte) error {
	return fromText(id, data)
}

// UserIDs
type UserID struct {
	baseID
}

func (UserID) GetType() string {
	return UserTag
}

func (id UserID) String() string {
	return String(id)
}

func NewUserID(ID uuid.UUID) UserID {
	return UserID{baseID(ID)}
}

func GenerateUserID() UserID {
	return NewUserID(uuid.New())
}

func (id UserID) MarshalText() ([]byte, error) {
	return toText(id)
}

func (id *UserID) UnmarshalText(data []byte) error {
	return fromText(id, data)
}

// MessageIDs
type MessageID struct {
	baseID
}

func (MessageID) GetType() string {
	return MessageTag
}

func (id MessageID) String() string {
	return String(id)
}

func NewMessageID(ID uuid.UUID) MessageID {
	return MessageID{baseID(ID)}
}

func GenerateMessageID() MessageID {
	return NewMessageID(uuid.New())
}

func (id MessageID) MarshalText() ([]byte, error) {
	return toText(id)
}

func (id *MessageID) UnmarshalText(data []byte) error {
	return fromText(id, data)
}

// MonitorIDs
type MonitorID struct {
	baseID
}

func (MonitorID) GetType() string {
	return MonitorTag
}

func (id MonitorID) String() string {
	return String(id)
}

func NewMonitorID(ID uuid.UUID) MonitorID {
	return MonitorID{baseID(ID)}
}

func GenerateMonitorID() MonitorID {
	return NewMonitorID(uuid.New())
}

func (id MonitorID) MarshalText() ([]byte, error) {
	return toText(id)
}

func (id *MonitorID) UnmarshalText(data []byte) error {
	return fromText(id, data)
}

// OrganizationIDs
type OrganizationID struct {
	baseID
}

func (OrganizationID) GetType() string {
	return OrganizationTag
}

func (id OrganizationID) String() string {
	return String(id)
}

func NewOrganizationID(ID uuid.UUID) OrganizationID {
	return OrganizationID{baseID(ID)}
}

func GenerateOrganizationID() OrganizationID {
	return NewOrganizationID(uuid.New())
}

func (id OrganizationID) MarshalText() ([]byte, error) {
	return toText(id)
}

func (id *OrganizationID) UnmarshalText(data []byte) error {
	return fromText(id, data)
}

// OutboundRequestIDs

type OutboundRequestID struct {
	baseID
}

func NewOutboundRequestID(ID uuid.UUID) OutboundRequestID {
	return OutboundRequestID{baseID(ID)}
}

func (OutboundRequestID) GetType() string {
	return OutboundRequestTag
}

func (id OutboundRequestID) String() string {
	return String(id)
}

func GenerateOutboundRequestID() OutboundRequestID {
	return NewOutboundRequestID(uuid.New())
}

func (id OutboundRequestID) MarshalText() ([]byte, error) {
	return toText(id)
}

func (id *OutboundRequestID) UnmarshalText(data []byte) error {
	return fromText(id, data)
}

type WitnessID struct {
	baseID
}

func NewWitnessID(ID uuid.UUID) WitnessID {
	return WitnessID{baseID(ID)}
}

func GenerateWitnessID() WitnessID {
	return NewWitnessID(uuid.New())
}

func (WitnessID) GetType() string {
	return WitnessTag
}

func (id WitnessID) String() string {
	return String(id)
}

func (id WitnessID) MarshalText() ([]byte, error) {
	return toText(id)
}

func (id *WitnessID) UnmarshalText(data []byte) error {
	return fromText(id, data)
}

// RuleIDs
type RuleID struct {
	baseID
}

func (RuleID) GetType() string {
	return RuleTag
}

func (id RuleID) String() string {
	return String(id)
}

func NewRuleID(ID uuid.UUID) RuleID {
	return RuleID{baseID(ID)}
}

func GenerateRuleID() RuleID {
	return NewRuleID(uuid.New())
}

func (id RuleID) MarshalText() ([]byte, error) {
	return toText(id)
}

func (id *RuleID) UnmarshalText(data []byte) error {
	return fromText(id, data)
}

// UsageTrackingEventIDs

type UsageTrackingEventID struct {
	baseID
}

func (UsageTrackingEventID) GetType() string {
	return UsageTrackingEventTag
}

func (id UsageTrackingEventID) String() string {
	return String(id)
}

func NewUsageTrackingEventID(ID uuid.UUID) UsageTrackingEventID {
	return UsageTrackingEventID{baseID(ID)}
}

func GenerateUsageTrackingEventID() UsageTrackingEventID {
	return NewUsageTrackingEventID(uuid.New())
}

func (id UsageTrackingEventID) MarshallText() ([]byte, error) {
	return toText(id)
}

func (id UsageTrackingEventID) UnmarshallText(data []byte) error {
	return fromText(id, data)
}
