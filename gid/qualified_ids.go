package gid

import "fmt"

// A service ID paired with its organization ID.
type QualifiedServiceID struct {
	OrganizationID OrganizationID `json:"organization_id"`
	ServiceID      ServiceID      `json:"service_id"`
}

func MakeQualifiedServiceID(organizationID OrganizationID, serviceID ServiceID) QualifiedServiceID {
	return QualifiedServiceID{
		OrganizationID: organizationID,
		ServiceID:      serviceID,
	}
}

// Qualifies the given learn session ID with this service ID.
func (serviceID QualifiedServiceID) QualifyLearnSessionID(learnSessionID LearnSessionID) QualifiedLearnSessionID {
	return MakeQualifiedLearnSessionID(serviceID.OrganizationID, serviceID.ServiceID, learnSessionID)
}

// Qualifies the given deployment with this service ID.
func (serviceID QualifiedServiceID) QualifyDeployment(deployment string) QualifiedDeploymentID {
	return MakeQualifiedDeploymentID(serviceID.OrganizationID, serviceID.ServiceID, deployment)
}

func (serviceID QualifiedServiceID) String() string {
	return fmt.Sprintf("%s/%s", serviceID.OrganizationID, serviceID.ServiceID)
}

// A learn session ID paired with its service ID and organization ID.
type QualifiedLearnSessionID struct {
	QualifiedServiceID
	LearnSessionID LearnSessionID `json:"learn_session_id"`
}

func MakeQualifiedLearnSessionID(organizationID OrganizationID, serviceID ServiceID, learnSessionID LearnSessionID) QualifiedLearnSessionID {
	return QualifiedLearnSessionID{
		QualifiedServiceID: MakeQualifiedServiceID(organizationID, serviceID),
		LearnSessionID:     learnSessionID,
	}
}

func (sessionID QualifiedLearnSessionID) String() string {
	return fmt.Sprintf("%s/%s", sessionID.QualifiedServiceID, sessionID.LearnSessionID)
}

// A deployment paired with its service ID and organization ID.
type QualifiedDeploymentID struct {
	QualifiedServiceID
	Deployment string `json:"deployment"`
}

func MakeQualifiedDeploymentID(organizationID OrganizationID, serviceID ServiceID, deployment string) QualifiedDeploymentID {
	return QualifiedDeploymentID{
		QualifiedServiceID: MakeQualifiedServiceID(organizationID, serviceID),
		Deployment:         deployment,
	}
}

func (d QualifiedDeploymentID) String() string {
	return fmt.Sprintf("%s/%s", d.QualifiedServiceID, d.Deployment)
}
