package pfcp

type MessageType uint8

const (
	PFCP_HEARTBEAT_REQUEST              MessageType = 1
	PFCP_HEARTBEAT_RESPONSE             MessageType = 2
	PFCP_PFD_MANAGEMENT_REQUEST         MessageType = 3
	PFCP_PFD_MANAGEMENT_RESPONSE        MessageType = 4
	PFCP_ASSOCIATION_SETUP_REQUEST      MessageType = 5
	PFCP_ASSOCIATION_SETUP_RESPONSE     MessageType = 6
	PFCP_ASSOCIATION_UPDATE_REQUEST     MessageType = 7
	PFCP_ASSOCIATION_UPDATE_RESPONSE    MessageType = 8
	PFCP_ASSOCIATION_RELEASE_REQUEST    MessageType = 9
	PFCP_ASSOCIATION_RELEASE_RESPONSE   MessageType = 10
	PFCP_VERSION_NOT_SUPPORTED_RESPONSE MessageType = 11
	PFCP_NODE_REPORT_REQUEST            MessageType = 12
	PFCP_NODE_REPORT_RESPONSE           MessageType = 13
	PFCP_SESSION_SET_DELETION_REQUEST   MessageType = 14
	PFCP_SESSION_SET_DELETION_RESPONSE  MessageType = 15

	PFCP_SESSION_ESTABLISHMENT_REQUEST    MessageType = 50
	PFCP_SESSION_ESTABLISHMENT_RESPONSE   MessageType = 51
	PFCP_SESSION_MODIFICATION_REQUEST     MessageType = 52
	PFCP_SESSION_MODIFICATION_RESPONSE    MessageType = 53
	PFCP_SESSION_DELETION_REQUEST         MessageType = 54
	PFCP_SESSION_DELETION_RESPONSE        MessageType = 55
	PFCP_SESSION_REPORT_REQUEST           MessageType = 56
	PFCP_SESSION_REPORT_RESPONSE          MessageType = 57
	PFCP_UPF_REPORT_REQUEST               MessageType = 200
	PFCP_UPF_REPORT_RESPONSE              MessageType = 201
	PDU_SESSION_DATA_REPORT_REQUEST       MessageType = 202
	PDU_SESSION_DATA_REPORT_RESPONSE      MessageType = 203
	PDU_SESSION_RELEASE_FROM_SMF_REQUEST  MessageType = 204
	PDU_SESSION_RELEASE_FROM_SMF_RESPONSE MessageType = 205
)
