package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"unsafe"

	"github.com/free5gc/smf/monitorhandler/mongolib"

	"github.com/fatih/structs"
	"github.com/free5gc/openapi/models"
	"github.com/free5gc/pfcp"
	"github.com/free5gc/pfcp/pfcpType"
	"github.com/free5gc/pfcp/pfcpUdp"
	smf_context "github.com/free5gc/smf/context"
	"github.com/free5gc/smf/logger"
	pfcp_message "github.com/free5gc/smf/pfcp/message"
	"github.com/free5gc/smf/producer"
	"go.mongodb.org/mongo-driver/bson"

	"strconv"
)

func HandlePfcpHeartbeatRequest(msg *pfcpUdp.Message) {
	h := msg.PfcpMessage.Header
	pfcp_message.SendHeartbeatResponse(msg.RemoteAddr, h.SequenceNumber)
}

func HandlePfcpHeartbeatResponse(msg *pfcpUdp.Message) {
	logger.PfcpLog.Warnf("PFCP Heartbeat Response handling is not implemented")
}

func HandlePfcpPfdManagementRequest(msg *pfcpUdp.Message) {
	logger.PfcpLog.Warnf("PFCP PFD Management Request handling is not implemented")
}

func HandlePfcpPfdManagementResponse(msg *pfcpUdp.Message) {
	logger.PfcpLog.Warnf("PFCP PFD Management Response handling is not implemented")
}

func HandlePfcpAssociationSetupRequest(msg *pfcpUdp.Message) {
	req := msg.PfcpMessage.Body.(pfcp.PFCPAssociationSetupRequest)

	nodeID := req.NodeID
	if nodeID == nil {
		logger.PfcpLog.Errorln("pfcp association needs NodeID")
		return
	}
	logger.PfcpLog.Infof("Handle PFCP Association Setup Request with NodeID[%s]", nodeID.ResolveNodeIdToIp().String())

	upf := smf_context.RetrieveUPFNodeByNodeID(*nodeID)
	if upf == nil {
		logger.PfcpLog.Errorf("can't find UPF[%s]", nodeID.ResolveNodeIdToIp().String())
		return
	}

	upf.UPIPInfo = *req.UserPlaneIPResourceInformation

	// Response with PFCP Association Setup Response
	cause := pfcpType.Cause{
		CauseValue: pfcpType.CauseRequestAccepted,
	}
	pfcp_message.SendPfcpAssociationSetupResponse(*nodeID, cause)
}

func HandlePfcpAssociationSetupResponse(msg *pfcpUdp.Message) {
	req := msg.PfcpMessage.Body.(pfcp.PFCPAssociationSetupResponse)
	logger.PfcpLog.Infoln("In HandlePfcpAssociationSetupResponse")

	nodeID := req.NodeID
	if req.Cause.CauseValue == pfcpType.CauseRequestAccepted {
		if nodeID == nil {
			logger.PfcpLog.Errorln("pfcp association needs NodeID")
			return
		}
		logger.PfcpLog.Infof("Handle PFCP Association Setup Response with NodeID[%s]", nodeID.ResolveNodeIdToIp().String())

		upf := smf_context.RetrieveUPFNodeByNodeID(*nodeID)
		if upf == nil {
			logger.PfcpLog.Errorf("can't find UPF[%s]", nodeID.ResolveNodeIdToIp().String())
			return
		}

		upf.UPFStatus = smf_context.AssociatedSetUpSuccess

		if req.UserPlaneIPResourceInformation != nil {
			upf.UPIPInfo = *req.UserPlaneIPResourceInformation

			logger.PfcpLog.Infof("UPF(%s)[%s] setup association",
				upf.NodeID.ResolveNodeIdToIp().String(), upf.UPIPInfo.NetworkInstance)
		} else {
			logger.PfcpLog.Errorln("pfcp association setup response has no UserPlane IP Resource Information")
		}
	}
}

func HandlePfcpAssociationUpdateRequest(msg *pfcpUdp.Message) {
	logger.PfcpLog.Warnf("PFCP Association Update Request handling is not implemented")
}

func HandlePfcpAssociationUpdateResponse(msg *pfcpUdp.Message) {
	logger.PfcpLog.Warnf("PFCP Association Update Response handling is not implemented")
}

func HandlePfcpAssociationReleaseRequest(msg *pfcpUdp.Message) {
	pfcpMsg := msg.PfcpMessage.Body.(pfcp.PFCPAssociationReleaseRequest)

	var cause pfcpType.Cause
	upf := smf_context.RetrieveUPFNodeByNodeID(*pfcpMsg.NodeID)

	if upf != nil {
		smf_context.RemoveUPFNodeByNodeID(*pfcpMsg.NodeID)
		cause.CauseValue = pfcpType.CauseRequestAccepted
	} else {
		cause.CauseValue = pfcpType.CauseNoEstablishedPfcpAssociation
	}

	pfcp_message.SendPfcpAssociationReleaseResponse(*pfcpMsg.NodeID, cause)
}

func HandlePfcpAssociationReleaseResponse(msg *pfcpUdp.Message) {
	pfcpMsg := msg.PfcpMessage.Body.(pfcp.PFCPAssociationReleaseResponse)

	if pfcpMsg.Cause.CauseValue == pfcpType.CauseRequestAccepted {
		smf_context.RemoveUPFNodeByNodeID(*pfcpMsg.NodeID)
	}
}

func HandlePfcpVersionNotSupportedResponse(msg *pfcpUdp.Message) {
	logger.PfcpLog.Warnf("PFCP Version Not Support Response handling is not implemented")
}

func HandlePfcpNodeReportRequest(msg *pfcpUdp.Message) {
	logger.PfcpLog.Warnf("PFCP Node Report Request handling is not implemented")
}

func HandlePfcpNodeReportResponse(msg *pfcpUdp.Message) {
	logger.PfcpLog.Warnf("PFCP Node Report Response handling is not implemented")
}

func HandlePfcpSessionSetDeletionRequest(msg *pfcpUdp.Message) {
	logger.PfcpLog.Warnf("PFCP Session Set Deletion Request handling is not implemented")
}

func HandlePfcpSessionSetDeletionResponse(msg *pfcpUdp.Message) {
	logger.PfcpLog.Warnf("PFCP Session Set Deletion Response handling is not implemented")
}

type PDUSessionInfo struct {
	SequenceNumber uint32 `json:"seqnum" structs:"seqnum"`
	TEID           uint32 `json:"teid" structs:"teid"`
	UEIP           string `json:"ueip" structs:"ueip"`
	PDUSessionID   int    `json:"pdusessionid" structs:"pdusessionid"`
}

func HandlePfcpSessionEstablishmentResponse(msg *pfcpUdp.Message) {
	rsp := msg.PfcpMessage.Body.(pfcp.PFCPSessionEstablishmentResponse)
	logger.PfcpLog.Infoln("In HandlePfcpSessionEstablishmentResponse")

	SEID := msg.PfcpMessage.Header.SEID
	smContext := smf_context.GetSMContextBySEID(SEID)
	//fmt.Printf("%v\n", rsp.CreatedPDR.LocalFTEID.Teid)

	if rsp.UPFSEID != nil {
		NodeIDtoIP := rsp.NodeID.ResolveNodeIdToIp().String()
		pfcpSessionCtx := smContext.PFCPContext[NodeIDtoIP]
		pfcpSessionCtx.RemoteSEID = rsp.UPFSEID.Seid
	}

	postData := make(map[string]interface{})
	postData["id"] = smContext.PDUSessionID
	postData["upfip"] = rsp.NodeID.ResolveNodeIdToIp().String()
	postData["dnn"] = smContext.Dnn
	postData["sst"] = smContext.Snssai.Sst
	postData["sd"] = smContext.Snssai.Sd

	bytesData, err := json.Marshal(postData)
	if err != nil {
		fmt.Println(err.Error())
	}

	reader := bytes.NewReader(bytesData)
	posturl := "http://192.168.56.159:9966/pdusession"

	postrequest, err := http.NewRequest("POST", posturl, reader)
	if err != nil {
		fmt.Println(err.Error())
	}

	postrequest.Header.Set("Content-Type", "application/json")
	postclient := http.Client{}
	postresp, err := postclient.Do(postrequest)
	if err != nil {
		fmt.Println(err.Error())
	}

	respBytes, err := ioutil.ReadAll(postresp.Body)
	if err != nil {
		fmt.Println(err.Error())
	}

	str := (*string)(unsafe.Pointer(&respBytes))
	fmt.Println(*str)

	ANUPF := smContext.Tunnel.DataPathPool.GetDefaultPath().FirstDPNode
	if rsp.Cause.CauseValue == pfcpType.CauseRequestAccepted &&
		ANUPF.UPF.NodeID.ResolveNodeIdToIp().Equal(rsp.NodeID.ResolveNodeIdToIp()) {
		n1n2Request := models.N1N2MessageTransferRequest{}

		if smNasBuf, err := smf_context.BuildGSMPDUSessionEstablishmentAccept(smContext); err != nil {
			logger.PduSessLog.Errorf("Build GSM PDUSessionEstablishmentAccept failed: %s", err)
		} else {
			n1n2Request.BinaryDataN1Message = smNasBuf
		}
		if n2Pdu, err := smf_context.BuildPDUSessionResourceSetupRequestTransfer(smContext); err != nil {
			logger.PduSessLog.Errorf("Build PDUSessionResourceSetupRequestTransfer failed: %s", err)
		} else {
			n1n2Request.BinaryDataN2Information = n2Pdu
		}

		n1n2Request.JsonData = &models.N1N2MessageTransferReqData{
			PduSessionId: smContext.PDUSessionID,
			N1MessageContainer: &models.N1MessageContainer{
				N1MessageClass:   "SM",
				N1MessageContent: &models.RefToBinaryData{ContentId: "GSM_NAS"},
			},
			N2InfoContainer: &models.N2InfoContainer{
				N2InformationClass: models.N2InformationClass_SM,
				SmInfo: &models.N2SmInformation{
					PduSessionId: smContext.PDUSessionID,
					N2InfoContent: &models.N2InfoContent{
						NgapIeType: models.NgapIeType_PDU_RES_SETUP_REQ,
						NgapData: &models.RefToBinaryData{
							ContentId: "N2SmInformation",
						},
					},
					SNssai: smContext.Snssai,
				},
			},
		}

		rspData, _, err := smContext.
			CommunicationClient.
			N1N2MessageCollectionDocumentApi.
			N1N2MessageTransfer(context.Background(), smContext.Supi, n1n2Request)
		smContext.SMContextState = smf_context.Active
		logger.CtxLog.Traceln("SMContextState Change State: ", smContext.SMContextState.String())
		if err != nil {
			logger.PfcpLog.Warnf("Send N1N2Transfer failed")
		}
		if rspData.Cause == models.N1N2MessageTransferCause_N1_MSG_NOT_TRANSFERRED {
			logger.PfcpLog.Warnf("%v", rspData.Cause)
		}

		perfclient := mongolib.PerfClient{"mongodb://192.168.56.155:27017", "PDUSessionInfo", "PDUs"}
		perfclient.ConnectDB(perfclient.DBurl, perfclient.DBname)

		postData := bson.M{"pdusessionid": int(smContext.PDUSessionID)}
		//		postDataMap := structs.Map(&postData)
		filter := bson.M{"seqnum": msg.PfcpMessage.Header.SequenceNumber}
		getresult := perfclient.PostOne(perfclient.Collname, filter, postData)
		if !getresult {
			logger.PfcpLog.Warnf("Post a New UPF Report Data to MongoDB succeed!")
		} else {
			logger.PfcpLog.Infof("Update a UPF Report Data succeed!")
		}
		//fmt.Printf("%d\n", rsp.CreatedPDR.PDRID.RuleId)
	}

	if smf_context.SMF_Self().ULCLSupport && smContext.BPManager != nil {
		if smContext.BPManager.BPStatus == smf_context.AddingPSA {
			logger.PfcpLog.Infoln("Keep Adding PSAndULCL")
			producer.AddPDUSessionAnchorAndULCL(smContext, *rsp.NodeID)
			smContext.BPManager.BPStatus = smf_context.AddingPSA
		}
	}
}

func HandlePfcpSessionModificationResponse(msg *pfcpUdp.Message) {
	pfcpRsp := msg.PfcpMessage.Body.(pfcp.PFCPSessionModificationResponse)

	SEID := msg.PfcpMessage.Header.SEID
	smContext := smf_context.GetSMContextBySEID(SEID)

	logger.PfcpLog.Infoln("In HandlePfcpSessionModificationResponse")

	if smf_context.SMF_Self().ULCLSupport && smContext.BPManager != nil {
		if smContext.BPManager.BPStatus == smf_context.AddingPSA {
			logger.PfcpLog.Infoln("Keep Adding PSAAndULCL")

			upfNodeID := smContext.GetNodeIDByLocalSEID(SEID)
			producer.AddPDUSessionAnchorAndULCL(smContext, upfNodeID)
		}
	}

	if pfcpRsp.Cause.CauseValue == pfcpType.CauseRequestAccepted {
		logger.PduSessLog.Infoln("[SMF] PFCP Modification Resonse Accept")
		if smContext.SMContextState == smf_context.PFCPModification {
			upfNodeID := smContext.GetNodeIDByLocalSEID(SEID)
			upfIP := upfNodeID.ResolveNodeIdToIp().String()
			delete(smContext.PendingUPF, upfIP)
			logger.PduSessLog.Tracef("Delete pending pfcp response: UPF IP [%s]\n", upfIP)

			if smContext.PendingUPF.IsEmpty() {
				smContext.SBIPFCPCommunicationChan <- smf_context.SessionUpdateSuccess
			}

			if smf_context.SMF_Self().ULCLSupport && smContext.BPManager != nil {
				if smContext.BPManager.BPStatus == smf_context.UnInitialized {
					logger.PfcpLog.Infoln("Add PSAAndULCL")
					upfNodeID := smContext.GetNodeIDByLocalSEID(SEID)
					producer.AddPDUSessionAnchorAndULCL(smContext, upfNodeID)
					smContext.BPManager.BPStatus = smf_context.AddingPSA
				}
			}
		}

		logger.PfcpLog.Infof("PFCP Session Modification Success[%d]\n", SEID)
	} else {
		logger.PfcpLog.Infof("PFCP Session Modification Failed[%d]\n", SEID)
		if smContext.SMContextState == smf_context.PFCPModification {
			smContext.SBIPFCPCommunicationChan <- smf_context.SessionUpdateFailed
		}
	}

	logger.CtxLog.Traceln("PFCP Session Context")
	for _, ctx := range smContext.PFCPContext {
		logger.CtxLog.Traceln(ctx.String())
	}
}

func HandlePfcpSessionDeletionResponse(msg *pfcpUdp.Message) {
	logger.PfcpLog.Infof("Handle PFCP Session Deletion Response")
	pfcpRsp := msg.PfcpMessage.Body.(pfcp.PFCPSessionDeletionResponse)
	SEID := msg.PfcpMessage.Header.SEID

	smContext := smf_context.GetSMContextBySEID(SEID)

	if smContext == nil {
		logger.PfcpLog.Warnf("PFCP Session Deletion Response Found SM Context NULL, Request Rejected")
		return
		// TODO fix: SEID should be the value sent by UPF but now the SEID value is from sm context
	}

	if pfcpRsp.Cause.CauseValue == pfcpType.CauseRequestAccepted {
		if smContext.SMContextState == smf_context.PFCPModification {
			upfNodeID := smContext.GetNodeIDByLocalSEID(SEID)
			upfIP := upfNodeID.ResolveNodeIdToIp().String()
			delete(smContext.PendingUPF, upfIP)
			logger.PduSessLog.Tracef("Delete pending pfcp response: UPF IP [%s]\n", upfIP)

			if smContext.PendingUPF.IsEmpty() {
				smContext.SBIPFCPCommunicationChan <- smf_context.SessionReleaseSuccess
			}
		}
		logger.PfcpLog.Infof("PFCP Session Deletion Success[%d]\n", SEID)
	} else {
		if smContext.SMContextState == smf_context.PFCPModification {
			smContext.SBIPFCPCommunicationChan <- smf_context.SessionReleaseFailed
		}
		logger.PfcpLog.Infof("PFCP Session Deletion Failed[%d]\n", SEID)
	}
}

func HandlePfcpSessionReportRequest(msg *pfcpUdp.Message) {
	req := msg.PfcpMessage.Body.(pfcp.PFCPSessionReportRequest)

	SEID := msg.PfcpMessage.Header.SEID
	smContext := smf_context.GetSMContextBySEID(SEID)
	seqFromUPF := msg.PfcpMessage.Header.SequenceNumber

	var cause pfcpType.Cause

	if smContext == nil {
		logger.PfcpLog.Warnf("PFCP Session Report Request Found SM Context NULL, Request Rejected")
		cause.CauseValue = pfcpType.CauseRequestRejected
		// TODO fix: SEID should be the value sent by UPF but now the SEID value is from sm context
		pfcp_message.SendPfcpSessionReportResponse(msg.RemoteAddr, cause, seqFromUPF, SEID)
		return
	}

	smContext.SMLock.Lock()
	defer smContext.SMLock.Unlock()

	if req.ReportType.Dldr {
		downlinkDataReport := req.DownlinkDataReport

		if downlinkDataReport.DownlinkDataServiceInformation != nil {
			logger.PfcpLog.Warnf("PFCP Session Report Request DownlinkDataServiceInformation handling is not implemented")
		}

		// TS 23.502 4.2.3.3 2b. Send Data Notification Ack, SMF->UPF
		cause.CauseValue = pfcpType.CauseRequestAccepted
		// TODO fix: SEID should be the value sent by UPF but now the SEID value is from sm context
		pfcp_message.SendPfcpSessionReportResponse(msg.RemoteAddr, cause, seqFromUPF, SEID)

		n1n2Request := models.N1N2MessageTransferRequest{}

		// TS 23.502 4.2.3.3 3a. Send Namf_Communication_N1N2MessageTransfer Request, SMF->AMF
		if n2SmBuf, err := smf_context.BuildPDUSessionResourceSetupRequestTransfer(smContext); err != nil {
			logger.PduSessLog.Errorln("Build PDUSessionResourceSetupRequestTransfer failed:", err)
		} else {
			n1n2Request.BinaryDataN2Information = n2SmBuf
		}

		n1n2Request.JsonData = &models.N1N2MessageTransferReqData{
			PduSessionId: smContext.PDUSessionID,
			// Temporarily assign SMF itself, TODO: TS 23.502 4.2.3.3 5. Namf_Communication_N1N2TransferFailureNotification
			N1n2FailureTxfNotifURI: fmt.Sprintf("%s://%s:%d",
				smf_context.SMF_Self().URIScheme,
				smf_context.SMF_Self().RegisterIPv4,
				smf_context.SMF_Self().SBIPort),
			N2InfoContainer: &models.N2InfoContainer{
				N2InformationClass: models.N2InformationClass_SM,
				SmInfo: &models.N2SmInformation{
					PduSessionId: smContext.PDUSessionID,
					N2InfoContent: &models.N2InfoContent{
						NgapIeType: models.NgapIeType_PDU_RES_SETUP_REQ,
						NgapData: &models.RefToBinaryData{
							ContentId: "N2SmInformation",
						},
					},
					SNssai: smContext.Snssai,
				},
			},
		}

		rspData, _, err := smContext.CommunicationClient.
			N1N2MessageCollectionDocumentApi.
			N1N2MessageTransfer(context.Background(), smContext.Supi, n1n2Request)
		if err != nil {
			logger.PfcpLog.Warnf("Send N1N2Transfer failed")
		}
		if rspData.Cause == models.N1N2MessageTransferCause_ATTEMPTING_TO_REACH_UE {
			logger.PfcpLog.Infof("Receive %v, AMF is able to page the UE", rspData.Cause)
		}
		if rspData.Cause == models.N1N2MessageTransferCause_UE_NOT_RESPONDING {
			logger.PfcpLog.Warnf("%v", rspData.Cause)
			// TODO: TS 23.502 4.2.3.3 3c. Failure indication
		}
	}
}

func HandlePfcpSessionReportResponse(msg *pfcpUdp.Message) {
	logger.PfcpLog.Warnf("PFCP Session Report Response handling is not implemented")
}

//接收report request暂不使用
func HandlePfcpUpfReportRequest(msg *pfcpUdp.Message) {
	logger.PfcpLog.Warnf("PFCP UPF Report Request handling is not implemented")
}

type UPFReportData struct {
	UPFip            string  `json:"upfip" structs:"upfip"`
	UPFcpu           float32 `json:"upfcpu" structs:"upfcpu"`
	UPFmem           float32 `json:"upfmem" structs:"upfmem"`
	UPFsto           float32 `json:"upfsto" structs:"upfsto"`
	UPFuplinkdata    uint16  `json:"upfuplinkdata" structs:"upfuplinkdata"`
	UPFdownlinkdata  uint16  `json:"upfdownlinkdata" structs:"upfdownlinkdata"`
	PFCPuplinkdata   uint16  `json:"pfcpuplinkdata" structs:"pfcpuplinkdata"`
	PFCPdownlinkdata uint16  `json:"pfcpdownlinkdata" structs:"pfcpdownlinkdata"`
	Timestamp        string  `json:"timestamp" structs:"timestamp"`
}

//接收report response，由SMF主动send request，然后持续监听UPF回复
func HandlePfcpUpfReportResponse(msg *pfcpUdp.Message) {
	logger.PfcpLog.Infof("Handling PFCP UPF Report Response")
	pfcpRsp := msg.PfcpMessage.Body.(pfcp.PFCPUPFReportResponse)
	//	SEID := msg.PfcpMessage.Header.SEID
	//	fmt.Printf("%d\n", SEID)
	//	smContext := smf_context.GetSMContextBySEID(SEID)
	//
	//	if smContext == nil {
	//		logger.PfcpLog.Warnf("PFCP UPF Report Response Found SM Context NULL, Request Rejected")
	//		return
	//	}
	//
	//	upfNodeID := smContext.GetNodeIDByLocalSEID(SEID)
	//	upfIP := upfNodeID.ResolveNodeIdToIp().String()
	//解析context内容，提取监控数据
	uul := pfcpRsp.UPFUplinkData.UpfdataValue
	udl := pfcpRsp.UPFDownlinkData.UpfdataValue
	pul := pfcpRsp.PFCPUplinkData.UpfdataValue
	pdl := pfcpRsp.PFCPDownlinkData.UpfdataValue
	uip := pfcpRsp.NodeID.ResolveNodeIdToIp().String()
	ucpu := pfcpRsp.UPFcpu.UpfdataValueF
	umem := pfcpRsp.UPFmem.UpfdataValueF
	usto := pfcpRsp.UPFsto.UpfdataValueF
	ts := pfcpRsp.Timestamp.UpfdatatValue
	tsstring := strconv.FormatUint(ts, 10)

	//fmt.Printf("%v\n",tsstring)
	//fmt.Printf("%v\n",uul)

	//数据库操作
	perfclient := mongolib.PerfClient{"mongodb://192.168.56.155:27017", "upf_monitor", "upfs"}
	perfclient.ConnectDB(perfclient.DBurl, perfclient.DBname)

	postData := UPFReportData{uip, ucpu, umem, usto, uul, udl, pul, pdl, tsstring}
	postDataMap := structs.Map(&postData)
	filter := bson.M{"timestamp": tsstring}
	getresult := perfclient.PostOne(perfclient.Collname, filter, postDataMap)
	if !getresult {
		logger.PfcpLog.Warnf("Post a New UPF Report Data to MongoDB succeed!")
	} else {
		logger.PfcpLog.Infof("Update a UPF Report Data succeed!")
	}
	//perfclient.DisconnectMongoDB()
}

//func HandlePduSessionDataReportResponse(msg *pfcpUdp.Message) {
//    logger.PfcpLog.Warnf("PFCP PFD Management Request handling is not implemented")
//}

type PDUSessionDataReport struct {
	UPFip     string `json:"upfip" structs:"upfip"`
	TEID      uint32 `json:"teid" structs:"teid"`
	UEIP      uint32 `json:"ueip" structs:"ueip"`
	Packet    uint32 `json:"packet" structs:"packet"`
	Timestamp string `json:"timestamp" structs:"timestamp"`
}

func HandlePduSessionDataReportResponse(msg *pfcpUdp.Message) {
	logger.PfcpLog.Infof("Handling PDU Session Data Report Response")
	pfcpRsp := msg.PfcpMessage.Body.(pfcp.PDUSessionDataReportResponse)
	SEID := msg.PfcpMessage.Header.SEID
	fmt.Printf("%d\n", SEID)

	uip := pfcpRsp.NodeID.ResolveNodeIdToIp().String()
	teid := pfcpRsp.PDUTEID.Pduteid
	ueip := pfcpRsp.PDUUEIP.Pduueip
	packet := pfcpRsp.PDUPacket.Pdupacket
	tsp := pfcpRsp.Timestamp.UpfdatatValue
	tspstring := strconv.FormatUint(tsp, 10)
	perfclient := mongolib.PerfClient{"mongodb://192.168.56.155:27017", "upf_monitor", "sessions"}
	perfclient.ConnectDB(perfclient.DBurl, perfclient.DBname)

	postData := PDUSessionDataReport{uip, teid, ueip, packet, tspstring}
	postDataMap := structs.Map(&postData)
	filter := bson.M{"timestamp": tspstring}
	getresult := perfclient.PostOne(perfclient.Collname, filter, postDataMap)
	if !getresult {
		logger.PfcpLog.Warnf("Post a New Session Data Report to MongoDB succeed!")
	} else {
		logger.PfcpLog.Infof("Update a Session Data Reportsucceed!")
	}
}

func HandlePDUSessionReleaseFromSMFRequest(msg *pfcpUdp.Message) {
	req := msg.PfcpMessage.Body.(pfcp.PDUSessionReleaseFromSMFRequest)

	SEID := msg.PfcpMessage.Header.SEID
	smContext := smf_context.GetSMContextBySEID(SEID)
	seqFromSMF := msg.PfcpMessage.Header.SequenceNumber
	//upfNodeID := smContext.GetNodeIDByLocalSEID(SEID)

	var cause pfcpType.Cause

	if smContext == nil {
		logger.PfcpLog.Warnf("Found SM Context NULL, Request Rejected")
		cause.CauseValue = pfcpType.CauseRequestRejected
		pfcp_message.SendPDUSessionReleaseFromSMFResponse(smf_context.SMF_Self().CPNodeID, cause, seqFromSMF, SEID)
		return
	}

	smContext.SMLock.Lock()
	defer smContext.SMLock.Unlock()

	cause.CauseValue = pfcpType.CauseRequestAccepted

	//pfcp_message.SendPfcpSessionDeletionRequest(upfNodeID, smContext)

	n1n2Request := models.N1N2MessageTransferRequest{}

	// TS 23.502 4.2.3.3 3a. Send Namf_Communication_N1N2MessageTransfer Request, SMF->AMF
	if n2SmBuf, err := smf_context.BuildPDUSessionResourceReleaseCommandTransfer(smContext); err != nil {
		logger.PduSessLog.Errorln("Build PDUSessionResourceSetupRequestTransfer failed:", err)
	} else {
		n1n2Request.BinaryDataN2Information = n2SmBuf
	}

	n1n2Request.JsonData = &models.N1N2MessageTransferReqData{
		PduSessionId: smContext.PDUSessionID,
		N1n2FailureTxfNotifURI: fmt.Sprintf("%s://%s:%d",
			smf_context.SMF_Self().URIScheme,
			smf_context.SMF_Self().RegisterIPv4,
			smf_context.SMF_Self().SBIPort),
		N2InfoContainer: &models.N2InfoContainer{
			N2InformationClass: models.N2InformationClass_SM,
			SmInfo: &models.N2SmInformation{
				PduSessionId: smContext.PDUSessionID,
				N2InfoContent: &models.N2InfoContent{
					NgapIeType: models.NgapIeType_PDU_RES_REL_CMD,
					NgapData: &models.RefToBinaryData{
						ContentId: "N2SmInformation",
					},
				},
				SNssai: smContext.Snssai,
			},
		},
	}

	rspData, _, err := smContext.CommunicationClient.
		N1N2MessageCollectionDocumentApi.
		N1N2MessageTransfer(context.Background(), smContext.Supi, n1n2Request)
	if err != nil {
		logger.PfcpLog.Warnf("Send N1N2Transfer failed")
	}
	if rspData.Cause == models.N1N2MessageTransferCause_ATTEMPTING_TO_REACH_UE {
		logger.PfcpLog.Infof("Receive %v, AMF is able to page the UE", rspData.Cause)
	}
	if rspData.Cause == models.N1N2MessageTransferCause_UE_NOT_RESPONDING {
		logger.PfcpLog.Warnf("%v", rspData.Cause)
	}
}
