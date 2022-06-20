#define TRACE_MODULE _n4_pfcp_build

#include <stdint.h>
#include <endian.h>
#include <string.h>
#include <arpa/inet.h>

#include "upf_context.h"
#include "utlt_buff.h"
#include "pfcp_message.h"
#include "pfcp_convert.h"

#include "n4_pfcp_build.h"

#include "updk/env.h"

#include <stdio.h>
#include <stdlib.h>

Status UpfN4BuildSessionEstablishmentResponse(Bufblk **bufBlk, uint8_t type,
                                              UpfSession *session, uint8_t cause,
                                              PFCPSessionEstablishmentRequest *establishRequest) {
    Status status;
    PfcpMessage pfcpMessage;
    PFCPSessionEstablishmentResponse *response = NULL;
    PfcpFSeid fSeid;
    PfcpNodeId nodeId;
    int len;

    response = &pfcpMessage.pFCPSessionEstablishmentResponse;
    memset(&pfcpMessage, 0, sizeof(pfcpMessage));

    /* Node Id */
    response->nodeID.presence = 1;
    /* TODO: IPv6 */
    nodeId.type = PFCP_NODE_ID_IPV4;
    nodeId.addr4 = Self()->pfcpAddr->s4.sin_addr;
    response->nodeID.value = &nodeId;
    response->nodeID.len = 1+4;

    /* cause */
    response->cause.presence = 1;
    response->cause.len = 1;
    response->cause.value = &cause;

    /* Condition or Option */
    if (cause == PFCP_CAUSE_REQUEST_ACCEPTED) {
        /* F-SEID */
        response->uPFSEID.presence = 1;
        response->uPFSEID.value = &fSeid;
        fSeid.seid = htobe64(session->upfSeid);
        status = PfcpSockaddrToFSeid(Self()->pfcpAddr,
                                     Self()->pfcpAddr, &fSeid, &len);
        response->uPFSEID.len = len;

        /* FQ-CSID */
    }

    pfcpMessage.header.type = type;
    status = PfcpBuildMessage(bufBlk, &pfcpMessage);
    UTLT_Assert(status == STATUS_OK, return STATUS_ERROR,
                "build msg faild");

    UTLT_Debug("PFCP session establishment response built!");
    return STATUS_OK;
}

Status UpfN4BuildSessionModificationResponse(Bufblk **bufBlkPtr, uint8_t type,
                                             UpfSession *session,
                                             PFCPSessionModificationRequest *modifyRequest) {
    Status status;
    PfcpMessage pfcpMessage;
    PFCPSessionModificationResponse *response = NULL;
    uint8_t cause;

    response = &pfcpMessage.pFCPSessionModificationResponse;
    memset(&pfcpMessage, 0, sizeof(pfcpMessage));

    /* cause */
    response->cause.presence = 1;
    cause = PFCP_CAUSE_REQUEST_ACCEPTED;
    response->cause.value = &cause;
    response->cause.len = 1;

    /* TODO: Set Offending IE, Create PDR, Load Control Information, Overload Control Information, Usage Report, Failed Rule ID, Additional Usage Reports Information, Created/Updated Traffic Endpoint */

    pfcpMessage.header.type = type;
    pfcpMessage.header.seidP = 1;
    pfcpMessage.header.seid = session->smfSeid;
    status = PfcpBuildMessage(bufBlkPtr, &pfcpMessage);
    UTLT_Assert(status == STATUS_OK, return STATUS_ERROR, "PFCP build error");

    UTLT_Debug("PFCP session modification response built!");
    return STATUS_OK;
}

Status UpfN4BuildSessionDeletionResponse(Bufblk **bufBlkPtr, uint8_t type,
                                         UpfSession *session,
                                         PFCPSessionDeletionRequest *deletionRequest) {
    Status status;
    PfcpMessage pfcpMessage;
    PFCPSessionDeletionResponse *response = NULL;
    uint8_t cause;

    response = &pfcpMessage.pFCPSessionDeletionResponse;
    memset(&pfcpMessage, 0, sizeof(PfcpMessage));

    /* cause */
    response->cause.presence = 1;
    cause = PFCP_CAUSE_REQUEST_ACCEPTED;
    response->cause.value = &cause;
    response->cause.len = 1;

    /* TODO: Set Offending IE, Load Control Information, Overload Control Information, Usage Report */

    pfcpMessage.header.type = type;
    status = PfcpBuildMessage(bufBlkPtr, &pfcpMessage);
    UTLT_Assert(status == STATUS_OK, return STATUS_ERROR, "PFCP build error");

    UTLT_Debug("PFCP session deletion response built!");
    return STATUS_OK;
}

Status UpfN4BuildSessionReportRequestDownlinkDataReport(Bufblk **bufBlkPtr,
                                                        uint8_t type,
                                                        UpfSession *session,
                                                        uint16_t pdrId) {
    Status status;
    PfcpMessage pfcpMessage;
    PFCPSessionReportRequest *request = NULL;
    PfcpReportType reportType;
    PfcpDownlinkDataServiceInformation downlinkDataServiceInformationValue;

    request = &pfcpMessage.pFCPSessionReportRequest;
    memset(&pfcpMessage, 0, sizeof(PfcpMessage));
    memset(&reportType, 0, sizeof(PfcpReportType));
    memset(&downlinkDataServiceInformationValue, 0,
           sizeof(PfcpDownlinkDataServiceInformation));

    reportType.dldr = 1;

    request->reportType.presence = 1;
    request->reportType.value = &reportType;
    request->reportType.len = sizeof(PfcpReportType);

    /* TODO: fill in downlinkDataReport */
    DownlinkDataReport *downlinkDataReport = &request->downlinkDataReport;
    downlinkDataReport->presence = 1;

    downlinkDataReport->pDRID.presence = 1;
    // This value is store in network type
    pdrId = htons(pdrId);
    downlinkDataReport->pDRID.value = &pdrId;
    downlinkDataReport->pDRID.len = sizeof(pdrId);
    // not support yet, TODO
    downlinkDataReport->downlinkDataServiceInformation.presence = 0;

    /* fill in downlinkDataServiceInformation in downlinkDataReport */
    /*
      DownlinkDataServiceInformation *downlinkDataServiceInformation =
      &downlinkDataReport->downlinkDataServiceInformation;
      // fill in value of downlinkDataServiceInformation
      downlinkDataServiceInformationValue.ppi = 0;
      downlinkDataServiceInformationValue.qfii = 0;
      downlinkDataServiceInformationValue.pagingPolicyIndicationValue = 0;
      downlinkDataServiceInformationValue.qfi = 0;
      // fill value back to ServiceInformation
      downlinkDataServiceInformation->presence = 1;
      downlinkDataServiceInformation->value =
      &downlinkDataServiceInformationValue;
      downlinkDataServiceInformation->len =
      PfcpDownlinkDataServiceInformationLen(downlinkDataServiceInformationValue);
    */

    pfcpMessage.header.type = type;
    status = PfcpBuildMessage(bufBlkPtr, &pfcpMessage);
    UTLT_Assert(status == STATUS_OK, return STATUS_ERROR, "PFCP build error");

    UTLT_Debug("PFCP session report request downlink data report built!");
    return STATUS_OK;
}

Status UpfN4BuildAssociationSetupResponse(Bufblk **bufBlkPtr, uint8_t type) {
    Status status;
    PfcpMessage pfcpMessage;
    PFCPAssociationSetupResponse *response = NULL;
    uint8_t cause;
    uint16_t upFunctionFeature;

    response = &pfcpMessage.pFCPAssociationSetupResponse;
    memset(&pfcpMessage, 0, sizeof(PfcpMessage));
    pfcpMessage.pFCPAssociationSetupResponse.presence = 1;

    /* node id */
    // TODO: IPv6
    response->nodeID.presence = 1;
    PfcpNodeId nodeId;
    nodeId.spare = 0;
    nodeId.type = PFCP_NODE_ID_IPV4;
    nodeId.addr4 = Self()->pfcpAddr->s4.sin_addr;
    response->nodeID.len = 1+4;
    response->nodeID.value = &nodeId;

    /* cause */
    cause = PFCP_CAUSE_REQUEST_ACCEPTED;
    response->cause.presence = 1;
    response->cause.value = &cause;
    response->cause.len = 1;

    /* Recovery Time Stamp */
    response->recoveryTimeStamp.presence = 1;
    response->recoveryTimeStamp.value = &Self()->recoveryTime;
    response->recoveryTimeStamp.len = 4;

    // TODO: support UP Function Feature report
    /* UP Function Feature (Condition) */
    upFunctionFeature = 0;
    if (upFunctionFeature) {
        response->uPFunctionFeatures.presence = 1;
        response->uPFunctionFeatures.value = &upFunctionFeature;
        response->uPFunctionFeatures.len = 2;
    } else {
        response->uPFunctionFeatures.presence = 0;
    }

    PfcpUserPlaneIpResourceInformation upIpResourceInformation;
    memset(&upIpResourceInformation, 0,
           sizeof(PfcpUserPlaneIpResourceInformation));

    // teid
    upIpResourceInformation.teidri = 1;
    upIpResourceInformation.teidRange = 0;

    // network instence
    upIpResourceInformation.assoni = 1;
    DNN *dnn;
    uint8_t dnnLen = 0;
    EnvParamsForEachDNN(dnn, Self()->envParams) {
        dnnLen = strlen(dnn->name);
        memcpy(upIpResourceInformation.networkInstance, &dnnLen, 1);
        memcpy(upIpResourceInformation.networkInstance + 1, dnn->name, dnnLen + 1);
        break;
    }

    // TODO: better algo. to select establish IP
    int isIpv6 = 0;
    VirtualPort *port;
    VirtualDeviceForEachVirtualPort(port, Self()->envParams->virtualDevice) {
        isIpv6 = (strchr(port->ipStr, ':') ? 1 : 0);
        if (!upIpResourceInformation.v4 && !isIpv6) {
            UTLT_Assert(inet_pton(AF_INET, port->ipStr, &upIpResourceInformation.addr4) == 1,
                continue, "IP address[%s] in VirtualPort is invalid", port->ipStr);
            upIpResourceInformation.v4 = 1;
        }
        /* TODO: IPv6
        if (!upIpResourceInformation.v6 && isIpv6) {
            UTLT_Assert(inet_pton(AF_INET6, port->ipStr, &upIpResourceInformation.addr6) == 1,
                continue, "IP address[%s] in VirtualPort is invalid", port->ipStr);
            upIpResourceInformation.v6 = 1;
        }
        */
        if (upIpResourceInformation.v4 && upIpResourceInformation.v6)
            break;
    }

    response->userPlaneIPResourceInformation.presence = 1;
    response->userPlaneIPResourceInformation.value = &upIpResourceInformation;
    // TODO: this is only IPv4, no network instence, no source interface
    response->userPlaneIPResourceInformation.len = 2+4+1+dnnLen;
    // HACK: sizeof(Internet) == 8, hardcord
    //response->userPlaneIPResourceInformation.len =
    //sizeof(PfcpUserPlaneIpResourceInformation);

    pfcpMessage.header.type = type;
    status = PfcpBuildMessage(bufBlkPtr, &pfcpMessage);
    UTLT_Assert(*bufBlkPtr, , "buff NULL");
    UTLT_Assert(status == STATUS_OK, return STATUS_ERROR, "PFCP build error");

    UTLT_Debug("PFCP association session setup response built!");
    return STATUS_OK;
}

Status UpfN4BuildAssociationReleaseResponse(Bufblk **bufBlkPtr, uint8_t type) {
    Status status;
    PfcpMessage pfcpMessage;
    PFCPAssociationReleaseResponse *response = NULL;
    PfcpNodeId nodeId;
    uint8_t cause;

    response = &pfcpMessage.pFCPAssociationReleaseResponse;
    memset(&pfcpMessage, 0, sizeof(PfcpMessage));
    response->presence = 0;

    /* nodeId */
    response->nodeID.presence = 1;
    nodeId.type = PFCP_NODE_ID_IPV4;
    // TODO: IPv6 version
    nodeId.addr4 = Self()->pfcpAddr->s4.sin_addr;
    response->nodeID.value = &nodeId;
    response->nodeID.len = 1+4; // ???

    /* cause */
    response->cause.presence = 1;
    cause = PFCP_CAUSE_REQUEST_ACCEPTED;
    response->cause.value = &cause;
    response->cause.len = 1;

    pfcpMessage.header.type = type;
    status = PfcpBuildMessage(bufBlkPtr, &pfcpMessage);
    UTLT_Assert(status == STATUS_OK, return STATUS_ERROR, "PFCP build error");

    UTLT_Debug("PFCP association release response built!");
    return STATUS_OK;
}

Status UpfN4BuildHeartbeatResponse(Bufblk **bufBlkPtr, uint8_t type) {
    Status status;
    PfcpMessage pfcpMessage;
    HeartbeatResponse *response;
    
    response = &pfcpMessage.heartbeatResponse;
    memset(&pfcpMessage, 0, sizeof(PfcpMessage));

    /* Set Recovery Time Stamp */
    response->recoveryTimeStamp.presence = 1;
    response->recoveryTimeStamp.value = &Self()->recoveryTime;
    response->recoveryTimeStamp.len = 4;

    pfcpMessage.header.type = type;
    status = PfcpBuildMessage(bufBlkPtr, &pfcpMessage);
    UTLT_Assert(status == STATUS_OK, return STATUS_ERROR, "PFCP build error");

    UTLT_Debug("PFCP heartbeat response built!");
    return STATUS_OK;
}

struct Value {
	int value;
};

float GetValueF(const char *cmd) {
    FILE * fp;
    char buffer[80];
    fp=popen(cmd, "r");
    fgets(buffer,sizeof(buffer),fp);
    pclose(fp);
	return atof(buffer);
};

unsigned long long int GetValue(const char *cmd) {
    FILE * fp;
    char buffer[160];
	char *endptr;
    fp=popen(cmd, "r");
    fgets(buffer,sizeof(buffer),fp);
    pclose(fp);
    return strtoull(buffer, &endptr, 10);
};

//char * GetValueS(const char *cmd) {
//	FILE * fp;
//	static char buffer[80] = {0};
//	fp=popen(cmd, "r");
//	fgets(buffer,sizeof(buffer),fp);
//	pclose(fp);
//	return buffer;
//}

Status UpfN4BuildUPFReportResponse(Bufblk **bufBlkPtr, uint8_t type) {
    Status status;
    PfcpMessage pfcpMessage;
    PFCPUPFReportResponse *response;
	PfcpNodeId nodeId;

	response = &pfcpMessage.pFCPUPFReportResponse;
	memset(&pfcpMessage, 0, sizeof(PfcpMessage));

	char *CMDforcpu = "mysql -h192.168.67.33 -uroot -p123456 monitor -Ne\"select value from resource WHERE type ='0' order by id desc limit 1\";";
	char *CMDformem = "mysql -h192.168.67.33 -uroot -p123456 monitor -Ne\"select value from resource WHERE type ='2' order by id desc limit 1\";";
	char *CMDforsto = "mysql -h192.168.67.33 -uroot -p123456 monitor -Ne\"select value from resource WHERE type ='3' order by id desc limit 1;\"";
	char *CMDforupfuplinkdata = "mysql -h192.168.67.33 -uroot -p123456 monitor -Ne\"select value from resource WHERE type ='4' && is_up ='1' order by id desc limit 1\";";
	char *CMDforupfdownlinkdata = "mysql -h192.168.67.33 -uroot -p123456 monitor -Ne\"select value from resource WHERE type ='4' && is_up ='0' order by id desc limit 1\";";
	char *CMDforpfcpuplinkdata = "";
	char *CMDforpfcpdownlinkdata = "";
	char *CMDfortimestamp = "mysql -h192.168.67.33 -uroot -p123456 monitor -Ne\"select timestape from resource WHERE type ='4' && is_up ='0' order by id desc limit 1\";";

	/* nodeId */
	response->nodeID.presence = 1;
	nodeId.type = PFCP_NODE_ID_IPV4;
	// TODO: IPv6 version
	nodeId.addr4 = Self()->pfcpAddr->s4.sin_addr;
	response->nodeID.value = &nodeId;
	response->nodeID.len = 1+4; // ???
    
	float cpu = GetValueF(CMDforcpu);
	response->upfcpu.presence = 1;
    response->upfcpu.value = &cpu;
    response->upfcpu.len = 4;

	float mem = GetValueF(CMDformem);
	response->upfmem.presence = 1;
	response->upfmem.value = &mem;
	response->upfmem.len = 4;

    float sto = GetValueF(CMDforsto);
	response->upfsto.presence = 1;
	response->upfsto.value = &sto;
	response->upfsto.len = 4;

	uint16_t uul = GetValue(CMDforupfuplinkdata);
	response->upfuplinkdata.presence = 1;
	response->upfuplinkdata.value = &uul;
	response->upfuplinkdata.len = 4;

	uint16_t udl = GetValue(CMDforupfdownlinkdata);
	response->upfdownlinkdata.presence = 1;
	response->upfdownlinkdata.value = &udl;
	response->upfdownlinkdata.len = 4;

	uint16_t pul = GetValue(CMDforpfcpuplinkdata);
	response->pfcpuplinkdata.presence = 1;
	response->pfcpuplinkdata.value = &pul;
	response->pfcpuplinkdata.len = 4;

	uint16_t pdl = GetValue(CMDforpfcpdownlinkdata);
	response->pfcpdownlinkdata.presence = 1;
	response->pfcpdownlinkdata.value = &pdl;
	response->pfcpdownlinkdata.len = 4;

    unsigned long long int ts = GetValue(CMDfortimestamp);
	//printf("%llu\n", ts);
	response->timestamp.presence = 1;
	response->timestamp.value = &ts;
	response->timestamp.len = 8;

    pfcpMessage.header.type = type;
    status = PfcpBuildMessage(bufBlkPtr, &pfcpMessage);
    UTLT_Assert(status == STATUS_OK, return STATUS_ERROR, "PFCP build error");

    UTLT_Debug("PFCP UPF report response built!");
    return STATUS_OK;
}

Status UpfN4BuildPDUSessionDataReportResponse(Bufblk **bufBlkPtr, uint8_t type, uint16_t sessionnum) {
    Status status;
    PfcpMessage pfcpMessage;
    PFCPPDUSessionDataReportResponse *response;
    PfcpNodeId nodeId;

    response = &pfcpMessage.pFCPPDUSessionDataReportResponse;
    memset(&pfcpMessage, 0, sizeof(PfcpMessage));
    /* nodeId */
    response->nodeID.presence = 1;
    nodeId.type = PFCP_NODE_ID_IPV4;
    // TODO: IPv6 version
    nodeId.addr4 = Self()->pfcpAddr->s4.sin_addr;
    response->nodeID.value = &nodeId;
    response->nodeID.len = 1+4; // ???

	char session[20];
	sprintf(session,"%d",sessionnum);
	char strx[] = ",1\";";
	strcat(session, strx);
	char CMDforteid[] = "mysql -h192.168.67.33 -uroot -p123456 monitor -Ne\"select TEID from resource WHERE TEID > 0 GROUP by TEID,ip DESC limit ";
	char CMDforueip[] = "mysql -h192.168.67.33 -uroot -p123456 monitor -Ne\"select ip from resource WHERE TEID > 0 GROUP by TEID,ip DESC limit ";
	char CMDforpacket[] = "mysql -h192.168.67.33 -uroot -p123456 monitor -Ne\"select max(value) from resource WHERE TEID > 0 GROUP by TEID,ip DESC;\";";
	char CMDfortimestamp[] = "mysql -h192.168.67.33 -uroot -p123456 monitor -Ne\"select max(timestape) from resource WHERE TEID > 0 GROUP by TEID,ip DESC;\";";

	strcat(CMDforteid, session);
	strcat(CMDforueip, session);

	unsigned long long int teid = GetValue(CMDforteid);
	response->teid.presence = 1;
	response->teid.value = &teid;
	response->teid.len = 4;
	
	unsigned long long int ueip = GetValue(CMDforueip);
	response->ueip.presence = 1;
	response->ueip.value = &ueip;
	response->ueip.len = 4;

	unsigned long long int packet = GetValue(CMDforpacket);
	response->packet.presence = 1;
	response->packet.value = &packet;
	response->packet.len = 4;

    unsigned long long int ts = GetValue(CMDfortimestamp);
	//printf("%llu\n", ts);
	response->timestamp.presence = 1;
	response->timestamp.value = &ts;
	response->timestamp.len = 8;

	pfcpMessage.header.type = type;
	status = PfcpBuildMessage(bufBlkPtr, &pfcpMessage);
	UTLT_Assert(status == STATUS_OK, return STATUS_ERROR, "PFCP build error");

	UTLT_Debug("PFCP UPF report response built!");
	return STATUS_OK;
}
