#define TRACE_MODULE _n4_dispatcher

#include "utlt_debug.h"
#include "utlt_event.h"
#include "n4_pfcp_handler.h"
#include "pfcp_xact.h"
#include "pfcp_path.h"
#include "n4_pfcp_build.h"


#include <stdio.h>
#include <stdlib.h>

unsigned long long int GetValueD(const char *cmd) {
    FILE * fp;
    char buffer[160];
    char *endptr;
    fp=popen(cmd, "r");
    fgets(buffer,sizeof(buffer),fp);
    pclose(fp);
    return strtoull(buffer, &endptr, 10);
};

void UpfDispatcher(const Event *event) {
    switch ((UpfEvent)event->type) {
    case UPF_EVENT_SESSION_REPORT: {
        Status status;
        PfcpHeader header;
        Bufblk *bufBlk = NULL;
        PfcpXact *xact = NULL;

        uint64_t seid = (uint64_t)event->arg0;
        uint16_t pdrId = (uint16_t)event->arg1;

        UpfSession *session = UpfSessionFindBySeid(seid);
        UTLT_Assert(session != NULL, return,
                    "Session not find by seid: %d", seid);

        memset(&header, 0, sizeof(PfcpHeader));
        header.type = PFCP_SESSION_REPORT_REQUEST;
        header.seid = seid;

        status = UpfN4BuildSessionReportRequestDownlinkDataReport(&bufBlk,
                                                                  header.type,
                                                                  session,
                                                                  pdrId);
        UTLT_Assert(status == STATUS_OK, return,
                    "Build Session Report Request error");

        xact = PfcpXactLocalCreate(session->pfcpNode, &header, bufBlk);
        UTLT_Assert(xact, return, "pfcpXactLocalCreate error");

        status = PfcpXactCommit(xact);
        UTLT_Assert(status == STATUS_OK, return, "xact commit error");

        BufblkFree(bufBlk);

        break;
    }
    case UPF_EVENT_N4_MESSAGE: {
        Status status;
        Bufblk *bufBlk = NULL;
        Bufblk *recvBufBlk = (Bufblk *)event->arg0;
        PfcpNode *upf = (PfcpNode *)event->arg1;
        PfcpMessage *pfcpMessage = NULL;
        PfcpXact *xact = NULL;
        UpfSession *session = NULL;

        UTLT_Assert(recvBufBlk, return, "recv buffer no data");
        bufBlk = BufblkAlloc(1, sizeof(PfcpMessage));
        UTLT_Assert(bufBlk, goto freeRecvBuf, "create buffer error");
        pfcpMessage = bufBlk->buf;
        UTLT_Assert(pfcpMessage, goto freeBuf, "pfcpMessage assigned error");

        status = PfcpParseMessage(pfcpMessage, recvBufBlk);
        UTLT_Assert(status == STATUS_OK, goto freeBuf, "PfcpParseMessage error");

        if (pfcpMessage->header.seidP) {

            // if SEID presence
            if (!pfcpMessage->header.seid) {
                // without SEID
                if (pfcpMessage->header.type == PFCP_SESSION_ESTABLISHMENT_REQUEST) {
                    session = UpfSessionAddByMessage(pfcpMessage);
                } else {
                    UTLT_Assert(0, goto freeBuf,
                                "no SEID but not SESSION ESTABLISHMENT");
                }
            } else {
                // with SEID
                session = UpfSessionFindBySeid(pfcpMessage->header.seid);
            }

            UTLT_Assert(session, goto freeBuf,
                        "do not find / establish session");

            if (pfcpMessage->header.type != PFCP_SESSION_REPORT_RESPONSE) {
                session->pfcpNode = upf;
            }

            status = PfcpXactReceive(session->pfcpNode,
                                     &pfcpMessage->header, &xact);
            UTLT_Assert(status == STATUS_OK, goto freeBuf, "");
        } else {
            status = PfcpXactReceive(upf, &pfcpMessage->header, &xact);
            UTLT_Assert(status == STATUS_OK, goto freeBuf, "");
        }

        switch (pfcpMessage->header.type) {
        case PFCP_HEARTBEAT_REQUEST:
            UTLT_Info("[PFCP] Handle PFCP heartbeat request");
            UpfN4HandleHeartbeatRequest(xact, &pfcpMessage->heartbeatRequest);
            break;
        case PFCP_HEARTBEAT_RESPONSE:
            UTLT_Info("[PFCP] Handle PFCP heartbeat response");
            UpfN4HandleHeartbeatResponse(xact, &pfcpMessage->heartbeatResponse);
            break;
        case PFCP_ASSOCIATION_SETUP_REQUEST:
            UTLT_Info("[PFCP] Handle PFCP association setup request");
            UpfN4HandleAssociationSetupRequest(xact,
                                               &pfcpMessage->pFCPAssociationSetupRequest);
            break;
        case PFCP_ASSOCIATION_UPDATE_REQUEST:
            UTLT_Info("[PFCP] Handle PFCP association update request");
            UpfN4HandleAssociationUpdateRequest(xact,
                                                &pfcpMessage->pFCPAssociationUpdateRequest);
            break;
        case PFCP_ASSOCIATION_RELEASE_RESPONSE:
            UTLT_Info("[PFCP] Handle PFCP association release response");
            UpfN4HandleAssociationReleaseRequest(xact,
                                                 &pfcpMessage->pFCPAssociationReleaseRequest);
            break;
        case PFCP_SESSION_ESTABLISHMENT_REQUEST:
            UTLT_Info("[PFCP] Handle PFCP session establishment request");
            UpfN4HandleSessionEstablishmentRequest(session, xact,
                                                   &pfcpMessage->pFCPSessionEstablishmentRequest);
            break;
        case PFCP_SESSION_MODIFICATION_REQUEST:
            UTLT_Info("[PFCP] Handle PFCP session modification request");
            UpfN4HandleSessionModificationRequest(session, xact,
                                                  &pfcpMessage->pFCPSessionModificationRequest);
            break;
        case PFCP_SESSION_DELETION_REQUEST:
            UTLT_Info("[PFCP] Handle PFCP session deletion request");
            UpfN4HandleSessionDeletionRequest(session, xact,
                                              &pfcpMessage->pFCPSessionDeletionRequest);
            break;
        case PFCP_SESSION_REPORT_RESPONSE:
            UTLT_Info("[PFCP] Handle PFCP session report response");
            UpfN4HandleSessionReportResponse(session, xact,
                                             &pfcpMessage->pFCPSessionReportResponse);
		case PFCP_UPF_REPORT_REQUEST:
            UTLT_Info("[PFCP] Handle PFCP UPF report request");
            UpfN4HandleUPFReportRequest(xact, &pfcpMessage->pFCPUPFReportRequest);
            break;
		case PFCP_PDU_SESSION_DATA_REPORT_REQUEST:
			UTLT_Info("[PFCP] Handle PFCP PDU Session Data report request");
			char CMDforsessioncount[] = "mysql -h192.168.67.33 -uroot -p123456 monitor -Ne\"select count(*) from (select TEID from resource WHERE TEID > 0 GROUP by TEID,ip DESC) as a;\"";
			uint16_t count = GetValueD(CMDforsessioncount);
			uint16_t i = 0;
			for (i=0;i<count;i++) {
				UpfN4HandlePDUSessionDataReportRequest(xact, &pfcpMessage->pFCPPDUSessionDataReportRequest, i);
			}
			break;
        default:
            UTLT_Error("No implement pfcp type: %d", pfcpMessage->header.type);
        }
        freeBuf:
        PfcpStructFree(pfcpMessage);
        BufblkFree(bufBlk);
        freeRecvBuf:
        BufblkFree(recvBufBlk);
        break;
    }
    case UPF_EVENT_N4_T3_RESPONSE:
    case UPF_EVENT_N4_T3_HOLDING:
        {
            uint8_t type;
            PfcpXactTimeout((uint32_t) event->arg0,
                            (UpfEvent)event->type, &type);
            break;
        }
    default: {
        UTLT_Error("No handler for event type: %d", event->type);
        break;
    }
    }
}
