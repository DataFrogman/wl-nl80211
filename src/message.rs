// SPDX-License-Identifier: MIT

use crate::attr::Nl80211Attr;
use crate::constants::*;
use anyhow::Context;
use netlink_packet_generic::{GenlFamily, GenlHeader};
use netlink_packet_utils::{
    nla::NlasIterator, DecodeError, Emitable, Parseable, ParseableParametrized,
};

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Nl80211Cmd {
    Unspecified,
    WiPhyGet,
    WiPhySet,
    WiPhyNew,
    WiPhyDel,
    InterfaceGet,
    InterfaceSet,
    InterfaceNew,
    InterfaceDel,
    KeyGet,
    KeySet,
    KeyNew,
    KeyDel,
    BeaconGet,
    BeaconSet,
    APStart,
    BeaconNew,
    BeaconDel,
    APStop,
    StationGet,
    StationSet,
    StationNew,
    StationDel,
    MPathGet,
    MPathSet,
    MPathNew,
    MPathDel,
    BSSSet,
    RegSet,
    RegReqSet,
    MeshConfigGet,
    MeshConfigSet,
    MGMTEXTRAIESet,
    RegGet,
    ScanGet,
    ScanTrigger,
    ScanResultsNew,
    ScanAborted,
    RegChange,
    Authenticate,
    Associate,
    Deauthenticate,
    Disassociate,
    MichaelMicFailure,
    RegBeaconHint,
    IBSSJoin,
    IBSSLeave,
    TestMode,
    Connect,
    Roam,
    Disconnect,
    WiPhyNetNS,
    SurveyGet,
    SurveyResultsNew,
    PMKSASet,
    PMKSADel,
    PMKSAFlush,
    RemainOnChannel,
    RemainOnChannelCancel,
    TxBitrateMaskSet,
    RegisterAction,
    RegisterFrame,
    Action,
    Frame,
    TxStatusFrame,
    TxStatusAction,
    PowerSaveSet,
    PowerSaveGet,
    CQMSet,
    CQMNotify,
    ChannelSet,
    WDSPeerSet,
    FrameWaitCancel,
    MeshJoin,
    MeshLeave,
    DeauthenticateUnprot,
    DisassociateUnprot,
    PeerCandidateNew,
    WoWLANGet,
    WoWLANSet,
    SchedScanStart,
    SchedScanStop,
    SchedScanResults,
    SchedScanStopped,
    RekeyOffloadSet,
    PMKSACandidate,
    TDLSOper,
    TDLSMgmt,
    UnexpectedFrame,
    ProbeClient,
    RegisterBeacons,
    Unexpected4AddrFrame,
    NoAckMapSet,
    SwitchNotifyCH,
    P2PDeviceStart,
    P2PDeviceStop,
    ConnFailed,
    MCastRateSet,
    MacAclSet,
    RadarDetect,
    ProtocolFeaturesGet,
    FTIESUpdate,
    FTEvent,
    CritProtocolStart,
    CritProtocolStop,
    CoalesceGet,
    CoalesceSet,
    ChannelSwitch,
    Vendor,
    QOSMapSet,
    TXTSAdd,
    TXTSDEL,
    MPPGet,
    OCBJoin,
    OCBLeave,
    CHSwitchStartedNotify,
    TDLSChannelSwitch,
    TDLSCancelChannelSwitch,
    WiPhyRegChange,
    ScanAbort,
    NANStart,
    NANStop,
    NANFunctionAdd,
    NANFunctionDel,
    NANConfigChange,
    NANMatch,
    SetMulticastToUnicast,
    UpdateConnectParams,
    PMKSet,
    PMKDel,
    PortAuthorized,
    ReloadREGDB,
    ExternalAuth,
    STAOpmodeChanged,
    ControlPortFrame,
    FTMResponderStatsGet,
    PeerMeasurementStart,
    PeerMeasurementResult,
    PeerMeasurementComplete,
    NotifyRadar,
    OWEInfoUpdate,
    ProbeMeshLink,
    TIDConfigSet,
    UnprotBeacon,
    ControlPortFrameTxStatus,
    SARSpecsSet,
    OBSSColorCollision,
    ColorChangeRequest,
    ColorChangeStarted,
    ColorChangeAborted,
    ColorChangeCompleted,
    SetFILSAAD,
    AssocComeback,
    AddLink,
    RemoveLink,
    AddLinkSta,
    ModifyLinkSta,
    RemoveLinkSta,
    SetHWTimestamp,
    LinksRemoved,
}

impl From<Nl80211Cmd> for u8 {
    fn from(cmd: Nl80211Cmd) -> Self {
        match cmd {
            Nl80211Cmd::InterfaceGet => NL80211_CMD_GET_INTERFACE,
            Nl80211Cmd::InterfaceNew => NL80211_CMD_NEW_INTERFACE,
            Nl80211Cmd::Unspecified => NL80211_CMD_UNSPEC,
            Nl80211Cmd::WiPhyGet => NL80211_CMD_GET_WIPHY,
            Nl80211Cmd::WiPhySet => NL80211_CMD_SET_WIPHY,
            Nl80211Cmd::WiPhyNew => NL80211_CMD_NEW_WIPHY,
            Nl80211Cmd::WiPhyDel => NL80211_CMD_DEL_WIPHY,
            Nl80211Cmd::InterfaceSet => NL80211_CMD_SET_INTERFACE,
            Nl80211Cmd::InterfaceDel => NL80211_CMD_DEL_INTERFACE,
            Nl80211Cmd::KeyGet => NL80211_CMD_GET_KEY,
            Nl80211Cmd::KeySet => NL80211_CMD_SET_KEY,
            Nl80211Cmd::KeyNew => NL80211_CMD_NEW_KEY,
            Nl80211Cmd::KeyDel => NL80211_CMD_DEL_KEY,
            Nl80211Cmd::BeaconGet => NL80211_CMD_GET_BEACON,
            Nl80211Cmd::BeaconSet => NL80211_CMD_SET_BEACON,
            Nl80211Cmd::APStart => NL80211_CMD_START_AP,
            Nl80211Cmd::BeaconNew => NL80211_CMD_NEW_BEACON,
            Nl80211Cmd::BeaconDel => NL80211_CMD_DEL_BEACON,
            Nl80211Cmd::APStop => NL80211_CMD_STOP_AP,
            Nl80211Cmd::StationGet => NL80211_CMD_GET_STATION,
            Nl80211Cmd::StationSet => NL80211_CMD_SET_STATION,
            Nl80211Cmd::StationNew => NL80211_CMD_NEW_STATION,
            Nl80211Cmd::StationDel => NL80211_CMD_DEL_STATION,
            Nl80211Cmd::MPathGet => NL80211_CMD_GET_MPATH,
            Nl80211Cmd::MPathSet => NL80211_CMD_SET_MPATH,
            Nl80211Cmd::MPathNew => NL80211_CMD_NEW_MPATH,
            Nl80211Cmd::MPathDel => NL80211_CMD_DEL_MPATH,
            Nl80211Cmd::BSSSet => NL80211_CMD_SET_BSS,
            Nl80211Cmd::RegSet => NL80211_CMD_SET_REG,
            Nl80211Cmd::RegReqSet => NL80211_CMD_REQ_SET_REG,
            Nl80211Cmd::MeshConfigGet => NL80211_CMD_GET_MESH_CONFIG,
            Nl80211Cmd::MeshConfigSet => NL80211_CMD_SET_MESH_CONFIG,
            Nl80211Cmd::MGMTEXTRAIESet => NL80211_CMD_SET_MGMT_EXTRA_IE,
            Nl80211Cmd::RegGet => NL80211_CMD_GET_REG,
            Nl80211Cmd::ScanGet => NL80211_CMD_GET_SCAN,
            Nl80211Cmd::ScanTrigger => NL80211_CMD_TRIGGER_SCAN,
            Nl80211Cmd::ScanResultsNew => NL80211_CMD_NEW_SCAN_RESULTS,
            Nl80211Cmd::ScanAborted => NL80211_CMD_SCAN_ABORTED,
            Nl80211Cmd::RegChange => NL80211_CMD_REG_CHANGE,
            Nl80211Cmd::Authenticate => NL80211_CMD_AUTHENTICATE,
            Nl80211Cmd::Associate => NL80211_CMD_ASSOCIATE,
            Nl80211Cmd::Deauthenticate => NL80211_CMD_DEAUTHENTICATE,
            Nl80211Cmd::Disassociate => NL80211_CMD_DISASSOCIATE,
            Nl80211Cmd::MichaelMicFailure => NL80211_CMD_MICHAEL_MIC_FAILURE,
            Nl80211Cmd::RegBeaconHint => NL80211_CMD_REG_BEACON_HINT,
            Nl80211Cmd::IBSSJoin => NL80211_CMD_JOIN_IBSS,
            Nl80211Cmd::IBSSLeave => NL80211_CMD_LEAVE_IBSS,
            Nl80211Cmd::TestMode => NL80211_CMD_TESTMODE,
            Nl80211Cmd::Connect => NL80211_CMD_CONNECT,
            Nl80211Cmd::Roam => NL80211_CMD_ROAM,
            Nl80211Cmd::Disconnect => NL80211_CMD_DISCONNECT,
            Nl80211Cmd::WiPhyNetNS => NL80211_CMD_SET_WIPHY_NETNS,
            Nl80211Cmd::SurveyGet => NL80211_CMD_GET_SURVEY,
            Nl80211Cmd::SurveyResultsNew => NL80211_CMD_NEW_SURVEY_RESULTS,
            Nl80211Cmd::PMKSASet => NL80211_CMD_SET_PMKSA,
            Nl80211Cmd::PMKSADel => NL80211_CMD_DEL_PMKSA,
            Nl80211Cmd::PMKSAFlush => NL80211_CMD_FLUSH_PMKSA,
            Nl80211Cmd::RemainOnChannel => NL80211_CMD_REMAIN_ON_CHANNEL,
            Nl80211Cmd::RemainOnChannelCancel => {
                NL80211_CMD_CANCEL_REMAIN_ON_CHANNEL
            }
            Nl80211Cmd::TxBitrateMaskSet => NL80211_CMD_SET_TX_BITRATE_MASK,
            Nl80211Cmd::RegisterAction => NL80211_CMD_REGISTER_ACTION,
            Nl80211Cmd::RegisterFrame => NL80211_CMD_REGISTER_FRAME,
            Nl80211Cmd::Action => NL80211_CMD_ACTION,
            Nl80211Cmd::Frame => NL80211_CMD_FRAME,
            Nl80211Cmd::TxStatusFrame => NL80211_CMD_FRAME_TX_STATUS,
            Nl80211Cmd::TxStatusAction => NL80211_CMD_ACTION_TX_STATUS,
            Nl80211Cmd::PowerSaveSet => NL80211_CMD_SET_POWER_SAVE,
            Nl80211Cmd::PowerSaveGet => NL80211_CMD_GET_POWER_SAVE,
            Nl80211Cmd::CQMSet => NL80211_CMD_SET_CQM,
            Nl80211Cmd::CQMNotify => NL80211_CMD_NOTIFY_CQM,
            Nl80211Cmd::ChannelSet => NL80211_CMD_SET_CHANNEL,
            Nl80211Cmd::WDSPeerSet => NL80211_CMD_SET_WDS_PEER,
            Nl80211Cmd::FrameWaitCancel => NL80211_CMD_FRAME_WAIT_CANCEL,
            Nl80211Cmd::MeshJoin => NL80211_CMD_JOIN_MESH,
            Nl80211Cmd::MeshLeave => NL80211_CMD_LEAVE_MESH,
            Nl80211Cmd::DeauthenticateUnprot => {
                NL80211_CMD_UNPROT_DEAUTHENTICATE
            }
            Nl80211Cmd::DisassociateUnprot => NL80211_CMD_UNPROT_DISASSOCIATE,
            Nl80211Cmd::PeerCandidateNew => NL80211_CMD_NEW_PEER_CANDIDATE,
            Nl80211Cmd::WoWLANGet => NL80211_CMD_GET_WOWLAN,
            Nl80211Cmd::WoWLANSet => NL80211_CMD_SET_WOWLAN,
            Nl80211Cmd::SchedScanStart => NL80211_CMD_START_SCHED_SCAN,
            Nl80211Cmd::SchedScanStop => NL80211_CMD_STOP_SCHED_SCAN,
            Nl80211Cmd::SchedScanResults => NL80211_CMD_SCHED_SCAN_RESULTS,
            Nl80211Cmd::SchedScanStopped => NL80211_CMD_SCHED_SCAN_STOPPED,
            Nl80211Cmd::RekeyOffloadSet => NL80211_CMD_SET_REKEY_OFFLOAD,
            Nl80211Cmd::PMKSACandidate => NL80211_CMD_PMKSA_CANDIDATE,
            Nl80211Cmd::TDLSOper => NL80211_CMD_TDLS_OPER,
            Nl80211Cmd::TDLSMgmt => NL80211_CMD_TDLS_MGMT,
            Nl80211Cmd::UnexpectedFrame => NL80211_CMD_UNEXPECTED_FRAME,
            Nl80211Cmd::ProbeClient => NL80211_CMD_PROBE_CLIENT,
            Nl80211Cmd::RegisterBeacons => NL80211_CMD_REGISTER_BEACONS,
            Nl80211Cmd::Unexpected4AddrFrame => {
                NL80211_CMD_UNEXPECTED_4ADDR_FRAME
            }
            Nl80211Cmd::NoAckMapSet => NL80211_CMD_SET_NOACK_MAP,
            Nl80211Cmd::SwitchNotifyCH => NL80211_CMD_CH_SWITCH_NOTIFY,
            Nl80211Cmd::P2PDeviceStart => NL80211_CMD_START_P2P_DEVICE,
            Nl80211Cmd::P2PDeviceStop => NL80211_CMD_STOP_P2P_DEVICE,
            Nl80211Cmd::ConnFailed => NL80211_CMD_CONN_FAILED,
            Nl80211Cmd::MCastRateSet => NL80211_CMD_SET_MCAST_RATE,
            Nl80211Cmd::MacAclSet => NL80211_CMD_SET_MAC_ACL,
            Nl80211Cmd::RadarDetect => NL80211_CMD_RADAR_DETECT,
            Nl80211Cmd::ProtocolFeaturesGet => {
                NL80211_CMD_GET_PROTOCOL_FEATURES
            }
            Nl80211Cmd::FTIESUpdate => NL80211_CMD_UPDATE_FT_IES,
            Nl80211Cmd::FTEvent => NL80211_CMD_FT_EVENT,
            Nl80211Cmd::CritProtocolStart => NL80211_CMD_CRIT_PROTOCOL_START,
            Nl80211Cmd::CritProtocolStop => NL80211_CMD_CRIT_PROTOCOL_STOP,
            Nl80211Cmd::CoalesceGet => NL80211_CMD_GET_COALESCE,
            Nl80211Cmd::CoalesceSet => NL80211_CMD_SET_COALESCE,
            Nl80211Cmd::ChannelSwitch => NL80211_CMD_CHANNEL_SWITCH,
            Nl80211Cmd::Vendor => NL80211_CMD_VENDOR,
            Nl80211Cmd::QOSMapSet => NL80211_CMD_SET_QOS_MAP,
            Nl80211Cmd::TXTSAdd => NL80211_CMD_ADD_TX_TS,
            Nl80211Cmd::TXTSDEL => NL80211_CMD_DEL_TX_TS,
            Nl80211Cmd::MPPGet => NL80211_CMD_GET_MPP,
            Nl80211Cmd::OCBJoin => NL80211_CMD_JOIN_OCB,
            Nl80211Cmd::OCBLeave => NL80211_CMD_LEAVE_OCB,
            Nl80211Cmd::CHSwitchStartedNotify => {
                NL80211_CMD_CH_SWITCH_STARTED_NOTIFY
            }
            Nl80211Cmd::TDLSChannelSwitch => NL80211_CMD_TDLS_CHANNEL_SWITCH,
            Nl80211Cmd::TDLSCancelChannelSwitch => {
                NL80211_CMD_TDLS_CANCEL_CHANNEL_SWITCH
            }
            Nl80211Cmd::WiPhyRegChange => NL80211_CMD_WIPHY_REG_CHANGE,
            Nl80211Cmd::ScanAbort => NL80211_CMD_ABORT_SCAN,
            Nl80211Cmd::NANStart => NL80211_CMD_START_NAN,
            Nl80211Cmd::NANStop => NL80211_CMD_STOP_NAN,
            Nl80211Cmd::NANFunctionAdd => NL80211_CMD_ADD_NAN_FUNCTION,
            Nl80211Cmd::NANFunctionDel => NL80211_CMD_DEL_NAN_FUNCTION,
            Nl80211Cmd::NANConfigChange => NL80211_CMD_CHANGE_NAN_CONFIG,
            Nl80211Cmd::NANMatch => NL80211_CMD_NAN_MATCH,
            Nl80211Cmd::SetMulticastToUnicast => {
                NL80211_CMD_SET_MULTICAST_TO_UNICAST
            }
            Nl80211Cmd::UpdateConnectParams => {
                NL80211_CMD_UPDATE_CONNECT_PARAMS
            }
            Nl80211Cmd::PMKSet => NL80211_CMD_SET_PMK,
            Nl80211Cmd::PMKDel => NL80211_CMD_DEL_PMK,
            Nl80211Cmd::PortAuthorized => NL80211_CMD_PORT_AUTHORIZED,
            Nl80211Cmd::ReloadREGDB => NL80211_CMD_RELOAD_REGDB,
            Nl80211Cmd::ExternalAuth => NL80211_CMD_EXTERNAL_AUTH,
            Nl80211Cmd::STAOpmodeChanged => NL80211_CMD_STA_OPMODE_CHANGED,
            Nl80211Cmd::ControlPortFrame => NL80211_CMD_CONTROL_PORT_FRAME,
            Nl80211Cmd::FTMResponderStatsGet => {
                NL80211_CMD_GET_FTM_RESPONDER_STATS
            }
            Nl80211Cmd::PeerMeasurementStart => {
                NL80211_CMD_PEER_MEASUREMENT_START
            }
            Nl80211Cmd::PeerMeasurementResult => {
                NL80211_CMD_PEER_MEASUREMENT_RESULT
            }
            Nl80211Cmd::PeerMeasurementComplete => {
                NL80211_CMD_PEER_MEASUREMENT_COMPLETE
            }
            Nl80211Cmd::NotifyRadar => NL80211_CMD_NOTIFY_RADAR,
            Nl80211Cmd::OWEInfoUpdate => NL80211_CMD_UPDATE_OWE_INFO,
            Nl80211Cmd::ProbeMeshLink => NL80211_CMD_PROBE_MESH_LINK,
            Nl80211Cmd::TIDConfigSet => NL80211_CMD_SET_TID_CONFIG,
            Nl80211Cmd::UnprotBeacon => NL80211_CMD_UNPROT_BEACON,
            Nl80211Cmd::ControlPortFrameTxStatus => {
                NL80211_CMD_CONTROL_PORT_FRAME_TX_STATUS
            }
            Nl80211Cmd::SARSpecsSet => NL80211_CMD_SET_SAR_SPECS,
            Nl80211Cmd::OBSSColorCollision => NL80211_CMD_OBSS_COLOR_COLLISION,
            Nl80211Cmd::ColorChangeRequest => NL80211_CMD_COLOR_CHANGE_REQUEST,
            Nl80211Cmd::ColorChangeStarted => NL80211_CMD_COLOR_CHANGE_STARTED,
            Nl80211Cmd::ColorChangeAborted => NL80211_CMD_COLOR_CHANGE_ABORTED,
            Nl80211Cmd::ColorChangeCompleted => {
                NL80211_CMD_COLOR_CHANGE_COMPLETED
            }
            Nl80211Cmd::SetFILSAAD => NL80211_CMD_SET_FILS_AAD,
            Nl80211Cmd::AssocComeback => NL80211_CMD_ASSOC_COMEBACK,
            Nl80211Cmd::AddLink => NL80211_CMD_ADD_LINK,
            Nl80211Cmd::RemoveLink => NL80211_CMD_REMOVE_LINK,
            Nl80211Cmd::AddLinkSta => NL80211_CMD_ADD_LINK_STA,
            Nl80211Cmd::ModifyLinkSta => NL80211_CMD_MODIFY_LINK_STA,
            Nl80211Cmd::RemoveLinkSta => NL80211_CMD_REMOVE_LINK_STA,
            Nl80211Cmd::SetHWTimestamp => NL80211_CMD_SET_HW_TIMESTAMP,
            Nl80211Cmd::LinksRemoved => NL80211_CMD_LINKS_REMOVED,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Nl80211Message {
    pub cmd: Nl80211Cmd,
    pub nlas: Vec<Nl80211Attr>,
}

impl GenlFamily for Nl80211Message {
    fn family_name() -> &'static str {
        "nl80211"
    }

    fn version(&self) -> u8 {
        match self.cmd {
            Nl80211Cmd::InterfaceSet => 0,
            _ => 1,
        }
    }

    fn command(&self) -> u8 {
        self.cmd.into()
    }

    fn family_id(&self) -> u16 {
        0x0020
    }
}

impl Nl80211Message {
    pub fn new_interface_get() -> Self {
        Nl80211Message {
            cmd: Nl80211Cmd::InterfaceGet,
            nlas: vec![],
        }
    }
}

impl Emitable for Nl80211Message {
    fn buffer_len(&self) -> usize {
        self.nlas.as_slice().buffer_len()
    }

    fn emit(&self, buffer: &mut [u8]) {
        self.nlas.as_slice().emit(buffer)
    }
}

fn parse_nlas(buffer: &[u8]) -> Result<Vec<Nl80211Attr>, DecodeError> {
    let mut nlas = Vec::new();
    for nla in NlasIterator::new(buffer) {
        let error_msg =
            format!("Failed to parse nl80211 message attribute {:?}", nla);
        let nla = &nla.context(error_msg.clone())?;
        nlas.push(Nl80211Attr::parse(nla).context(error_msg)?);
    }
    Ok(nlas)
}

impl ParseableParametrized<[u8], GenlHeader> for Nl80211Message {
    fn parse_with_param(
        buffer: &[u8],
        header: GenlHeader,
    ) -> Result<Self, DecodeError> {
        Ok(match header.cmd {
            NL80211_CMD_NEW_INTERFACE => Self {
                cmd: Nl80211Cmd::InterfaceNew,
                nlas: parse_nlas(buffer)?,
            },
            cmd => {
                return Err(DecodeError::from(format!(
                    "Unsupported nl80211 reply command: {}",
                    cmd
                )))
            }
        })
    }
}
