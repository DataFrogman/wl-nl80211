use crate::constants::*;
use netlink_packet_utils::nla::Nla;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Nl80211MonitorModeFlags {
    Invalid,
    FcsFail,
    PlcpFail,
    Control,
    OtherBSS,
    CookFrames,
    Active,
    Other(u8),
}

impl Nla for Nl80211MonitorModeFlags {
    fn value_len(&self) -> usize {
        match self {
            Self::Invalid
            | Self::FcsFail
            | Self::PlcpFail
            | Self::Control
            | Self::OtherBSS
            | Self::CookFrames
            | Self::Active
            | Self::Other(_) => 0,
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Self::Invalid => __NL80211_MNTR_FLAG_INVALID as u16,
            Self::FcsFail => NL80211_MNTR_FLAG_FCSFAIL as u16,
            Self::PlcpFail => NL80211_MNTR_FLAG_PLCPFAIL as u16,
            Self::Control => NL80211_MNTR_FLAG_CONTROL as u16,
            Self::OtherBSS => NL80211_MNTR_FLAG_OTHER_BSS as u16,
            Self::CookFrames => NL80211_MNTR_FLAG_COOK_FRAMES as u16,
            Self::Active => NL80211_MNTR_FLAG_ACTIVE as u16,
            Self::Other(d) => *d as u16,
        }
    }

    fn emit_value(&self, _: &mut [u8]) {
        match self {
            Self::Invalid
            | Self::FcsFail
            | Self::PlcpFail
            | Self::Control
            | Self::OtherBSS
            | Self::CookFrames
            | Self::Active
            | Self::Other(_) => {}
        }
    }
}

impl From<u8> for Nl80211MonitorModeFlags {
    fn from(d: u8) -> Self {
        match d {
            __NL80211_MNTR_FLAG_INVALID => Self::Invalid,
            NL80211_MNTR_FLAG_FCSFAIL => Self::FcsFail,
            NL80211_MNTR_FLAG_PLCPFAIL => Self::PlcpFail,
            NL80211_MNTR_FLAG_CONTROL => Self::Control,
            NL80211_MNTR_FLAG_OTHER_BSS => Self::OtherBSS,
            NL80211_MNTR_FLAG_COOK_FRAMES => Self::CookFrames,
            NL80211_MNTR_FLAG_ACTIVE => Self::Active,
            _ => Self::Other(d),
        }
    }
}

impl From<Nl80211MonitorModeFlags> for u8 {
    fn from(v: Nl80211MonitorModeFlags) -> u8 {
        match v {
            Nl80211MonitorModeFlags::Invalid => __NL80211_MNTR_FLAG_INVALID,
            Nl80211MonitorModeFlags::FcsFail => NL80211_MNTR_FLAG_FCSFAIL,
            Nl80211MonitorModeFlags::PlcpFail => NL80211_MNTR_FLAG_PLCPFAIL,
            Nl80211MonitorModeFlags::Control => NL80211_MNTR_FLAG_CONTROL,
            Nl80211MonitorModeFlags::OtherBSS => NL80211_MNTR_FLAG_OTHER_BSS,
            Nl80211MonitorModeFlags::CookFrames => {
                NL80211_MNTR_FLAG_COOK_FRAMES
            }
            Nl80211MonitorModeFlags::Active => NL80211_MNTR_FLAG_ACTIVE,
            Nl80211MonitorModeFlags::Other(d) => d,
        }
    }
}
