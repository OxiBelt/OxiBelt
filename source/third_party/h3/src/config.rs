use std::convert::TryFrom;

use crate::proto::{frame, varint::VarInt};

/// Configures the HTTP/3 connection
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct Config {
    /// Just like in HTTP/2, HTTP/3 also uses the concept of "grease"
    /// to prevent potential interoperability issues in the future.
    /// In HTTP/3, the concept of grease is used to ensure that the protocol can evolve
    /// and accommodate future changes without breaking existing implementations.
    pub(crate) send_grease: bool,

    #[cfg(test)]
    pub(crate) send_settings: bool,

    /// HTTP/3 Settings
    pub settings: Settings,
}

/// HTTP/3 Settings
#[derive(Debug, Clone, Copy)]
pub struct Settings {
    /// The MAX_FIELD_SECTION_SIZE in HTTP/3 refers to the maximum size of the dynamic table used in HPACK compression.
    /// HPACK is the compression algorithm used in HTTP/3 to reduce the size of the header fields in HTTP requests and responses.

    /// In HTTP/3, the MAX_FIELD_SECTION_SIZE is set to 12.
    /// This means that the dynamic table used for HPACK compression can have a maximum size of 2^12 bytes, which is 4KB.
    pub(crate) max_field_section_size: u64,

    /// https://datatracker.ietf.org/doc/html/draft-ietf-webtrans-http3/#section-3.1
    /// Sets `SETTINGS_ENABLE_WEBTRANSPORT` if enabled
    pub(crate) enable_webtransport: bool,
    /// draft-ietf-webtrans-http3-16 SETTINGS_WT_ENABLED.
    pub(crate) enable_webtransport_h3: bool,
    /// https://www.rfc-editor.org/info/rfc8441 defines an extended CONNECT method in Section 4,
    /// enabled by the SETTINGS_ENABLE_CONNECT_PROTOCOL parameter.
    /// That parameter is only defined for HTTP/2.
    /// for extended CONNECT in HTTP/3; instead, the SETTINGS_ENABLE_WEBTRANSPORT setting implies that an endpoint supports extended CONNECT.
    pub(crate) enable_extended_connect: bool,
    /// Enable HTTP Datagrams, see https://datatracker.ietf.org/doc/rfc9297/ for details
    pub(crate) enable_datagram: bool,
    /// The maximum number of concurrent streams that can be opened by the peer.
    pub(crate) max_webtransport_sessions: u64,
    /// Initial per-session receive credit advertised for draft 16.
    pub(crate) wt_initial_max_streams_uni: u64,
    /// Initial per-session receive credit advertised for draft 16.
    pub(crate) wt_initial_max_streams_bidi: u64,
    /// Initial per-session receive byte credit advertised for draft 16.
    pub(crate) wt_initial_max_data: u64,
}

impl From<&frame::Settings> for Settings {
    fn from(settings: &frame::Settings) -> Self {
        let defaults: Self = Default::default();
        Self {
            max_field_section_size: settings
                .get(frame::SettingId::MAX_HEADER_LIST_SIZE)
                .unwrap_or(defaults.max_field_section_size),
            enable_webtransport: settings
                .get(frame::SettingId::ENABLE_WEBTRANSPORT)
                .map(|value| value != 0)
                .unwrap_or(defaults.enable_webtransport),
            enable_webtransport_h3: settings
                .get(frame::SettingId::WT_ENABLED)
                .map(|value| value == 1)
                .unwrap_or(defaults.enable_webtransport_h3),
            max_webtransport_sessions: settings
                .get(frame::SettingId::WEBTRANSPORT_MAX_SESSIONS)
                .unwrap_or(defaults.max_webtransport_sessions),
            wt_initial_max_streams_uni: settings
                .get(frame::SettingId::WT_INITIAL_MAX_STREAMS_UNI)
                .unwrap_or(defaults.wt_initial_max_streams_uni),
            wt_initial_max_streams_bidi: settings
                .get(frame::SettingId::WT_INITIAL_MAX_STREAMS_BIDI)
                .unwrap_or(defaults.wt_initial_max_streams_bidi),
            wt_initial_max_data: settings
                .get(frame::SettingId::WT_INITIAL_MAX_DATA)
                .unwrap_or(defaults.wt_initial_max_data),
            enable_datagram: settings
                .get(frame::SettingId::H3_DATAGRAM)
                .map(|value| value != 0)
                .unwrap_or(defaults.enable_datagram),
            enable_extended_connect: settings
                .get(frame::SettingId::ENABLE_CONNECT_PROTOCOL)
                .map(|value| value != 0)
                .unwrap_or(defaults.enable_extended_connect),
        }
    }
}

impl TryFrom<Config> for frame::Settings {
    type Error = frame::SettingsError;
    fn try_from(value: Config) -> Result<Self, Self::Error> {
        let mut settings = frame::Settings::default();

        let Config {
            send_grease,
            #[cfg(test)]
                send_settings: _,
            settings:
                Settings {
                    max_field_section_size,
                    enable_webtransport,
                    enable_webtransport_h3,
                    enable_extended_connect,
                    enable_datagram,
                    max_webtransport_sessions,
                    wt_initial_max_streams_uni,
                    wt_initial_max_streams_bidi,
                    wt_initial_max_data,
                },
        } = value;

        if send_grease {
            //  Grease Settings (https://www.rfc-editor.org/rfc/rfc9114.html#name-defined-settings-parameters)
            //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.4.1
            //# Setting identifiers of the format 0x1f * N + 0x21 for non-negative
            //# integer values of N are reserved to exercise the requirement that
            //# unknown identifiers be ignored.  Such settings have no defined
            //# meaning.  Endpoints SHOULD include at least one such setting in their
            //# SETTINGS frame.

            //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.4.1
            //# Setting identifiers that were defined in [HTTP/2] where there is no
            //# corresponding HTTP/3 setting have also been reserved
            //# (Section 11.2.2).  These reserved settings MUST NOT be sent, and
            //# their receipt MUST be treated as a connection error of type
            //# H3_SETTINGS_ERROR.
            match settings.insert(frame::SettingId::grease(), 0) {
                Ok(_) => (),
                Err(_err) => {
                    #[cfg(feature = "tracing")]
                    tracing::warn!("Error when adding the grease Setting. Reason {}", _err);
                }
            }
        }

        settings.insert(
            frame::SettingId::MAX_HEADER_LIST_SIZE,
            max_field_section_size,
        )?;
        settings.insert(
            frame::SettingId::ENABLE_CONNECT_PROTOCOL,
            enable_extended_connect as u64,
        )?;
        settings.insert(
            frame::SettingId::ENABLE_WEBTRANSPORT,
            enable_webtransport as u64,
        )?;
        if enable_webtransport_h3 {
            settings.insert(frame::SettingId::WT_ENABLED, 1)?;
            settings.insert(frame::SettingId::WT_INITIAL_MAX_STREAMS_UNI, wt_initial_max_streams_uni)?;
            settings.insert(frame::SettingId::WT_INITIAL_MAX_STREAMS_BIDI, wt_initial_max_streams_bidi)?;
            settings.insert(frame::SettingId::WT_INITIAL_MAX_DATA, wt_initial_max_data)?;
        }
        settings.insert(frame::SettingId::H3_DATAGRAM, enable_datagram as u64)?;
        settings.insert(
            frame::SettingId::WEBTRANSPORT_MAX_SESSIONS,
            max_webtransport_sessions,
        )?;

        Ok(settings)
    }
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            max_field_section_size: VarInt::MAX.0,
            enable_webtransport: false,
            enable_webtransport_h3: false,
            enable_extended_connect: false,
            enable_datagram: false,
            max_webtransport_sessions: 0,
            wt_initial_max_streams_uni: 0,
            wt_initial_max_streams_bidi: 0,
            wt_initial_max_data: 0,
        }
    }
}

impl Settings {
    /// https://datatracker.ietf.org/doc/html/draft-ietf-webtrans-http3/#section-3.1
    /// Sets `SETTINGS_ENABLE_WEBTRANSPORT` if enabled
    pub fn enable_webtransport(&self) -> bool {
        self.enable_webtransport
    }

    /// Whether the peer advertised WebTransport over HTTP/3 draft 16.
    pub fn enable_webtransport_h3(&self) -> bool {
        self.enable_webtransport_h3
    }

    /// Initial unidirectional stream credit advertised by the peer.
    pub fn wt_initial_max_streams_uni(&self) -> u64 {
        self.wt_initial_max_streams_uni
    }

    /// Initial bidirectional stream credit advertised by the peer.
    pub fn wt_initial_max_streams_bidi(&self) -> u64 {
        self.wt_initial_max_streams_bidi
    }

    /// Initial session data credit advertised by the peer.
    pub fn wt_initial_max_data(&self) -> u64 {
        self.wt_initial_max_data
    }

    /// Enable HTTP Datagrams, see https://datatracker.ietf.org/doc/rfc9297/ for details
    pub fn enable_datagram(&self) -> bool {
        self.enable_datagram
    }

    /// https://www.rfc-editor.org/info/rfc8441 defines an extended CONNECT method in Section 4,
    /// enabled by the SETTINGS_ENABLE_CONNECT_PROTOCOL parameter.
    /// That parameter is only defined for HTTP/2.
    /// for extended CONNECT in HTTP/3; instead, the SETTINGS_ENABLE_WEBTRANSPORT setting implies that an endpoint supports extended CONNECT.
    pub fn enable_extended_connect(&self) -> bool {
        self.enable_extended_connect
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            send_grease: true,
            #[cfg(test)]
            send_settings: true,
            settings: Default::default(),
        }
    }
}

#[cfg(test)]
mod webtransport_draft_tests {
    use super::*;

    #[test]
    fn draft16_settings_are_explicit_opt_in() {
        let mut settings = Settings::default();
        settings.enable_webtransport = true;
        let default_wire: frame::Settings = Config { send_grease: false, settings, ..Config::default() }.try_into().unwrap();
        assert_eq!(default_wire.get(frame::SettingId::WT_ENABLED), None);
        assert_eq!(default_wire.get(frame::SettingId::WT_INITIAL_MAX_DATA), None);
        assert_eq!(default_wire.get(frame::SettingId::ENABLE_WEBTRANSPORT), Some(1));

        settings.enable_webtransport_h3 = true;
        settings.wt_initial_max_streams_uni = 7;
        settings.wt_initial_max_streams_bidi = 8;
        settings.wt_initial_max_data = 4096;
        let opt_in_wire: frame::Settings = Config { send_grease: false, settings, ..Config::default() }.try_into().unwrap();
        assert_eq!(opt_in_wire.get(frame::SettingId::WT_ENABLED), Some(1));
        assert_eq!(opt_in_wire.get(frame::SettingId::WT_INITIAL_MAX_STREAMS_UNI), Some(7));
        assert_eq!(opt_in_wire.get(frame::SettingId::WT_INITIAL_MAX_STREAMS_BIDI), Some(8));
        assert_eq!(opt_in_wire.get(frame::SettingId::WT_INITIAL_MAX_DATA), Some(4096));
    }
}
