use std::fmt;

use crate::frame::{util, Error, Frame, FrameSize, Head, Kind, StreamId};
use bytes::{BufMut, BytesMut};

#[derive(Clone, Default, Eq, PartialEq)]
pub struct Settings {
  flags: SettingsFlags,
  // Fields
  header_table_size: Option<u32>,
  enable_push: Option<u32>,
  max_concurrent_streams: Option<u32>,
  initial_window_size: Option<u32>,
  max_frame_size: Option<u32>,
  max_header_list_size: Option<u32>,
  enable_connect_protocol: Option<u32>,
  webtransport_enabled: Option<u32>,
  webtransport_initial_max_data: Option<u32>,
  webtransport_initial_max_stream_data_uni: Option<u32>,
  webtransport_initial_max_stream_data_bidi_local: Option<u32>,
  webtransport_initial_max_streams_uni: Option<u32>,
  webtransport_initial_max_stream_data_bidi_remote: Option<u32>,
  webtransport_initial_max_streams_bidi: Option<u32>,
}

/// An enum that lists all valid settings that can be sent in a SETTINGS
/// frame.
///
/// Each setting has a value that is a 32 bit unsigned integer (6.5.1.).
#[derive(Debug)]
pub enum Setting {
  HeaderTableSize(u32),
  EnablePush(u32),
  MaxConcurrentStreams(u32),
  InitialWindowSize(u32),
  MaxFrameSize(u32),
  MaxHeaderListSize(u32),
  EnableConnectProtocol(u32),
  WebTransportEnabled(u32),
  WebTransportInitialMaxData(u32),
  WebTransportInitialMaxStreamDataUni(u32),
  WebTransportInitialMaxStreamDataBidiLocal(u32),
  WebTransportInitialMaxStreamsUni(u32),
  WebTransportInitialMaxStreamDataBidiRemote(u32),
  WebTransportInitialMaxStreamsBidi(u32),
}

#[derive(Copy, Clone, Eq, PartialEq, Default)]
pub struct SettingsFlags(u8);

const ACK: u8 = 0x1;
const ALL: u8 = ACK;

/// The default value of SETTINGS_HEADER_TABLE_SIZE
pub const DEFAULT_SETTINGS_HEADER_TABLE_SIZE: usize = 4_096;

/// The default value of SETTINGS_INITIAL_WINDOW_SIZE
pub const DEFAULT_INITIAL_WINDOW_SIZE: u32 = 65_535;

/// The default value of MAX_FRAME_SIZE
pub const DEFAULT_MAX_FRAME_SIZE: FrameSize = 16_384;

/// INITIAL_WINDOW_SIZE upper bound
pub const MAX_INITIAL_WINDOW_SIZE: usize = (1 << 31) - 1;

/// MAX_FRAME_SIZE upper bound
pub const MAX_MAX_FRAME_SIZE: FrameSize = (1 << 24) - 1;

// ===== impl Settings =====

impl Settings {
  pub fn ack() -> Settings {
    Settings {
      flags: SettingsFlags::ack(),
      ..Settings::default()
    }
  }

  pub fn is_ack(&self) -> bool {
    self.flags.is_ack()
  }

  pub fn initial_window_size(&self) -> Option<u32> {
    self.initial_window_size
  }

  pub fn set_initial_window_size(&mut self, size: Option<u32>) {
    self.initial_window_size = size;
  }

  pub fn max_concurrent_streams(&self) -> Option<u32> {
    self.max_concurrent_streams
  }

  pub fn set_max_concurrent_streams(&mut self, max: Option<u32>) {
    self.max_concurrent_streams = max;
  }

  pub fn max_frame_size(&self) -> Option<u32> {
    self.max_frame_size
  }

  pub fn set_max_frame_size(&mut self, size: Option<u32>) {
    if let Some(val) = size {
      assert!(DEFAULT_MAX_FRAME_SIZE <= val && val <= MAX_MAX_FRAME_SIZE);
    }
    self.max_frame_size = size;
  }

  pub fn max_header_list_size(&self) -> Option<u32> {
    self.max_header_list_size
  }

  pub fn set_max_header_list_size(&mut self, size: Option<u32>) {
    self.max_header_list_size = size;
  }

  pub fn is_push_enabled(&self) -> Option<bool> {
    self.enable_push.map(|val| val != 0)
  }

  pub fn set_enable_push(&mut self, enable: bool) {
    self.enable_push = Some(enable as u32);
  }

  pub fn is_extended_connect_protocol_enabled(&self) -> Option<bool> {
    self.enable_connect_protocol.map(|val| val != 0)
  }

  pub fn set_enable_connect_protocol(&mut self, val: Option<u32>) {
    self.enable_connect_protocol = val;
  }

  pub fn set_webtransport_settings(&mut self, settings: crate::webtransport::Settings) {
    self.webtransport_enabled = settings.enabled.then_some(1);
    self.webtransport_initial_max_data = settings.initial_max_data;
    self.webtransport_initial_max_stream_data_uni = settings.initial_max_stream_data_uni;
    self.webtransport_initial_max_stream_data_bidi_local =
      settings.initial_max_stream_data_bidi_local;
    self.webtransport_initial_max_stream_data_bidi_remote =
      settings.initial_max_stream_data_bidi_remote;
    self.webtransport_initial_max_streams_uni = settings.initial_max_streams_uni;
    self.webtransport_initial_max_streams_bidi = settings.initial_max_streams_bidi;
  }

  pub(crate) fn apply_webtransport_settings_to(
    &self,
    settings: &mut crate::webtransport::Settings,
  ) {
    if let Some(enabled) = self.webtransport_enabled {
      settings.enabled = enabled == 1;
    }
    if let Some(value) = self.webtransport_initial_max_data {
      settings.initial_max_data = Some(value);
    }
    if let Some(value) = self.webtransport_initial_max_stream_data_uni {
      settings.initial_max_stream_data_uni = Some(value);
    }
    if let Some(value) = self.webtransport_initial_max_stream_data_bidi_local {
      settings.initial_max_stream_data_bidi_local = Some(value);
    }
    if let Some(value) = self.webtransport_initial_max_stream_data_bidi_remote {
      settings.initial_max_stream_data_bidi_remote = Some(value);
    }
    if let Some(value) = self.webtransport_initial_max_streams_uni {
      settings.initial_max_streams_uni = Some(value);
    }
    if let Some(value) = self.webtransport_initial_max_streams_bidi {
      settings.initial_max_streams_bidi = Some(value);
    }
  }

  pub fn header_table_size(&self) -> Option<u32> {
    self.header_table_size
  }

  pub fn set_header_table_size(&mut self, size: Option<u32>) {
    self.header_table_size = size;
  }

  pub fn load(head: Head, payload: &[u8]) -> Result<Settings, Error> {
    use self::Setting::*;

    debug_assert_eq!(head.kind(), crate::frame::Kind::Settings);

    if !head.stream_id().is_zero() {
      return Err(Error::InvalidStreamId);
    }

    // Load the flag
    let flag = SettingsFlags::load(head.flag());

    if flag.is_ack() {
      // Ensure that the payload is empty
      if !payload.is_empty() {
        return Err(Error::InvalidPayloadLength);
      }

      // Return the ACK frame
      return Ok(Settings::ack());
    }

    // Ensure the payload length is correct, each setting is 6 bytes long.
    if payload.len() % 6 != 0 {
      tracing::debug!("invalid settings payload length; len={:?}", payload.len());
      return Err(Error::InvalidPayloadAckSettings);
    }

    let mut settings = Settings::default();
    debug_assert!(!settings.flags.is_ack());

    for raw in payload.chunks(6) {
      match Setting::load(raw) {
        Some(HeaderTableSize(val)) => {
          settings.header_table_size = Some(val);
        }
        Some(EnablePush(val)) => match val {
          0 | 1 => {
            settings.enable_push = Some(val);
          }
          _ => {
            return Err(Error::InvalidSettingValue);
          }
        },
        Some(MaxConcurrentStreams(val)) => {
          settings.max_concurrent_streams = Some(val);
        }
        Some(InitialWindowSize(val)) => {
          if val as usize > MAX_INITIAL_WINDOW_SIZE {
            return Err(Error::InvalidSettingValue);
          } else {
            settings.initial_window_size = Some(val);
          }
        }
        Some(MaxFrameSize(val)) => {
          if DEFAULT_MAX_FRAME_SIZE <= val && val <= MAX_MAX_FRAME_SIZE {
            settings.max_frame_size = Some(val);
          } else {
            return Err(Error::InvalidSettingValue);
          }
        }
        Some(MaxHeaderListSize(val)) => {
          settings.max_header_list_size = Some(val);
        }
        Some(EnableConnectProtocol(val)) => match val {
          0 | 1 => {
            settings.enable_connect_protocol = Some(val);
          }
          _ => {
            return Err(Error::InvalidSettingValue);
          }
        },
        Some(WebTransportEnabled(val)) => match val {
          0 | 1 => settings.webtransport_enabled = Some(val),
          _ => return Err(Error::InvalidSettingValue),
        },
        Some(WebTransportInitialMaxData(val)) => settings.webtransport_initial_max_data = Some(val),
        Some(WebTransportInitialMaxStreamDataUni(val)) => {
          settings.webtransport_initial_max_stream_data_uni = Some(val)
        }
        Some(WebTransportInitialMaxStreamDataBidiLocal(val)) => {
          settings.webtransport_initial_max_stream_data_bidi_local = Some(val)
        }
        Some(WebTransportInitialMaxStreamsUni(val)) => {
          settings.webtransport_initial_max_streams_uni = Some(val)
        }
        Some(WebTransportInitialMaxStreamDataBidiRemote(val)) => {
          settings.webtransport_initial_max_stream_data_bidi_remote = Some(val)
        }
        Some(WebTransportInitialMaxStreamsBidi(val)) => {
          settings.webtransport_initial_max_streams_bidi = Some(val)
        }
        None => {}
      }
    }

    Ok(settings)
  }

  fn payload_len(&self) -> usize {
    let mut len = 0;
    self.for_each(|_| len += 6);
    len
  }

  pub fn encode(&self, dst: &mut BytesMut) {
    // Create & encode an appropriate frame head
    let head = Head::new(Kind::Settings, self.flags.into(), StreamId::zero());
    let payload_len = self.payload_len();

    tracing::trace!("encoding SETTINGS; len={}", payload_len);

    head.encode(payload_len, dst);

    // Encode the settings
    self.for_each(|setting| {
      tracing::trace!("encoding setting; val={:?}", setting);
      setting.encode(dst)
    });
  }

  fn for_each<F: FnMut(Setting)>(&self, mut f: F) {
    use self::Setting::*;

    if let Some(v) = self.header_table_size {
      f(HeaderTableSize(v));
    }

    if let Some(v) = self.enable_push {
      f(EnablePush(v));
    }

    if let Some(v) = self.max_concurrent_streams {
      f(MaxConcurrentStreams(v));
    }

    if let Some(v) = self.initial_window_size {
      f(InitialWindowSize(v));
    }

    if let Some(v) = self.max_frame_size {
      f(MaxFrameSize(v));
    }

    if let Some(v) = self.max_header_list_size {
      f(MaxHeaderListSize(v));
    }

    if let Some(v) = self.enable_connect_protocol {
      f(EnableConnectProtocol(v));
    }
    if let Some(v) = self.webtransport_enabled {
      f(WebTransportEnabled(v));
    }
    if let Some(v) = self.webtransport_initial_max_data {
      f(WebTransportInitialMaxData(v));
    }
    if let Some(v) = self.webtransport_initial_max_stream_data_uni {
      f(WebTransportInitialMaxStreamDataUni(v));
    }
    if let Some(v) = self.webtransport_initial_max_stream_data_bidi_local {
      f(WebTransportInitialMaxStreamDataBidiLocal(v));
    }
    if let Some(v) = self.webtransport_initial_max_streams_uni {
      f(WebTransportInitialMaxStreamsUni(v));
    }
    if let Some(v) = self.webtransport_initial_max_stream_data_bidi_remote {
      f(WebTransportInitialMaxStreamDataBidiRemote(v));
    }
    if let Some(v) = self.webtransport_initial_max_streams_bidi {
      f(WebTransportInitialMaxStreamsBidi(v));
    }
  }
}

impl<T> From<Settings> for Frame<T> {
  fn from(src: Settings) -> Frame<T> {
    Frame::Settings(src)
  }
}

impl fmt::Debug for Settings {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    let mut builder = f.debug_struct("Settings");
    builder.field("flags", &self.flags);

    self.for_each(|setting| match setting {
      Setting::EnablePush(v) => {
        builder.field("enable_push", &v);
      }
      Setting::HeaderTableSize(v) => {
        builder.field("header_table_size", &v);
      }
      Setting::InitialWindowSize(v) => {
        builder.field("initial_window_size", &v);
      }
      Setting::MaxConcurrentStreams(v) => {
        builder.field("max_concurrent_streams", &v);
      }
      Setting::MaxFrameSize(v) => {
        builder.field("max_frame_size", &v);
      }
      Setting::MaxHeaderListSize(v) => {
        builder.field("max_header_list_size", &v);
      }
      Setting::EnableConnectProtocol(v) => {
        builder.field("enable_connect_protocol", &v);
      }
      Setting::WebTransportEnabled(v) => {
        builder.field("webtransport_enabled", &v);
      }
      Setting::WebTransportInitialMaxData(v) => {
        builder.field("webtransport_initial_max_data", &v);
      }
      Setting::WebTransportInitialMaxStreamDataUni(v) => {
        builder.field("webtransport_initial_max_stream_data_uni", &v);
      }
      Setting::WebTransportInitialMaxStreamDataBidiLocal(v) => {
        builder.field("webtransport_initial_max_stream_data_bidi_local", &v);
      }
      Setting::WebTransportInitialMaxStreamsUni(v) => {
        builder.field("webtransport_initial_max_streams_uni", &v);
      }
      Setting::WebTransportInitialMaxStreamDataBidiRemote(v) => {
        builder.field("webtransport_initial_max_stream_data_bidi_remote", &v);
      }
      Setting::WebTransportInitialMaxStreamsBidi(v) => {
        builder.field("webtransport_initial_max_streams_bidi", &v);
      }
    });

    builder.finish()
  }
}

// ===== impl Setting =====

impl Setting {
  /// Creates a new `Setting` with the correct variant corresponding to the
  /// given setting id, based on the settings IDs defined in section
  /// 6.5.2.
  pub fn from_id(id: u16, val: u32) -> Option<Setting> {
    use self::Setting::*;

    match id {
      1 => Some(HeaderTableSize(val)),
      2 => Some(EnablePush(val)),
      3 => Some(MaxConcurrentStreams(val)),
      4 => Some(InitialWindowSize(val)),
      5 => Some(MaxFrameSize(val)),
      6 => Some(MaxHeaderListSize(val)),
      8 => Some(EnableConnectProtocol(val)),
      0x2b60 => Some(WebTransportEnabled(val)),
      0x2b61 => Some(WebTransportInitialMaxData(val)),
      0x2b62 => Some(WebTransportInitialMaxStreamDataUni(val)),
      0x2b63 => Some(WebTransportInitialMaxStreamDataBidiLocal(val)),
      0x2b64 => Some(WebTransportInitialMaxStreamsUni(val)),
      0x2b65 => Some(WebTransportInitialMaxStreamsBidi(val)),
      0x2b66 => Some(WebTransportInitialMaxStreamDataBidiRemote(val)),
      _ => None,
    }
  }

  /// Creates a new `Setting` by parsing the given buffer of 6 bytes, which
  /// contains the raw byte representation of the setting, according to the
  /// "SETTINGS format" defined in section 6.5.1.
  ///
  /// The `raw` parameter should have length at least 6 bytes, since the
  /// length of the raw setting is exactly 6 bytes.
  ///
  /// # Panics
  ///
  /// If given a buffer shorter than 6 bytes, the function will panic.
  fn load(raw: &[u8]) -> Option<Setting> {
    let id: u16 = (u16::from(raw[0]) << 8) | u16::from(raw[1]);
    let val: u32 = unpack_octets_4!(raw, 2, u32);

    Setting::from_id(id, val)
  }

  fn encode(&self, dst: &mut BytesMut) {
    use self::Setting::*;

    let (kind, val) = match *self {
      HeaderTableSize(v) => (1, v),
      EnablePush(v) => (2, v),
      MaxConcurrentStreams(v) => (3, v),
      InitialWindowSize(v) => (4, v),
      MaxFrameSize(v) => (5, v),
      MaxHeaderListSize(v) => (6, v),
      EnableConnectProtocol(v) => (8, v),
      WebTransportEnabled(v) => (0x2b60, v),
      WebTransportInitialMaxData(v) => (0x2b61, v),
      WebTransportInitialMaxStreamDataUni(v) => (0x2b62, v),
      WebTransportInitialMaxStreamDataBidiLocal(v) => (0x2b63, v),
      WebTransportInitialMaxStreamsUni(v) => (0x2b64, v),
      WebTransportInitialMaxStreamsBidi(v) => (0x2b65, v),
      WebTransportInitialMaxStreamDataBidiRemote(v) => (0x2b66, v),
    };

    dst.put_u16(kind);
    dst.put_u32(val);
  }
}

// ===== impl SettingsFlags =====

impl SettingsFlags {
  pub fn empty() -> SettingsFlags {
    SettingsFlags(0)
  }

  pub fn load(bits: u8) -> SettingsFlags {
    SettingsFlags(bits & ALL)
  }

  pub fn ack() -> SettingsFlags {
    SettingsFlags(ACK)
  }

  pub fn is_ack(&self) -> bool {
    self.0 & ACK == ACK
  }
}

impl From<SettingsFlags> for u8 {
  fn from(src: SettingsFlags) -> u8 {
    src.0
  }
}

impl fmt::Debug for SettingsFlags {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    util::debug_flags(f, self.0)
      .flag_if(self.is_ack(), "ACK")
      .finish()
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn webtransport_settings_round_trip_on_the_wire() {
    let webtransport = crate::webtransport::Settings {
      enabled: true,
      initial_max_data: Some(1),
      initial_max_stream_data_uni: Some(2),
      initial_max_stream_data_bidi_local: Some(3),
      initial_max_stream_data_bidi_remote: Some(4),
      initial_max_streams_uni: Some(5),
      initial_max_streams_bidi: Some(6),
    };
    let mut settings = Settings::default();
    settings.set_webtransport_settings(webtransport);

    let mut encoded = BytesMut::new();
    settings.encode(&mut encoded);
    assert_eq!(&encoded[9..11], &0x2b60u16.to_be_bytes());
    assert_eq!(&encoded[39..41], &0x2b66u16.to_be_bytes());
    assert_eq!(&encoded[45..47], &0x2b65u16.to_be_bytes());

    let decoded = Settings::load(
      Head::new(
        Kind::Settings,
        SettingsFlags::empty().into(),
        StreamId::zero(),
      ),
      &encoded[9..],
    )
    .unwrap();
    let mut applied = crate::webtransport::Settings::disabled();
    decoded.apply_webtransport_settings_to(&mut applied);
    assert_eq!(applied, webtransport);
  }

  #[test]
  fn webtransport_enabled_rejects_non_boolean_value() {
    let payload = [0x2b, 0x60, 0, 0, 0, 2];
    let error = Settings::load(
      Head::new(
        Kind::Settings,
        SettingsFlags::empty().into(),
        StreamId::zero(),
      ),
      &payload,
    )
    .unwrap_err();
    assert!(matches!(error, Error::InvalidSettingValue));
  }
}
