//! A single selected actual header owner; no parallel context or codec algorithm.
use super::*;
#[derive(Clone)]
pub(super) enum EncoderHeader {
    Ethernet(HeaderEncoder),
    Ip(tcp_header::IpHeaderEncoder),
}
impl EncoderHeader {
    pub fn new(maximum: usize, ip: bool) -> Result<Self, tcp_header::Error> {
        Ok(if ip {
            Self::Ip(tcp_header::IpHeaderEncoder::new(maximum)?)
        } else {
            Self::Ethernet(HeaderEncoder::new(HeaderProfile::TcpDelta, maximum)?)
        })
    }
    pub fn encode(&mut self, bytes: &[u8], output: &mut [u8]) -> Result<usize, tcp_header::Error> {
        match self {
            Self::Ethernet(header) => header.encode(bytes, output),
            Self::Ip(header) => header.encode(bytes, output),
        }
    }
    pub fn view(&self) -> Option<tcp_header::ContextView<'_>> {
        match self {
            Self::Ethernet(header) => header.context_view(),
            Self::Ip(header) => header.context_view(),
        }
    }
    pub fn delta_tag(&self) -> u8 {
        match self {
            Self::Ethernet(_) => 3,
            Self::Ip(_) => 9,
        }
    }
    pub fn max_encoded_len(&self) -> usize {
        match self {
            Self::Ethernet(header) => header.max_encoded_len(),
            Self::Ip(header) => header.max_encoded_len(),
        }
    }
    pub fn has_context(&self) -> bool {
        self.view().is_some()
    }
    pub fn reset(&mut self) {
        match self {
            Self::Ethernet(header) => header.reset(),
            Self::Ip(header) => header.reset(),
        }
    }
    #[cfg(test)]
    pub fn context(&self) -> Option<&[u8; tcp_header::CONTEXT_BYTES]> {
        match self {
            Self::Ethernet(header) => header.context(),
            Self::Ip(_) => None,
        }
    }
}
#[derive(Clone)]
pub(crate) enum DecoderState {
    Ethernet(HeaderDecoder),
    Ip(tcp_header::IpHeaderDecoder),
}
impl DecoderState {
    pub fn new(maximum: usize, ip: bool) -> Result<Self, tcp_header::Error> {
        Ok(if ip {
            Self::Ip(tcp_header::IpHeaderDecoder::new(maximum)?)
        } else {
            Self::Ethernet(HeaderDecoder::new(maximum)?)
        })
    }
    pub fn decode_next(
        &mut self,
        bytes: &[u8],
        output: &mut [u8],
    ) -> Result<tcp_header::Decoded, tcp_header::Error> {
        match self {
            Self::Ethernet(header) => header.decode_next(bytes, output),
            Self::Ip(header) => header.decode_next(bytes, output),
        }
    }
    pub fn view(&self) -> Option<tcp_header::ContextView<'_>> {
        match self {
            Self::Ethernet(header) => header.context_view(),
            Self::Ip(header) => header.context_view(),
        }
    }
    pub fn delta_tag(&self) -> u8 {
        match self {
            Self::Ethernet(_) => 3,
            Self::Ip(_) => 9,
        }
    }
    pub fn has_context(&self) -> bool {
        self.view().is_some()
    }
    pub fn reset(&mut self) {
        match self {
            Self::Ethernet(header) => header.reset(),
            Self::Ip(header) => header.reset(),
        }
    }
    #[cfg(test)]
    pub fn context(&self) -> Option<&[u8; tcp_header::CONTEXT_BYTES]> {
        match self {
            Self::Ethernet(header) => header.context(),
            Self::Ip(_) => None,
        }
    }
}
