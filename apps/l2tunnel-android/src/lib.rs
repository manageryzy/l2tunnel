//! Android wrapper staging crate. JNI and VpnService integration are planned.
/// Describes this scaffold without opening a device or accepting an FD.
pub fn implementation_status() -> &'static str {
    l2tunnel::IMPLEMENTATION_STATUS
}
