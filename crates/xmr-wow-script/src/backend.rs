pub trait Backend {}
#[cfg(feature = "stub-crypto")]
pub struct StubBackend;
#[cfg(feature = "stub-crypto")]
impl Backend for StubBackend {}
#[cfg(feature = "stub-crypto")]
pub struct AlwaysFailBackend;
#[cfg(feature = "stub-crypto")]
impl Backend for AlwaysFailBackend {}
