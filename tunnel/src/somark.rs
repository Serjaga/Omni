
use socket2::SockRef;
use std::io;

#[derive(Copy, Clone, Debug)]
#[repr(transparent)]
pub struct SoMark {
    #[cfg(target_os = "linux")]
    inner: Option<u32>,
}

impl SoMark {
    #[cfg_attr(not(target_os = "linux"), expect(unused_variables))]
    pub fn new(so_mark: Option<u32>) -> Self {
        SoMark { #[cfg(target_os = "linux")] inner: so_mark }
    }

    #[cfg(not(target_os = "linux"))]
    #[inline]
    pub fn set_mark(self, _: SockRef) -> Result<(), std::convert::Infallible> { Ok(()) }

    #[cfg(target_os = "linux")]
    #[inline]
    pub fn set_mark(self, socket: SockRef) -> io::Result<()> {
        let Some(so_mark) = self.inner else { return Ok(()) };
        socket.set_mark(so_mark).map_err(|_| io::Error::last_os_error())
    }
}
