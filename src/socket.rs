use crate::Cow;
use crate::ebpf::BpfFilter;
use crate::{Filter, UniqueFilter};
use std::io;

use std::ffi::{OsStr, OsString};

use crate::netlink_msg::{UdevMsg, msg::Owned};

pub enum EventSource {
    Udev,
    Kernel,
}

pub struct Monitor<'a, 'c, S> {
    sock: neli::socket::NlSocket,
    filters: SocketFilters<'a>,
    ebpf_filter: BpfFilter,
    state: S,
    enumerate: Option<&'c crate::Udev>,
}

pub mod socket_state {
    use crate::{Device, device};
    pub struct Listening {
        pub(crate) enumerated:
            Option<std::vec::IntoIter<Device<device::instance::Owned, device::origin::Hotplug>>>,
    }
    pub struct Initalizing;
}

use crate::device;

#[derive(Default)]
struct SocketFilters<'a> {
    tags: UniqueFilter<'a>,
    subsystems: Filter<'a>,
}

impl crate::enumerate::EnumFilter for SocketFilters<'_> {
    fn matches_subsystem(&self, subsystem: &OsStr) -> bool {
        if !self.subsystems.contains(subsystem) {
            return self.subsystems.is_empty();
        }
        true
    }

    fn tags(&self) -> &UniqueFilter<'_> {
        &self.tags
    }
}

impl<'a, 'c> Monitor<'a, 'c, socket_state::Initalizing> {
    pub fn new() -> io::Result<Self> {
        use neli::{consts::socket::NlFamily, socket::NlSocket};
        let sock = NlSocket::new(NlFamily::KobjectUevent)?;
        sock.nonblock()?;

        Ok(Self {
            sock,
            filters: Default::default(),
            ebpf_filter: Default::default(),
            state: socket_state::Initalizing,
            enumerate: None,
        })
    }

    pub fn enumerate(&mut self, ctx: &'c crate::Udev) {
        self.enumerate = Some(ctx);
    }

    pub fn match_tag<T: Into<Cow<'a, OsStr>>>(
        &mut self,
        tag: T,
    ) -> io::Result<Option<Cow<'a, OsStr>>> {
        self.filters.tags.insert(tag)
    }

    pub fn match_subsystem<K: Into<Cow<'a, OsStr>>>(&mut self, key: K) -> io::Result<()> {
        self.filters.subsystems.insert(key, None::<OsString>)?;
        Ok(())
    }

    pub fn match_subsystem_devtype<K: Into<Cow<'a, OsStr>>>(
        &mut self,
        key: K,
        val: impl Into<Cow<'a, OsStr>>,
    ) -> io::Result<Option<Cow<'a, OsStr>>> {
        self.filters.subsystems.insert(key, Some(val))
    }

    pub fn attach_filters(&mut self) -> io::Result<()> {
        use std::os::fd::AsRawFd;
        self.ebpf_filter.attach(
            &self.filters.tags,
            &self.filters.subsystems,
            self.sock.as_raw_fd(),
        )
    }

    pub fn detatch_filters(&mut self) -> io::Result<()> {
        let filter = unsafe { core::mem::zeroed::<libc::sock_fprog>() };

        use std::os::fd::AsRawFd;
        let res = unsafe {
            libc::setsockopt(
                self.sock.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_ATTACH_FILTER,
                &filter as *const _ as _,
                core::mem::size_of::<libc::sock_fprog>() as _,
            )
        };

        if res < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    pub fn listen(
        self,
        source: Option<EventSource>,
    ) -> io::Result<Monitor<'a, 'c, socket_state::Listening>> {
        let Self {
            sock,
            filters,
            mut ebpf_filter,
            state: _,
            enumerate,
        } = self;

        let group = match source {
            None => 0,
            Some(EventSource::Udev) => 1,
            Some(EventSource::Kernel) => 2,
        };

        use neli::utils::Groups;
        let groups = Groups::new_bitmask(group);

        use std::os::fd::AsRawFd;
        ebpf_filter.attach(&filters.tags, &filters.subsystems, sock.as_raw_fd())?;

        // allow credentials to be sent in ancillary messages
        let passcred = true as libc::c_int;
        #[allow(clippy::fn_to_numeric_cast_with_truncation)]
        match unsafe {
            libc::setsockopt(
                sock.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PASSCRED,
                &passcred as *const _ as *const libc::c_void,
                core::mem::size_of::<libc::c_int> as _,
            )
        } {
            0 => (),
            _ => return Err(io::Error::last_os_error()),
        }

        sock.bind(None, groups)?;

        let enumerated = enumerate
            .map(|ctx| {
                crate::enumerate::FilteredDeviceIter::new(
                    crate::enumerate::DeviceIter::new(&filters, ctx)?,
                    &filters,
                    ctx,
                )
                .map(|res| res.map(|dev| dev.into_hotplug_event()))
                .collect::<io::Result<Vec<_>>>()
            })
            .transpose()?
            .map(|enumer| enumer.into_iter());

        Ok(Monitor {
            sock,
            filters,
            ebpf_filter,
            state: socket_state::Listening { enumerated },
            enumerate,
        })
    }
}

use crate::netlink_msg::MsgTy as RecvTy;

impl Monitor<'_, '_, socket_state::Listening> {
    pub fn recv_enum(
        &mut self,
    ) -> Option<crate::Device<device::instance::Owned, device::origin::Hotplug>> {
        self.state.enumerated.as_mut()?.next()
    }

    pub fn recv<'a>(&self, buf: &'a mut [u8]) -> RecvTy<'a, impl FnMut(&u8) -> bool> {
        let mut iov = unsafe { core::mem::zeroed::<libc::iovec>() };
        iov.iov_base = buf as *mut _ as *mut libc::c_void;
        iov.iov_len = buf.len() as _;
        let mut cred_msg = unsafe { core::mem::zeroed::<libc::ucred>() };

        let mut netlink_addr = unsafe { core::mem::zeroed::<libc::sockaddr_nl>() };

        let mut msghdr = unsafe { core::mem::zeroed::<libc::msghdr>() };

        msghdr.msg_iov = &mut iov;
        msghdr.msg_iovlen = 1;

        msghdr.msg_control = &mut cred_msg as *mut _ as *mut libc::c_void;
        msghdr.msg_controllen = core::mem::size_of::<libc::ucred>() as _;

        msghdr.msg_name = &mut netlink_addr as *mut _ as *mut libc::c_void;
        msghdr.msg_namelen = core::mem::size_of::<libc::sockaddr_nl>() as _;

        use std::os::fd::AsRawFd;
        let len = unsafe { libc::recvmsg(self.as_raw_fd(), &mut msghdr, 0) };

        if len < 0 {
            let err = io::Error::last_os_error();
            if matches!(err.kind(), io::ErrorKind::WouldBlock) {
                return Ok(None);
            } else {
                return Err(err);
            }
        }
        let bytes = &buf[..(len as _)];
        UdevMsg::new(bytes)
    }

    pub fn recv_owned(&self, buf: &mut [u8]) -> io::Result<Option<UdevMsg<Owned>>> {
        Ok(self.recv(buf)?.map(|msg| msg.to_owned()))
    }
}

impl std::os::fd::AsRawFd for Monitor<'_, '_, socket_state::Listening> {
    fn as_raw_fd(&self) -> i32 {
        self.sock.as_raw_fd()
    }
}
