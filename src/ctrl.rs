use crate::Udev;
use std::io;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path;

pub struct Ctrl {
    socket: UnixListener,
}

impl Ctrl {
    pub fn new(ctx: &Udev) -> io::Result<Self> {
        let mut path = path::PathBuf::from(ctx.run_path());
        path.push("connect");

        let socket = UnixListener::bind(path)?;
        socket.set_nonblocking(true)?;

        Ok(Ctrl { socket })
    }

    pub fn connection(&self) -> io::Result<Option<CtrlSocket>> {
        let conn = match self.socket.accept() {
            Ok((stream, _)) => stream,
            Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock) => return Ok(None),
            Err(e) => return Err(e),
        };

        conn.set_nonblocking(true)?;

        //FIXME: check credentials of socket

        Ok(Some(CtrlSocket { stream: conn }))
    }
}

pub struct CtrlSocket {
    stream: UnixStream,
}

impl CtrlSocket {
    pub fn recv(&mut self) -> io::Result<Option<CtrlMsg>> {
        let mut ctrl_msg_wire = unsafe { core::mem::zeroed::<CtrlWireMsg>() };

        let mut iov = unsafe { core::mem::zeroed::<libc::iovec>() };
        iov.iov_base = &mut ctrl_msg_wire as *mut _ as *mut libc::c_void;
        iov.iov_len = core::mem::size_of::<CtrlWireMsg>() as _;
        let mut cred_msg = unsafe { core::mem::zeroed::<libc::ucred>() };

        let mut msghdr = unsafe { core::mem::zeroed::<libc::msghdr>() };

        msghdr.msg_iov = &mut iov;
        msghdr.msg_iovlen = 1;

        msghdr.msg_control = &mut cred_msg as *mut _ as *mut libc::c_void;
        msghdr.msg_controllen = core::mem::size_of::<libc::ucred>() as _;

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

        //FIXME: check ucred ancillary

        if ctrl_msg_wire.magic != CtrlWireMsg::MAGIC {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "bad message magic",
            ));
        }
        Ok(Some(CtrlMsg::from_wire(ctrl_msg_wire)))
    }

    pub fn send(&mut self, msg: CtrlMsg) -> io::Result<()> {
        let mut version = [0; 16];

        const VERSION: &[u8] = b"";

        let (v, _) = version.split_at_mut(VERSION.len());
        v.copy_from_slice(VERSION);

        let mut ctrl_msg = CtrlWireMsg {
            version,
            magic: CtrlWireMsg::MAGIC,
            ..unsafe { core::mem::zeroed() }
        };

        match msg {
            CtrlMsg::LogLevel(i) => {
                ctrl_msg.ty = CtrlWireMsgType::SetLogLevel;
                ctrl_msg.variants.intval = i as _;
            }
            CtrlMsg::StopExecQueue => ctrl_msg.ty = CtrlWireMsgType::StopExecQueue,
            CtrlMsg::StartExecQueue => ctrl_msg.ty = CtrlWireMsgType::StartExecQueue,
            CtrlMsg::Reload => ctrl_msg.ty = CtrlWireMsgType::Reload,
            CtrlMsg::SetEnv(buf) => {
                ctrl_msg.ty = CtrlWireMsgType::SetEnv;
                ctrl_msg.variants.buf = buf;
            }
            CtrlMsg::MaxChildren(i) => {
                ctrl_msg.ty = CtrlWireMsgType::SetChildrenMax;
                ctrl_msg.variants.intval = i as _;
            }
            CtrlMsg::Ping => ctrl_msg.ty = CtrlWireMsgType::Ping,
            CtrlMsg::Exit => ctrl_msg.ty = CtrlWireMsgType::Exit,
            CtrlMsg::Unknown => ctrl_msg.ty = CtrlWireMsgType::Unknown,
        }

        use std::os::fd::AsRawFd;
        let res = unsafe {
            libc::write(
                self.as_raw_fd(),
                &ctrl_msg as *const _ as *const libc::c_void,
                core::mem::size_of::<CtrlWireMsg>(),
            )
        };
        if res < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

#[allow(clippy::large_enum_variant)]
pub enum CtrlMsg {
    LogLevel(u32),
    StopExecQueue,
    StartExecQueue,
    Reload,
    SetEnv([u8; 256]),
    MaxChildren(u32),
    Ping,
    Exit,
    Unknown,
}

impl CtrlMsg {
    fn from_wire(msg: CtrlWireMsg) -> Self {
        unsafe {
            match msg.ty {
                CtrlWireMsgType::SetLogLevel => Self::LogLevel(msg.variants.intval as _),
                CtrlWireMsgType::StopExecQueue => Self::StopExecQueue,
                CtrlWireMsgType::StartExecQueue => Self::StartExecQueue,
                CtrlWireMsgType::Reload => Self::Reload,
                CtrlWireMsgType::SetEnv => Self::SetEnv(msg.variants.buf),
                CtrlWireMsgType::SetChildrenMax => Self::MaxChildren(msg.variants.intval as _),
                CtrlWireMsgType::Ping => Self::Ping,
                CtrlWireMsgType::Exit => Self::Exit,
                _ => Self::Unknown,
            }
        }
    }
}

impl std::os::fd::AsRawFd for CtrlSocket {
    fn as_raw_fd(&self) -> i32 {
        self.stream.as_raw_fd()
    }
}

#[repr(C, packed)]
struct CtrlWireMsg {
    version: [u8; 16],
    magic: u32,
    ty: CtrlWireMsgType,
    variants: CtrlWireMsgVariants,
}

impl CtrlWireMsg {
    const MAGIC: u32 = 0xdead1dea;
}

union CtrlWireMsgVariants {
    intval: i32,
    buf: [u8; 256],
}

enum CtrlWireMsgType {
    Unknown = 0,
    SetLogLevel = 1,
    StopExecQueue = 2,
    StartExecQueue = 3,
    Reload = 4,
    SetEnv = 5,
    SetChildrenMax = 6,
    Ping = 7,
    Exit = 8,
}
