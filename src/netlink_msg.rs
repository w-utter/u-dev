use std::io;

#[repr(packed, C)]
pub(crate) struct UdevNetlinkHeader {
    pub(crate) prefix: [u8; 8],
    pub(crate) magic: u32,
    header_size: u32,
    properties_offset: u32,
    properties_len: u32,
    pub(crate) filter_subsystem_hash: u32,
    pub(crate) filter_devtype_hash: u32,
    pub(crate) filter_tag_bloom_hi: u32,
    pub(crate) filter_tag_bloom_lo: u32,
}

impl UdevNetlinkHeader {
    pub(crate) const MAGIC: u32 = 0xfeedcafe;
}

#[derive(Debug)]
pub struct UdevMsg<T> {
    pub(crate) inner: T,
}

pub use action::Action;
use std::ffi::{OsStr, OsString};

pub(crate) mod action {
    #[derive(Debug, Clone, Copy)]
    pub enum Action<T> {
        Add,
        Remove,
        Change,
        Online,
        Offline,
        Bind,
        Unbind,
        Other(T),
    }

    use std::ffi::{OsStr, OsString};

    impl<'a> Action<Borrowed<'a>> {
        pub(crate) fn new(buf: &'a [u8]) -> Self {
            use std::os::unix::ffi::OsStrExt;
            match buf {
                b"add" => Self::Add,
                b"remove" => Self::Remove,
                b"change" => Self::Change,
                b"online" => Self::Online,
                b"offline" => Self::Offline,
                b"bind" => Self::Bind,
                b"unbind" => Self::Unbind,
                _ => Self::Other(Borrowed(OsStr::from_bytes(buf))),
            }
        }

        pub(crate) fn to_owned(self) -> Action<Owned> {
            match self {
                Self::Add => Action::Add,
                Self::Remove => Action::Remove,
                Self::Change => Action::Change,
                Self::Online => Action::Online,
                Self::Offline => Action::Offline,
                Self::Bind => Action::Bind,
                Self::Unbind => Action::Unbind,
                Self::Other(Borrowed(str)) => Action::Other(Owned(str.to_os_string())),
            }
        }
    }

    #[derive(Debug, Clone, Copy)]
    pub struct Borrowed<'a>(&'a OsStr);
    #[derive(Debug, Clone)]
    pub struct Owned(OsString);

    impl Action<Owned> {
        pub(crate) fn as_ref(&self) -> Action<Borrowed<'_>> {
            match self {
                Self::Add => Action::Add,
                Self::Remove => Action::Remove,
                Self::Change => Action::Change,
                Self::Online => Action::Online,
                Self::Offline => Action::Offline,
                Self::Bind => Action::Bind,
                Self::Unbind => Action::Unbind,
                Self::Other(Owned(str)) => Action::Other(Borrowed(str.as_ref())),
            }
        }
    }
}

pub use tags::Tags;
pub(crate) mod tags {
    #[derive(Debug, Clone, Copy)]
    pub struct Tags<T> {
        pub(crate) inner: T,
    }

    use std::collections::BTreeSet;

    use core::fmt;
    use std::ffi::{OsStr, OsString};
    #[derive(Clone, Copy)]
    pub struct Borrowed<'a>(&'a [u8]);
    #[derive(Debug, Clone)]
    pub struct Owned(pub(crate) BTreeSet<OsString>);

    impl Owned {
        pub(crate) fn to_iter(&self) -> impl Iterator<Item = &OsStr> {
            self.0.iter().map(|tag| tag.as_ref())
        }
    }

    impl<'a> Borrowed<'a> {
        pub(crate) fn iter(&self) -> impl Iterator<Item = &'a OsStr> {
            use std::os::unix::ffi::OsStrExt;
            self.0
                .split(|&ch| ch == b':')
                .filter(|tag| !tag.is_empty())
                .map(OsStr::from_bytes)
        }
    }

    impl fmt::Debug for Borrowed<'_> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_list().entries(self.iter()).finish()
        }
    }

    impl<'a> Tags<Borrowed<'a>> {
        pub(crate) fn new(buf: &'a [u8]) -> Self {
            Self {
                inner: Borrowed(buf),
            }
        }

        pub fn iter(&self) -> impl Iterator<Item = &'a OsStr> {
            self.inner.iter()
        }

        pub(crate) fn to_owned(self) -> Tags<Owned> {
            let inner = Owned(self.iter().map(|tag| tag.to_os_string()).collect());
            Tags { inner }
        }
    }

    impl Tags<Owned> {
        pub fn iter(&self) -> impl Iterator<Item = &OsStr> {
            self.inner.to_iter()
        }
    }
}

pub use devlinks::Devlinks;
pub(crate) mod devlinks {
    #[derive(Debug, Clone, Copy)]
    pub struct Devlinks<T> {
        pub(crate) inner: T,
    }

    use core::fmt;

    impl fmt::Debug for Borrowed<'_> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_list().entries(self.iter()).finish()
        }
    }

    use std::collections::BTreeSet;
    use std::ffi::{OsStr, OsString};
    #[derive(Clone, Copy)]
    pub struct Borrowed<'a>(&'a [u8]);
    #[derive(Debug, Clone)]
    pub struct Owned(pub(crate) BTreeSet<OsString>);

    impl<'a> Borrowed<'a> {
        pub fn iter(&self) -> impl Iterator<Item = &'a OsStr> {
            use std::os::unix::ffi::OsStrExt;
            self.0
                .split(|&ch| ch == b' ')
                .filter(|link| !link.is_empty())
                .map(OsStr::from_bytes)
        }
    }

    impl Owned {
        pub fn iter(&self) -> impl Iterator<Item = &OsStr> {
            self.0.iter().map(|link| link.as_ref())
        }
    }

    impl<'a> Devlinks<Borrowed<'a>> {
        pub(crate) fn new(buf: &'a [u8]) -> Self {
            Self {
                inner: Borrowed(buf),
            }
        }

        pub fn iter(&self) -> impl Iterator<Item = &'a OsStr> {
            self.inner.iter()
        }

        pub(crate) fn to_owned(self) -> Devlinks<Owned> {
            let inner = Owned(self.iter().map(|link| link.to_os_string()).collect());
            Devlinks { inner }
        }
    }

    impl Devlinks<Owned> {
        pub fn iter(&self) -> impl Iterator<Item = &OsStr> {
            self.inner.iter()
        }
    }
}

use core::fmt;
use std::collections::BTreeMap;

pub mod msg {
    use super::*;

    pub struct Borrowed<'a, F: for<'b> FnMut(&'b u8) -> bool> {
        pub(crate) devpath: Option<&'a OsStr>,
        pub(crate) subsystem: Option<&'a OsStr>,
        pub(crate) devtype: Option<&'a OsStr>,
        pub(crate) devname: Option<&'a OsStr>,
        pub(crate) devlinks: Option<Devlinks<devlinks::Borrowed<'a>>>,
        pub(crate) tags: Option<Tags<tags::Borrowed<'a>>>,
        pub(crate) usec_initialized: Option<u64>,
        pub(crate) driver: Option<&'a OsStr>,
        pub(crate) action: Option<Action<action::Borrowed<'a>>>,
        pub(crate) major: Option<u64>,
        pub(crate) minor: Option<u64>,
        pub(crate) devpath_old: Option<&'a OsStr>,
        pub(crate) seqnum: Option<u64>,
        pub(crate) devnum: Option<u64>,
        pub(crate) if_index: Option<u64>,
        pub(crate) devmode: Option<u32>,
        kv_pairs: std::slice::Split<'a, u8, F>,
    }

    impl<'a, F: for<'b> FnMut(&'b u8) -> bool> Borrowed<'a, F> {
        pub(crate) fn new(kv_pairs: std::slice::Split<'a, u8, F>) -> Self {
            Self {
                devpath: None,
                subsystem: None,
                devtype: None,
                devname: None,
                devlinks: None,
                tags: None,
                usec_initialized: None,
                driver: None,
                action: None,
                major: None,
                minor: None,
                devpath_old: None,
                seqnum: None,
                devnum: None,
                if_index: None,
                devmode: None,
                kv_pairs,
            }
        }

        pub(crate) fn owned(self, additional_properties: BTreeMap<OsString, OsString>) -> Owned {
            let Self {
                devpath,
                subsystem,
                devtype,
                devname,
                devlinks,
                tags,
                usec_initialized,
                driver,
                action,
                major,
                minor,
                devpath_old,
                seqnum,
                devnum,
                if_index,
                devmode,
                kv_pairs: _,
            } = self;

            Owned {
                devpath: devpath.map(|p| p.to_os_string()),
                subsystem: subsystem.map(|p| p.to_os_string()),
                devtype: devtype.map(|t| t.to_os_string()),
                devname: devname.map(|n| n.to_os_string()),
                devlinks: devlinks.map(|d| d.to_owned()),
                tags: tags.map(|t| t.to_owned()),
                usec_initialized,
                driver: driver.map(|d| d.to_os_string()),
                action: action.map(|a| a.to_owned()),
                major,
                minor,
                devpath_old: devpath_old.map(|p| p.to_os_string()),
                seqnum,
                devnum,
                if_index,
                devmode,
                additional_properties,
            }
        }
    }

    #[derive(Debug)]

    pub struct Owned {
        pub(crate) devpath: Option<OsString>,
        pub(crate) subsystem: Option<OsString>,
        pub(crate) devtype: Option<OsString>,
        pub(crate) devname: Option<OsString>,
        pub(crate) devlinks: Option<Devlinks<devlinks::Owned>>,
        pub(crate) tags: Option<Tags<tags::Owned>>,
        pub(crate) usec_initialized: Option<u64>,
        pub(crate) driver: Option<OsString>,
        pub(crate) action: Option<Action<action::Owned>>,
        pub(crate) major: Option<u64>,
        pub(crate) minor: Option<u64>,
        pub(crate) devpath_old: Option<OsString>,
        pub(crate) seqnum: Option<u64>,
        pub(crate) devnum: Option<u64>,
        pub(crate) if_index: Option<u64>,
        pub(crate) devmode: Option<u32>,
        pub(crate) additional_properties: BTreeMap<OsString, OsString>,
    }

    impl<F: for<'b> FnMut(&'b u8) -> bool> fmt::Debug for Borrowed<'_, F> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("Borrowed")
                .field("devpath", &self.devpath)
                .field("subsystem", &self.subsystem)
                .field("devtype", &self.devtype)
                .field("devname", &self.devname)
                .field("devlinks", &self.devlinks)
                .field("tags", &self.tags)
                .field("usec_initialized", &self.usec_initialized)
                .field("driver", &self.driver)
                .field("action", &self.action)
                .field("major", &self.major)
                .field("minor", &self.minor)
                .field("devpath_old", &self.devpath_old)
                .field("seqnum", &self.seqnum)
                .field("devnum", &self.devnum)
                .field("if_index", &self.if_index)
                .field("devmode", &self.devmode)
                .finish()
        }
    }

    impl<F: for<'b> FnMut(&'b u8) -> bool> crate::private::Sealed for Borrowed<'_, F> {}

    impl<F: for<'b> FnMut(&'b u8) -> bool> Msg for Borrowed<'_, F> {
        fn devpath(&self) -> Option<&OsStr> {
            self.devpath
        }
        fn subsystem(&self) -> Option<&OsStr> {
            self.subsystem
        }
        fn devtype(&self) -> Option<&OsStr> {
            self.devtype
        }
        fn devlinks(&self) -> Option<impl Iterator<Item = &OsStr>> {
            self.devlinks.as_ref().map(|links| links.iter())
        }
        fn tags(&self) -> Option<impl Iterator<Item = &OsStr>> {
            self.tags.as_ref().map(|tags| tags.iter())
        }
        fn usec_initialized(&self) -> Option<u64> {
            self.usec_initialized
        }
        fn driver(&self) -> Option<&OsStr> {
            self.driver
        }
        fn action(&self) -> Option<Action<action::Borrowed<'_>>> {
            self.action
        }
        fn major(&self) -> Option<u64> {
            self.major
        }
        fn minor(&self) -> Option<u64> {
            self.minor
        }
        fn devpath_old(&self) -> Option<&OsStr> {
            self.devpath_old
        }
        fn seqnum(&self) -> Option<u64> {
            self.seqnum
        }
        fn devnum(&self) -> Option<u64> {
            self.devnum
        }
        fn if_index(&self) -> Option<u64> {
            self.if_index
        }
        fn devmode(&self) -> Option<u32> {
            self.devmode
        }
        fn devname(&self) -> Option<&OsStr> {
            self.devname
        }
    }

    impl crate::private::Sealed for Owned {}

    impl Msg for Owned {
        fn devpath(&self) -> Option<&OsStr> {
            self.devpath.as_ref().map(|p| p.as_ref())
        }
        fn subsystem(&self) -> Option<&OsStr> {
            self.subsystem.as_ref().map(|s| s.as_ref())
        }
        fn devtype(&self) -> Option<&OsStr> {
            self.devtype.as_ref().map(|d| d.as_ref())
        }
        fn devlinks(&self) -> Option<impl Iterator<Item = &OsStr>> {
            self.devlinks.as_ref().map(|links| links.iter())
        }
        fn tags(&self) -> Option<impl Iterator<Item = &OsStr>> {
            self.tags.as_ref().map(|tags| tags.iter())
        }
        fn usec_initialized(&self) -> Option<u64> {
            self.usec_initialized
        }
        fn driver(&self) -> Option<&OsStr> {
            self.driver.as_ref().map(|d| d.as_ref())
        }
        fn action(&self) -> Option<Action<action::Borrowed<'_>>> {
            self.action.as_ref().map(|a| a.as_ref())
        }
        fn major(&self) -> Option<u64> {
            self.major
        }
        fn minor(&self) -> Option<u64> {
            self.minor
        }
        fn devpath_old(&self) -> Option<&OsStr> {
            self.devpath_old.as_ref().map(|p| p.as_ref())
        }
        fn seqnum(&self) -> Option<u64> {
            self.seqnum
        }
        fn devnum(&self) -> Option<u64> {
            self.devnum
        }
        fn if_index(&self) -> Option<u64> {
            self.if_index
        }
        fn devmode(&self) -> Option<u32> {
            self.devmode
        }
        fn devname(&self) -> Option<&OsStr> {
            self.devname.as_ref().map(|p| p.as_ref())
        }
    }

    macro_rules! parse_from_int {
        ($t:ty, $buf:expr, $base:expr) => {{
            if $base == 10 {
                let Ok(num) = ::atoi_simd::parse::<$t>($buf) else {
                    continue;
                };
                num
            } else {
                let Ok(str) = std::str::from_utf8($buf) else {
                    continue;
                };
                let Ok(num) = <$t>::from_str_radix(str, $base) else {
                    continue;
                };
                num
            }
        }};
        ($t:ty, $buf:expr) => {{
            let Ok(num) = ::atoi_simd::parse::<$t>($buf) else {
                continue;
            };
            num
        }};
    }

    impl<'a, F: for<'b> FnMut(&'b u8) -> bool> Iterator for UdevMsg<msg::Borrowed<'a, F>> {
        type Item = (&'a OsStr, &'a OsStr);

        fn next(&mut self) -> Option<Self::Item> {
            let this = &mut self.inner;
            loop {
                let kv_pair = this.kv_pairs.next()?;

                if kv_pair.is_empty() {
                    continue;
                }

                let Some((k, v)) = kv_pair
                    .iter()
                    .position(|&ch| ch == b'=')
                    .map(|pos| (&kv_pair[..pos], &kv_pair[pos + 1..]))
                else {
                    println!("invalid kv pair");
                    continue;
                };

                use std::os::unix::ffi::OsStrExt;
                match k {
                    b"DEVPATH" => this.devpath = Some(OsStr::from_bytes(v)),
                    b"SUBSYSTEM" => this.subsystem = Some(OsStr::from_bytes(v)),
                    b"DEVTYPE" => this.devtype = Some(OsStr::from_bytes(v)),
                    b"DEVNAME" => this.devname = Some(OsStr::from_bytes(v)),
                    b"DEVLINKS" => this.devlinks = Some(Devlinks::new(v)),
                    b"TAGS" => this.tags = Some(Tags::new(v)),
                    b"USEC_INITIALIZED" => this.usec_initialized = Some(parse_from_int!(u64, v)),
                    b"DRIVER" => this.driver = Some(OsStr::from_bytes(v)),
                    b"ACTION" => this.action = Some(Action::new(v)),
                    b"MAJOR" => this.major = Some(parse_from_int!(u64, v)),
                    b"MINOR" => this.minor = Some(parse_from_int!(u64, v)),
                    b"DEVPATH_OLD" => this.devpath_old = Some(OsStr::from_bytes(v)),
                    b"SEQNUM" => this.seqnum = Some(parse_from_int!(u64, v)),
                    b"DEVNUM" => this.devnum = Some(parse_from_int!(u64, v)),
                    b"IFINDEX" => this.if_index = Some(parse_from_int!(u64, v)),
                    b"DEVMODE" => this.devmode = Some(parse_from_int!(u32, v, 8)),
                    _ => return Some((OsStr::from_bytes(k), OsStr::from_bytes(v))),
                }
            }
        }
    }
}

pub(crate) type MsgTy<'a, F> = io::Result<Option<UdevMsg<msg::Borrowed<'a, F>>>>;

impl UdevMsg<()> {
    pub fn new(mut bytes: &[u8]) -> MsgTy<'_, impl FnMut(&u8) -> bool> {
        if bytes.len() < 32 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid message length",
            ));
        }

        if matches!(&bytes[..8], b"libudev\0") {
            let msg = bytes.as_ptr() as *const UdevNetlinkHeader;
            let header = unsafe { &core::ptr::read_unaligned(msg) };

            let magic = header.magic;

            if magic != UdevNetlinkHeader::MAGIC.to_be() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "invalid message magic",
                ));
            }

            let offset = header.properties_offset as usize;
            if offset + 32 > bytes.len() {
                return Ok(None);
            }
            bytes = &bytes[offset..];
        } else {
            let Some(pos) = bytes.iter().position(|&ch| ch == b'\0') else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "invalid message header",
                ));
            };

            if pos < b"a@/d".len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "invalid message length",
                ));
            }

            const NEEDLE: &[u8] = b"@/";
            if !&bytes[..pos]
                .windows(NEEDLE.len())
                .any(|window| window == NEEDLE)
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "invalid message header",
                ));
            }
            bytes = &bytes[pos..];
        }

        Ok(Some(UdevMsg {
            inner: msg::Borrowed::new(bytes.split(|&ch| ch == b'\0')),
        }))
    }
}

impl<'a, F: for<'b> FnMut(&'b u8) -> bool> UdevMsg<msg::Borrowed<'a, F>> {
    // this is one time consumable.
    pub fn additional_properties(&mut self) -> impl Iterator<Item = (&'a OsStr, &'a OsStr)> {
        self
    }

    pub fn to_owned(mut self) -> UdevMsg<msg::Owned> {
        let additional_properties = self
            .additional_properties()
            .map(|(k, v)| (k.to_os_string(), v.to_os_string()))
            .collect();

        let Self { inner } = self;

        UdevMsg {
            inner: inner.owned(additional_properties),
        }
    }
}

pub trait Msg: crate::private::Sealed {
    fn devpath(&self) -> Option<&OsStr>;
    fn subsystem(&self) -> Option<&OsStr>;
    fn devtype(&self) -> Option<&OsStr>;
    fn devlinks(&self) -> Option<impl Iterator<Item = &OsStr>>;
    fn tags(&self) -> Option<impl Iterator<Item = &OsStr>>;
    fn usec_initialized(&self) -> Option<u64>;
    fn driver(&self) -> Option<&OsStr>;
    fn action(&self) -> Option<Action<action::Borrowed<'_>>>;
    fn major(&self) -> Option<u64>;
    fn minor(&self) -> Option<u64>;
    fn devpath_old(&self) -> Option<&OsStr>;
    fn seqnum(&self) -> Option<u64>;
    fn devnum(&self) -> Option<u64>;
    fn if_index(&self) -> Option<u64>;
    fn devmode(&self) -> Option<u32>;
    fn devname(&self) -> Option<&OsStr>;
}

impl<T: Msg> UdevMsg<T> {
    pub fn devpath(&self) -> Option<&OsStr> {
        self.inner.devpath()
    }
    pub fn subsystem(&self) -> Option<&OsStr> {
        self.inner.subsystem()
    }
    pub fn devtype(&self) -> Option<&OsStr> {
        self.inner.devtype()
    }
    pub fn devlinks(&self) -> Option<impl Iterator<Item = &OsStr>> {
        self.inner.devlinks()
    }
    pub fn tags(&self) -> Option<impl Iterator<Item = &OsStr>> {
        self.inner.tags()
    }
    pub fn usec_initialized(&self) -> Option<u64> {
        self.inner.usec_initialized()
    }
    pub fn driver(&self) -> Option<&OsStr> {
        self.inner.driver()
    }
    pub fn action(&self) -> Option<Action<action::Borrowed>> {
        self.inner.action()
    }
    pub fn major(&self) -> Option<u64> {
        self.inner.major()
    }
    pub fn minor(&self) -> Option<u64> {
        self.inner.minor()
    }
    pub fn devpath_old(&self) -> Option<&OsStr> {
        self.inner.devpath_old()
    }
    pub fn seqnum(&self) -> Option<u64> {
        self.inner.seqnum()
    }
    pub fn devnum(&self) -> Option<u64> {
        self.inner.devnum()
    }
    pub fn if_index(&self) -> Option<u64> {
        self.inner.if_index()
    }
    pub fn devmode(&self) -> Option<u32> {
        self.inner.devmode()
    }
    pub fn devname(&self) -> Option<&OsStr> {
        self.inner.devname()
    }
}

impl UdevMsg<msg::Owned> {
    pub fn additional_properties(&self) -> &BTreeMap<OsString, OsString> {
        &self.inner.additional_properties
    }
}
