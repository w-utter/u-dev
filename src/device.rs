macro_rules! parse_from_int {
    ($t:ty, $buf:expr, $base:expr) => {{
        let buf = $buf.as_encoded_bytes();
        if $base == 10 {
            let Ok(num) = ::atoi_simd::parse::<$t>(buf) else {
                return Ok(());
            };
            num
        } else {
            let Ok(str) = std::str::from_utf8(buf) else {
                return Ok(());
            };
            let Ok(num) = <$t>::from_str_radix(str, $base) else {
                return Ok(());
            };
            num
        }
    }};
    ($t:ty, $buf:expr) => {{
        let buf = $buf.as_encoded_bytes();
        let Ok(num) = ::atoi_simd::parse::<$t>(buf) else {
            return Ok(());
        };
        num
    }};
}

macro_rules! get_field {
    ($this:expr, $field:expr) => {{
        match $field {
            Some(_) => (),
            None => {
                $this.try_update_from_uevent_file()?;
            }
        }
        Ok($field)
    }};

    ($this:expr, $field:expr, $ctx:expr, $uevent:expr) => {{
        match $field {
            Some(_) => (),
            None => {
                if $uevent {
                    $this.try_update_from_uevent_file()?;
                }
                $this.try_update_from_hw_db($ctx)?;
            }
        }
        Ok($field)
    }};
    ($this:expr, $field:expr, $ctx:expr) => {
        get_field!($this, $field, $ctx, false)
    };
}

use crate::Udev;
use std::ffi::OsString;

pub(crate) mod dev {
    use crate::Cow;
    use crate::DevKind;
    use crate::Udev;
    use crate::Watch;
    use crate::netlink_msg;
    use std::collections::{BTreeMap, BTreeSet};
    use std::ffi::{OsStr, OsString};
    use std::path;

    pub mod origin {
        #[derive(Debug)]
        pub struct Enumerate;
        #[derive(Debug)]
        pub struct Hotplug;
    }

    impl crate::private::Sealed for Enumerate {}

    impl<K> Extra<K> for Enumerate {
        type Output = ();
        type Borrowed<'a> = ();
        type Owned = ();
        fn to_owned(_: &Self::Output) -> Self::Owned {}
        fn as_ref(_: &Self::Output) -> Self::Borrowed<'_> {}
        fn update_from_property(_: &mut Self::Output, _: &OsStr, _: &OsStr) -> bool {
            false
        }
    }

    impl crate::private::Sealed for Hotplug {}

    impl Extra<Owned> for Hotplug {
        type Output = Option<netlink_msg::Action<netlink_msg::action::Owned>>;
        type Borrowed<'a> = Option<netlink_msg::Action<netlink_msg::action::Borrowed<'a>>>;
        type Owned = Option<netlink_msg::Action<netlink_msg::action::Owned>>;
        fn to_owned(this: &Self::Output) -> Self::Owned {
            this.clone()
        }
        fn as_ref(this: &Self::Output) -> Self::Borrowed<'_> {
            this.as_ref().map(|a| a.as_ref())
        }

        fn update_from_property(this: &mut Self::Output, key: &OsStr, val: &OsStr) -> bool {
            if this.is_none() && matches!(key.as_encoded_bytes(), b"ACTION") {
                let action = netlink_msg::Action::new(val.as_encoded_bytes());
                *this = Some(action.to_owned());
                true
            } else {
                false
            }
        }
    }

    #[derive(Debug)]
    pub enum Action<'a> {
        Owned(netlink_msg::Action<netlink_msg::action::Owned>),
        Borrowed(netlink_msg::Action<netlink_msg::action::Borrowed<'a>>),
    }

    impl<'b> Extra<Borrowed<'b>> for Hotplug {
        type Output = Option<Action<'b>>;
        type Borrowed<'a> = Option<netlink_msg::Action<netlink_msg::action::Borrowed<'a>>>;
        type Owned = Option<netlink_msg::Action<netlink_msg::action::Owned>>;

        fn to_owned(this: &Self::Output) -> Self::Owned {
            this.as_ref().map(|action| match action {
                Action::Owned(o) => o.clone(),
                Action::Borrowed(b) => (*b).to_owned(),
            })
        }

        fn as_ref(this: &Self::Output) -> Self::Borrowed<'_> {
            this.as_ref().map(|action| match action {
                Action::Owned(o) => o.as_ref(),
                Action::Borrowed(b) => *b,
            })
        }

        fn update_from_property(this: &mut Self::Output, key: &OsStr, val: &OsStr) -> bool {
            if this.is_none() && matches!(key.as_encoded_bytes(), b"ACTION") {
                let action = netlink_msg::Action::new(val.as_encoded_bytes());
                *this = Some(Action::Owned(action.to_owned()));
                true
            } else {
                false
            }
        }
    }

    #[derive(Debug)]
    pub struct Device<D, K: Extra<D>> {
        if_index: Option<u64>,
        devnum: Option<u64>,
        devmode: Option<u32>,
        devlink_priority: Option<i32>,

        usec_initialized: Option<u64>,

        watch_handle: Option<i32>,
        seqnum: Option<u64>,

        parent: Option<Option<Box<Device<Owned, Enumerate>>>>,

        database_version: Option<u32>,

        uevent_read: bool,
        hw_db_read: bool,

        initialized: bool,
        watch: Option<Watch>,
        id_filename: Option<OsString>,

        sysattrs: Option<BTreeMap<OsString, OsString>>,

        sysnum: Option<Option<u32>>,

        inner: D,
        extra: K::Output,
    }

    impl<D: DevImpl, K: Extra<D>> Device<D, K> {
        pub fn devpath(&self, ctx: &Udev) -> &path::Path {
            self.inner.devpath(ctx)
        }

        pub fn subsystem(&mut self, ctx: &Udev) -> io::Result<&OsStr> {
            match self.inner.subsystem() {
                Some(_) => (),
                None => {
                    let subsys = self.inner.search_subsystem(ctx)?;
                    self.inner.set_subsystem(subsys);
                }
            }
            Ok(self.inner.subsystem().unwrap())
        }

        pub fn sysname(&mut self, ctx: &Udev) -> &OsStr {
            let devpath = self.devpath(ctx);
            let mut devpath_components = devpath.components();
            let _ = devpath_components.next();
            let sysname = devpath_components.next();
            sysname.map(|sn| sn.as_os_str()).unwrap_or_default()
        }

        fn try_update_from_uevent_file(&mut self) -> io::Result<()> {
            if self.uevent_read {
                return Ok(());
            }

            let mut minor = None;
            let mut major = None;
            self.inner.read_uevent(|this, k, v| {
                match k.as_encoded_bytes() {
                    b"MAJOR" => major = Some(parse_from_int!(u32, v)),
                    b"MINOR" => minor = Some(parse_from_int!(u32, v)),
                    b"SEQNUM" => self.seqnum = Some(parse_from_int!(u64, v)),
                    b"DEVNUM" => self.devnum = Some(parse_from_int!(u64, v)),
                    b"IFINDEX" => self.if_index = Some(parse_from_int!(u64, v)),
                    b"DEVMODE" => self.devmode = Some(parse_from_int!(u32, v, 8)),
                    _ if K::update_from_property(&mut self.extra, k, v) => (),
                    _ => this.update_from_uevent(k, v)?,
                }
                Ok(())
            })?;

            if let Some(devnum) = match (major, minor) {
                (Some(maj), Some(min)) => Some(libc::makedev(maj, min)),
                (Some(maj), None) => Some(libc::makedev(maj, 0)),
                (None, Some(min)) => Some(libc::makedev(0, min)),
                _ => None,
            } {
                self.devnum = Some(devnum);
            }

            self.uevent_read = true;
            Ok(())
        }

        /// reads the uevent file line by line, seperating key=value pairs
        pub fn uevent_entries(
            &mut self,
            mut f: impl FnMut(&OsStr, &OsStr) -> io::Result<()>,
        ) -> io::Result<()> {
            self.inner.read_uevent(|_, k, v| f(k, v))
        }

        pub fn id_filename(&mut self, ctx: &Udev) -> io::Result<&OsStr> {
            match self.id_filename.as_ref() {
                Some(_) => (),
                None => {
                    let id = if let Some(devnum) = self.devnum()? {
                        let subsystem = self.subsystem(ctx)?;

                        let kind = match subsystem.as_encoded_bytes() {
                            b"block" => "b",
                            _ => "c",
                        };
                        let major = libc::major(devnum);
                        let minor = libc::minor(devnum);

                        use std::fmt::Write;
                        let mut id = OsString::from(kind);
                        write!(id, "{major}:{minor}").map_err(|_| {
                            io::Error::new(
                                io::ErrorKind::OutOfMemory,
                                "could not format block/character id",
                            )
                        })?;

                        id
                    } else if let Some(if_index) = self.if_index()? {
                        let mut id = OsString::from("n");

                        use std::fmt::Write;
                        write!(id, "{if_index}").map_err(|_| {
                            io::Error::new(io::ErrorKind::OutOfMemory, "could not format net id")
                        })?;

                        id
                    } else {
                        let subsystem = self.subsystem(ctx)?;
                        let mut module = OsString::from("+");
                        module.push(subsystem);
                        module.push(":");

                        let sysname = self.sysname(ctx);
                        module.push(sysname);
                        module
                    };
                    self.id_filename = Some(id);
                }
            }
            Ok(self.id_filename.as_ref().unwrap())
        }

        pub fn syspath(&self) -> &path::Path {
            self.inner.syspath()
        }

        pub fn sysattrs(&mut self) -> io::Result<&BTreeMap<OsString, OsString>> {
            match self.sysattrs.as_ref() {
                Some(_) => (),
                None => {
                    let mut sysattrs = BTreeMap::new();

                    let syspath = self.syspath();
                    for entry in fs::read_dir(syspath)? {
                        let entry = entry?;
                        let ty = entry.file_type()?;

                        let path = entry.path();
                        use std::os::linux::fs::MetadataExt;

                        let path = if ty.is_symlink() {
                            fs::canonicalize(&path)?
                        } else if ty.is_file() {
                            path
                        } else {
                            continue;
                        };

                        if matches!(
                            path.file_name().map(|f| f.as_encoded_bytes()),
                            Some(b"uevent")
                        ) {
                            continue;
                        }

                        let metadata = fs::metadata(&path)?;

                        use std::os::unix::fs::MetadataExt as MDE2;
                        if !metadata.file_type().is_file()
                            || metadata.st_mode() & (libc::S_IRUSR | libc::S_IROTH)
                                != libc::S_IRUSR | libc::S_IROTH
                            || metadata.mode() & (libc::S_IRUSR | libc::S_IROTH)
                                != libc::S_IRUSR | libc::S_IROTH
                        {
                            continue;
                        }

                        let mut file = fs::OpenOptions::new().read(true).open(&path)?;
                        use std::io::Read;
                        let mut buf = Vec::new();
                        if file.read_to_end(&mut buf).is_err() {
                            // there are a couple of files that have the correct
                            // permissions but still cannot be read
                            continue;
                        };

                        let _ = buf.pop();

                        use std::os::unix::ffi::OsStringExt;
                        let key = entry.file_name();
                        let value = OsString::from_vec(buf);
                        sysattrs.insert(key, value);
                    }
                    self.sysattrs = Some(sysattrs);
                }
            }
            Ok(self.sysattrs.as_ref().unwrap())
        }

        pub fn sysattr(&mut self, attr: &OsStr) -> io::Result<Option<&OsStr>> {
            let attrs = self.sysattrs()?;
            Ok(attrs.get(attr).map(|val| &**val))
        }

        pub fn sysnum(&mut self) -> Option<u32> {
            match self.sysnum {
                Some(_) => (),
                None => {
                    let syspath = self.syspath().as_os_str().as_encoded_bytes();

                    if let Some(pos) = syspath.iter().rposition(|ch| !ch.is_ascii_digit()) {
                        if pos == 0 {
                            self.sysnum = Some(None)
                        } else {
                            self.sysnum = Some(::atoi_simd::parse::<u32>(&syspath[pos..]).ok())
                        }
                    } else {
                        self.sysnum = Some(None);
                    }
                }
            }
            self.sysnum.unwrap()
        }

        pub fn if_index(&mut self) -> io::Result<Option<u64>> {
            get_field!(self, self.if_index)
        }

        pub fn devnum(&mut self) -> io::Result<Option<u64>> {
            get_field!(self, self.devnum)
        }

        pub fn devmode(&mut self) -> io::Result<Option<u32>> {
            get_field!(self, self.devmode)
        }

        pub fn devlink_priority(&mut self, ctx: &Udev) -> io::Result<Option<i32>> {
            get_field!(self, self.devlink_priority, ctx, true)
        }

        pub fn usec_initalized(&mut self, ctx: &Udev) -> io::Result<Option<u64>> {
            get_field!(self, self.usec_initialized, ctx, true)
        }

        pub fn seqnum(&mut self) -> io::Result<Option<u64>> {
            get_field!(self, self.seqnum)
        }

        pub fn hw_db_version(&mut self, ctx: &Udev) -> io::Result<Option<u32>> {
            get_field!(self, self.database_version, ctx)
        }

        pub fn properties(
            &mut self,
            ctx: &Udev,
        ) -> io::Result<Option<&BTreeMap<OsString, OsString>>> {
            if self.inner.properties().is_some() {
                self.try_update_from_uevent_file()?;
                self.try_update_from_hw_db(ctx)?;
            }
            Ok(self.inner.properties())
        }

        pub fn devname(&mut self) -> io::Result<Option<&OsStr>> {
            get_field!(self, self.inner.devname())
        }

        pub fn devnode(&mut self) -> io::Result<Option<&OsStr>> {
            self.devname()
        }

        pub fn tags(&mut self, ctx: &Udev) -> io::Result<impl Iterator<Item = &OsStr>> {
            let tags = self.inner.tags();
            if tags.is_none() {
                drop(tags);
                self.try_update_from_hw_db(ctx)?;
            }

            Ok(self.inner.tags().into_iter().flatten())
        }

        pub fn driver(&mut self) -> io::Result<Option<&OsStr>> {
            get_field!(self, self.inner.driver())
        }

        pub fn devpath_old(&mut self) -> io::Result<Option<&OsStr>> {
            get_field!(self, self.inner.devpath_old())
        }

        fn hw_db_path(&mut self, ctx: &Udev) -> io::Result<path::PathBuf> {
            let mut path = path::PathBuf::from(ctx.run_path());
            path.push("data");
            let file_id = self.id_filename(ctx)?;
            path.push(file_id);
            Ok(path)
        }

        pub fn is_initalized(&mut self, ctx: &Udev) -> io::Result<bool> {
            if self.hw_db_read {
                return Ok(true);
            }

            let path = self.hw_db_path(ctx)?;
            std::fs::exists(path)
        }

        fn read_hw_db(
            &mut self,
            ctx: &Udev,
            mut f: impl FnMut(&mut Self, &OsStr, &OsStr) -> io::Result<()>,
        ) -> io::Result<bool> {
            let path = self.hw_db_path(ctx)?;

            let mut file = match fs::OpenOptions::new().read(true).open(&path) {
                Ok(file) => file,
                Err(e) if matches!(e.kind(), io::ErrorKind::NotFound) => return Ok(false),
                Err(e) => return Err(e),
            };

            use std::io::Read;
            let mut buf = Vec::new();
            file.read_to_end(&mut buf)?;

            for line in buf.split(|&ch| ch == b'\n').filter(|line| !line.is_empty()) {
                let Some((kind, val)) = line
                    .iter()
                    .position(|&ch| ch == b':')
                    .map(|pos| (&line[..pos], &line[pos + 1..]))
                else {
                    println!("invalid key:value pair");
                    continue;
                };

                use std::os::unix::ffi::OsStrExt;
                f(self, OsStr::from_bytes(kind), OsStr::from_bytes(val))?;
            }
            Ok(true)
        }

        /// reads the hw db file line by line, seperating key:value pairs
        pub fn hw_db_entries(
            &mut self,
            ctx: &Udev,
            mut f: impl FnMut(&OsStr, &OsStr) -> io::Result<()>,
        ) -> io::Result<()> {
            self.read_hw_db(ctx, |_, k, v| f(k, v))?;
            Ok(())
        }

        fn try_update_from_hw_db(&mut self, ctx: &Udev) -> io::Result<()> {
            if self.hw_db_read {
                return Ok(());
            }

            let mut minor = None;
            let mut major = None;

            self.initialized = self.read_hw_db(ctx, |this, k, val| {
                match k.as_encoded_bytes() {
                    b"S" => {
                        let mut devlink = path::PathBuf::from(ctx.dev_path());
                        devlink.push(val);
                        this.inner.add_devlink(devlink.into())?;
                    }
                    b"L" => {
                        // devlink priority
                        this.devlink_priority = Some(parse_from_int!(i32, val));
                    }
                    b"E" => {
                        // property from string
                        let val = val.as_encoded_bytes();
                        use std::os::unix::ffi::OsStrExt;
                        let Some((k, v)) = val.iter().position(|&ch| ch == b'=').map(|pos| {
                            (
                                OsStr::from_bytes(&val[..pos]),
                                OsStr::from_bytes(&val[pos + 1..]),
                            )
                        }) else {
                            println!("invalid kv pair");
                            return Ok(());
                        };

                        match k.as_encoded_bytes() {
                            // NOTE: none of these should happen
                            b"DEVPATH" | b"ACTION" | b"DEVLINKS" | b"TAGS" => panic!(),
                            b"USEC_INITIALIZED" => {
                                this.usec_initialized = Some(parse_from_int!(u64, v))
                            }
                            b"MAJOR" => major = Some(parse_from_int!(u32, v)),
                            b"MINOR" => minor = Some(parse_from_int!(u32, v)),
                            b"SEQNUM" => this.seqnum = Some(parse_from_int!(u64, v)),
                            b"DEVNUM" => this.devnum = Some(parse_from_int!(u64, v)),
                            b"IFINDEX" => this.if_index = Some(parse_from_int!(u64, v)),
                            b"DEVMODE" => this.devmode = Some(parse_from_int!(u32, v, 8)),
                            _ => this.inner.update_from_uevent(k, v)?,
                        }
                    }
                    // any tag or current tag
                    b"G" | b"Q" => {
                        // tag
                        if val
                            .as_encoded_bytes()
                            .iter()
                            .any(|&ch| matches!(ch, b':' | b' '))
                        {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidInput,
                                "invalid character in tag",
                            ));
                        }
                        this.inner.add_tag(val)?;
                    }
                    b"W" => {
                        // watch
                        this.watch_handle = Some(parse_from_int!(i32, val));
                    }
                    b"I" => {
                        // usec initalized
                        this.usec_initialized = Some(parse_from_int!(u64, val));
                    }
                    b"V" => {
                        this.database_version = Some(parse_from_int!(u32, val));
                    }
                    _ => {
                        println!("unknown hw db kind: {k:?} = {val:?}");
                    }
                }
                Ok(())
            })?;

            if let Some(devnum) = match (major, minor) {
                (Some(maj), Some(min)) => Some(libc::makedev(maj, min)),
                (Some(maj), None) => Some(libc::makedev(maj, 0)),
                (None, Some(min)) => Some(libc::makedev(0, min)),
                _ => None,
            } {
                self.devnum = Some(devnum);
            }

            self.hw_db_read = true;
            Ok(())
        }

        pub fn devlinks(&mut self, ctx: &Udev) -> io::Result<impl Iterator<Item = &OsStr>> {
            let links = self.inner.devlinks();

            if links.is_none() {
                drop(links);
                self.try_update_from_hw_db(ctx)?;
            }
            self.inner
                .devlinks()
                .ok_or(io::Error::from_raw_os_error(libc::ENOENT))
        }

        pub fn parent(&mut self) -> Option<&Device<Owned, Enumerate>> {
            match self.parent {
                Some(_) => (),
                None => {
                    let syspath = self.syspath();
                    let mut components = syspath.components();

                    let mut found_parent = false;
                    while components.next_back().is_some() {
                        let path = components.as_path();

                        if let Ok(Some(dev)) = Device::try_new_inner(path) {
                            self.parent = Some(Some(Box::new(dev)));
                            found_parent = true;
                            break;
                        }
                    }
                    if !found_parent {
                        self.parent = Some(None);
                    }
                }
            }
            self.parent.as_ref().unwrap().as_ref().map(|p| p.as_ref())
        }

        pub fn watch(&mut self, ctx: &Udev) -> io::Result<Option<&Watch>> {
            match self.watch {
                Some(_) => (),
                None => {
                    self.try_update_from_hw_db(ctx)?;
                    let mut path = path::PathBuf::from(ctx.run_path());

                    path.push("watch");

                    let mut from_file_id = false;

                    if let Some(handle) = self.watch_handle {
                        path.push(format!("{handle}"));
                    } else if let Ok(file_name) = self.id_filename(ctx) {
                        path.push(file_name);
                        from_file_id = true;
                    }

                    match fs::read_link(&path) {
                        Ok(w) => {
                            if from_file_id {
                                // pull out the watch handle from the symlink
                                self.watch_handle = Some(
                                    atoi_simd::parse::<i32>(w.as_os_str().as_encoded_bytes())
                                        .map_err(|_| {
                                            io::Error::new(
                                                io::ErrorKind::InvalidInput,
                                                "bad watch handle",
                                            )
                                        })?,
                                );
                            }
                            self.watch = Some(Watch::new(path));
                        }
                        Err(e) if matches!(e.kind(), io::ErrorKind::NotFound) => (),
                        Err(e) => return Err(e),
                    }
                }
            }
            Ok(self.watch.as_ref())
        }

        pub fn devlink_paths(
            &mut self,
            ctx: &Udev,
        ) -> io::Result<impl Iterator<Item = path::PathBuf>> {
            use super::DevlinkPathIter;
            let devlinks = self.devlinks(ctx)?;
            Ok(DevlinkPathIter::new(ctx, devlinks))
        }

        pub fn linked_devices(
            &mut self,
            ctx: &Udev,
        ) -> io::Result<impl Iterator<Item = io::Result<Device<instance::Owned, origin::Enumerate>>>>
        {
            use super::LinkedDevices;
            let paths = self.devlink_paths(ctx)?;
            Ok(LinkedDevices::new(paths, ctx))
        }
    }

    impl<D: DevImpl> Device<D, Hotplug>
    where
        Hotplug: Extra<D>,
    {
        pub fn action(&self) -> <Hotplug as Extra<D>>::Borrowed<'_> {
            Hotplug::as_ref(&self.extra)
        }
    }

    impl<K: Extra<Owned>> Device<Owned, K> {
        pub fn has_tag(&self, tag: &OsStr) -> bool {
            self.inner.has_tag(tag)
        }

        pub fn has_devlink(&self, devlink: &OsStr) -> bool {
            self.inner.has_devlink(devlink)
        }

        pub fn property(&self, property: &OsStr) -> Option<&OsStr> {
            self.inner.property(property)
        }
    }

    impl Device<Owned, Hotplug> {
        pub fn from_monitor_owned<'a, F: for<'b> FnMut(&'b u8) -> bool>(
            ctx: &Udev,
            msg: netlink_msg::UdevMsg<netlink_msg::msg::Borrowed<'a, F>>,
        ) -> Option<Self> {
            let owned = msg.to_owned();

            let netlink_msg::UdevMsg {
                inner:
                    netlink_msg::msg::Owned {
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
                        additional_properties,
                    },
            } = owned;

            let devpath = devpath?;
            let devpath: &path::Path = devpath.as_ref();

            let devnum = match (devnum, major, minor) {
                (Some(d), _, _) => Some(d),
                (_, Some(maj), Some(min)) => Some(libc::makedev(maj as _, min as _)),
                (_, Some(maj), None) => Some(libc::makedev(maj as _, 0)),
                (_, None, Some(min)) => Some(libc::makedev(0, min as _)),
                _ => None,
            };

            // strip leading '/'
            let mut components = devpath.components();
            let _ = components.next();

            let mut syspath = path::PathBuf::from(ctx.sys_path());
            syspath.push(components.as_path());

            Some(Self {
                usec_initialized,
                extra: action,
                seqnum,
                devnum,
                if_index,
                devmode,
                database_version: None,
                devlink_priority: None,
                hw_db_read: false,
                uevent_read: false,
                id_filename: None,
                initialized: false,
                parent: None,
                sysattrs: None,
                sysnum: None,
                watch_handle: None,
                watch: None,
                inner: Owned {
                    devname,
                    devpath_old,
                    devtype,
                    driver,
                    properties: additional_properties,
                    subsystem,
                    syspath,
                    tags: tags.map(|t| t.inner.0).unwrap_or_default(),
                    devlinks: devlinks.map(|l| l.inner.0).unwrap_or_default(),
                },
            })
        }
    }

    impl<'a> Device<Borrowed<'a>, Hotplug> {
        pub fn from_monitor<F: for<'b> FnMut(&'b u8) -> bool>(
            ctx: &Udev,
            mut msg: netlink_msg::UdevMsg<netlink_msg::msg::Borrowed<'a, F>>,
            mut f: impl FnMut(&OsStr, &OsStr),
        ) -> Option<Self> {
            for (k, v) in msg.additional_properties() {
                f(k, v)
            }

            let netlink_msg::UdevMsg {
                inner:
                    netlink_msg::msg::Borrowed {
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
                        ..
                    },
            } = msg;

            let devpath = devpath?;
            let devpath: &path::Path = devpath.as_ref();

            let devnum = match (devnum, major, minor) {
                (Some(d), _, _) => Some(d),
                (_, Some(maj), Some(min)) => Some(libc::makedev(maj as _, min as _)),
                (_, Some(maj), None) => Some(libc::makedev(maj as _, 0)),
                (_, None, Some(min)) => Some(libc::makedev(0, min as _)),
                _ => None,
            };

            // strip leading '/'
            let mut components = devpath.components();
            let _ = components.next();

            let mut syspath = path::PathBuf::from(ctx.sys_path());
            syspath.push(components.as_path());

            Some(Self {
                usec_initialized,
                extra: action.map(Action::Borrowed),
                seqnum,
                devnum,
                if_index,
                devmode,
                database_version: None,
                devlink_priority: None,
                hw_db_read: false,
                uevent_read: false,
                id_filename: None,
                initialized: false,
                parent: None,
                sysattrs: None,
                sysnum: None,
                watch_handle: None,
                watch: None,
                inner: Borrowed {
                    syspath,
                    devname: devname.map(Into::into),
                    devpath_old: devpath_old.map(Into::into),
                    devtype: devtype.map(Into::into),
                    driver: driver.map(Into::into),
                    subsystem: subsystem.map(Into::into),
                    tags: tags.map(Tags::Borrowed),
                    devlinks: devlinks.map(Devlinks::Borrowed),
                },
            })
        }

        pub fn to_owned(self) -> Device<Owned, Hotplug> {
            let Self {
                usec_initialized,
                extra,
                seqnum,
                devnum,
                if_index,
                devmode,
                database_version,
                devlink_priority,
                hw_db_read,
                uevent_read,
                id_filename,
                initialized,
                parent,
                sysattrs,
                sysnum,
                watch_handle,
                watch,
                inner:
                    Borrowed {
                        syspath,
                        devname,
                        devpath_old,
                        devtype,
                        driver,
                        subsystem,
                        tags,
                        devlinks,
                    },
            } = self;

            Device {
                usec_initialized,
                extra: <Hotplug as Extra<Borrowed>>::to_owned(&extra),
                seqnum,
                devnum,
                if_index,
                devmode,
                database_version,
                devlink_priority,
                hw_db_read,
                uevent_read,
                id_filename,
                initialized,
                parent,
                sysattrs,
                sysnum,
                watch_handle,
                watch,
                inner: Owned {
                    syspath: syspath.clone(),
                    devname: devname.map(|d| d.into_owned()),
                    devpath_old: devpath_old.map(|d| d.into_owned()),
                    devtype: devtype.map(|d| d.into_owned()),
                    driver: driver.map(|d| d.into_owned()),
                    subsystem: subsystem.map(|s| s.into_owned()),
                    tags: tags.map(|t| t.to_owned()).unwrap_or_default(),
                    devlinks: devlinks.map(|d| d.to_owned()).unwrap_or_default(),
                    properties: Default::default(),
                },
            }
        }
    }

    impl Device<Owned, Enumerate> {
        fn with_syspath(syspath: path::PathBuf) -> Self {
            Self {
                usec_initialized: None,
                extra: (),
                seqnum: None,
                devnum: None,
                if_index: None,
                devmode: None,
                database_version: None,
                devlink_priority: None,
                hw_db_read: false,
                uevent_read: false,
                id_filename: None,
                initialized: false,
                parent: None,
                sysattrs: None,
                sysnum: None,
                watch_handle: None,
                watch: None,
                inner: Owned {
                    devname: None,
                    devpath_old: None,
                    devtype: None,
                    driver: None,
                    properties: Default::default(),
                    subsystem: None,
                    syspath,
                    tags: Default::default(),
                    devlinks: Default::default(),
                },
            }
        }

        pub(crate) fn try_new_inner<P: AsRef<path::Path>>(path: P) -> io::Result<Option<Self>> {
            use std::fs;
            let path = fs::canonicalize(path)?;

            use std::ffi::OsStr;
            let is_device = path.iter().any(|name| name == OsStr::new("devices"));

            if is_device {
                let mut uevent_path = path.clone();
                uevent_path.push("uevent");
                if !fs::exists(&uevent_path)? {
                    return Ok(None);
                }
            } else if std::fs::metadata(&path)?.is_dir() {
            } else {
                return Ok(None);
            }

            Ok(Some(Device::with_syspath(path)))
        }

        pub(crate) fn try_from_id_filename(ctx: &Udev, name: &OsStr) -> Option<io::Result<Self>> {
            let bytes = name.as_encoded_bytes();

            use super::DeviceKind;
            let devkind = match bytes.iter().next() {
                Some(b'b') => DeviceKind::Block,
                Some(b'c') => DeviceKind::Character,
                Some(b'n') => DeviceKind::Net,
                Some(b'+') => DeviceKind::Other,
                None => return Some(Err(io::Error::new(io::ErrorKind::InvalidInput, "no entry"))),
                _ => return None,
            };
            devkind.create_device(ctx, &bytes[1..])
        }

        pub fn from_devnum(ctx: &Udev, devkind: DevKind, devnum: u64) -> io::Result<Option<Self>> {
            let major = libc::major(devnum);
            let minor = libc::minor(devnum);

            use path::PathBuf;

            let mut path = PathBuf::from(ctx.sys_path());
            path.push("dev");
            path.push(format!("{devkind}/{major}:{minor}"));

            Self::try_new_inner(path)
        }

        pub fn from_subsystem_sysname<S1: AsRef<OsStr>, S2: AsRef<OsStr>>(
            ctx: &Udev,
            subsystem: S1,
            sysname: S2,
        ) -> io::Result<Option<Self>> {
            use path::PathBuf;
            let mut path = PathBuf::from(ctx.sys_path());

            macro_rules! add_subdir {
                ($dir:expr, $($subdirs:expr),*) => {
                    path.push($dir);
                    add_subdir!($($subdirs),*)
                };
                ($dir:expr) => {
                    path.push($dir);
                };
            }

            macro_rules! cleanup {
                ($dir:expr, $($subdirs:expr),*) => {
                    path.pop();
                    cleanup!($($subdirs),*)
                };
                ($dir:expr) => {
                    path.pop();
                };
            }

            macro_rules! check_subdirs {
                ($($subdirs:expr),*) => {
                    add_subdir!($($subdirs),*);

                    let exists = fs::exists(&path)?;

                    if exists {
                        return Self::try_new_inner(path)
                    } else {
                        cleanup!($($subdirs),*);
                    }
                };
            }

            let subsystem = subsystem.as_ref();
            let sysname = sysname.as_ref();

            match subsystem.as_encoded_bytes() {
                b"subsystem" => {
                    check_subdirs!("subsystem", sysname);
                    check_subdirs!("bus", sysname);
                    check_subdirs!("class", sysname);
                }
                b"module" => {
                    check_subdirs!("module", sysname);
                }
                b"drivers" => {
                    let bytes = sysname.as_encoded_bytes();
                    let Some((subsys, driver)) = bytes
                        .iter()
                        .position(|&ch| ch == b':')
                        .map(|pos| (&bytes[..pos], &bytes[pos + 1..]))
                    else {
                        println!("invalid character/block tag device format");
                        return Ok(None);
                    };

                    // SAFETY: bytes were initally from an OsStr
                    let (subsys, driver) = unsafe {
                        (
                            OsStr::from_encoded_bytes_unchecked(subsys),
                            OsStr::from_encoded_bytes_unchecked(driver),
                        )
                    };

                    check_subdirs!("subsystem", subsys, "drivers", driver);
                    check_subdirs!("bus", subsys, "drivers", driver);
                }
                _ => {
                    check_subdirs!("subsystem", subsystem, "devices", sysname);
                    check_subdirs!("bus", subsystem, "devices", sysname);
                    check_subdirs!("class", subsystem, sysname);
                }
            }
            Ok(None)
        }

        /// treats the enumerated device as an added hotplug device
        /// used when enumerating existing devices that are being monitored
        pub(crate) fn into_hotplug_event(self) -> Device<Owned, Hotplug> {
            let Self {
                usec_initialized,
                extra: _,
                seqnum,
                devnum,
                if_index,
                devmode,
                database_version,
                devlink_priority,
                hw_db_read,
                uevent_read,
                id_filename,
                initialized,
                parent,
                sysattrs,
                sysnum,
                watch_handle,
                watch,
                inner,
            } = self;

            Device {
                usec_initialized,
                extra: Some(netlink_msg::Action::Add),
                seqnum,
                devnum,
                if_index,
                devmode,
                database_version,
                devlink_priority,
                hw_db_read,
                uevent_read,
                id_filename,
                initialized,
                parent,
                sysattrs,
                sysnum,
                watch_handle,
                watch,
                inner,
            }
        }
    }

    pub mod instance {
        use super::*;

        #[derive(Debug)]
        pub struct Owned {
            pub(crate) syspath: path::PathBuf,
            pub(crate) properties: BTreeMap<OsString, OsString>,
            pub(crate) subsystem: Option<OsString>,

            pub(crate) devname: Option<OsString>,
            pub(crate) devtype: Option<OsString>,

            pub(crate) devlinks: BTreeSet<OsString>,
            pub(crate) tags: BTreeSet<OsString>,

            pub(crate) driver: Option<OsString>,
            pub(crate) devpath_old: Option<OsString>,
        }

        #[derive(Debug)]
        pub struct Borrowed<'a> {
            pub(crate) syspath: path::PathBuf,

            pub(crate) subsystem: Option<Cow<'a, OsStr>>,

            pub(crate) devname: Option<Cow<'a, OsStr>>,
            pub(crate) devtype: Option<Cow<'a, OsStr>>,

            pub(crate) devlinks: Option<Devlinks<'a>>,
            pub(crate) tags: Option<Tags<'a>>,

            pub(crate) driver: Option<Cow<'a, OsStr>>,
            pub(crate) devpath_old: Option<Cow<'a, OsStr>>,
        }
    }

    use instance::{Borrowed, Owned};
    use origin::{Enumerate, Hotplug};

    impl Owned {
        fn has_tag(&self, tag: &OsStr) -> bool {
            self.tags.contains(tag)
        }

        fn has_devlink(&self, tag: &OsStr) -> bool {
            self.devlinks.contains(tag)
        }

        fn property(&self, key: &OsStr) -> Option<&OsStr> {
            self.properties.get(key).map(|v| &**v)
        }
    }

    impl crate::private::Sealed for Owned {}

    impl DevImpl for Owned {
        fn properties(&self) -> Option<&BTreeMap<OsString, OsString>> {
            Some(&self.properties)
        }
        fn add_devlink(&mut self, link: OsString) -> io::Result<()> {
            self.devlinks.insert(link);
            Ok(())
        }

        fn add_tag(&mut self, tag: &OsStr) -> io::Result<()> {
            self.tags.insert(tag.to_owned());
            Ok(())
        }

        fn update_from_uevent(&mut self, key: &OsStr, value: &OsStr) -> io::Result<()> {
            match key.as_encoded_bytes() {
                b"SUBSYSTEM" => self.subsystem = Some(value.to_owned()),
                b"DEVNAME" => self.devname = Some(value.to_owned()),
                b"DEVTYPE" => self.devtype = Some(value.to_owned()),
                b"DRIVER" => self.driver = Some(value.to_owned()),
                b"DEVPATH_OLD" => self.devpath_old = Some(value.to_owned()),
                _ => {
                    self.properties.insert(key.to_owned(), value.to_owned());
                }
            }
            Ok(())
        }

        fn syspath(&self) -> &path::Path {
            &self.syspath
        }

        fn subsystem(&self) -> Option<&OsStr> {
            self.subsystem.as_deref()
        }

        fn set_subsystem(&mut self, subsys: OsString) {
            self.subsystem = Some(subsys);
        }
        fn devname(&self) -> Option<&OsStr> {
            self.devname.as_deref()
        }
        fn devlinks(&self) -> Option<impl Iterator<Item = &OsStr>> {
            if self.devlinks.is_empty() {
                None
            } else {
                Some(self.devlinks.iter().map(|link| link.as_ref()))
            }
        }
        fn tags(&self) -> Option<impl Iterator<Item = &OsStr>> {
            if self.tags.is_empty() {
                None
            } else {
                Some(self.tags.iter().map(|tag| tag.as_ref()))
            }
        }
        fn driver(&self) -> Option<&OsStr> {
            self.driver.as_deref()
        }
        fn devpath_old(&self) -> Option<&OsStr> {
            self.devpath_old.as_deref()
        }
    }

    #[derive(Debug)]
    pub(crate) enum Devlinks<'a> {
        Borrowed(netlink_msg::Devlinks<netlink_msg::devlinks::Borrowed<'a>>),
        Owned(BTreeSet<OsString>),
    }

    impl Devlinks<'_> {
        fn iter(&self) -> impl Iterator<Item = &OsStr> {
            match self {
                Self::Borrowed(b) => CowIter::Borrowed(b.iter()),
                Self::Owned(o) => CowIter::Owned(o.iter().map(|tag| tag.as_ref())),
            }
        }

        fn to_owned(&self) -> BTreeSet<OsString> {
            match self {
                Self::Borrowed(b) => (*b).to_owned().inner.0,
                Self::Owned(o) => o.clone(),
            }
        }
    }

    enum CowIter<'a, T: Iterator<Item = &'a OsStr>, U: Iterator<Item = &'a OsStr>> {
        Borrowed(T),
        Owned(U),
    }

    impl<'a, T: Iterator<Item = &'a OsStr>, U: Iterator<Item = &'a OsStr>> Iterator
        for CowIter<'a, T, U>
    {
        type Item = &'a OsStr;
        fn next(&mut self) -> Option<Self::Item> {
            match self {
                Self::Borrowed(b) => b.next(),
                Self::Owned(o) => o.next(),
            }
        }
    }

    #[derive(Debug)]
    pub enum Tags<'a> {
        Borrowed(netlink_msg::Tags<netlink_msg::tags::Borrowed<'a>>),
        Owned(BTreeSet<OsString>),
    }

    impl Tags<'_> {
        fn iter(&self) -> impl Iterator<Item = &OsStr> {
            match self {
                Self::Borrowed(b) => CowIter::Borrowed(b.iter()),
                Self::Owned(o) => CowIter::Owned(o.iter().map(|tag| tag.as_ref())),
            }
        }

        fn to_owned(&self) -> BTreeSet<OsString> {
            match self {
                Self::Borrowed(b) => {
                    let owned = (*b).to_owned();
                    owned.inner.0
                }
                Self::Owned(o) => o.clone(),
            }
        }
    }

    pub trait Extra<S>: crate::private::Sealed {
        type Output;
        type Owned;
        type Borrowed<'a>;
        fn to_owned(this: &Self::Output) -> Self::Owned;
        fn as_ref(this: &Self::Output) -> Self::Borrowed<'_>;
        fn update_from_property(this: &mut Self::Output, key: &OsStr, val: &OsStr) -> bool;
    }

    pub trait DevImpl: crate::private::Sealed {
        fn properties(&self) -> Option<&BTreeMap<OsString, OsString>>;
        fn update_from_uevent(&mut self, key: &OsStr, value: &OsStr) -> io::Result<()>;
        fn add_devlink(&mut self, link: OsString) -> io::Result<()>;
        fn add_tag(&mut self, tag: &OsStr) -> io::Result<()>;
        fn syspath(&self) -> &path::Path;
        fn subsystem(&self) -> Option<&OsStr>;
        fn set_subsystem(&mut self, subsys: OsString);
        fn devname(&self) -> Option<&OsStr>;
        fn devlinks(&self) -> Option<impl Iterator<Item = &OsStr>>;
        fn tags(&self) -> Option<impl Iterator<Item = &OsStr>>;
        fn driver(&self) -> Option<&OsStr>;
        fn devpath_old(&self) -> Option<&OsStr>;

        fn devpath(&self, ctx: &Udev) -> &path::Path {
            let mut components = self.syspath().components();

            let mut root_dir_components = path::Path::new(ctx.sys_path()).components();

            while root_dir_components.next().is_some() {
                let _ = components.next();
            }

            components.as_path()
        }

        fn search_subsystem(&mut self, ctx: &Udev) -> io::Result<OsString> {
            let mut p = self.syspath().to_owned();
            p.push("subsystem");

            match fs::read_link(&p) {
                Ok(path) => {
                    let mut components = path.components();
                    let subsystem = components.next_back().ok_or(io::Error::new(
                        io::ErrorKind::NotFound,
                        "could not get subsystem",
                    ))?;

                    Ok((&subsystem).into())
                }
                Err(e) if matches!(e.kind(), io::ErrorKind::NotFound) => {
                    let devpath = self.devpath(ctx);
                    let mut components = devpath.components();

                    let implicit_name = components.next().ok_or(io::Error::new(
                        io::ErrorKind::NotFound,
                        "could not get name from devpath",
                    ))?;

                    let subsystem = match implicit_name.as_os_str().as_encoded_bytes() {
                        b"module" => "module",
                        b"drivers" => "drivers",
                        b"subsystem" | b"class" | b"bus" => "subsystem",
                        _ => {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidInput,
                                "invalid subsystem",
                            ));
                        }
                    };

                    Ok(OsString::from(subsystem))
                }
                Err(e) => {
                    println!("err opening subsystem: {e:?}");
                    Err(e)
                }
            }
        }

        fn read_uevent(
            &mut self,
            mut f: impl FnMut(&mut Self, &OsStr, &OsStr) -> io::Result<()>,
        ) -> io::Result<()> {
            let mut path = self.syspath().to_owned();
            path.push("uevent");

            use std::io::Read;

            let mut file = match fs::OpenOptions::new().read(true).open(&path) {
                Ok(file) => file,
                Err(e) if matches!(e.kind(), io::ErrorKind::PermissionDenied) => return Ok(()),
                Err(e) => return Err(e),
            };
            let mut buf = Vec::new();
            file.read_to_end(&mut buf)?;

            for line in buf.split(|&ch| ch == b'\n').filter(|line| !line.is_empty()) {
                let Some((k, v)) = line
                    .iter()
                    .position(|&ch| ch == b'=')
                    .map(|pos| (&line[..pos], &line[pos + 1..]))
                else {
                    println!("invalid key=value pair");
                    continue;
                };

                use std::os::unix::ffi::OsStrExt;
                f(self, OsStr::from_bytes(k), OsStr::from_bytes(v))?;
            }
            Ok(())
        }
    }

    impl crate::private::Sealed for Borrowed<'_> {}

    impl DevImpl for Borrowed<'_> {
        fn properties(&self) -> Option<&BTreeMap<OsString, OsString>> {
            None
        }

        fn add_devlink(&mut self, link: OsString) -> io::Result<()> {
            match &mut self.devlinks {
                None => {
                    let mut links = BTreeSet::new();
                    links.insert(link);
                    self.devlinks = Some(Devlinks::Owned(links));
                }
                Some(Devlinks::Borrowed(b)) => {
                    if !b.iter().any(|l| l == link) {
                        let mut links = (*b).to_owned().inner.0;
                        links.insert(link);
                        self.devlinks = Some(Devlinks::Owned(links));
                    }
                }
                Some(Devlinks::Owned(o)) => {
                    o.insert(link);
                }
            }
            Ok(())
        }

        fn add_tag(&mut self, tag: &OsStr) -> io::Result<()> {
            match &mut self.tags {
                None => {
                    let mut tags = BTreeSet::new();
                    tags.insert(tag.to_owned());
                    self.tags = Some(Tags::Owned(tags));
                }
                Some(Tags::Borrowed(b)) => {
                    if !b.iter().any(|t| t == tag) {
                        let mut tags = (*b).to_owned().inner.0;
                        tags.insert(tag.to_owned());
                        self.tags = Some(Tags::Owned(tags));
                    }
                }
                Some(Tags::Owned(o)) => {
                    o.insert(tag.to_owned());
                }
            }
            Ok(())
        }

        fn update_from_uevent(&mut self, key: &OsStr, value: &OsStr) -> io::Result<()> {
            match key.as_encoded_bytes() {
                b"SUBSYSTEM" => self.subsystem = Some(value.to_owned().into()),
                b"DEVNAME" => self.devname = Some(value.to_owned().into()),
                b"DEVTYPE" => self.devtype = Some(value.to_owned().into()),
                b"DRIVER" => self.driver = Some(value.to_owned().into()),
                b"DEVPATH_OLD" => self.devpath_old = Some(value.to_owned().into()),
                _ => (),
            }
            Ok(())
        }

        fn syspath(&self) -> &path::Path {
            &self.syspath
        }

        fn subsystem(&self) -> Option<&OsStr> {
            self.subsystem.as_deref()
        }

        fn set_subsystem(&mut self, subsys: OsString) {
            self.subsystem = Some(subsys.into())
        }
        fn devname(&self) -> Option<&OsStr> {
            self.devname.as_deref()
        }
        fn devlinks(&self) -> Option<impl Iterator<Item = &OsStr>> {
            self.devlinks.as_ref().map(|links| links.iter())
        }
        fn tags(&self) -> Option<impl Iterator<Item = &OsStr>> {
            self.tags.as_ref().map(|tags| tags.iter())
        }
        fn driver(&self) -> Option<&OsStr> {
            self.driver.as_deref()
        }

        fn devpath_old(&self) -> Option<&OsStr> {
            self.devpath_old.as_deref()
        }
    }

    use std::{fs, io};
}

pub(crate) enum DeviceKind {
    Block,
    Character,
    Net,
    // subsystem specified
    Other,
}

use std::ffi::OsStr;
use std::io;

use dev::Device;

pub use dev::{instance, origin};

impl DeviceKind {
    pub(crate) fn create_device(
        self,
        ctx: &Udev,
        name: &[u8],
    ) -> Option<io::Result<Device<instance::Owned, origin::Enumerate>>> {
        match &self {
            Self::Character | Self::Block => {
                let Some((maj, min)) = name
                    .iter()
                    .position(|&ch| ch == b':')
                    .map(|pos| (&name[..pos], &name[pos + 1..]))
                else {
                    println!("invalid character/block tag device format");
                    return None;
                };

                let major = match atoi_simd::parse::<u32>(maj)
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "bad major"))
                {
                    Ok(m) => m,
                    Err(e) => return Some(Err(e)),
                };

                let minor = match atoi_simd::parse::<u32>(min)
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "bad minor"))
                {
                    Ok(m) => m,
                    Err(e) => return Some(Err(e)),
                };

                let devnum = libc::makedev(major, minor);

                let devkind = match self {
                    Self::Character => DevKind::Character,
                    Self::Block => DevKind::Block,
                    _ => unreachable!(),
                };

                Device::from_devnum(ctx, devkind, devnum).transpose()
            }
            Self::Net => {
                let ifindex = match atoi_simd::parse::<i32>(name)
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "bad network if"))
                {
                    Ok(m) => m,
                    Err(e) => return Some(Err(e)),
                };

                let socket = unsafe { libc::socket(libc::PF_INET, libc::SOCK_DGRAM, 0) };

                if socket < 0 {
                    return Some(Err(io::Error::last_os_error()));
                }

                let mut interface = unsafe { core::mem::zeroed::<libc::ifreq>() };

                interface.ifr_ifru.ifru_ifindex = ifindex;

                let err = unsafe { libc::ioctl(socket, libc::SIOCGIFNAME, &mut interface) } != 0;
                unsafe { libc::close(socket) };
                if err {
                    return Some(Err(io::Error::last_os_error()));
                }

                let name = interface.ifr_name;
                let name = name
                    .iter()
                    .position(|&ch| ch == b'\0')
                    .map(|pos| &name[..pos])
                    .unwrap_or(&name);
                use std::os::unix::ffi::OsStrExt;
                let name = OsStr::from_bytes(name);

                Device::from_subsystem_sysname(ctx, "net", name).transpose()
            }
            Self::Other => {
                let Some((subsystem, sysname)) = name
                    .iter()
                    .position(|&ch| ch == b':')
                    .map(|pos| (&name[..pos], &name[pos + 1..]))
                else {
                    println!("invalid subsystem/sysname format");
                    return None;
                };

                if subsystem.is_empty() || sysname.is_empty() {
                    println!("empty subsystem/sysname");
                    return None;
                }

                use std::os::unix::ffi::OsStrExt;

                let (subsystem, sysname) =
                    (OsStr::from_bytes(subsystem), OsStr::from_bytes(sysname));
                Device::from_subsystem_sysname(ctx, subsystem, sysname).transpose()
            }
        }
    }
}

use std::collections::BTreeSet;
use std::fs;
use std::path;

pub struct DevlinkPathIter<I> {
    path_buf: path::PathBuf,
    devlinks: I,
    devpath_len: usize,
    pop: bool,
}

impl<'a, I: Iterator<Item = &'a OsStr>> DevlinkPathIter<I> {
    fn new(ctx: &Udev, iter: I) -> Self {
        let mut path_buf = path::PathBuf::from(ctx.run_path());
        path_buf.push("links");

        let devpath_len = ctx.dev_path().len() + 1;

        Self {
            path_buf,
            devlinks: iter,
            pop: false,
            devpath_len,
        }
    }
}

impl<'a, I: Iterator<Item = &'a OsStr>> Iterator for DevlinkPathIter<I> {
    type Item = path::PathBuf;

    fn next(&mut self) -> Option<Self::Item> {
        let link = self.devlinks.next()?;

        if self.pop {
            self.path_buf.pop();
        }

        enum ReplaceIter<'a> {
            Char(std::iter::Once<&'a u8>),
            Escaped(std::slice::Iter<'a, u8>),
        }

        impl<'a> Iterator for ReplaceIter<'a> {
            type Item = &'a u8;
            fn next(&mut self) -> Option<Self::Item> {
                match self {
                    Self::Char(s) => s.next(),
                    Self::Escaped(e) => e.next(),
                }
            }
        }

        use std::os::unix::ffi::OsStringExt;
        let bytes = &link.as_encoded_bytes()[self.devpath_len..];

        let encoded = OsString::from_vec(
            bytes
                .iter()
                .flat_map(|ch| match ch {
                    b'/' => ReplaceIter::Escaped(b"\\x2f".iter()),
                    b'\\' => ReplaceIter::Escaped(b"\\x5c".iter()),
                    c => ReplaceIter::Char(std::iter::once(c)),
                })
                .copied()
                .collect(),
        );

        self.path_buf.push(encoded);
        self.pop = true;
        Some(self.path_buf.clone())
    }
}

impl<'b, I> LinkedDevices<'b, I> {
    fn new(iter: I, ctx: &'b Udev) -> Self {
        Self {
            linked_paths: iter,
            link_dir: None,
            ctx,
            id_set: BTreeSet::new(),
        }
    }
}

pub struct LinkedDevices<'b, I> {
    linked_paths: I,
    link_dir: Option<fs::ReadDir>,
    ctx: &'b Udev,
    id_set: BTreeSet<OsString>,
}

impl<I: Iterator<Item = path::PathBuf>> Iterator for LinkedDevices<'_, I> {
    type Item = io::Result<Device<instance::Owned, origin::Enumerate>>;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(dir) = self.link_dir.as_mut() {
            for entry in dir.by_ref() {
                let entry = match entry {
                    Ok(entry) => entry,
                    Err(e) => return Some(Err(e)),
                };
                let name = entry.file_name();
                if !self.id_set.insert(name.clone()) {
                    continue;
                }
                return Device::try_from_id_filename(self.ctx, &name);
            }
            self.link_dir = None;
        }

        while let Some(link) = self.linked_paths.next() {
            match fs::read_dir(link) {
                Ok(dir) => {
                    self.link_dir = Some(dir);
                    return self.next();
                }
                Err(e) if matches!(e.kind(), io::ErrorKind::NotFound) => (),
                Err(e) => return Some(Err(e)),
            }
        }
        None
    }
}

/// udev watch that can be used with inotify
#[derive(Debug)]
pub struct Watch {
    path: path::PathBuf,
}

impl Watch {
    fn new(path: path::PathBuf) -> Self {
        Self { path }
    }

    pub fn path(&self) -> &path::Path {
        &self.path
    }
}

pub enum DevKind {
    Block,
    Character,
}

use core::fmt;

impl fmt::Display for DevKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Block => write!(f, "block"),
            Self::Character => write!(f, "char"),
        }
    }
}
