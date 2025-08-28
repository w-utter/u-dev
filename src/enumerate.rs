use std::ffi::{OsStr, OsString};
use std::fs;
use std::io;
use std::path;

use crate::Cow;
use crate::Udev;
use crate::{Device, device};
use std::collections::BTreeMap;

use crate::filters::{Filter, UniqueFilter};

#[derive(Default)]
struct EnumeratorFilters<'a, P> {
    sysattr_matches: Filter<'a>,
    sysattr_nomatches: Filter<'a>,
    subsystem_matches: UniqueFilter<'a>,
    subsystem_nomatches: UniqueFilter<'a>,
    sysnames: UniqueFilter<'a>,
    properties: Filter<'a>,
    tags: UniqueFilter<'a>,
    is_initalized: bool,
    parent: P,
}

pub(crate) trait EnumFilter {
    fn matches_sysattrs(&self, _sysattrs: &BTreeMap<OsString, OsString>) -> bool {
        true
    }

    fn matches_subsystem(&self, subsystem: &OsStr) -> bool;

    fn matches_properties(&self, _properties: &BTreeMap<OsString, OsString>) -> bool {
        true
    }

    fn tags(&self) -> &UniqueFilter<'_>;

    fn matched_parent(
        &self,
    ) -> Option<&Device<device::instance::Owned, device::origin::Enumerate>> {
        None
    }

    fn matches_sysname(&self, _sysname: &OsStr) -> bool {
        true
    }

    fn matches_initalized(&self, _is_initalized: bool) -> bool {
        true
    }
}

pub struct Enumerator<'a, 'b, P> {
    inner: EnumeratorInner<EnumeratorFilters<'a, P>>,
    ctx: &'b Udev,
}

impl<'b> Enumerator<'_, 'b, ()> {
    pub fn new(ctx: &'b Udev) -> Self {
        Self {
            ctx,
            inner: Default::default(),
        }
    }
}

pub trait ParentFilter: crate::private::Sealed {
    fn parent(&self) -> Option<&Device<device::instance::Owned, device::origin::Enumerate>>;
}

impl crate::private::Sealed for () {}

impl ParentFilter for () {
    fn parent(&self) -> Option<&Device<device::instance::Owned, device::origin::Enumerate>> {
        None
    }
}

impl<P: AsRef<Device<device::instance::Owned, device::origin::Enumerate>>> crate::private::Sealed
    for P
{
}

impl<P: AsRef<Device<device::instance::Owned, device::origin::Enumerate>>> ParentFilter for P {
    fn parent(&self) -> Option<&Device<device::instance::Owned, device::origin::Enumerate>> {
        Some(self.as_ref())
    }
}

impl<P: ParentFilter> EnumFilter for EnumeratorFilters<'_, P> {
    fn matches_sysattrs(&self, sysattrs: &BTreeMap<OsString, OsString>) -> bool {
        if sysattrs.iter().any(|(k, v)| {
            if let Some(matching) = self.sysattr_nomatches.get(k.as_os_str()) {
                matching.is_empty() || matching.contains(v.as_os_str())
            } else {
                false
            }
        }) {
            return false;
        }

        if !self.sysattr_matches.to_iter().all(|(k, v)| {
            let attr: &OsStr = k.as_ref();
            if let Some(matching) = sysattrs.get(attr) {
                v.is_empty() || v.contains(matching.as_os_str())
            } else {
                false
            }
        }) {
            return false;
        }
        true
    }

    fn matches_subsystem(&self, subsystem: &OsStr) -> bool {
        if self.subsystem_nomatches.contains(subsystem) {
            return false;
        }

        if !self.subsystem_matches.contains(subsystem) {
            return self.subsystem_matches.is_empty();
        }
        true
    }

    fn matches_properties(&self, properties: &BTreeMap<OsString, OsString>) -> bool {
        if !self.properties.to_iter().all(|(k, v)| {
            // for some reason there are a couple of files that have the correct permissions but
            // still cannot be read
            let attr: &OsStr = k.as_ref();
            if let Some(matching) = properties.get(attr) {
                v.is_empty() || v.contains(matching.as_os_str())
            } else {
                false
            }
        }) {
            return false;
        }
        true
    }

    fn tags(&self) -> &UniqueFilter<'_> {
        &self.tags
    }

    fn matched_parent(
        &self,
    ) -> Option<&Device<device::instance::Owned, device::origin::Enumerate>> {
        self.parent.parent()
    }

    fn matches_sysname(&self, sysname: &OsStr) -> bool {
        self.sysnames.is_empty() || self.sysnames.contains(sysname)
    }

    fn matches_initalized(&self, is_initalized: bool) -> bool {
        if self.is_initalized {
            is_initalized
        } else {
            true
        }
    }
}

impl<'a, 'b, P: ParentFilter> Enumerator<'a, 'b, P> {
    pub fn nomatch_parent(self) -> Enumerator<'a, 'b, ()> {
        self.change_parent(())
    }

    pub fn match_parent<D: AsRef<Device<device::instance::Owned, device::origin::Enumerate>>>(
        self,
        parent: D,
    ) -> Enumerator<'a, 'b, D> {
        self.change_parent(parent)
    }

    fn change_parent<R: ParentFilter>(self, replacement: R) -> Enumerator<'a, 'b, R> {
        let Self {
            inner:
                EnumeratorInner {
                    filters:
                        EnumeratorFilters {
                            sysattr_matches,
                            sysattr_nomatches,
                            subsystem_matches,
                            subsystem_nomatches,
                            sysnames,
                            properties,
                            tags,
                            is_initalized,
                            parent: _,
                        },
                },
            ctx,
        } = self;

        Enumerator {
            inner: EnumeratorInner {
                filters: EnumeratorFilters {
                    sysattr_matches,
                    sysattr_nomatches,
                    subsystem_matches,
                    subsystem_nomatches,
                    sysnames,
                    properties,
                    tags,
                    is_initalized,
                    parent: replacement,
                },
            },
            ctx,
        }
    }

    pub fn match_subsystem<S: Into<Cow<'a, OsStr>>>(
        &mut self,
        subsystem: S,
    ) -> io::Result<Option<Cow<'a, OsStr>>> {
        self.inner.filters.subsystem_matches.insert(subsystem)
    }

    pub fn nomatch_subsystem<S: Into<Cow<'a, OsStr>>>(
        &mut self,
        subsystem: S,
    ) -> io::Result<Option<Cow<'a, OsStr>>> {
        self.inner.filters.subsystem_nomatches.insert(subsystem)
    }

    pub fn match_sysattr_value<S: Into<Cow<'a, OsStr>>>(
        &mut self,
        sysattr: S,
        value: impl Into<Cow<'a, OsStr>>,
    ) -> io::Result<Option<Cow<'a, OsStr>>> {
        self.inner
            .filters
            .sysattr_matches
            .insert(sysattr, Some(value))
    }

    pub fn match_sysattr<S: Into<Cow<'a, OsStr>>>(&mut self, sysattr: S) -> io::Result<()> {
        self.inner
            .filters
            .sysattr_matches
            .insert(sysattr, None::<OsString>)?;
        Ok(())
    }

    pub fn nomatch_sysattr_value<S: Into<Cow<'a, OsStr>>>(
        &mut self,
        sysattr: S,
        value: impl Into<Cow<'a, OsStr>>,
    ) -> io::Result<Option<Cow<'a, OsStr>>> {
        self.inner
            .filters
            .sysattr_nomatches
            .insert(sysattr, Some(value))
    }

    pub fn nomatch_sysattr<S: Into<Cow<'a, OsStr>>>(&mut self, sysattr: S) -> io::Result<()> {
        self.inner
            .filters
            .sysattr_nomatches
            .insert(sysattr, None::<OsString>)?;
        Ok(())
    }

    pub fn match_property_value<V: Into<Cow<'a, OsStr>>>(
        &mut self,
        property: V,
        value: impl Into<Cow<'a, OsStr>>,
    ) -> io::Result<Option<Cow<'a, OsStr>>> {
        self.inner.filters.properties.insert(property, Some(value))
    }

    pub fn match_property<V: Into<Cow<'a, OsStr>>>(&mut self, property: V) -> io::Result<()> {
        self.inner
            .filters
            .properties
            .insert(property, None::<OsString>)?;
        Ok(())
    }

    pub fn match_tag<T: Into<Cow<'a, OsStr>>>(
        &mut self,
        tag: T,
    ) -> io::Result<Option<Cow<'a, OsStr>>> {
        self.inner.filters.tags.insert(tag)
    }

    pub fn match_initalized(&mut self, is_initalized: bool) {
        self.inner.filters.is_initalized = is_initalized
    }

    pub fn devices(
        &self,
    ) -> io::Result<
        impl Iterator<Item = io::Result<Device<device::instance::Owned, device::origin::Enumerate>>>,
    > {
        Ok(FilteredDeviceIter::new(
            DeviceIter::new(&self.inner.filters, self.ctx)?,
            &self.inner.filters,
            self.ctx,
        ))
    }

    pub fn subsystems(
        &self,
    ) -> io::Result<
        impl Iterator<Item = io::Result<Device<device::instance::Owned, device::origin::Enumerate>>>,
    > {
        SubsystemIter::new(self.ctx, &self.inner.filters)
    }
}

#[derive(Default)]
struct EnumeratorInner<F> {
    filters: F,
}

macro_rules! map_err {
    ($res:expr) => {
        match $res {
            Ok(o) => o,
            Err(e) => return Some(Err(e)),
        }
    };
}

struct TagDirIter<'a, 'b, 'c> {
    run_dir: path::PathBuf,
    tags: std::collections::btree_set::Iter<'b, Cow<'a, OsStr>>,
    read_dir: Option<fs::ReadDir>,
    ctx: &'c Udev,
}

impl<'a, 'b, 'c> TagDirIter<'a, 'b, 'c> {
    fn new(basedir: path::PathBuf, filter: &'b UniqueFilter<'a>, ctx: &'c Udev) -> Self {
        let tags = filter.to_iter();
        Self {
            run_dir: basedir,
            tags,
            read_dir: None,
            ctx,
        }
    }
}

impl Iterator for TagDirIter<'_, '_, '_> {
    type Item = io::Result<Device<device::instance::Owned, device::origin::Enumerate>>;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(read_dir) = self.read_dir.as_mut() {
            for entry in read_dir.by_ref() {
                let entry = map_err!(entry);
                let name = entry.file_name();
                if let Some(res) = Device::try_from_id_filename(self.ctx, &name) {
                    return Some(res);
                }
            }
            self.read_dir = None;
        }

        while let Some(tag) = self.tags.next() {
            self.run_dir.push(tag);
            let res = fs::read_dir(&self.run_dir);
            self.run_dir.pop();
            match res {
                Ok(iter) => {
                    self.read_dir = Some(iter);
                    return self.next();
                }
                Err(e)
                    if !matches!(
                        e.kind(),
                        io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
                    ) =>
                {
                    return Some(Err(e));
                }
                Err(_) => (),
            }
        }
        None
    }
}

struct ParentDirIter {
    subdirs: Vec<fs::ReadDir>,
}

impl ParentDirIter {
    fn new(
        parent: &Device<device::instance::Owned, device::origin::Enumerate>,
    ) -> io::Result<Self> {
        let syspath = parent.syspath();
        let subdir = fs::read_dir(syspath)?;

        Ok(Self {
            subdirs: vec![subdir],
        })
    }
}

impl Iterator for ParentDirIter {
    type Item = io::Result<Device<device::instance::Owned, device::origin::Enumerate>>;
    fn next(&mut self) -> Option<Self::Item> {
        let last = self.subdirs.last_mut()?;

        for entry in last.by_ref() {
            let entry = map_err!(entry);
            let metadata = map_err!(entry.metadata());
            if !metadata.file_type().is_dir() {
                continue;
            }

            let path = entry.path();
            let readdir = fs::read_dir(&path);
            let child = map_err!(Device::try_new_inner(path));

            match (readdir, child) {
                (Ok(dir), Some(child)) => {
                    self.subdirs.push(dir);
                    return Some(Ok(child));
                }
                (_, Some(child)) => return Some(Ok(child)),
                _ => (),
            }
        }

        self.subdirs.pop();
        self.next()
    }
}

struct DirIter {
    read_dir: fs::ReadDir,
    basedir: OsString,
    subdir: Option<OsString>,
    subread_dir: Option<fs::ReadDir>,
}

impl DirIter {
    fn new(basedir: OsString, subdir: Option<OsString>) -> io::Result<Self> {
        let read_dir = fs::read_dir(&basedir)?;
        Ok(Self {
            read_dir,
            basedir,
            subdir,
            subread_dir: None,
        })
    }
}

impl Iterator for DirIter {
    type Item = io::Result<Device<device::instance::Owned, device::origin::Enumerate>>;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(nested) = self.subread_dir.as_mut() {
            for entry in nested.by_ref() {
                let entry = map_err!(entry);
                let p = entry.path();
                if let Some(dev) = map_err!(Device::try_new_inner(p)) {
                    return Some(Ok(dev));
                }
            }
        }

        while let Some(entry) = self.read_dir.next() {
            let entry = map_err!(entry);
            let name = entry.file_name();

            use path::PathBuf;
            let mut dir = PathBuf::from(&self.basedir);
            dir.push(name);
            if let Some(sub) = self.subdir.as_ref() {
                dir.push(sub)
            }

            match fs::read_dir(&dir) {
                Ok(read) => {
                    self.subread_dir = Some(read);
                    return self.next();
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
                    ) => {}
                Err(e) => {
                    println!("{e:?} on {dir:?}");
                    return Some(Err(e));
                }
            }
        }
        None
    }
}

pub(crate) struct FilteredDeviceIter<'a, 'b, 'c, F> {
    iter: DeviceIter<'a, 'b, 'c>,
    filter: &'a F,
    ctx: &'c Udev,
}

impl<'a, 'b, 'c, F> FilteredDeviceIter<'a, 'b, 'c, F> {
    pub(crate) fn new(iter: DeviceIter<'a, 'b, 'c>, filter: &'a F, ctx: &'c Udev) -> Self {
        Self { iter, filter, ctx }
    }
}

impl<F: EnumFilter> Iterator for FilteredDeviceIter<'_, '_, '_, F> {
    type Item = io::Result<Device<device::instance::Owned, device::origin::Enumerate>>;
    fn next(&mut self) -> Option<Self::Item> {
        let in_tags = matches!(self.iter.state, Some(DeviceIterState::Tags(_)));
        for device in self.iter.by_ref() {
            let mut device = map_err!(device);

            if let Some(parent) = self.filter.matched_parent() {
                if !in_tags && parent.devpath(self.ctx) != device.devpath(self.ctx) {
                    continue;
                }
            }

            let subsystem = match device.subsystem(self.ctx) {
                Ok(subsys) => subsys,
                Err(e) => return Some(Err(e)),
            };

            if !self.filter.matches_subsystem(subsystem) {
                continue;
            }

            if !self.filter.matches_sysname(device.sysname(self.ctx)) {
                continue;
            }

            let initialized = map_err!(device.is_initalized(self.ctx));

            if !self.filter.matches_initalized(initialized) {
                continue;
            }

            let sysattrs = match device.sysattrs() {
                Ok(attrs) => attrs,
                Err(e) => return Some(Err(e)),
            };

            if !self.filter.matches_sysattrs(sysattrs) {
                continue;
            }

            let properties = match device.properties(self.ctx) {
                Ok(properties) => properties,
                Err(e) => return Some(Err(e)),
            };

            if let Some(properties) = properties {
                if !self.filter.matches_properties(properties) {
                    continue;
                }
            }

            return Some(Ok(device));
        }
        None
    }
}

pub(crate) struct DeviceIter<'a, 'b, 'c> {
    mount_path: OsString,
    state: Option<DeviceIterState<'a, 'b, 'c>>,
}

impl<'a, 'c> DeviceIter<'a, '_, 'c> {
    pub(crate) fn new<F: EnumFilter>(filter: &'a F, ctx: &'c Udev) -> io::Result<Self> {
        use path::PathBuf;

        let tags = filter.tags();
        if !tags.is_empty() {
            let run_path = ctx.run_path();
            let mut path = PathBuf::from(&run_path);
            path.push("tags");

            return Ok(DeviceIter {
                mount_path: run_path.into(),
                state: Some(DeviceIterState::Tags(TagDirIter::new(path, tags, ctx))),
            });
        }

        if let Some(parent) = filter.matched_parent() {
            return Ok(DeviceIter {
                mount_path: PathBuf::new().into(),
                state: Some(DeviceIterState::Parent(ParentDirIter::new(parent)?)),
            });
        }

        let mount_path = ctx.sys_path();
        let mut path = PathBuf::from(&mount_path);
        path.push("subsystem");

        Ok(if fs::exists(&path)? {
            DeviceIter {
                mount_path: mount_path.into(),
                state: Some(DeviceIterState::Subsystem(DirIter::new(path.into(), None)?)),
            }
        } else {
            path.pop();
            path.push("bus");
            DeviceIter {
                mount_path: mount_path.into(),
                state: Some(DeviceIterState::Brute(BruteDeviceIterState::Bus(
                    DirIter::new(path.into(), Some(OsString::from("devices")))?,
                ))),
            }
        })
    }
}

impl Iterator for DeviceIter<'_, '_, '_> {
    type Item = io::Result<Device<device::instance::Owned, device::origin::Enumerate>>;

    fn next(&mut self) -> Option<Self::Item> {
        let state = self.state.as_mut()?;

        match state {
            DeviceIterState::Subsystem(iter) => {
                let next = iter.next();
                if next.is_none() {
                    self.state = None;
                }
                next
            }
            DeviceIterState::Parent(iter) => {
                let next = iter.next();
                if next.is_none() {
                    self.state = None;
                }
                next
            }
            DeviceIterState::Tags(iter) => {
                let next = iter.next();
                if next.is_none() {
                    self.state = None;
                }
                next
            }
            DeviceIterState::Brute(BruteDeviceIterState::Bus(iter)) => {
                let next = iter.next();
                if next.is_none() {
                    use path::PathBuf;
                    let mut path = PathBuf::from(&self.mount_path);
                    path.push("class");

                    let res = DirIter::new(path.into(), None);

                    match res {
                        Ok(iter) => {
                            self.state =
                                Some(DeviceIterState::Brute(BruteDeviceIterState::Class(iter)));
                            self.next()
                        }
                        Err(e) => {
                            self.state = None;
                            if matches!(
                                e.kind(),
                                io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
                            ) {
                                None
                            } else {
                                Some(Err(e))
                            }
                        }
                    }
                } else {
                    next
                }
            }
            DeviceIterState::Brute(BruteDeviceIterState::Class(iter)) => {
                let next = iter.next();

                if next.is_none() {
                    self.state = None
                }
                next
            }
        }
    }
}

enum DeviceIterState<'a, 'b, 'c> {
    Tags(TagDirIter<'a, 'b, 'c>),
    Parent(ParentDirIter),
    Subsystem(DirIter),
    Brute(BruteDeviceIterState),
}

enum BruteDeviceIterState {
    Bus(DirIter),
    Class(DirIter),
}

struct SubsystemIter {
    module: Option<DirIter>,
    subsystem: Option<DirIter>,
    drivers: Option<DirIter>,
}

impl Iterator for SubsystemIter {
    type Item = io::Result<Device<device::instance::Owned, device::origin::Enumerate>>;
    fn next(&mut self) -> Option<Self::Item> {
        if let Some(module) = self.module.as_mut() {
            let next = module.next();
            if next.is_some() {
                return next;
            }
            self.module = None;
        }

        if let Some(subsystem) = self.subsystem.as_mut() {
            let next = subsystem.next();
            if next.is_some() {
                return next;
            }
            self.subsystem = None;
        }

        if let Some(drivers) = self.drivers.as_mut() {
            let next = drivers.next();
            if next.is_some() {
                return next;
            }
            self.drivers = None;
        }
        None
    }
}

impl SubsystemIter {
    fn new<P: ParentFilter>(udev: &Udev, filters: &EnumeratorFilters<'_, P>) -> io::Result<Self> {
        let mount_path = udev.sys_path();

        use path::PathBuf;
        let mut path = PathBuf::from(&mount_path);
        path.push("module");

        let module = if filters.matches_subsystem(OsStr::new("module")) {
            match DirIter::new(path.clone().into(), None) {
                Ok(module) => Some(module),
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
                    ) =>
                {
                    None
                }
                Err(e) => return Err(e),
            }
        } else {
            None
        };

        path.pop();
        path.push("subsystem");

        let (subsystem, subsystem_exists) = if filters.matches_subsystem(OsStr::new("subsystem")) {
            let subsystem = match DirIter::new(path.clone().into(), None) {
                Ok(subsystem) => Some(subsystem),
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
                    ) =>
                {
                    None
                }
                Err(e) => return Err(e),
            };
            let exists = subsystem.is_some();
            (subsystem, exists)
        } else {
            (None, fs::exists(&path)?)
        };

        let subdir = if subsystem_exists { "subsystem" } else { "bus" };

        path.pop();
        path.push(subdir);

        let drivers = match DirIter::new(path.into(), Some(OsString::from("drivers"))) {
            Ok(drivers) => Some(drivers),
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
                ) =>
            {
                None
            }
            Err(e) => return Err(e),
        };

        Ok(Self {
            module,
            subsystem,
            drivers,
        })
    }
}
