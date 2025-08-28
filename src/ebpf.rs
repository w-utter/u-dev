use crate::filters::{Filter, UniqueFilter};
use crate::netlink_msg::UdevNetlinkHeader;

#[derive(Default)]
pub(crate) struct BpfFilter {
    instructions: Vec<libc::sock_filter>,
}

impl BpfFilter {
    pub(crate) fn raw_instructions(&mut self) -> (*mut libc::sock_filter, usize) {
        (self.instructions.as_mut_ptr(), self.instructions.len())
    }

    fn stmt(&mut self, code: u16, data: u32) {
        let mut ins = unsafe { core::mem::zeroed::<libc::sock_filter>() };
        ins.code = code;
        ins.k = data;
        self.instructions.push(ins);
    }

    fn jmp(&mut self, code: u16, data: u32, jt: u8, jf: u8) {
        let mut ins = unsafe { core::mem::zeroed::<libc::sock_filter>() };
        ins.code = code;
        ins.jt = jt;
        ins.jf = jf;
        ins.k = data;
        self.instructions.push(ins);
    }

    fn pass_packet(&mut self) {
        self.stmt((libc::BPF_RET | libc::BPF_K) as _, 0xffffffff);
    }

    fn drop_packet(&mut self) {
        self.stmt((libc::BPF_RET | libc::BPF_K) as _, 0);
    }

    fn update_tag_matches(&mut self, tags: &UniqueFilter) {
        let mut tag_matches = tags.len();

        for tag in tags.to_iter() {
            let tag_bloom = bloom(tag);
            let bloom_high = (tag_bloom >> 32) as u32;
            let bloom_low = tag_bloom as u32;

            //load low bits in reg A
            self.stmt(
                (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as _,
                core::mem::offset_of!(UdevNetlinkHeader, filter_tag_bloom_hi) as _,
            );
            // clear bits
            self.stmt(
                (libc::BPF_ALU | libc::BPF_AND | libc::BPF_K) as _,
                bloom_high,
            );
            // jump to next tag if not matching, otherwise check high bloom bits
            self.jmp(
                (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as _,
                bloom_high,
                0,
                3,
            );

            //load high bits in reg A
            self.stmt(
                (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as _,
                core::mem::offset_of!(UdevNetlinkHeader, filter_tag_bloom_lo) as _,
            );
            // clear bits
            self.stmt(
                (libc::BPF_ALU | libc::BPF_AND | libc::BPF_K) as _,
                bloom_low,
            );
            // jump to next tag if not matching, otherwise jump to check other filters
            tag_matches -= 1;
            self.jmp(
                (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as _,
                bloom_low,
                (1 + (tag_matches * 6)) as _,
                0,
            );
        }

        if !tags.is_empty() {
            // nothing matched, drop packet
            self.drop_packet()
        }
    }

    fn update_subsystem_matches(&mut self, subsystems: &Filter) {
        let mut subsystem_matches: usize = subsystems
            .to_iter()
            .map(|(_, devtypes)| 2 + 2 * devtypes.len())
            .sum();

        for (subsystem, devtypes) in subsystems.to_iter() {
            let subsystem_hash = hash32(subsystem);
            //load filter in reg A

            self.stmt(
                (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as _,
                core::mem::offset_of!(UdevNetlinkHeader, filter_subsystem_hash) as _,
            );

            subsystem_matches -= 2 * (devtypes.len() + 1);
            if devtypes.is_empty() {
                // jump to next check if subsystem does not match
                self.jmp(
                    (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as _,
                    subsystem_hash,
                    (subsystem_matches + 1) as _,
                    0,
                );
            } else {
                // jump to next check if subsystem does not match
                let mut devtype_matches = devtypes.len();
                self.jmp(
                    (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as _,
                    subsystem_hash,
                    0,
                    (2 * devtype_matches) as _,
                );

                for devtype in devtypes {
                    // load devtype hash into reg A
                    self.stmt(
                        (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as _,
                        core::mem::offset_of!(UdevNetlinkHeader, filter_devtype_hash) as _,
                    );
                    let devtype_hash = hash32(devtype);
                    devtype_matches -= 1;
                    // jump to end if devtype matches
                    self.jmp(
                        (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as _,
                        devtype_hash,
                        (subsystem_matches + (devtype_matches * 2) + 1) as _,
                        0,
                    );
                }
            }
        }

        if !subsystems.is_empty() {
            // drop packet
            self.drop_packet()
        }
    }

    pub(crate) fn update_filter(&mut self, tags: &UniqueFilter, subsystems: &Filter) {
        self.instructions.clear();

        // load magic in reg A
        self.stmt(
            (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as _,
            core::mem::offset_of!(UdevNetlinkHeader, magic) as _,
        );
        // jump if magic matches
        self.jmp(
            (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as _,
            UdevNetlinkHeader::MAGIC,
            1,
            0,
        );
        // wrong magic, drop packet
        self.drop_packet();

        self.update_tag_matches(tags);
        self.update_subsystem_matches(subsystems);

        // matched, pass packet
        self.pass_packet();
    }

    pub(crate) fn attach(
        &mut self,
        tags: &UniqueFilter,
        subsystems: &Filter,
        fd: impl std::os::fd::AsRawFd,
    ) -> std::io::Result<()> {
        self.update_filter(tags, subsystems);
        let (ptr, len) = self.raw_instructions();

        let mut fprog = unsafe { core::mem::zeroed::<libc::sock_fprog>() };
        fprog.len = len as _;
        fprog.filter = ptr;

        let res = unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_ATTACH_FILTER,
                &fprog as *const _ as _,
                core::mem::size_of::<libc::sock_fprog>() as _,
            )
        };

        if res < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }
}

use std::ffi::OsStr;

fn bloom(input: &OsStr) -> u64 {
    let mut bits = 0;
    let hash = hash32(input);
    bits |= 1 << (hash & 63);
    bits |= 1 << ((hash >> 6) & 63);
    bits |= 1 << ((hash >> 12) & 63);
    bits |= 1 << ((hash >> 18) & 63);
    bits
}

fn hash32(input: &OsStr) -> u32 {
    // 'm' and 'r' are mixing constants generated offline.
    // They're not really 'magic', they just happen to work well.
    let m = 0x5bd1e995;
    let r = 24;

    let data = input.as_encoded_bytes();
    // Initialize the hash to a 'random' value
    let seed = 0;
    let h = (seed ^ data.len()) as u32;

    let mut chunks = data.chunks_exact(4);

    // Mix 4 bytes at a time into the hash
    let mut h = (&mut chunks).fold(h as _, |mut h: u32, k| {
        let mut k = u32::from_ne_bytes(k.try_into().unwrap());
        k = k.wrapping_mul(m);
        k ^= k >> r;
        k = k.wrapping_mul(m);
        h = h.wrapping_mul(m);
        h ^= k;
        h
    });

    match chunks.remainder() {
        [a] => {
            h ^= *a as u32;
            h = h.wrapping_mul(m);
        }
        [a, b] => {
            h ^= *a as u32;
            h ^= (*b as u32) << 8;
            h = h.wrapping_mul(m);
        }
        [a, b, c] => {
            h ^= *a as u32;
            h ^= (*b as u32) << 8;
            h ^= (*c as u32) << 16;
            h = h.wrapping_mul(m);
        }
        _ => (),
    }

    h ^= h >> 13;
    h = h.wrapping_mul(m);
    h ^= h >> 15;

    h
}
