//! Cgroup socket address programs.

use std::{hash::Hash, os::fd::AsFd, path::Path};

use aya_obj::generated::bpf_prog_type::BPF_PROG_TYPE_CGROUP_SOCK_ADDR;
pub use aya_obj::programs::CgroupSockAddrAttachType;

use crate::{
    VerifierLogLevel,
    programs::{
        CgroupAttachMode, FdLink, Link, ProgAttachLink, ProgramData, ProgramError, ProgramType,
        define_link_wrapper, id_as_key, impl_try_into_fdlink, load_program_with_attach_type, query,
    },
    sys::{LinkTarget, ProgQueryTarget, SyscallError, bpf_link_create},
    util::KernelVersion,
};

/// A program that can be used to inspect or modify socket addresses (`struct sockaddr`).
///
/// [`CgroupSockAddr`] programs can be used to inspect or modify socket addresses passed to
/// various syscalls within a [cgroup]. They can be attached to a number of different
/// places as described in [`CgroupSockAddrAttachType`].
///
/// [cgroup]: https://man7.org/linux/man-pages/man7/cgroups.7.html
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 4.17.
///
/// # Examples
///
/// ```no_run
/// # #[derive(thiserror::Error, Debug)]
/// # enum Error {
/// #     #[error(transparent)]
/// #     IO(#[from] std::io::Error),
/// #     #[error(transparent)]
/// #     Map(#[from] aya::maps::MapError),
/// #     #[error(transparent)]
/// #     Program(#[from] aya::programs::ProgramError),
/// #     #[error(transparent)]
/// #     Ebpf(#[from] aya::EbpfError)
/// # }
/// # let mut bpf = aya::Ebpf::load(&[])?;
/// use std::fs::File;
/// use aya::programs::{CgroupAttachMode, CgroupSockAddr, CgroupSockAddrAttachType};
///
/// let file = File::open("/sys/fs/cgroup/unified")?;
/// let egress: &mut CgroupSockAddr = bpf.program_mut("connect4").unwrap().try_into()?;
/// egress.load()?;
/// egress.attach(file, CgroupAttachMode::Single)?;
/// # Ok::<(), Error>(())
/// ```
#[derive(Debug)]
#[doc(alias = "BPF_PROG_TYPE_CGROUP_SOCK_ADDR")]
pub struct CgroupSockAddr {
    pub(crate) data: ProgramData<CgroupSockAddrLink>,
    pub(crate) attach_type: CgroupSockAddrAttachType,
}

impl CgroupSockAddr {
    /// The type of the program according to the kernel.
    pub const PROGRAM_TYPE: ProgramType = ProgramType::CgroupSockAddr;

    /// Loads the program inside the kernel.
    pub fn load(&mut self) -> Result<(), ProgramError> {
        let Self { data, attach_type } = self;
        load_program_with_attach_type(BPF_PROG_TYPE_CGROUP_SOCK_ADDR, *attach_type, data)
    }

    /// Attaches the program to the given cgroup.
    ///
    /// The returned value can be used to detach, see [`CgroupSockAddr::detach`].
    pub fn attach<T: AsFd>(
        &mut self,
        cgroup: T,
        mode: CgroupAttachMode,
    ) -> Result<CgroupSockAddrLinkId, ProgramError> {
        let Self { data, attach_type } = self;
        let prog_fd = data.fd()?;
        let prog_fd = prog_fd.as_fd();
        let cgroup_fd = cgroup.as_fd();
        if KernelVersion::at_least(5, 7, 0) {
            match bpf_link_create(
                prog_fd,
                LinkTarget::Fd(cgroup_fd),
                *attach_type,
                mode.into(),
                None,
            ) {
                Ok(link_fd) => {
                    data.links
                        .insert(CgroupSockAddrLink::new(CgroupSockAddrLinkInner::Fd(
                            FdLink::new(link_fd),
                        )))
                }
                // Android vendor kernels frequently report a modern release
                // while omitting or restricting cgroup BPF links. The legacy
                // BPF_PROG_ATTACH API is supported by the same cgroup hook and
                // provides equivalent lifetime management through
                // ProgAttachLink.
                Err(io_error) if should_retry_with_prog_attach(&io_error) => {
                    let link = ProgAttachLink::attach(prog_fd, cgroup_fd, *attach_type, mode)?;
                    data.links.insert(CgroupSockAddrLink::new(
                        CgroupSockAddrLinkInner::ProgAttach(link),
                    ))
                }
                Err(io_error) => Err(SyscallError {
                    call: "bpf_link_create",
                    io_error,
                }
                .into()),
            }
        } else {
            let link = ProgAttachLink::attach(prog_fd, cgroup_fd, *attach_type, mode)?;

            data.links.insert(CgroupSockAddrLink::new(
                CgroupSockAddrLinkInner::ProgAttach(link),
            ))
        }
    }

    /// Queries programs and attach flags already present for this program's
    /// socket-address hook on the target cgroup.
    pub fn query<T: AsFd>(&self, cgroup: T) -> Result<(u32, Vec<u32>), ProgramError> {
        let mut attach_flags = Some(0);
        let (_, program_ids) = query(
            ProgQueryTarget::Fd(cgroup.as_fd()),
            self.attach_type,
            0,
            &mut attach_flags,
        )?;
        Ok((attach_flags.unwrap_or_default(), program_ids))
    }

    /// Creates a program from a pinned entry on a bpffs.
    ///
    /// Existing links will not be populated. To work with existing links you should use [`crate::programs::links::PinnedLink`].
    ///
    /// On drop, any managed links are detached and the program is unloaded. This will not result in
    /// the program being unloaded from the kernel if it is still pinned.
    pub fn from_pin<P: AsRef<Path>>(
        path: P,
        attach_type: CgroupSockAddrAttachType,
    ) -> Result<Self, ProgramError> {
        let data = ProgramData::from_pinned_path(path, VerifierLogLevel::default())?;
        Ok(Self { data, attach_type })
    }
}

fn should_retry_with_prog_attach(error: &std::io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(libc::EPERM)
            | Some(libc::EACCES)
            | Some(libc::EINVAL)
            | Some(libc::ENOSYS)
            | Some(libc::EOPNOTSUPP)
    )
}

#[derive(Debug, Hash, Eq, PartialEq)]
enum CgroupSockAddrLinkIdInner {
    Fd(<FdLink as Link>::Id),
    ProgAttach(<ProgAttachLink as Link>::Id),
}

#[derive(Debug)]
enum CgroupSockAddrLinkInner {
    Fd(FdLink),
    ProgAttach(ProgAttachLink),
}

impl Link for CgroupSockAddrLinkInner {
    type Id = CgroupSockAddrLinkIdInner;

    fn id(&self) -> Self::Id {
        match self {
            Self::Fd(fd) => CgroupSockAddrLinkIdInner::Fd(fd.id()),
            Self::ProgAttach(p) => CgroupSockAddrLinkIdInner::ProgAttach(p.id()),
        }
    }

    fn detach(self) -> Result<(), ProgramError> {
        match self {
            Self::Fd(fd) => fd.detach(),
            Self::ProgAttach(p) => p.detach(),
        }
    }
}

id_as_key!(CgroupSockAddrLinkInner, CgroupSockAddrLinkIdInner);

define_link_wrapper!(
    CgroupSockAddrLink,
    CgroupSockAddrLinkId,
    CgroupSockAddrLinkInner,
    CgroupSockAddrLinkIdInner,
    CgroupSockAddr,
);

impl_try_into_fdlink!(CgroupSockAddrLink, CgroupSockAddrLinkInner);
