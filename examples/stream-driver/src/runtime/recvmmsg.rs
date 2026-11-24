//! Batched UDP receive on Linux: `recvmmsg(2)`, several datagrams per system call.

use super::RecvMeta;
use std::io::{self, IoSliceMut};
use std::mem::{MaybeUninit, size_of};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::fd::RawFd;

/// The most datagrams one call takes.
pub(crate) const BATCH: usize = 32;

/// Receives up to `bufs.len()` (at most [`BATCH`]) datagrams from the non-blocking socket
/// `fd` without waiting: how many, with `meta` filled alongside. `WouldBlock` when none is
/// waiting.
pub(crate) fn recv(
    fd: RawFd,
    bufs: &mut [IoSliceMut<'_>],
    meta: &mut [RecvMeta],
) -> io::Result<usize> {
    let n = bufs.len().min(meta.len()).min(BATCH);
    if n == 0 {
        return Ok(0);
    }
    // SAFETY: all-zero is a valid value of these plain C structures.
    let mut names: [libc::sockaddr_storage; BATCH] = unsafe { MaybeUninit::zeroed().assume_init() };
    let mut iovecs: [libc::iovec; BATCH] = unsafe { MaybeUninit::zeroed().assume_init() };
    let mut headers: [libc::mmsghdr; BATCH] = unsafe { MaybeUninit::zeroed().assume_init() };
    for i in 0..n {
        iovecs[i] = libc::iovec {
            iov_base: bufs[i].as_mut_ptr().cast(),
            iov_len: bufs[i].len(),
        };
        headers[i].msg_hdr.msg_name = (&raw mut names[i]).cast();
        headers[i].msg_hdr.msg_namelen = size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        headers[i].msg_hdr.msg_iov = &raw mut iovecs[i];
        headers[i].msg_hdr.msg_iovlen = 1;
    }
    // SAFETY: the headers point at `n` live buffers, iovecs and address slots, each valid for
    // the length given; the kernel writes no further.
    let received = unsafe {
        libc::recvmmsg(
            fd,
            headers.as_mut_ptr(),
            n as libc::c_uint,
            libc::MSG_DONTWAIT,
            std::ptr::null_mut(),
        )
    };
    if received < 0 {
        return Err(io::Error::last_os_error());
    }
    let received = received as usize;
    for i in 0..received {
        let len = headers[i].msg_len as usize;
        meta[i] = RecvMeta {
            addr: socket_addr(&names[i])
                .unwrap_or_else(|| SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0)),
            len,
            stride: len,
            ecn: None,
            dst_ip: None,
        };
    }
    Ok(received)
}

fn socket_addr(storage: &libc::sockaddr_storage) -> Option<SocketAddr> {
    match i32::from(storage.ss_family) {
        libc::AF_INET => {
            // SAFETY: the family says the storage holds a sockaddr_in.
            let v4 =
                unsafe { &*(storage as *const libc::sockaddr_storage).cast::<libc::sockaddr_in>() };
            Some(SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::from(u32::from_be(v4.sin_addr.s_addr)),
                u16::from_be(v4.sin_port),
            )))
        }
        libc::AF_INET6 => {
            // SAFETY: the family says the storage holds a sockaddr_in6.
            let v6 = unsafe {
                &*(storage as *const libc::sockaddr_storage).cast::<libc::sockaddr_in6>()
            };
            Some(SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::from(v6.sin6_addr.s6_addr),
                u16::from_be(v6.sin6_port),
                u32::from_be(v6.sin6_flowinfo),
                v6.sin6_scope_id,
            )))
        }
        _ => None,
    }
}
