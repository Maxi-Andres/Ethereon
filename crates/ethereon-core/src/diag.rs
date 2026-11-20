//! Diagnostico de red para la interfaz: ping (ICMP), conexion TCP con el banner del
//! servidor, traceroute y nombres DNS inversos. Solo lo usa la persona desde la app (el
//! test de conexion y el mapa de red); el agente no llega aca.
//!
//! ICMP en Windows va por `IcmpSendEcho` (iphlpapi), que no necesita permisos de
//! administrador y no depende del idioma de Windows como parsear `ping.exe`. Es lo mismo
//! que usan `ping` y `tracert`. En Linux, por sockets ICMP sin root (como `ping` y
//! `tracepath`). Solo IPv4. En otros sistemas el ICMP devuelve `Unsupported` y queda lo de
//! TCP.

use serde::Serialize;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};
use tokio::io::AsyncReadExt;

/// Lo que contesto un paquete ICMP.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Echo {
    /// Contesto el destino.
    Reply { from: Ipv4Addr, ms: f64, ttl: u8 },
    /// Un router del camino avisa que se acabo el TTL (traceroute).
    Expired { from: Ipv4Addr, ms: f64 },
    /// Un router avisa que no hay camino.
    Unreachable { from: Ipv4Addr },
    /// No contesto nadie a tiempo.
    Timeout,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct PingStats {
    pub sent: u32,
    pub received: u32,
    /// Porcentaje de paquetes perdidos (0 a 100).
    pub loss: f64,
    pub min_ms: Option<f64>,
    pub avg_ms: Option<f64>,
    pub max_ms: Option<f64>,
    /// Variacion media entre respuestas seguidas (como la calcula RFC 3550, sin suavizar).
    pub jitter_ms: Option<f64>,
    /// El TTL con el que llego la respuesta: da una idea del sistema (64 Linux, 128
    /// Windows, 255 equipos de red) y de cuantos saltos hay.
    pub ttl: Option<u8>,
    /// Cada paquete, en orden: ms o None si se perdio.
    pub samples: Vec<Option<f64>>,
    /// Si no se pudo hacer ping (por ejemplo, sin ICMP en este sistema).
    pub error: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct TcpProbe {
    pub ok: bool,
    /// Lo que tardo en abrir la conexion (el SYN / SYN-ACK).
    pub connect_ms: Option<f64>,
    /// La primera linea que manda el servidor: `SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13`.
    pub banner: Option<String>,
    pub error: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct TraceHop {
    pub ttl: u8,
    /// La IP del router de este salto; None si no contesto ninguna prueba (`*`).
    pub ip: Option<String>,
    /// El nombre del host del vault que tiene esa IP, si hay uno.
    pub host: Option<String>,
    /// El nombre DNS inverso, si tiene.
    pub dns: Option<String>,
    /// Cada prueba: ms o None si no contesto.
    pub rtts: Vec<Option<f64>>,
    /// Este salto es el destino.
    pub last: bool,
}

/// Una direccion a IPv4 (resuelve nombres). Prefiere IPv4 si el nombre tiene las dos.
pub async fn resolve_v4(host: &str, port: u16) -> std::io::Result<Ipv4Addr> {
    let addrs: Vec<SocketAddr> = tokio::time::timeout(Duration::from_secs(5), tokio::net::lookup_host((host, port)))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "DNS timed out"))??
        .collect();
    addrs
        .iter()
        .find_map(|a| match a.ip() {
            IpAddr::V4(v) => Some(v),
            IpAddr::V6(_) => None,
        })
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::Unsupported, format!("{host} has no IPv4 address")))
}

/// Abre una conexion TCP, mide cuanto tarda y lee la primera linea que manda el servidor.
pub async fn tcp_probe(host: &str, port: u16, timeout: Duration) -> TcpProbe {
    let started = Instant::now();
    let mut s = match tokio::time::timeout(timeout, tokio::net::TcpStream::connect((host, port))).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return TcpProbe { error: Some(e.to_string()), ..Default::default() },
        Err(_) => return TcpProbe { error: Some(format!("no answer on port {port} after {} s", timeout.as_secs())), ..Default::default() },
    };
    let connect_ms = ms(started.elapsed());
    let mut buf = vec![0u8; 512];
    let mut n = 0;
    // El banner llega solo (SSH lo manda apenas se conecta). Se lee hasta el fin de linea.
    let _ = tokio::time::timeout(Duration::from_secs(3), async {
        while n < buf.len() {
            match s.read(&mut buf[n..]).await {
                Ok(0) | Err(_) => break,
                Ok(k) => {
                    n += k;
                    if buf[..n].contains(&b'\n') {
                        break;
                    }
                }
            }
        }
    })
    .await;
    let banner = String::from_utf8_lossy(&buf[..n]).lines().next().map(|l| l.trim().to_string()).filter(|l| !l.is_empty());
    TcpProbe { ok: true, connect_ms: Some(connect_ms), banner, error: None }
}

/// `count` pings, uno por vez, separados por `gap`.
pub async fn ping(ip: Ipv4Addr, count: u32, timeout: Duration, gap: Duration) -> PingStats {
    let mut st = PingStats { sent: count, ..Default::default() };
    for i in 0..count {
        if i > 0 {
            tokio::time::sleep(gap).await;
        }
        match tokio::task::spawn_blocking(move || echo(ip, 128, timeout)).await {
            Ok(Ok(Echo::Reply { ms, ttl, .. })) => {
                st.samples.push(Some(round2(ms)));
                st.ttl = Some(ttl);
            }
            Ok(Ok(_)) => st.samples.push(None),
            Ok(Err(e)) => {
                st.error = Some(e.to_string());
                st.samples.clear();
                break;
            }
            Err(e) => {
                st.error = Some(e.to_string());
                break;
            }
        }
    }
    summarize(&mut st);
    st
}

fn summarize(st: &mut PingStats) {
    let ok: Vec<f64> = st.samples.iter().flatten().copied().collect();
    st.received = ok.len() as u32;
    st.loss = if st.sent == 0 { 0.0 } else { round1(100.0 * (st.sent - st.received) as f64 / st.sent as f64) };
    if ok.is_empty() {
        return;
    }
    st.min_ms = ok.iter().copied().reduce(f64::min).map(round2);
    st.max_ms = ok.iter().copied().reduce(f64::max).map(round2);
    st.avg_ms = Some(round2(ok.iter().sum::<f64>() / ok.len() as f64));
    if ok.len() > 1 {
        let d: f64 = ok.windows(2).map(|w| (w[1] - w[0]).abs()).sum();
        st.jitter_ms = Some(round2(d / (ok.len() - 1) as f64));
    }
}

/// Traceroute: manda `probes` paquetes con TTL 1, 2, 3... hasta que contesta el destino o se
/// llega a `max_hops`. Los TTL van en paralelo (de a `max_hops`), asi tarda lo que el salto
/// mas lento y no la suma. Los saltos despues del destino se descartan.
pub async fn traceroute(ip: Ipv4Addr, max_hops: u8, probes: u8, timeout: Duration) -> std::io::Result<Vec<TraceHop>> {
    // Una prueba para ver si hay ICMP antes de lanzar todo.
    tokio::task::spawn_blocking(move || echo(ip, 1, Duration::from_millis(1))).await.map_err(std::io::Error::other)??;
    let mut tasks = Vec::new();
    for ttl in 1..=max_hops {
        tasks.push(tokio::spawn(async move {
            let mut out: Vec<Echo> = Vec::new();
            for _ in 0..probes {
                let e = tokio::task::spawn_blocking(move || echo(ip, ttl, timeout)).await.ok().and_then(|r| r.ok()).unwrap_or(Echo::Timeout);
                out.push(e);
            }
            (ttl, out)
        }));
    }
    let mut hops = Vec::new();
    for t in tasks {
        let (ttl, echoes) = t.await.map_err(std::io::Error::other)?;
        let mut from = None;
        let mut last = false;
        let rtts = echoes
            .iter()
            .map(|e| match *e {
                Echo::Reply { from: f, ms, .. } => {
                    from = Some(f);
                    last = true;
                    Some(round2(ms))
                }
                Echo::Expired { from: f, ms } => {
                    from.get_or_insert(f);
                    Some(round2(ms))
                }
                Echo::Unreachable { from: f } => {
                    from.get_or_insert(f);
                    last = true;
                    None
                }
                Echo::Timeout => None,
            })
            .collect();
        hops.push(TraceHop { ttl, ip: from.map(|f| f.to_string()), rtts, last, ..Default::default() });
    }
    // Se corta en el primer salto que es el destino (los TTL mayores tambien llegan).
    if let Some(i) = hops.iter().position(|h| h.last) {
        hops.truncate(i + 1);
    } else {
        // Sin llegar: se sacan los `*` del final, salvo uno que muestra que se corto ahi.
        while hops.len() > 1 && hops[hops.len() - 1].ip.is_none() && hops[hops.len() - 2].ip.is_none() {
            hops.pop();
        }
    }
    Ok(hops)
}

/// El nombre DNS inverso de una IP (PTR), o None.
pub async fn reverse_dns(ip: Ipv4Addr) -> Option<String> {
    tokio::time::timeout(Duration::from_secs(2), tokio::task::spawn_blocking(move || sys::reverse(ip)))
        .await
        .ok()?
        .ok()?
        .filter(|n| n != &ip.to_string())
}

fn ms(d: Duration) -> f64 {
    round2(d.as_secs_f64() * 1000.0)
}
fn round2(x: f64) -> f64 {
    (x * 100.0).round() / 100.0
}
fn round1(x: f64) -> f64 {
    (x * 10.0).round() / 10.0
}

/// Un paquete ICMP echo con `ttl`, bloqueante.
pub fn echo(ip: Ipv4Addr, ttl: u8, timeout: Duration) -> std::io::Result<Echo> {
    sys::echo(ip, ttl, timeout)
}

#[cfg(windows)]
mod sys {
    use super::Echo;
    use std::ffi::c_void;
    use std::net::Ipv4Addr;
    use std::time::{Duration, Instant};

    #[repr(C)]
    struct IpOptionInformation {
        ttl: u8,
        tos: u8,
        flags: u8,
        options_size: u8,
        options_data: *mut u8,
    }

    #[repr(C)]
    struct IcmpEchoReply {
        address: u32,
        status: u32,
        round_trip_time: u32,
        data_size: u16,
        reserved: u16,
        data: *mut c_void,
        options: IpOptionInformation,
    }

    #[repr(C)]
    struct SockaddrIn {
        family: u16,
        port: u16,
        addr: [u8; 4],
        zero: [u8; 8],
    }

    #[link(name = "iphlpapi")]
    extern "system" {
        fn IcmpCreateFile() -> *mut c_void;
        fn IcmpCloseHandle(h: *mut c_void) -> i32;
        fn IcmpSendEcho(
            h: *mut c_void,
            dest: u32,
            data: *const c_void,
            size: u16,
            opts: *const IpOptionInformation,
            reply: *mut c_void,
            reply_size: u32,
            timeout: u32,
        ) -> u32;
    }

    #[link(name = "ws2_32")]
    extern "system" {
        fn GetNameInfoW(sa: *const SockaddrIn, salen: i32, host: *mut u16, hostlen: u32, serv: *mut u16, servlen: u32, flags: i32) -> i32;
    }

    // ipexport.h
    const IP_SUCCESS: u32 = 0;
    const IP_DEST_NET_UNREACHABLE: u32 = 11002;
    const IP_DEST_HOST_UNREACHABLE: u32 = 11003;
    const IP_DEST_PROT_UNREACHABLE: u32 = 11004;
    const IP_DEST_PORT_UNREACHABLE: u32 = 11005;
    const IP_TTL_EXPIRED_TRANSIT: u32 = 11013;
    const NI_NAMEREQD: i32 = 0x04;

    struct Handle(*mut c_void);
    impl Drop for Handle {
        fn drop(&mut self) {
            unsafe { IcmpCloseHandle(self.0) };
        }
    }

    pub fn echo(ip: Ipv4Addr, ttl: u8, timeout: Duration) -> std::io::Result<Echo> {
        let h = unsafe { IcmpCreateFile() };
        if h.is_null() || h as isize == -1 {
            return Err(std::io::Error::last_os_error());
        }
        let h = Handle(h);
        let payload = [0x45u8; 32];
        let opts = IpOptionInformation { ttl, tos: 0, flags: 0, options_size: 0, options_data: std::ptr::null_mut() };
        // La respuesta + el payload + 8 bytes de un posible error ICMP (lo pide la doc).
        let mut buf = vec![0u8; std::mem::size_of::<IcmpEchoReply>() + payload.len() + 8 + 64];
        let started = Instant::now();
        let n = unsafe {
            IcmpSendEcho(
                h.0,
                u32::from_ne_bytes(ip.octets()),
                payload.as_ptr() as *const c_void,
                payload.len() as u16,
                &opts,
                buf.as_mut_ptr() as *mut c_void,
                buf.len() as u32,
                timeout.as_millis().clamp(1, u32::MAX as u128) as u32,
            )
        };
        let took = started.elapsed().as_secs_f64() * 1000.0;
        // Con TTL vencido o destino inalcanzable, IcmpSendEcho puede devolver 0 pero dejar
        // la respuesta del router en el buffer: se lee igual.
        let r = unsafe { std::ptr::read_unaligned(buf.as_ptr() as *const IcmpEchoReply) };
        let from = Ipv4Addr::from(r.address.to_ne_bytes());
        // RoundTripTime es en ms enteros (0 si fue menos de 1 ms): se usa el reloj propio,
        // que tiene decimales, salvo que el del sistema sea mayor (el propio no puede ser menor).
        let ms = took.max(r.round_trip_time as f64);
        if n == 0 && r.address == 0 {
            return Ok(Echo::Timeout);
        }
        Ok(match r.status {
            IP_SUCCESS if n > 0 => Echo::Reply { from, ms, ttl: r.options.ttl },
            IP_TTL_EXPIRED_TRANSIT => Echo::Expired { from, ms },
            IP_DEST_NET_UNREACHABLE | IP_DEST_HOST_UNREACHABLE | IP_DEST_PROT_UNREACHABLE | IP_DEST_PORT_UNREACHABLE => Echo::Unreachable { from },
            _ => Echo::Timeout,
        })
    }

    pub fn reverse(ip: Ipv4Addr) -> Option<String> {
        // Winsock tiene que estar iniciado; std lo inicia al crear el primer socket.
        let _ = std::net::UdpSocket::bind("0.0.0.0:0");
        let sa = SockaddrIn { family: 2, port: 0, addr: ip.octets(), zero: [0; 8] };
        let mut host = [0u16; 1025];
        let rc = unsafe {
            GetNameInfoW(&sa, std::mem::size_of::<SockaddrIn>() as i32, host.as_mut_ptr(), host.len() as u32, std::ptr::null_mut(), 0, NI_NAMEREQD)
        };
        if rc != 0 {
            return None;
        }
        let len = host.iter().position(|&c| c == 0).unwrap_or(host.len());
        Some(String::from_utf16_lossy(&host[..len]))
    }
}

/// Linux: sockets ICMP "ping" (SOCK_DGRAM + IPPROTO_ICMP), que no necesitan root si el
/// grupo del usuario esta en `net.ipv4.ping_group_range` (asi viene en Ubuntu, Debian,
/// Fedora y casi todas las de systemd). El kernel arma el identificador y filtra las
/// respuestas de este socket. Los avisos de los routers (TTL vencido, inalcanzable) llegan
/// por la cola de errores (`IP_RECVERR`), como en `tracepath`.
#[cfg(target_os = "linux")]
mod sys {
    use super::Echo;
    use std::io;
    use std::mem::{size_of, zeroed};
    use std::net::Ipv4Addr;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::sync::atomic::{AtomicU16, Ordering};
    use std::time::{Duration, Instant};

    static SEQ: AtomicU16 = AtomicU16::new(1);

    fn setopt(fd: i32, level: i32, name: i32, value: libc::c_int) -> io::Result<()> {
        let r = unsafe { libc::setsockopt(fd, level, name, &value as *const _ as *const libc::c_void, size_of::<libc::c_int>() as libc::socklen_t) };
        if r < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn from_sockaddr(sa: &libc::sockaddr_in) -> Ipv4Addr {
        Ipv4Addr::from(sa.sin_addr.s_addr.to_ne_bytes())
    }

    pub fn echo(ip: Ipv4Addr, ttl: u8, timeout: Duration) -> io::Result<Echo> {
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, libc::IPPROTO_ICMP) };
        if fd < 0 {
            let e = io::Error::last_os_error();
            return Err(match e.raw_os_error() {
                Some(libc::EACCES) | Some(libc::EPERM) | Some(libc::EPROTONOSUPPORT) => io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "this user can't send ping: allow it with `sudo sysctl -w net.ipv4.ping_group_range=\"0 2147483647\"`",
                ),
                _ => e,
            });
        }
        let sock = unsafe { OwnedFd::from_raw_fd(fd) };
        let fd = sock.as_raw_fd();
        setopt(fd, libc::IPPROTO_IP, libc::IP_TTL, ttl as libc::c_int)?;
        setopt(fd, libc::IPPROTO_IP, libc::IP_RECVERR, 1)?;
        setopt(fd, libc::IPPROTO_IP, libc::IP_RECVTTL, 1)?;

        // Echo request: tipo 8, codigo 0; el kernel pone el identificador y el checksum.
        let seq = SEQ.fetch_add(1, Ordering::Relaxed);
        let mut pkt = [0x45u8; 8 + 32];
        pkt[..8].copy_from_slice(&[8, 0, 0, 0, 0, 0, 0, 0]);
        pkt[6..8].copy_from_slice(&seq.to_be_bytes());
        let mut to: libc::sockaddr_in = unsafe { zeroed() };
        to.sin_family = libc::AF_INET as libc::sa_family_t;
        to.sin_addr.s_addr = u32::from_ne_bytes(ip.octets());
        let started = Instant::now();
        let sent = unsafe {
            libc::sendto(fd, pkt.as_ptr() as *const libc::c_void, pkt.len(), 0, &to as *const _ as *const libc::sockaddr, size_of::<libc::sockaddr_in>() as libc::socklen_t)
        };
        if sent < 0 {
            let e = io::Error::last_os_error();
            // Sin ruta (red caida): para el traceroute es "no contesto".
            if matches!(e.raw_os_error(), Some(libc::ENETUNREACH) | Some(libc::EHOSTUNREACH)) {
                return Ok(Echo::Timeout);
            }
            return Err(e);
        }

        let mut buf = [0u8; 1500];
        let mut ctrl = [0u8; 512];
        loop {
            let left = timeout.saturating_sub(started.elapsed());
            if left.is_zero() {
                return Ok(Echo::Timeout);
            }
            let mut pfd = libc::pollfd { fd, events: libc::POLLIN, revents: 0 };
            let r = unsafe { libc::poll(&mut pfd, 1, left.as_millis().clamp(1, i32::MAX as u128) as i32) };
            if r < 0 {
                let e = io::Error::last_os_error();
                if e.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(e);
            }
            if r == 0 {
                return Ok(Echo::Timeout);
            }
            let errq = pfd.revents & libc::POLLERR != 0;
            let mut from: libc::sockaddr_in = unsafe { zeroed() };
            let mut iov = libc::iovec { iov_base: buf.as_mut_ptr() as *mut libc::c_void, iov_len: buf.len() };
            let mut msg: libc::msghdr = unsafe { zeroed() };
            msg.msg_name = &mut from as *mut _ as *mut libc::c_void;
            msg.msg_namelen = size_of::<libc::sockaddr_in>() as libc::socklen_t;
            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1;
            msg.msg_control = ctrl.as_mut_ptr() as *mut libc::c_void;
            msg.msg_controllen = ctrl.len() as _;
            let n = unsafe { libc::recvmsg(fd, &mut msg, if errq { libc::MSG_ERRQUEUE } else { 0 }) };
            if n < 0 {
                let e = io::Error::last_os_error();
                if matches!(e.kind(), io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock) {
                    continue;
                }
                return Err(e);
            }
            let ms = started.elapsed().as_secs_f64() * 1000.0;
            let n = n as usize;
            // En los dos casos el paquete trae la cabecera ICMP: la nuestra (en la cola de
            // errores) o la respuesta. Que sea de este envio.
            if n < 8 || buf[6..8] != seq.to_be_bytes() {
                continue;
            }
            let mut reply_ttl = 0u8;
            let mut err: Option<(libc::sock_extended_err, Ipv4Addr)> = None;
            unsafe {
                let mut c = libc::CMSG_FIRSTHDR(&msg);
                while !c.is_null() {
                    let h = &*c;
                    if h.cmsg_level == libc::IPPROTO_IP && h.cmsg_type == libc::IP_TTL {
                        reply_ttl = std::ptr::read_unaligned(libc::CMSG_DATA(c) as *const libc::c_int) as u8;
                    } else if h.cmsg_level == libc::IPPROTO_IP && h.cmsg_type == libc::IP_RECVERR {
                        let ee = std::ptr::read_unaligned(libc::CMSG_DATA(c) as *const libc::sock_extended_err);
                        // El que aviso (SO_EE_OFFENDER) va justo despues de la estructura.
                        let off = std::ptr::read_unaligned((libc::CMSG_DATA(c) as *const libc::sock_extended_err).add(1) as *const libc::sockaddr_in);
                        err = Some((ee, from_sockaddr(&off)));
                    }
                    c = libc::CMSG_NXTHDR(&msg, c);
                }
            }
            if errq {
                let Some((ee, who)) = err else { continue };
                if ee.ee_origin != libc::SO_EE_ORIGIN_ICMP {
                    continue;
                }
                return Ok(match ee.ee_type {
                    11 => Echo::Expired { from: who, ms },
                    3 => Echo::Unreachable { from: who },
                    _ => continue,
                });
            }
            // Echo reply: tipo 0.
            if buf[0] == 0 {
                return Ok(Echo::Reply { from: from_sockaddr(&from), ms, ttl: reply_ttl });
            }
        }
    }

    pub fn reverse(ip: Ipv4Addr) -> Option<String> {
        let mut sa: libc::sockaddr_in = unsafe { zeroed() };
        sa.sin_family = libc::AF_INET as libc::sa_family_t;
        sa.sin_addr.s_addr = u32::from_ne_bytes(ip.octets());
        let mut host = [0 as libc::c_char; 1025];
        let rc = unsafe {
            libc::getnameinfo(
                &sa as *const _ as *const libc::sockaddr,
                size_of::<libc::sockaddr_in>() as libc::socklen_t,
                host.as_mut_ptr(),
                host.len() as libc::socklen_t,
                std::ptr::null_mut(),
                0,
                libc::NI_NAMEREQD,
            )
        };
        if rc != 0 {
            return None;
        }
        let s = unsafe { std::ffi::CStr::from_ptr(host.as_ptr()) };
        Some(s.to_string_lossy().into_owned())
    }
}

#[cfg(not(any(windows, target_os = "linux")))]
mod sys {
    use super::Echo;
    use std::net::Ipv4Addr;
    use std::time::Duration;

    pub fn echo(_ip: Ipv4Addr, _ttl: u8, _timeout: Duration) -> std::io::Result<Echo> {
        Err(std::io::Error::new(std::io::ErrorKind::Unsupported, "ICMP is only available on Windows and Linux for now"))
    }

    pub fn reverse(_ip: Ipv4Addr) -> Option<String> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stats() {
        let mut st = PingStats { sent: 4, samples: vec![Some(10.0), None, Some(14.0), Some(12.0)], ..Default::default() };
        summarize(&mut st);
        assert_eq!(st.received, 3);
        assert_eq!(st.loss, 25.0);
        assert_eq!(st.min_ms, Some(10.0));
        assert_eq!(st.max_ms, Some(14.0));
        assert_eq!(st.avg_ms, Some(12.0));
        assert_eq!(st.jitter_ms, Some(3.0));
    }

    #[test]
    fn all_lost() {
        let mut st = PingStats { sent: 3, samples: vec![None, None, None], ..Default::default() };
        summarize(&mut st);
        assert_eq!(st.loss, 100.0);
        assert_eq!(st.avg_ms, None);
    }

    #[tokio::test]
    async fn tcp_closed_port() {
        // Un puerto local que nadie escucha: falla rapido y con error.
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        drop(l);
        let p = tcp_probe("127.0.0.1", port, Duration::from_secs(2)).await;
        assert!(!p.ok);
        assert!(p.error.is_some());
    }

    #[tokio::test]
    async fn tcp_banner() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            use tokio::io::AsyncWriteExt;
            s.write_all(b"SSH-2.0-Test_1.0\r\n").await.unwrap();
            tokio::time::sleep(Duration::from_millis(200)).await;
        });
        let p = tcp_probe("127.0.0.1", port, Duration::from_secs(2)).await;
        assert!(p.ok);
        assert_eq!(p.banner.as_deref(), Some("SSH-2.0-Test_1.0"));
    }

    /// Contra internet: `cargo test -p ethereon-core diag -- --ignored --nocapture`.
    #[cfg(any(windows, target_os = "linux"))]
    #[tokio::test]
    #[ignore]
    async fn trace_internet() {
        let ip = resolve_v4("one.one.one.one", 443).await.unwrap();
        let st = ping(ip, 3, Duration::from_secs(2), Duration::from_millis(200)).await;
        println!("ping {ip}: {st:?}");
        let hops = traceroute(ip, 30, 3, Duration::from_millis(1500)).await.unwrap();
        for h in &hops {
            let dns = match h.ip.as_deref().and_then(|s| s.parse().ok()) {
                Some(ip) => reverse_dns(ip).await,
                None => None,
            };
            println!("{:>2} {:<16} {:?} {:?}", h.ttl, h.ip.as_deref().unwrap_or("*"), h.rtts, dns);
        }
        assert!(hops.last().unwrap().last, "did not reach {ip}");
    }

    #[cfg(any(windows, target_os = "linux"))]
    #[test]
    fn ping_localhost() {
        match echo(Ipv4Addr::LOCALHOST, 64, Duration::from_secs(1)) {
            Ok(e) => assert!(matches!(e, Echo::Reply { .. }), "{e:?}"),
            // Un Linux que no deja ping sin root (ping_group_range): no es un error del codigo.
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => eprintln!("ping not allowed here: {e}"),
            Err(e) => panic!("{e}"),
        }
    }
}
