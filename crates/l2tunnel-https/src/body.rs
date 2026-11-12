use bytes::{Buf, Bytes};
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
};
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Observation only of maintained h2's own outgoing frames on stream1. This
/// never constructs/parses peer HTTP or substitutes for maintained HTTP framing.
/// A control-only or earlier flush cannot satisfy a later DATA staging target.
#[derive(Default)]
pub(crate) struct Witness {
    data: AtomicU64,
    end: AtomicBool,
    work: AtomicUsize,
}
impl Witness {
    pub(crate) fn reset(&self) {
        self.work.store(64, Ordering::Relaxed);
    }
    fn permit(&self, cx: &Context<'_>) -> bool {
        if self
            .work
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_sub(1))
            .is_ok()
        {
            true
        } else {
            cx.waker().wake_by_ref();
            false
        }
    }
}
struct Wire {
    preface: usize,
    header: [u8; 9],
    head: usize,
    left: usize,
    data: bool,
    end_frame: bool,
    bytes: u64,
    ended: bool,
}
impl Wire {
    fn new(client: bool) -> Self {
        Self {
            preface: if client { 24 } else { 0 },
            header: [0; 9],
            head: 0,
            left: 0,
            data: false,
            end_frame: false,
            bytes: 0,
            ended: false,
        }
    }
    fn observe(&mut self, mut bytes: &[u8]) -> io::Result<()> {
        if self.preface > 0 {
            let n = self.preface.min(bytes.len());
            self.preface -= n;
            bytes = &bytes[n..];
        }
        while !bytes.is_empty() {
            if self.head < 9 {
                let n = (9 - self.head).min(bytes.len());
                self.header[self.head..self.head + n].copy_from_slice(&bytes[..n]);
                self.head += n;
                bytes = &bytes[n..];
                if self.head < 9 {
                    continue;
                }
                self.left = ((self.header[0] as usize) << 16)
                    | ((self.header[1] as usize) << 8)
                    | self.header[2] as usize;
                self.data = self.header[3] == 0 && self.header[5..9] == [0, 0, 0, 1];
                if self.data && self.header[4] & 8 != 0 {
                    return Err(io::Error::other("unexpected locally padded DATA"));
                }
                self.end_frame = self.data && self.header[4] & 1 != 0;
            }
            let n = self.left.min(bytes.len());
            if self.data {
                self.bytes = self
                    .bytes
                    .checked_add(n as u64)
                    .ok_or_else(|| io::Error::other("HTTPS DATA count exhausted"))?;
            }
            self.left -= n;
            bytes = &bytes[n..];
            if self.left == 0 {
                self.ended |= self.end_frame;
                self.head = 0;
            }
        }
        Ok(())
    }
}
pub(crate) struct FlushIo<I> {
    io: I,
    witness: Arc<Witness>,
    wire: Wire,
}
impl<I> FlushIo<I> {
    pub(crate) fn new(io: I, client: bool) -> (Self, Arc<Witness>) {
        let witness = Arc::new(Witness::default());
        witness.reset();
        (
            Self {
                io,
                witness: witness.clone(),
                wire: Wire::new(client),
            },
            witness,
        )
    }
}
impl<I: AsyncRead + Unpin> AsyncRead for FlushIo<I> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.witness.permit(cx) {
            return Poll::Pending;
        }
        Pin::new(&mut self.io).poll_read(cx, out)
    }
}
impl<I: AsyncWrite + Unpin> AsyncWrite for FlushIo<I> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        if !self.witness.permit(cx) {
            return Poll::Pending;
        }
        match Pin::new(&mut self.io).poll_write(cx, data) {
            Poll::Ready(Ok(n)) => {
                if n > data.len() {
                    return Poll::Ready(Err(io::Error::other("invalid TLS write count")));
                }
                if n == 0 && !data.is_empty() {
                    return Poll::Ready(Err(io::Error::from(io::ErrorKind::WriteZero)));
                }
                self.wire.observe(&data[..n])?;
                Poll::Ready(Ok(n))
            }
            other => other,
        }
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !self.witness.permit(cx) {
            return Poll::Pending;
        }
        match Pin::new(&mut self.io).poll_flush(cx) {
            Poll::Ready(Ok(())) => {
                self.witness.data.store(self.wire.bytes, Ordering::Relaxed);
                self.witness.end.store(self.wire.ended, Ordering::Relaxed);
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

pub(crate) enum Driver<I> {
    Client(h2::client::Connection<I, Bytes>, Arc<Witness>),
    Server(h2::server::Connection<I, Bytes>, Arc<Witness>),
}
impl<I: AsyncRead + AsyncWrite + Unpin> Driver<I> {
    pub(crate) fn poll(&mut self, cx: &mut Context<'_>) -> io::Result<()> {
        match self {
            Self::Client(_, w) | Self::Server(_, w) => w.reset(),
        };
        match self {
            Self::Client(c, _) => match Pin::new(c).poll(cx) {
                Poll::Pending => Ok(()),
                Poll::Ready(Ok(())) => Err(io::Error::from(io::ErrorKind::UnexpectedEof)),
                Poll::Ready(Err(e)) => Err(io::Error::other(e)),
            },
            Self::Server(c, _) => match c.poll_accept(cx) {
                Poll::Pending => Ok(()),
                Poll::Ready(Some(Ok(_))) => Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "second HTTPS stream",
                )),
                Poll::Ready(Some(Err(e))) => Err(io::Error::other(e)),
                Poll::Ready(None) => Err(io::Error::from(io::ErrorKind::UnexpectedEof)),
            },
        }
    }
}

pub(crate) struct Body<I> {
    pub(crate) driver: Driver<I>,
    pub(crate) send: h2::SendStream<Bytes>,
    pub(crate) recv: h2::RecvStream,
    chunk: Bytes,
    pub(crate) held: usize,
    pub(crate) hold: bool,
    generation: Arc<Witness>,
    staged: u64,
    shutdown: bool,
}
impl<I: AsyncRead + AsyncWrite + Unpin> Body<I> {
    pub(crate) fn new(
        driver: Driver<I>,
        send: h2::SendStream<Bytes>,
        recv: h2::RecvStream,
        generation: Arc<Witness>,
    ) -> Self {
        Self {
            driver,
            send,
            recv,
            chunk: Bytes::new(),
            held: 0,
            hold: false,
            generation,
            staged: 0,
            shutdown: false,
        }
    }
    pub(crate) fn release(&mut self) -> io::Result<()> {
        self.recv
            .flow_control()
            .release_capacity(self.held)
            .map_err(io::Error::other)?;
        self.held = 0;
        Ok(())
    }
}
impl<I: AsyncRead + AsyncWrite + Unpin> AsyncRead for Body<I> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.driver.poll(cx)?;
        if out.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if self.chunk.is_empty() {
            match self.recv.poll_data(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Some(Ok(chunk))) => self.chunk = chunk,
                Poll::Ready(Some(Err(e))) => return Poll::Ready(Err(io::Error::other(e))),
                Poll::Ready(None) => {
                    return Poll::Ready(Err(io::Error::from(io::ErrorKind::UnexpectedEof)));
                }
            }
            if self.chunk.is_empty() {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
        }
        let n = out.remaining().min(self.chunk.len());
        out.put_slice(&self.chunk[..n]);
        self.chunk.advance(n);
        if self.hold {
            self.held = self
                .held
                .checked_add(n)
                .ok_or_else(|| io::Error::other("HTTPS receive bound"))?;
        } else {
            self.recv
                .flow_control()
                .release_capacity(n)
                .map_err(io::Error::other)?;
        }
        Poll::Ready(Ok(()))
    }
}
impl<I: AsyncRead + AsyncWrite + Unpin> AsyncWrite for Body<I> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.driver.poll(cx)?;
        if self.shutdown {
            return Poll::Ready(Err(io::Error::from(io::ErrorKind::BrokenPipe)));
        }
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        self.send.reserve_capacity(data.len().min(16384));
        let capacity = match self.send.poll_capacity(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Some(Ok(n))) if n > 0 => n,
            Poll::Ready(Some(Ok(_))) => {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            Poll::Ready(Some(Err(e))) => return Poll::Ready(Err(io::Error::other(e))),
            Poll::Ready(None) => {
                return Poll::Ready(Err(io::Error::from(io::ErrorKind::BrokenPipe)));
            }
        };
        let n = data.len().min(capacity).min(16384);
        self.staged = self
            .staged
            .checked_add(n as u64)
            .ok_or_else(|| io::Error::other("HTTPS DATA count exhausted"))?;
        self.send
            .send_data(Bytes::copy_from_slice(&data[..n]), false)
            .map_err(io::Error::other)?;
        self.driver.poll(cx)?;
        Poll::Ready(Ok(n))
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.driver.poll(cx)?;
        if self.generation.data.load(Ordering::Relaxed) >= self.staged
            && (!self.shutdown || self.generation.end.load(Ordering::Relaxed))
        {
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !self.shutdown {
            self.send
                .send_data(Bytes::new(), true)
                .map_err(io::Error::other)?;
            self.shutdown = true;
        }
        self.as_mut().poll_flush(cx)
    }
}

#[cfg(test)]
#[path = "body_tests.rs"]
mod tests;
