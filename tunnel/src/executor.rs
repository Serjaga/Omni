
use std::future::Future;
use tokio::runtime::Handle;
use tokio::task::AbortHandle;

pub trait TokioExecutorRef: Clone + Send + Sync + 'static {
    fn spawn<F>(&self, f: F) -> AbortHandle
    where F: Future + Send + 'static, F::Output: Send + 'static;
}

#[derive(Clone)]
pub struct DefaultTokioExecutor { handle: Handle }

impl DefaultTokioExecutor { pub fn new(handle: Handle) -> Self { Self { handle } } }
impl Default for DefaultTokioExecutor { fn default() -> Self { Self::new(Handle::current()) } }

impl TokioExecutorRef for DefaultTokioExecutor {
    fn spawn<F>(&self, f: F) -> AbortHandle
    where F: Future + Send + 'static, F::Output: Send + 'static { self.handle.spawn(f).abort_handle() }
}
