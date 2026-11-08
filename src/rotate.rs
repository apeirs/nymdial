//! Trying exits in order until one gives a working tunnel.
//!
//! Kept generic over "what establishing means" so the rotation logic is tested without a network.

use std::future::Future;
use std::time::Duration;

use tokio::time::Instant;

use serde::Serialize;

use crate::exits::Exit;
use crate::Error;

/// What happened with one exit.
#[derive(Debug, Clone, Serialize)]
pub struct Attempt {
    pub node_id: u32,
    pub label: String,
    pub elapsed: Duration,
    /// `None` = this exit worked.
    pub error: Option<String>,
}

/// Try `establish` on the candidates in order, at most `max_attempts` of them, each bounded by `per_attempt`.
/// Returns the first success with its exit, and the log of every attempt.
///
/// An attempt that runs past its budget is not cancelled half-way (nym-sdk has no async drop, and a mixnet
/// client dropped mid-handshake can leave tasks behind). It keeps running in the background and is handed to
/// `reap` when it finishes, so a late success can be shut down cleanly instead of leaking.
pub async fn first_working<T, F, Fut, R, RFut>(
    candidates: &[Exit],
    max_attempts: usize,
    per_attempt: Duration,
    mut establish: F,
    reap: R,
    log: &mut Vec<Attempt>,
) -> Result<(T, Exit), Error>
where
    T: Send + 'static,
    F: FnMut(Exit) -> Fut,
    Fut: Future<Output = Result<T, String>> + Send + 'static,
    R: Fn(T) -> RFut + Clone + Send + Sync + 'static,
    RFut: Future<Output = ()> + Send + 'static,
{
    if candidates.is_empty() {
        return Err(Error::NoExit("the candidate list is empty".into()));
    }
    let mut last = String::from("nothing tried");
    let mut tried = 0;
    for exit in candidates.iter().take(max_attempts.max(1)) {
        tried += 1;
        let start = Instant::now();
        let mut handle = tokio::spawn(establish(exit.clone()));
        let outcome = match tokio::time::timeout(per_attempt, &mut handle).await {
            Ok(Ok(Ok(t))) => Ok(t),
            Ok(Ok(Err(e))) => Err(e),
            Ok(Err(join)) => Err(format!("task failed: {join}")),
            Err(_) => {
                let reap = reap.clone();
                tokio::spawn(async move {
                    if let Ok(Ok(t)) = handle.await {
                        reap(t).await;
                    }
                });
                Err(format!("no answer within {per_attempt:?}"))
            }
        };
        let elapsed = start.elapsed();
        match outcome {
            Ok(t) => {
                tracing::info!("{}: tunnel up in {elapsed:.1?}", exit.label());
                log.push(Attempt { node_id: exit.node_id, label: exit.label(), elapsed, error: None });
                return Ok((t, exit.clone()));
            }
            Err(e) => {
                tracing::warn!("{}: {e} after {elapsed:.1?}; trying the next exit", exit.label());
                log.push(Attempt { node_id: exit.node_id, label: exit.label(), elapsed, error: Some(e.clone()) });
                last = format!("{}: {e}", exit.label());
            }
        }
    }
    Err(Error::ExitsExhausted { attempts: tried, last })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    fn exit(id: u32) -> Exit {
        Exit {
            node_id: id,
            identity: format!("id{id}"),
            ipr_address: format!("c.e@id{id}"),
            performance: 0.9,
            version: "1.43.0".into(),
            country: None,
            ips: vec![],
        }
    }

    // Exit 1 hangs forever, exit 2 fails fast, exit 3 works.
    async fn fake(e: Exit) -> Result<u32, String> {
        match e.node_id {
            1 => std::future::pending().await,
            2 => Err("handshake refused".into()),
            3 => {
                tokio::time::sleep(Duration::from_secs(3)).await;
                Ok(3)
            }
            4 => {
                // answers, but only after the budget
                tokio::time::sleep(Duration::from_secs(50)).await;
                Ok(4)
            }
            _ => unreachable!(),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn skips_a_dead_and_a_failing_exit() {
        let mut log = vec![];
        let (t, e) = first_working(&[exit(1), exit(2), exit(3)], 5, Duration::from_secs(20), fake, |_| async {}, &mut log)
            .await
            .unwrap();
        assert_eq!((t, e.node_id), (3, 3));
        assert_eq!(log.len(), 3);
        assert!(log[0].error.as_deref().unwrap().contains("no answer"));
        assert!(log[0].elapsed >= Duration::from_secs(20) && log[0].elapsed < Duration::from_secs(21));
        assert_eq!(log[1].error.as_deref(), Some("handshake refused"));
        assert!(log[1].elapsed < Duration::from_secs(1));
        assert!(log[2].error.is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn stops_after_max_attempts() {
        let mut log = vec![];
        let r = first_working(&[exit(1), exit(2), exit(3)], 2, Duration::from_secs(20), fake, |_| async {}, &mut log).await;
        match r {
            Err(Error::ExitsExhausted { attempts: 2, last }) => assert!(last.contains("handshake refused")),
            other => panic!("{other:?}"),
        }
        assert_eq!(log.len(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn a_late_success_is_reaped_not_leaked() {
        let reaped = Arc::new(AtomicUsize::new(0));
        let r2 = reaped.clone();
        let mut log = vec![];
        let (t, _) = first_working(
            &[exit(4), exit(3)],
            5,
            Duration::from_secs(20),
            fake,
            move |t| {
                let r2 = r2.clone();
                async move {
                    r2.store(t as usize, Ordering::SeqCst);
                }
            },
            &mut log,
        )
        .await
        .unwrap();
        assert_eq!(t, 3);
        assert_eq!(reaped.load(Ordering::SeqCst), 0);
        tokio::time::sleep(Duration::from_secs(60)).await;
        assert_eq!(reaped.load(Ordering::SeqCst), 4, "exit 4's late tunnel must be handed to reap");
    }

    #[tokio::test]
    async fn empty_list_is_an_error() {
        let mut log = vec![];
        let r = first_working(&[], 5, Duration::from_secs(1), fake, |_| async {}, &mut log).await;
        assert!(matches!(r, Err(Error::NoExit(_))));
    }
}
