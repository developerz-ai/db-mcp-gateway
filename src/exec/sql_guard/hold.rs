//! For tests: the guard holds a statement until the test lets it go, so a
//! test can act while a guarded parse is in progress.

use std::sync::mpsc::{Receiver, SyncSender, sync_channel};
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

/// Long enough for any test; a held statement is let go after it regardless.
const AT_MOST: Duration = Duration::from_secs(60);

type Held = (String, SyncSender<()>, Receiver<()>);

static HELD: Mutex<Vec<Held>> = Mutex::new(Vec::new());

/// A hold on the next guarded statement that contains `marker`. Dropping it
/// lets the statement go, or forgets the marker if none came.
#[derive(Debug)]
pub struct Hold {
    /// Receives once the statement is held: its parse has started.
    pub entered: Receiver<()>,
    marker: String,
    _release: SyncSender<()>,
}

impl Drop for Hold {
    fn drop(&mut self) {
        let mut list = HELD.lock().unwrap_or_else(PoisonError::into_inner);
        list.retain(|(marker, ..)| *marker != self.marker);
    }
}

pub fn hold(marker: &str) -> Hold {
    let (entered, held) = sync_channel(1);
    let (release, released) = sync_channel(1);
    let mut list = HELD.lock().unwrap_or_else(PoisonError::into_inner);
    list.push((marker.to_owned(), entered, released));
    Hold {
        entered: held,
        marker: marker.to_owned(),
        _release: release,
    }
}

pub(super) fn wait_if_held(sql: &str) {
    let found = {
        let mut list = HELD.lock().unwrap_or_else(PoisonError::into_inner);
        let at = list
            .iter()
            .position(|(marker, ..)| sql.contains(marker.as_str()));
        at.map(|at| list.swap_remove(at))
    };
    if let Some((_, entered, released)) = found {
        let _ = entered.send(());
        let _ = released.recv_timeout(AT_MOST);
    }
}
