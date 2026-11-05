//! The fallback to Link requests and Resources through Python RNS, with feature
//! `reticulum-py`: an embedded interpreter runs a Reticulum instance of its own, from its own
//! config directory, and `pigeonhole_rns.rnsio.Links` identified with this replica's identity,
//! to reach replicas that do not serve the replica paths in mode 2. The Python packages `RNS`
//! and `pigeonhole_rns` must be importable by the Python this was built against
//! (`PYO3_PYTHON`); a virtual environment named by `VIRTUAL_ENV` is added to its path.

use std::path::Path;
use std::sync::Arc;

use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict};

pub struct PyLinks(Arc<Py<PyAny>>);

impl PyLinks {
    /// Starts Reticulum from `config_dir` and the replica's Links. Reticulum starts only on
    /// Python's main thread, the thread that first uses Python, so call this first. Its signal
    /// handlers are put back to the defaults, which Python would run only while that thread
    /// runs Python.
    pub fn start(config_dir: &Path, identity_file: &Path) -> PyResult<PyLinks> {
        Python::attach(|py| {
            if let Ok(venv) = std::env::var("VIRTUAL_ENV") {
                let v = py.version_info();
                let dir = format!("{venv}/lib/python{}.{}/site-packages", v.major, v.minor);
                py.import("site")?.call_method1("addsitedir", (dir,))?;
            }
            let rns = py.import("RNS")?;
            let kw = PyDict::new(py);
            kw.set_item("loglevel", rns.getattr("LOG_ERROR")?)?;
            rns.getattr("Reticulum")?.call((config_dir.to_string_lossy().into_owned(),), Some(&kw))?;
            let signal = py.import("signal")?;
            for s in ["SIGINT", "SIGTERM"] {
                signal.call_method1("signal", (signal.getattr(s)?, signal.getattr("SIG_DFL")?))?;
            }
            let identity =
                rns.getattr("Identity")?.call_method1("from_file", (identity_file.to_string_lossy().into_owned(),))?;
            let kw = PyDict::new(py);
            kw.set_item("identity", identity)?;
            let links = py.import("pigeonhole_rns.rnsio")?.getattr("Links")?.call((), Some(&kw))?;
            Ok(PyLinks(Arc::new(links.unbind())))
        })
    }

    /// A Link request to `path` of the replica at `dest`: its response, or `None` when it did
    /// not answer.
    pub async fn request(&self, dest: &[u8], path: &str, data: &[u8]) -> Option<Vec<u8>> {
        let (links, dest, path, data) = (self.0.clone(), dest.to_vec(), path.to_string(), data.to_vec());
        tokio::task::spawn_blocking(move || {
            Python::attach(|py| -> PyResult<Option<Vec<u8>>> {
                let r = links.bind(py).call_method1(
                    "request",
                    (PyBytes::new(py, &dest), path, PyBytes::new(py, &data)),
                )?;
                if r.is_none() {
                    return Ok(None);
                }
                Ok(Some(r.cast::<PyBytes>()?.as_bytes().to_vec()))
            })
        })
        .await
        .ok()?
        .map_err(|e| log::debug!("pigeonhole: python request: {e}"))
        .ok()
        .flatten()
    }
}
