// SPDX-License-Identifier: AGPL-3.0-or-later
//! Certificates for the mail protocols from files (`mail.tls`) – for kernoid behind a reverse proxy that holds the
//! certificates, e.g. Caddy: its files are read again whenever they change, so that a renewal takes effect without a
//! restart. A file that cannot be read keeps the certificate in use.

use std::{
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
    time::{Duration, SystemTime},
};

use rustls::{
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
};

use crate::acme::{AcmeError, static_certificate};

/// How often the files are looked at.
const EVERY: Duration = Duration::from_secs(60);

#[derive(Debug)]
pub struct FileCertificates {
    certificate: PathBuf,
    key: PathBuf,
    /// The certificate in use, and the newer of the two files' modification times it was read at.
    current: RwLock<(Arc<CertifiedKey>, Option<SystemTime>)>,
}

/// The later modification time of two files.
fn modified(certificate: &Path, key: &Path) -> Option<SystemTime> {
    let time = |path: &Path| std::fs::metadata(path).and_then(|meta| meta.modified()).ok();
    time(certificate).max(time(key))
}

impl FileCertificates {
    /// Reads the files; they must hold a certificate chain and its key now.
    pub fn load(certificate: &Path, key: &Path) -> Result<Self, AcmeError> {
        let read_at = modified(certificate, key);
        let current = Arc::new(static_certificate(certificate, key)?);
        Ok(Self { certificate: certificate.to_owned(), key: key.to_owned(), current: RwLock::new((current, read_at)) })
    }

    /// Reads the files again if they changed; whether the certificate in use changed.
    pub fn reload(&self) -> Result<bool, AcmeError> {
        let read_at = modified(&self.certificate, &self.key);
        if read_at == self.current.read().expect("not poisoned").1 {
            return Ok(false);
        }
        let certificate = Arc::new(static_certificate(&self.certificate, &self.key)?);
        *self.current.write().expect("not poisoned") = (certificate, read_at);
        Ok(true)
    }

    /// Looks at the files every minute until `shutdown`.
    pub async fn keep_fresh(self: Arc<Self>, shutdown: impl std::future::Future<Output = ()>) {
        tokio::pin!(shutdown);
        loop {
            tokio::select! {
                () = &mut shutdown => return,
                () = tokio::time::sleep(EVERY) => {}
            }
            let files = self.clone();
            match tokio::task::spawn_blocking(move || files.reload()).await {
                Ok(Ok(true)) => tracing::info!(certificate = %self.certificate.display(), "mail certificate reloaded"),
                Ok(Ok(false)) => {}
                // A renewal may be half written: the next look reads it whole.
                Ok(Err(error)) => tracing::warn!(%error, "reading the mail certificate failed; keeping the one in use"),
                Err(error) => tracing::warn!(%error, "reading the mail certificate failed"),
            }
        }
    }
}

impl ResolvesServerCert for FileCertificates {
    fn resolve(&self, _hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.current.read().expect("not poisoned").0.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_pair(directory: &Path, name: &str) -> String {
        let key = rcgen::KeyPair::generate().unwrap();
        let certificate = rcgen::CertificateParams::new(vec![name.to_owned()]).unwrap().self_signed(&key).unwrap();
        std::fs::write(directory.join("cert.pem"), certificate.pem()).unwrap();
        std::fs::write(directory.join("key.pem"), key.serialize_pem()).unwrap();
        certificate.pem()
    }

    #[test]
    fn files_are_read_again_when_they_change() {
        let directory = std::env::temp_dir().join(format!("kernoid-cert-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&directory).unwrap();
        let (cert, key) = (directory.join("cert.pem"), directory.join("key.pem"));
        write_pair(&directory, "mail.one.example");
        let files = FileCertificates::load(&cert, &key).unwrap();
        let first = files.current.read().unwrap().0.cert[0].clone();
        assert!(!files.reload().unwrap(), "nothing changed");

        // A renewal: new files, a later time.
        std::thread::sleep(Duration::from_millis(1100));
        write_pair(&directory, "mail.two.example");
        assert!(files.reload().unwrap());
        assert_ne!(files.current.read().unwrap().0.cert[0], first);

        // A broken file keeps the certificate in use.
        std::thread::sleep(Duration::from_millis(1100));
        std::fs::write(&key, "not a key").unwrap();
        let in_use = files.current.read().unwrap().0.cert[0].clone();
        assert!(files.reload().is_err());
        assert_eq!(files.current.read().unwrap().0.cert[0], in_use);
        std::fs::remove_dir_all(&directory).unwrap();
    }
}
