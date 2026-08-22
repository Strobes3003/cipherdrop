import { useCallback, useEffect, useMemo, useState } from 'react';
import { Link, useLocation, useParams } from 'react-router-dom';
import CopyButton from '../components/common/CopyButton';
import Loading from '../components/common/Loading';
import { SecretApiError, deleteSecret, getSecretStatus } from '../services/secretApi';

const STATUS_LABELS = {
  READY: 'Active',
  PASSWORD_REQUIRED: 'Password protected',
  EXPIRED: 'Expired',
  CONSUMED: 'Consumed',
  VIEW_LIMIT_REACHED: 'View limit reached',
  DELETED: 'Deleted',
};

function readFragment() {
  const rawFragment = window.location.hash.slice(1);
  try {
    return rawFragment ? decodeURIComponent(rawFragment) : '';
  } catch {
    return '';
  }
}

export default function ManageSecretPage() {
  const { id } = useParams();
  const location = useLocation();
  const managementToken = useMemo(readFragment, []);
  const metadata = location.state?.policies || null;
  const shareUrl = location.state?.shareUrl || '';
  const [status, setStatus] = useState('LOADING');
  const [statusError, setStatusError] = useState('');
  const [deleteError, setDeleteError] = useState('');
  const [isDeleting, setIsDeleting] = useState(false);

  const refreshStatus = useCallback(async () => {
    setStatus('LOADING');
    try {
      const response = await getSecretStatus(id);
      setStatus(response?.access || response?.status || 'UNKNOWN');
      setStatusError('');
    } catch (error) {
      setStatus('UNKNOWN');
      setStatusError(error.message || 'Status is unavailable.');
    }
  }, [id]);

  useEffect(() => { refreshStatus(); }, [refreshStatus]);

  async function handleDelete() {
    if (!managementToken || !window.confirm('Delete this drop? This cannot be undone.')) return;
    setIsDeleting(true);
    setDeleteError('');
    try {
      await deleteSecret(id, managementToken);
      setStatus('DELETED');
    } catch (error) {
      setDeleteError(error instanceof SecretApiError ? error.message : 'The drop could not be deleted.');
    } finally {
      setIsDeleting(false);
    }
  }

  if (status === 'LOADING') return <main className="page-shell centered-page"><Loading label="Loading drop details…" /></main>;

  return (
    <main className="page-shell narrow-page manage-page">
      <div className="page-intro manage-intro"><h1><span className="material-symbols-outlined" aria-hidden="true">lock_open</span> Manage Secret</h1><p>Review status, share, or destruct.</p></div>
      <section className="manage-card" aria-labelledby="manage-status-title">
        <div className="manage-status-row">
          <div><span className="eyebrow">Current status</span><h2 id="manage-status-title">{STATUS_LABELS[status] || 'Unknown'}</h2></div>
          <span className={`status-pill status-${status.toLowerCase()}`}><span className="status-dot" />{status.replaceAll('_', ' ')}</span>
        </div>
        {statusError && <p className="field-error" role="alert">{statusError}</p>}
        <div className="metadata-grid">
          <div><span>Expiration</span><strong>{metadata?.expiresAt ? new Date(metadata.expiresAt).toLocaleString() : metadata?.expiration ? metadata.expiration : 'No expiration'}</strong></div>
          <div><span>Maximum views</span><strong>{metadata?.maxViews ?? 'Unlimited'}</strong></div>
          <div><span>Password</span><strong>{metadata?.password ? 'Protected' : 'Not enabled'}</strong></div>
          <div><span>Burn after reading</span><strong>{metadata?.burnAfterReading ? 'Enabled' : 'Off'}</strong></div>
        </div>
      </section>
      <section className="manage-actions">
        <h2>Actions</h2>
        {shareUrl ? <div className="share-row"><input aria-label="Share link" value={shareUrl} readOnly /><CopyButton value={shareUrl} /></div> : <p className="muted-copy">The share link is only available in the session where the drop was created. The encryption key is never recovered from the server.</p>}
        {deleteError && <div className="inline-alert error-alert" role="alert">{deleteError}</div>}
        <button className="button button-danger" type="button" onClick={handleDelete} disabled={isDeleting || status === 'DELETED' || !managementToken}>
          <span className="material-symbols-outlined" aria-hidden="true">local_fire_department</span>{isDeleting ? 'Deleting…' : status === 'DELETED' ? 'Drop deleted' : 'Burn Secret Now'}
        </button>
        {!managementToken && <p className="field-hint">Open the management URL returned when the drop was created to enable deletion.</p>}
      </section>
      <Link className="text-link" to="/">← Back to CipherDrop</Link>
    </main>
  );
}
