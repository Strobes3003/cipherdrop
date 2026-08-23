import { useCallback, useEffect, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import PasswordPrompt from '../components/PasswordPrompt';
import SecretViewer from '../components/SecretViewer';
import Loading from '../components/common/Loading';
import { SecretApiError, accessSecret, getSecretStatus } from '../services/secretApi';
import { getSecurityAdapter } from '../services/securityIntegration';

const ACCESS_COPY = {
  EXPIRED: { title: 'This drop has expired.', body: 'Its access window has closed and the content is no longer available.' },
  CONSUMED: { title: 'This drop has been consumed.', body: 'It was configured to disappear after a successful read.' },
  VIEW_LIMIT_REACHED: { title: 'This drop has reached its view limit.', body: 'The maximum number of successful accesses has already been used.' },
  DELETED: { title: 'This drop was deleted.', body: 'The creator removed it before you could access the content.' },
  NOT_FOUND: { title: 'We could not find that drop.', body: 'The link may be incomplete, or this drop may no longer exist.' },
};

const DECRYPTION_ERROR_MESSAGE = 'This secret could not be decrypted. Check that you are using the original share link.';

function unavailableReason(error) {
  return error?.reason || error?.details?.reason || 'NOT_FOUND';
}

function readFragment() {
  const rawFragment = window.location.hash.slice(1);
  try {
    return rawFragment ? decodeURIComponent(rawFragment) : '';
  } catch {
    return '';
  }
}

function friendlyAccessError(error) {
  if (error?.name === 'DecryptionError') return DECRYPTION_ERROR_MESSAGE;
  return error?.message || 'The secret could not be unlocked.';
}

export default function SecretAccessPage() {
  const { id } = useParams();
  const adapter = getSecurityAdapter();
  const key = readFragment();
  const [status, setStatus] = useState('LOADING');
  const [errorReason, setErrorReason] = useState('');
  const [networkError, setNetworkError] = useState('');
  const [accessError, setAccessError] = useState('');
  const [isAccessing, setIsAccessing] = useState(false);
  const [plaintext, setPlaintext] = useState('');

  const loadStatus = useCallback(async () => {
    setStatus('LOADING');
    setNetworkError('');
    try {
      const response = await getSecretStatus(id);
      const access = response?.access || response?.status;
      if (access === 'PASSWORD_REQUIRED') setStatus('PASSWORD_REQUIRED');
      else if (access === 'READY') setStatus('READY');
      else {
        setErrorReason(access || 'NOT_FOUND');
        setStatus('UNAVAILABLE');
      }
    } catch (error) {
      setErrorReason(unavailableReason(error));
      setStatus(error instanceof SecretApiError && error.status === 0 ? 'ERROR' : 'UNAVAILABLE');
      if (error instanceof SecretApiError && error.status === 0) setNetworkError(error.message);
    }
  }, [id]);

  useEffect(() => { loadStatus(); }, [loadStatus]);

  async function handleAccess(password = '') {
    setIsAccessing(true);
    setAccessError('');
    try {
      const response = await accessSecret(id, password);
      if (response?.access !== 'ACCESS_GRANTED' || !response.encryptedContent || !response.iv) {
        throw new SecretApiError('This secret could not be released.', { reason: response?.reason || 'REQUEST_FAILED' });
      }
      if (!key) throw new Error('The browser key is missing from this link.');
      if (!adapter?.decryptSecret) throw new Error('Browser security is not connected on this build yet.');
      const revealed = await adapter.decryptSecret({ encryptedContent: response.encryptedContent, iv: response.iv, key });
      setPlaintext(revealed);
      setStatus('VIEWING');
    } catch (error) {
      const reason = unavailableReason(error);
      if (error?.name === 'DecryptionError') setAccessError(DECRYPTION_ERROR_MESSAGE);
      else if (reason === 'INVALID_PASSWORD') setAccessError('That password is incorrect. Try again.');
      else if (ACCESS_COPY[reason]) {
        setErrorReason(reason);
        setStatus('UNAVAILABLE');
      } else setAccessError(friendlyAccessError(error));
    } finally {
      setIsAccessing(false);
    }
  }

  if (status === 'LOADING') return <main className="page-shell centered-page"><Loading label="Checking drop availability…" /></main>;
  if (status === 'ERROR') return <main className="page-shell centered-page"><StateCard title="CipherDrop is unreachable." body={networkError || 'Check your connection and try again.'} action={<button className="button button-primary" type="button" onClick={loadStatus}>Try again</button>} /></main>;
  if (status === 'VIEWING') return <main className="page-shell narrow-page access-page"><SecretViewer plaintext={plaintext} /></main>;
  if (status === 'UNAVAILABLE') {
    const copy = ACCESS_COPY[errorReason] || { title: 'This drop is unavailable.', body: 'The server did not release this secret.' };
    return <main className="page-shell centered-page"><StateCard title={copy.title} body={copy.body} action={<Link className="button button-primary" to="/">Back to CipherDrop</Link>} /></main>;
  }

  return (
    <main className="page-shell narrow-page access-page">
      <div className="access-kicker"><span className="pulse-dot" /> SECURE DROP / {id}</div>
      <section className="access-card" aria-labelledby="access-title">
        <div className="access-icon material-symbols-outlined" aria-hidden="true">lock</div>
        <h1 id="access-title">Encrypted Secret</h1>
        <p>This message is self-destructing and requires a decryption key to view.</p>
        {!key && <div className="inline-alert error-alert" role="alert"><strong>Incomplete share link</strong><span>The browser key is missing, so this secret cannot be decrypted.</span></div>}
        {status === 'PASSWORD_REQUIRED' ? (
          <PasswordPrompt onSubmit={handleAccess} loading={isAccessing} error={accessError} />
        ) : (
          <div className="unlock-panel">
            {accessError && <p className="field-error" role="alert">{accessError}</p>}
            <button className="button button-primary button-large button-wide" type="button" onClick={() => handleAccess()} disabled={isAccessing || !key}>
              <span className="material-symbols-outlined" aria-hidden="true">lock_open</span>{isAccessing ? 'Unlocking…' : 'Decrypt Secret'}
            </button>
          </div>
        )}
        <div className="access-meta"><span><span className="material-symbols-outlined" aria-hidden="true">shield</span> AES-256 GCM</span><span><span className="material-symbols-outlined" aria-hidden="true">timer</span> Protected by policy</span></div>
      </section>
      <p className="access-footnote"><span className="material-symbols-outlined" aria-hidden="true">info</span> Data is encrypted client-side. We cannot recover lost keys.</p>
    </main>
  );
}

function StateCard({ title, body, action }) {
  return <section className="state-card" aria-live="polite"><span className="state-symbol" aria-hidden="true">!</span><h1>{title}</h1><p>{body}</p>{action}</section>;
}
