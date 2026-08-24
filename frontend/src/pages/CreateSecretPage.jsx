import { useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { QRCodeSVG } from 'qrcode.react';
import SecretEditor from '../components/SecretEditor';
import PolicyControls from '../components/PolicyControls';
import SecurityAdvisor from '../components/SecurityAdvisor';
import CopyButton from '../components/common/CopyButton';
import Loading from '../components/common/Loading';
import { createSecret } from '../services/secretApi';
import { getSecurityAdapter } from '../services/securityIntegration';


const INITIAL_POLICIES = {
  expiration: '1h',
  maxViews: 1,
  burnAfterReading: true,
  passwordEnabled: false,
  password: '',
};

function expirationToIso(value) {
  if (!value) return null;
  const units = { m: 60 * 1000, h: 60 * 60 * 1000, d: 24 * 60 * 60 * 1000 };
  const amount = Number(value.slice(0, -1));
  const unit = value.slice(-1);
  return new Date(Date.now() + amount * units[unit]).toISOString();
}

function friendlyCreationError(error) {
  if (error?.name === 'SecretApiError') return error.message;
  return 'We could not create that drop. Please try again.';
}

export default function CreateSecretPage() {
  const adapter = getSecurityAdapter();
  const [secret, setSecret] = useState('');
  const [policies, setPolicies] = useState(INITIAL_POLICIES);
  const [detections, setDetections] = useState([]);
  const [scoreResult, setScoreResult] = useState(null);
  const [editorError, setEditorError] = useState('');
  const [submitError, setSubmitError] = useState('');
  const [isCreating, setIsCreating] = useState(false);
  const [result, setResult] = useState(null);
  const [showQr, setShowQr] = useState(false);

  useEffect(() => {
    let cancelled = false;
    async function analyse() {
      if (!adapter || !secret.trim()) {
        setDetections([]);
        setScoreResult(null);
        return;
      }
      try {
        const nextDetections = adapter.detectSensitiveData ? await adapter.detectSensitiveData(secret) : [];
        const nextScore = adapter.calculateSecurityScore
          ? await adapter.calculateSecurityScore({ detections: nextDetections, policies })
          : null;
        if (!cancelled) {
          setDetections(Array.isArray(nextDetections) ? nextDetections : []);
          setScoreResult(nextScore);
        }
      } catch {
        if (!cancelled) {
          setDetections([]);
          setScoreResult(null);
        }
      }
    }
    analyse();
    return () => { cancelled = true; };
  }, [adapter, policies, secret]);

  const policyPayload = useMemo(() => ({
    expiresAt: expirationToIso(policies.expiration),
    burnAfterReading: policies.burnAfterReading,
    maxViews: policies.maxViews,
    password: policies.passwordEnabled ? policies.password : null,
  }), [policies]);

  async function handleCreate(event) {
    event.preventDefault();
    setSubmitError('');
    if (!secret.trim()) {
      setEditorError('Enter something to protect before creating a drop.');
      return;
    }
    if (policies.passwordEnabled && !policies.password.trim()) {
      setSubmitError('Add an access password or turn password protection off.');
      return;
    }
    if (!adapter?.encryptSecret) {
      setSubmitError('Browser security is not connected on this build yet. The secret was not sent.');
      return;
    }

    setEditorError('');
    setIsCreating(true);
    try {
      const encrypted = await adapter.encryptSecret(secret);
      if (!encrypted?.encryptedContent || !encrypted?.iv || !encrypted?.key) {
        throw new Error('Incomplete encryption result');
      }

      const created = await createSecret({
        encryptedContent: encrypted.encryptedContent,
        iv: encrypted.iv,
        ...policyPayload,
      });
      const shareUrl = `${window.location.origin}/s/${encodeURIComponent(created.id)}#${encodeURIComponent(encrypted.key)}`;
      const managementUrl = created.managementToken
        ? `${window.location.origin}/manage/${encodeURIComponent(created.id)}#${encodeURIComponent(created.managementToken)}`
        : null;
      setResult({
        id: created.id,
        shareUrl,
        managementUrl,
        policies: {
          ...policyPayload,
          password: Boolean(policyPayload.password),
        },
      });
    } catch (error) {
      setSubmitError(friendlyCreationError(error));
    } finally {
      setIsCreating(false);
    }
  }

  if (result) {
    return (
      <main className="page-shell narrow-page">
        <section className="success-card" aria-labelledby="created-title">
          <div className="success-icon" aria-hidden="true">✓</div>
          <span className="eyebrow">Drop created</span>
          <h1 id="created-title">Your secret is ready to share.</h1>
          <p>The link contains the browser key. Anyone with it can attempt access, so share it carefully.</p>
          <div className="share-field">
            <label htmlFor="share-url">Share link</label>

            <div className="share-row">
              <input id="share-url" value={result.shareUrl} readOnly />
              <CopyButton value={result.shareUrl} />
              <button
                type="button"
                className="button button-quiet"
                onClick={() => setShowQr((visible) => !visible)}
                aria-expanded={showQr}
                aria-controls="share-qr"
              >
                {showQr ? 'Hide QR' : 'Show QR'}
              </button>
            </div>
          </div>
          {showQr && (
            <div className="qr-section" id="share-qr">
              <h2>Scan to open</h2>

              <div className="qr-code">
                <QRCodeSVG
                  value={result.shareUrl}
                  size={220}
                  level="M"
                  includeMargin
                />
              </div>

              <p className="muted-copy">
                Scan this QR code with a phone to open the secret.
              </p>
            </div>
          )}
          {result.managementUrl && (
            <div className="management-callout">
              <strong>Keep your management link somewhere safe.</strong>
              <p>It is the only way to delete this drop before its policy expires it.</p>
              <CopyButton value={result.managementUrl} label="Copy management link" />
            </div>
          )}
          <div className="success-actions">
            <Link className="button button-primary" to="/create">Create another</Link>
            {result.managementUrl && <Link className="button button-quiet" to={result.managementUrl} state={{ policies: result.policies, shareUrl: result.shareUrl }}>Manage this drop</Link>}
          </div>
        </section>
      </main>
    );
  }

  return (
    <main className="page-shell create-page">
      <div className="page-intro"><h1>Create New Secret</h1><p>Enter sensitive information below. It will be encrypted client-side.</p></div>
      <form className="create-layout" onSubmit={handleCreate}>
        <div className="create-main-column">
          <SecretEditor value={secret} onChange={(value) => { setSecret(value); if (editorError) setEditorError(''); }} disabled={isCreating} error={editorError} />
          <PolicyControls policies={policies} onChange={setPolicies} disabled={isCreating} />
          <SecurityAdvisor detections={detections} scoreResult={scoreResult} />
          {submitError && <div className="inline-alert error-alert" role="alert"><strong>Could not create drop</strong><span>{submitError}</span></div>}
          {isCreating && <Loading label="Encrypting and creating drop…" />}
          <button className="button button-primary button-large create-submit" type="submit" disabled={isCreating}>
            <span className="material-symbols-outlined" aria-hidden="true">link</span>{isCreating ? 'Creating secure link…' : 'Create Secure Link'}
          </button>
          <p className="form-footnote"><span aria-hidden="true">⌁</span> Plaintext never goes to the API. The browser-security module must be connected before creation can proceed.</p>
        </div>
        <aside className="how-it-works-card" aria-label="How CipherDrop works">
          <h2><span className="material-symbols-outlined" aria-hidden="true">help</span> How it Works</h2>
          <div className="how-step"><span className="step-icon material-symbols-outlined" aria-hidden="true">encrypted</span><div><strong>End-to-End Encryption</strong><p>Your data is encrypted in your browser before being sent. We cannot read your secrets.</p></div></div>
          <div className="how-step"><span className="step-icon material-symbols-outlined" aria-hidden="true">key</span><div><strong>Decryption Key</strong><p>The key stays in the link fragment and is never sent to our servers.</p></div></div>
          <div className="how-step"><span className="step-icon material-symbols-outlined" aria-hidden="true">timer</span><div><strong>Ephemeral Data</strong><p>Secrets expire or disappear according to the policy you choose.</p></div></div>
          <div className="how-status"><span>STATUS</span><strong><i /> SYSTEM SECURE</strong></div>
        </aside>
      </form>
    </main>
  );
}
