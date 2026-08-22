import { useState } from 'react';

export default function SecretViewer({ plaintext }) {
  const [copied, setCopied] = useState(false);

  async function copySecret() {
    try {
      await navigator.clipboard.writeText(plaintext);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 2200);
    } catch {
      setCopied(false);
    }
  }

  return (
    <section className="viewer-card" aria-labelledby="viewer-title">
      <div className="viewer-heading">
        <div>
          <span className="eyebrow">Access granted</span>
          <h1 id="viewer-title">Your secret</h1>
        </div>
        <button className="button button-secondary" type="button" onClick={copySecret}>
          {copied ? '✓ Copied' : 'Copy secret'}
        </button>
      </div>
      <pre className="secret-output" tabIndex="0">{plaintext}</pre>
      <div className="viewer-note"><span aria-hidden="true">◉</span> Keep this information private. This page does not save it to browser storage.</div>
    </section>
  );
}
