import { useState } from 'react';

export default function CopyButton({ value, label = 'Copy', successLabel = 'Copied', className = '' }) {
  const [copied, setCopied] = useState(false);
  const [error, setError] = useState('');

  async function handleCopy() {
    setError('');
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 2200);
    } catch {
      setError('Copy was blocked. Select the link and copy it manually.');
    }
  }

  return (
    <span className={`copy-control ${className}`}>
      <button className="button button-secondary" type="button" onClick={handleCopy}>
        {copied ? `✓ ${successLabel}` : label}
      </button>
      {error && <span className="copy-error" role="status">{error}</span>}
    </span>
  );
}
