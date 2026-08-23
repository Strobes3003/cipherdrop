export default function SecretEditor({ value, onChange, disabled = false, error = '' }) {
  const characterCount = value.length;
  const wordCount = value.trim() ? value.trim().split(/\s+/).length : 0;

  return (
    <div className="editor-wrap">
      <label className="field-label editor-label" htmlFor="secret-content"><span className="material-symbols-outlined" aria-hidden="true">lock</span> Secret Content</label>
      <div className={`editor-shell ${error ? 'has-error' : ''}`}>
        <textarea
          id="secret-content"
          name="secret-content"
          value={value}
          onChange={(event) => onChange(event.target.value)}
          placeholder="Paste passwords, keys, or sensitive text here…"
          disabled={disabled}
          aria-describedby="secret-help secret-count secret-error"
          aria-invalid={Boolean(error)}
          spellCheck="false"
          autoComplete="off"
        />
        <div className="editor-meta">
          <span id="secret-help"><span className="material-symbols-outlined" aria-hidden="true">info</span> Data never leaves your device unencrypted.</span>
          <span id="secret-count">{wordCount.toLocaleString()} words · {characterCount.toLocaleString()} characters</span>
        </div>
      </div>
      {error && <p className="field-error" id="secret-error" role="alert">{error}</p>}
    </div>
  );
}
