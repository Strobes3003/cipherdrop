import PasswordInput from './PasswordInput';

const EXPIRATION_OPTIONS = [
  { value: '', label: 'No expiration' },
  { value: '15m', label: '15 minutes' },
  { value: '1h', label: '1 hour' },
  { value: '24h', label: '24 hours' },
  { value: '7d', label: '7 days' },
];

export default function PolicyControls({ policies, onChange, disabled = false }) {
  function update(field, value) {
    onChange({ ...policies, [field]: value });
  }

  return (
    <fieldset className="policy-card" disabled={disabled}>
      <legend><span className="material-symbols-outlined" aria-hidden="true">policy</span> Security Policies</legend>
      <p className="section-intro">Set the guardrails for this drop. CipherDrop enforces these on the server.</p>

      <div className="policy-grid">
        <label className="form-field">
          <span>Expires after</span>
          <select value={policies.expiration} onChange={(event) => update('expiration', event.target.value)}>
            {EXPIRATION_OPTIONS.map((option) => <option key={option.value || 'none'} value={option.value}>{option.label}</option>)}
          </select>
        </label>

        <label className="form-field">
          <span>Maximum views</span>
          <select value={policies.maxViews ?? ''} onChange={(event) => update('maxViews', event.target.value ? Number(event.target.value) : null)}>
            <option value="">Unlimited</option>
            {[1, 2, 3, 5, 10].map((views) => <option key={views} value={views}>{views} {views === 1 ? 'view' : 'views'}</option>)}
          </select>
        </label>
      </div>

      <label className="toggle-row">
        <input aria-label="Burn after reading" type="checkbox" checked={policies.burnAfterReading} onChange={(event) => update('burnAfterReading', event.target.checked)} />
        <span className="toggle-copy"><strong>Burn after reading</strong><small>Mark the drop consumed after a successful access.</small></span>
        <span className="toggle-track" aria-hidden="true"><span /></span>
      </label>

      <label className="toggle-row">
        <input aria-label="Password protection" type="checkbox" checked={policies.passwordEnabled} onChange={(event) => update('passwordEnabled', event.target.checked)} />
        <span className="toggle-copy"><strong>Password protection</strong><small>Require a second credential before releasing the ciphertext.</small></span>
        <span className="toggle-track" aria-hidden="true"><span /></span>
      </label>

      {policies.passwordEnabled && (
        <label className="form-field password-field">
          <span>Access password</span>
          <PasswordInput
            value={policies.password}
            onChange={(event) => update('password', event.target.value)}
            placeholder="Choose a strong password"
            autoComplete="new-password"
            required
          />
          <small>Share this password separately from the CipherDrop link.</small>
        </label>
      )}
    </fieldset>
  );
}
