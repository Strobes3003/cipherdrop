import { useState } from 'react';
import PasswordInput from './PasswordInput';

export default function PasswordPrompt({ onSubmit, loading = false, error = '' }) {
  const [password, setPassword] = useState('');

  function handleSubmit(event) {
    event.preventDefault();
    if (password.trim()) onSubmit(password);
  }

  return (
    <form className="password-prompt" onSubmit={handleSubmit}>
      <div className="prompt-icon material-symbols-outlined" aria-hidden="true">key</div>
      <div>
        <h2>Password required</h2>
        <p>This drop has an additional access password. It is checked by the server.</p>
      </div>
      <label className="form-field" htmlFor="access-password">
        <span>Access password</span>
        <PasswordInput
          id="access-password"
          value={password}
          onChange={(event) => setPassword(event.target.value)}
          autoComplete="one-time-code"
          disabled={loading}
          aria-describedby="password-error"
          autoFocus
          required
        />
      </label>
      {error && <p className="field-error" id="password-error" role="alert">{error}</p>}
      <button className="button button-primary button-wide" type="submit" disabled={loading || !password.trim()}>
        {loading ? 'Unlocking…' : 'Unlock secret'}
      </button>
    </form>
  );
}
