import { useId, useState } from 'react';

export default function PasswordInput({ id, value, onChange, disabled = false, ...inputProps }) {
  const generatedId = useId();
  const inputId = id || generatedId;
  const [visible, setVisible] = useState(false);

  return (
    <span className="password-input-wrap">
      <input
        {...inputProps}
        id={inputId}
        type={visible ? 'text' : 'password'}
        value={value}
        onChange={onChange}
        disabled={disabled}
      />
      <button
        className="password-visibility"
        type="button"
        onClick={() => setVisible((current) => !current)}
        aria-label={visible ? 'Hide password' : 'Show password'}
        aria-pressed={visible}
        aria-controls={inputId}
        disabled={disabled}
      >
        <span className="material-symbols-outlined" aria-hidden="true">{visible ? 'visibility_off' : 'visibility'}</span>
      </button>
    </span>
  );
}
