const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL || '/api').replace(/\/$/, '');

export class SecretApiError extends Error {
  constructor(message, { status = 0, reason = 'NETWORK_ERROR', details = null } = {}) {
    super(message);
    this.name = 'SecretApiError';
    this.status = status;
    this.reason = reason;
    this.details = details;
  }
}

async function parseResponse(response) {
  const contentType = response.headers.get('content-type') || '';
  if (response.status === 204) return null;

  if (contentType.includes('application/json')) {
    try {
      return await response.json();
    } catch {
      return null;
    }
  }

  const text = await response.text();
  return text ? { message: text } : null;
}

function messageForFailure(status, reason, payload) {
  const messages = {
    NOT_FOUND: 'This secret could not be found.',
    EXPIRED: 'This secret has expired and is no longer available.',
    CONSUMED: 'This secret has already been consumed.',
    VIEW_LIMIT_REACHED: 'This secret has reached its view limit.',
    INVALID_PASSWORD: 'That password is incorrect.',
    INVALID_MANAGEMENT_TOKEN: 'The management link is invalid or has expired.',
  };

  return messages[reason]
    || payload?.message
    || (status >= 500 ? 'The CipherDrop service is temporarily unavailable.' : 'The request could not be completed.');
}

async function request(path, options = {}) {
  let response;
  try {
    response = await fetch(`${API_BASE_URL}${path}`, {
      ...options,
      headers: {
        Accept: 'application/json',
        ...(options.body ? { 'Content-Type': 'application/json' } : {}),
        ...options.headers,
      },
    });
  } catch {
    throw new SecretApiError('Unable to reach the CipherDrop service.', { reason: 'NETWORK_ERROR' });
  }

  const payload = await parseResponse(response);
  if (!response.ok) {
    const reason = payload?.reason || payload?.access || 'REQUEST_FAILED';
    throw new SecretApiError(messageForFailure(response.status, reason, payload), {
      status: response.status,
      reason,
      details: payload,
    });
  }

  return payload;
}

export function createSecret(payload) {
  return request('/secrets', {
    method: 'POST',
    body: JSON.stringify(payload),
  });
}

export function getSecretStatus(id) {
  return request(`/secrets/${encodeURIComponent(id)}`);
}

export function accessSecret(id, password = '') {
  return request(`/secrets/${encodeURIComponent(id)}/access`, {
    method: 'POST',
    body: JSON.stringify(password ? { password } : {}),
  });
}

export function deleteSecret(id, managementToken) {
  return request(`/secrets/${encodeURIComponent(id)}`, {
    method: 'DELETE',
    headers: {
      Authorization: `Bearer ${managementToken}`,
    },
  });
}

export { API_BASE_URL };
