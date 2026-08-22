import { Link } from 'react-router-dom';

const featureCards = [
  { icon: 'lock', title: 'Client-Side Encryption', text: 'Your secret is protected in the browser before it is sent anywhere.', status: 'AES-GCM-256 enabled' },
  { icon: 'local_fire_department', title: 'Absolute Ephemerality', text: 'Once viewed or expired, secrets follow the policy you set and disappear from access.', status: 'status: volatile', danger: true },
  { icon: 'key', title: 'Password Protection', text: 'Add a separate password so the link alone is not enough to release your secret.', status: 'optional access layer' },
];

export default function HomePage() {
  return (
    <main>
      <section className="hero page-shell">
        <div className="hero-copy">
          <div className="system-badge"><span className="status-dot" /> SYSTEM ONLINE</div>
          <h1>Share secrets securely.<br /><em>They vanish when you're done.</em></h1>
          <p className="hero-lede">End-to-end encrypted, single-view links. CipherDrop keeps sensitive data confidential until its access policy says it is time to disappear.</p>
          <div className="hero-actions">
            <Link className="button button-primary button-large" to="/create"><span className="material-symbols-outlined" aria-hidden="true">add_circle</span> Create Secret</Link>
            <a className="button button-outline button-large" href="#how-it-works">Learn More <span className="material-symbols-outlined" aria-hidden="true">arrow_forward</span></a>
          </div>
        </div>
        <div className="hero-visual" aria-hidden="true"><div className="hero-terminal"><span className="terminal-line"><i /> CIPHERDROP / SECURE</span><span className="terminal-key">⌑</span><span className="terminal-line muted"><i /> STATUS: EPHEMERAL</span></div></div>
      </section>

      <section className="how-section page-shell" id="how-it-works">
        <div className="feature-grid">
          {featureCards.map((card) => (
            <article className="feature-card" key={card.title}>
              <span className="feature-icon material-symbols-outlined" data-icon={card.icon} aria-hidden="true">{card.icon}</span>
              <h3>{card.title}</h3>
              <p>{card.text}</p>
              <span className={`feature-status ${card.danger ? 'danger' : ''}`}><span className="status-marker material-symbols-outlined" aria-hidden="true">check_circle</span><span>{card.status}</span><i /></span>
            </article>
          ))}
        </div>
      </section>
    </main>
  );
}
