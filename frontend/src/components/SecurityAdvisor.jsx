function scoreDetails(scoreResult) {
  if (typeof scoreResult === 'number') return { score: scoreResult, label: '' };
  return scoreResult || { score: null, label: '' };
}

export default function SecurityAdvisor({ detections = [], scoreResult = null }) {
  const { score, label, recommendations = [] } = scoreDetails(scoreResult);
  const hasSignals = detections.length > 0 || score !== null;

  if (!hasSignals) {
    return (
      <aside className="advisor-card advisor-muted" aria-label="Security advisor">
        <div className="advisor-icon" aria-hidden="true">✦</div>
        <div>
          <strong>Security advisor</strong>
          <p>The browser-security module will add detection and recommendations here when connected.</p>
        </div>
      </aside>
    );
  }

  return (
    <aside className="advisor-card" aria-label="Security advisor">
      <div className="advisor-topline">
        <div className="advisor-icon" aria-hidden="true">✦</div>
        <div>
          <span className="eyebrow">Security advisor</span>
          <strong>
            {score !== null ? `${score}/100 ${label || 'security score'}` : 'Review before sharing'}
            <span className="finding-count"> · {detections.length} {detections.length === 1 ? 'finding' : 'findings'}</span>
          </strong>
        </div>
      </div>
      {detections.length > 0 && (
        <div className="detection-list">
          <p className="advisor-label">Signals detected</p>
          {detections.map((detection, index) => (
            <div className="detection-item" key={`${detection.type || 'signal'}-${index}`}>
              <span className="severity-badge">{detection.severity || 'NOTICE'}</span>
              <span>{detection.label || detection.type || 'Sensitive-looking content'}</span>
            </div>
          ))}
        </div>
      )}
      {recommendations.length > 0 && (
        <div className="recommendation-list">
          <p className="advisor-label">Recommendations</p>
          {recommendations.map((recommendation, index) => <p key={`${recommendation}-${index}`}>✓ {recommendation}</p>)}
        </div>
      )}
    </aside>
  );
}
