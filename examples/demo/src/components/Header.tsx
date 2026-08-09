import type React from 'react';
import { useState } from 'react';
import { Link } from 'react-router-dom';

const GITHUB_URL = 'https://github.com/dipsettheory/ignoti';

export function Header({ slug, actions }: { slug?: string; actions?: React.ReactNode }) {
  const [docsOpen, setDocsOpen] = useState(false);

  return (
    <header className="app-header">
      <Link to="/" className="app-header-logo" style={{ textDecoration: 'none' }}>
        ignoti://{slug && <span className="header-slug">{slug}</span>}
      </Link>
      <nav className="app-header-actions" onMouseLeave={() => setDocsOpen(false)}>
        <div className="dropdown">
          <button
            type="button"
            className="link-btn"
            onMouseEnter={() => setDocsOpen(true)}
            onClick={() => setDocsOpen(o => !o)}
          >
            docs ▾
          </button>
          {docsOpen && (
            <div className="dropdown-menu">
              <Link
                to="/docs/getting-started"
                className="dropdown-item"
                onClick={() => setDocsOpen(false)}
              >
                getting started
              </Link>
              <Link
                to="/docs/security"
                className="dropdown-item"
                onClick={() => setDocsOpen(false)}
              >
                security
              </Link>
              <Link to="/docs/privacy" className="dropdown-item" onClick={() => setDocsOpen(false)}>
                privacy
              </Link>
              <Link
                to="/docs/threat-model"
                className="dropdown-item"
                onClick={() => setDocsOpen(false)}
              >
                threat model
              </Link>
              <Link
                to="/docs/api-reference"
                className="dropdown-item"
                onClick={() => setDocsOpen(false)}
              >
                api reference
              </Link>
            </div>
          )}
        </div>
        <a href={GITHUB_URL} className="link-btn" target="_blank" rel="noreferrer">
          github
        </a>
        {actions}
      </nav>
    </header>
  );
}
