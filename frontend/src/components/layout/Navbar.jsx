import { NavLink, Link } from 'react-router-dom';
import ThemeToggle from './ThemeToggle';

export default function Navbar() {
  return (
    <header className="site-header">
      <div className="site-header-inner">
        <Link className="brand" to="/" aria-label="CipherDrop home">
          <span className="brand-mark" aria-hidden="true">
            <svg className="brand-logo" viewBox="0 0 48 48" focusable="false">
              <path d="M24 3.5 40 10v11.4c0 10.4-6.5 19.4-16 23.1-9.5-3.7-16-12.7-16-23.1V10L24 3.5Z" />
              <path className="brand-logo-lock" d="M24 14.5a6 6 0 0 0-6 6v3h-2v10h16v-10h-2v-3a6 6 0 0 0-6-6Zm-3 9v-3a3 3 0 1 1 6 0v3h-6Zm3 3a2 2 0 0 1 1 3.7V33h-2v-2.8A2 2 0 0 1 24 26.5Z" />
            </svg>
          </span>
          <span>Cipher<span>Drop</span></span>
        </Link>
        <nav className="main-nav" aria-label="Primary navigation">
          <NavLink className={({ isActive }) => isActive ? 'nav-link active' : 'nav-link'} to="/">
            <span className="material-symbols-outlined" aria-hidden="true">home</span><span>Home</span>
          </NavLink>
          <NavLink className={({ isActive }) => isActive ? 'nav-link active' : 'nav-link'} to="/create">
            <span className="material-symbols-outlined" aria-hidden="true">add_circle</span><span>Create</span>
          </NavLink>
        </nav>
        <div className="header-actions" aria-label="Display settings">
          <ThemeToggle />
        </div>
      </div>
    </header>
  );
}
