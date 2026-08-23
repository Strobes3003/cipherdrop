import { Navigate, Route, Routes } from 'react-router-dom';
import Navbar from './components/layout/Navbar';
import Footer from './components/layout/Footer';
import AmbientGrid from './components/layout/AmbientGrid';
import HomePage from './pages/HomePage';
import CreateSecretPage from './pages/CreateSecretPage';
import SecretAccessPage from './pages/SecretAccessPage';
import ManageSecretPage from './pages/ManageSecretPage';

function NotFoundPage() {
  return (
    <main className="page-shell centered-page">
      <section className="state-card" aria-labelledby="not-found-title">
        <span className="eyebrow">404 · Not found</span>
        <h1 id="not-found-title">That drop does not exist.</h1>
        <p>Check the link, or start a new secure share.</p>
        <a className="button button-primary" href="/create">Create a secret</a>
      </section>
    </main>
  );
}

export default function App() {
  return (
    <div className="app-shell">
      <AmbientGrid />
      <Navbar />
      <Routes>
        <Route path="/" element={<HomePage />} />
        <Route path="/create" element={<CreateSecretPage />} />
        <Route path="/s/:id" element={<SecretAccessPage />} />
        <Route path="/manage/:id" element={<ManageSecretPage />} />
        <Route path="/404" element={<NotFoundPage />} />
        <Route path="*" element={<Navigate to="/404" replace />} />
      </Routes>
      <Footer />
    </div>
  );
}
