export default function Footer() {
  return (
    <footer className="site-footer">
      <div className="site-footer-inner">
        <strong>CIPHERDROP</strong>
        <span>© {new Date().getFullYear()} CipherDrop.</span>
      </div>
    </footer>
  );
}
