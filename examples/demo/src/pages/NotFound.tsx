import { Link } from 'react-router-dom';
import { Header } from '../components/Header';

export function NotFound() {
  return (
    <>
      <Header />
      <main className="app-main app-main--centered">
        <div style={{ textAlign: 'center' }}>
          <p>nothing here but us ghosts</p>
          <Link to="/">← back home</Link>
        </div>
      </main>
    </>
  );
}
