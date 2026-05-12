import type React from 'react';
import { useEffect } from 'react';

export function AuthModal({
  title,
  onClose,
  children,
}: {
  title: string;
  onClose: () => void;
  children: React.ReactNode;
}) {
  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (e.key === 'Escape') {
        onClose();
      }
    }
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);

  return (
    <div className="modal-backdrop">
      <button type="button" className="modal-backdrop-close" aria-label="Close" onClick={onClose} />
      <div className="modal">
        <div className="modal-titlebar">
          <h2>{title}</h2>
          <button type="button" onClick={onClose}>
            [x]
          </button>
        </div>
        {children}
      </div>
    </div>
  );
}
