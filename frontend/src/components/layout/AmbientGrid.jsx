import { useEffect } from 'react';

export default function AmbientGrid() {
  useEffect(() => {
    let frame = 0;

    const updatePointer = (event) => {
      if (frame) return;

      frame = window.requestAnimationFrame(() => {
        document.documentElement.style.setProperty('--mouse-x', `${event.clientX}px`);
        document.documentElement.style.setProperty('--mouse-y', `${event.clientY}px`);
        frame = 0;
      });
    };

    window.addEventListener('pointermove', updatePointer, { passive: true });

    return () => {
      window.removeEventListener('pointermove', updatePointer);
      if (frame) window.cancelAnimationFrame(frame);
    };
  }, []);

  return <div className="ambient-grid" aria-hidden="true" />;
}
