import { Minus, Square, X, Copy } from 'lucide-react';
import { getCurrentWindow } from '@tauri-apps/api/window';
import { useEffect, useState } from 'react';

const appWindow = getCurrentWindow();

export default function TitleBar() {
  const [maximized, setMaximized] = useState(false);

  useEffect(() => {
    let unlisten: (() => void) | undefined;
    appWindow.onResized(() => {
      void appWindow.isMaximized().then(setMaximized);
    }).then((fn) => (unlisten = fn));
    return () => unlisten?.();
  }, []);

  return (
    <div className="titlebar">
      <div className="titlebar__drag" data-tauri-drag-region>
        Vulpini X
      </div>
      <div className="titlebar__controls">
        <button
          className="titlebar__btn"
          aria-label="Minimize"
          onClick={() => void appWindow.minimize()}
        >
          <Minus size={15} />
        </button>
        <button
          className="titlebar__btn"
          aria-label="Maximize"
          onClick={() => void appWindow.toggleMaximize()}
        >
          {maximized ? <Copy size={13} /> : <Square size={13} />}
        </button>
        <button
          className="titlebar__btn titlebar__btn--close"
          aria-label="Close"
          onClick={() => void appWindow.close()}
        >
          <X size={16} />
        </button>
      </div>
    </div>
  );
}
