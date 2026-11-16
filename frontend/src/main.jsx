import { useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import './styles/style.css';

function App() {
  const [status, setStatus] = useState('Проверяем подключение к серверу…');

  useEffect(() => {
    const controller = new AbortController();
    fetch('/api/users/health', { signal: controller.signal })
      .then((response) => {
        if (!response.ok) throw new Error('Server unavailable');
        return response.json();
      })
      .then((data) => setStatus(data.status === 'ok' ? 'Сервер работает' : 'Неожиданный ответ сервера'))
      .catch((error) => {
        if (error.name !== 'AbortError') setStatus('Не удалось подключиться к серверу');
      });
    return () => controller.abort();
  }, []);

  return <main><h1>MTLS</h1><p role="status">{status}</p></main>;
}

createRoot(document.getElementById('root')).render(<App />);
