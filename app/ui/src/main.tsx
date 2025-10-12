import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App';
import './styles/global.css';
import './setup-i18n';

const rootElement = document.getElementById('root');
if (!rootElement) {
  throw new Error('Root element missing');
}

const root = ReactDOM.createRoot(rootElement);
root.render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
