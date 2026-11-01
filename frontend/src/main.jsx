import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import App from './App.jsx';
import './styles/base.css';
import './styles/overview.css';
import './styles/incidents.css';
import './styles/findings.css';
import './styles/traffic.css';
import './styles/evidence.css';
import './styles/report.css';
import './styles/print.css';

createRoot(document.getElementById('root')).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
