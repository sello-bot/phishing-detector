import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import PhishingDetector from './PhishingDetector.jsx'

createRoot(document.getElementById('root')).render(
  <StrictMode>
    <PhishingDetector />
  </StrictMode>
)