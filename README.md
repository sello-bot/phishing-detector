# PhishGuard AI

AI-powered phishing detection system built with React + Flask + RandomForest ML.

## Live Demo
Frontend: Deployed on Vercel  
Backend: Flask API (localhost or Railway)

## Stack
- React 18 + Vite (frontend)
- Python Flask REST API (backend)
- scikit-learn RandomForest (ML model)
- 28-feature URL analysis

## Run Locally

### Backend
cd phishing-detector
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r backend/requirements.txt
python ml/train_model.py
python backend/app.py

### Frontend
npm install
npm run dev
