# XAI-IDS — An Explainable AI-Based Intrusion Detection System

A network intrusion detection system that does three things at once: it classifies network flows, explains *why* it reached each verdict using SHAP, and tells the analyst what to do about it.

Most machine-learning IDS models behave as black boxes — they return a label with no justification. In a security operations context that is a real obstacle: analysts have to triage quickly, justify escalations, and trust the tool. XAI-IDS pairs a Random Forest classifier with per-prediction SHAP attributions and a rule-based response engine, delivered through a FastAPI service and a single-page dashboard.

Built as the artefact for **7005SCN Individual Research Project**, MSc Cybersecurity, Coventry University.

---

## Features

- **Multi-class flow classification** across seven traffic classes: BENIGN, DoS Hulk, DDoS, PortScan, FTP-Patator, SSH-Patator and Web Attack
- **Per-prediction SHAP explanations** — every verdict comes with a ranked, signed contribution for each of the twenty flow features, computed exactly via TreeSHAP
- **Actionable response guidance** — each detected class maps to a severity rating and a prioritised list of mitigation steps
- **Live traffic sniffer** — Scapy-based capture with an automatic fallback to a statistically realistic traffic simulator when a live interface is unavailable
- **Manual flow analyser** — enter or load a single flow and get classification, confidence, explanation and response plan in one call
- **Model insights view** — headline metrics, per-class diagnostics, confusion matrix, and one-click retraining
- **One-command launch** — the launcher provisions a virtual environment, installs pinned dependencies, trains the model on first run and starts the server

---

## Quick start

**Requirements:** Python 3.12 (64-bit). Windows, macOS or Linux. No GPU needed.

```bash
git clone https://github.com/<your-username>/xai-ids.git
cd xai-ids
python run.py
```

The launcher creates `.venv/`, installs everything from `requirements.txt`, trains the Random Forest if no saved model is found, and starts Uvicorn.

Then open **http://127.0.0.1:8000** in your browser.

> On Windows you may see a WinPcap deprecation notice from Scapy. This is expected and does not affect the simulator-based capture path. Live packet capture requires [Npcap](https://npcap.com/) and elevated privileges; without them the system falls back to the simulator automatically.

---

## Dashboard

| View | What it does |
|---|---|
| **Security Dashboard** | Flows processed, alert count, top threat type, headline accuracy, live threat-level indicator and a rolling alerts feed |
| **Traffic Sniffer** | Streams classified flows in real time, with attack injection toggle and CSV export; click any row for full analysis |
| **Manual Flow Analyser** | Submit one flow (or load a preset) and get prediction, confidence, SHAP feature-impact log and a severity-tagged response plan |
| **Model Insights** | Accuracy, weighted precision/recall/F1, per-class breakdown, confusion matrix and a retrain control |

---

## API

The REST interface is deliberately small. Interactive docs are available at `/docs` once the server is running.

| Method | Endpoint | Purpose |
|---|---|---|
| `GET` | `/api/status` | Server, model and sniffer state |
| `POST` | `/api/train` | (Re)train the classifier and return fresh metrics |
| `GET` | `/api/metrics` | Retrieve stored evaluation results |
| `POST` | `/api/sniff/start` | Start capture or simulation |
| `POST` | `/api/sniff/stop` | Stop capture |
| `POST` | `/api/sniff/toggle_attacks` | Enable or disable attack injection in the simulator |
| `GET` | `/api/sniff/traffic` | Recent flows with live classifications |
| `POST` | `/api/analyze` | Classify one flow and return prediction, confidence, SHAP explanation and recommendations together |

`/api/analyze` is where the three concerns meet — one call returns the verdict, the evidence for it, and the response plan.

---

## Project structure

```
XAI/
├── run.py                          Launcher: venv provisioning, training, server start
├── requirements.txt                Pinned dependency versions
├── backend/
│   ├── main.py                     FastAPI application and REST endpoints
│   ├── data_handler.py             Dataset generation, cleaning, scaling, encoding
│   ├── model_handler.py            Random Forest training, persistence, prediction
│   ├── xai_handler.py              SHAP TreeExplainer and per-flow attribution
│   ├── recommendation_engine.py    Rule-based mitigation guidance
│   └── sniff_handler.py            Live Scapy capture with simulator fallback
├── frontend/
│   ├── index.html                  Single-page dashboard markup
│   ├── css/style.css               Dashboard styling
│   └── js/app.js                   View logic and API calls
└── data/                           Generated at run time (git-ignored)
```

---

## How it works

A flow travels through the system in five steps:

1. **Capture or entry** — the sniffer assembles packets into bidirectional flows, or the user submits one manually
2. **Preprocessing** — the persisted `StandardScaler` applies exactly the transformation used during training, preventing training–serving skew
3. **Classification** — a Random Forest (100 estimators, max depth 12) predicts the class and returns per-class probabilities
4. **Explanation** — a SHAP `TreeExplainer`, built over a persisted 100-sample background set, returns a signed contribution per feature toward the predicted class, ranked by magnitude
5. **Recommendation** — the predicted class is mapped to a severity rating and an ordered list of mitigation actions

### Feature set

Twenty flow-level features modelled on the CICIDS2017 schema, chosen to balance discriminative power against interpretability — because every feature is surfaced in the explanations, features an analyst can reason about (ports, durations, packet sizes, rates) beat opaque derived quantities.

| Category | Features |
|---|---|
| Connection | Destination Port, Flow Duration |
| Volume (counts) | Total Fwd/Backward Packets, Fwd/Bwd Header Length |
| Volume (bytes) | Total Length of Fwd/Bwd Packets |
| Packet size | Fwd and Bwd Packet Length Max/Min/Mean |
| Aggregate size | Packet Length Mean, Average Packet Size |
| Rate & timing | Flow Bytes/s, Flow Packets/s, Flow IAT Mean, Flow IAT Max |

### Why Random Forest and SHAP

Tree ensembles deliver competitive accuracy on tabular flow features at low computational cost, expose native feature importances, and — critically — support TreeSHAP, which computes exact Shapley attributions efficiently. A deep network would have been harder to explain faithfully, which works against the whole point of the project.

---

## Data and validity — please read

**This system is trained and evaluated on synthetically generated data, not on captured network traffic.** The feature schema and attack taxonomy mirror CICIDS2017 (Sharafaldin et al., 2018), and per-class feature values are sampled from parametric distributions chosen to reproduce each traffic type's characteristic statistical signature. Benign traffic is deliberately generated as a mixture of active HTTP/HTTPS sessions, short DNS/NTP queries and single-packet ephemeral flows so that it is not trivially separable from low-volume attacks.

The advantages are full control over class balance, reproducibility, and no processing of anyone's real communications. The cost is external validity: **high accuracy on parametric synthetic data primarily demonstrates that the pipeline works and that the modelled class distributions are separable — it is not a claim of real-world benchmark performance.** On real traffic, accuracy would be expected to fall and false positives to rise, consistent with the well-known cautions of Sommer and Paxson (2010).

Other limitations worth stating plainly:

- Results come from a single stratified train/test split, not cross-validation, so there is no variance estimate
- The explanations are assessed for face validity against expected attack signatures, not through a user study
- The recommendation engine is static rather than context-aware
- The system **detects and recommends; it does not block or prevent**, and it does not consider adversarial evasion

---

## Scope

**In scope:** flow-based classification, Random Forest development, SHAP explanation generation, rule-based recommendations, and a dashboard for visualisation, live simulation and manual analysis.

**Out of scope:** production enterprise deployment, novel ML algorithms, automated firewall enforcement, and adversarial-attack simulation against the detector itself.

---

## Legal and ethical use

Capture traffic **only on networks you are authorised to monitor.** Unauthorised interception of network communications may breach computer-misuse and data-protection legislation in your jurisdiction. Deployed on real traffic, this kind of system engages data-protection law — including the GDPR and, in the UK, the Data Protection Act 2018 — and would require a lawful basis, data minimisation, and appropriate retention and access controls.

This tool is intended as a **decision-support aid for trained analysts**, not an autonomous enforcement mechanism. That positioning is reflected in its detect-and-recommend design. There is also a dual-use dimension: detailed knowledge of how a detector characterises attacks could in principle inform evasion.

---

## Tech stack

FastAPI · Uvicorn · scikit-learn · SHAP · pandas · NumPy · joblib · Scapy · vanilla HTML/CSS/JavaScript

All versions are pinned in `requirements.txt`. Pinning matters here: minor releases of scikit-learn and SHAP can change both model behaviour and the shape of the explanation output.

---

## References

- Breiman, L. (2001). Random forests. *Machine Learning*, 45(1), 5–32.
- Lundberg, S. M., & Lee, S.-I. (2017). A unified approach to interpreting model predictions. *NeurIPS 30*, 4765–4774.
- Sharafaldin, I., Lashkari, A. H., & Ghorbani, A. A. (2018). Toward generating a new intrusion detection dataset and intrusion traffic characterization. *ICISSP*, 108–116.
- Sommer, R., & Paxson, V. (2010). Outside the closed world: On using machine learning for network intrusion detection. *IEEE S&P*, 305–316.
- Khraisat, A., Gondal, I., Vamplew, P., & Kamruzzaman, J. (2019). Survey of intrusion detection systems. *Cybersecurity*, 2(1), 20.

---

## Author

**Varshini Yadav Chunchu** — Student ID 16377066
MSc Cybersecurity, Coventry University · 7005SCN Individual Research Project

## Licence

Released for academic and educational purposes. Please credit the author if you build on this work.
