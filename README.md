# DarkScope – Intelligent Dark Web Crawler

DarkScope is an intelligent dark web crawling and analysis platform developed for cybersecurity research and threat intelligence. The system connects to the Tor network to crawl `.onion` websites and performs multiple layers of analysis including NLP-based entity extraction, machine learning classification, OPSEC analysis, DNS leakage detection, identity correlation, and graph-based intelligence visualization.

---

## Features

* Dark web crawling using the Tor network
* BFS-based link traversal and automated page discovery
* NLP-based entity extraction using spaCy
* Machine learning classification using TF-IDF and Logistic Regression
* OPSEC analysis for detecting operational security weaknesses
* DNS leakage detection and clearnet dependency analysis
* HTTP header fingerprinting and infrastructure analysis
* Identity correlation across platforms
* Graph-based intelligence analysis using NetworkX
* Flask-based dashboard visualization
* STIX export support for threat intelligence sharing

---

## System Architecture

```text
Seed URLs → Tor Network → Crawler → Data Processing → NLP/ML Analysis → Database → Dashboard Visualization
```

---

## Technologies Used

| Category             | Technologies            |
| -------------------- | ----------------------- |
| Programming Language | Python                  |
| Web Framework        | Flask                   |
| Database             | MongoDB                 |
| Machine Learning     | scikit-learn            |
| NLP                  | spaCy                   |
| Graph Analysis       | NetworkX                |
| Web Crawling         | Requests, BeautifulSoup |
| Dark Web Access      | Tor (SOCKS5 Proxy)      |

---

## Core Modules

### 1. Dark Web Crawler

* Connects to the Tor network using SOCKS5 proxy
* Crawls `.onion` websites using BFS traversal
* Extracts links and avoids duplicate crawling

### 2. Data Processing Module

* Parses HTML content
* Removes scripts and unnecessary elements
* Extracts clean textual data for analysis

### 3. NLP Pipeline

* Extracts entities such as:

  * Emails
  * Cryptocurrency addresses
  * Usernames
  * URLs

### 4. Machine Learning Classifier

* Uses TF-IDF for feature extraction
* Uses Logistic Regression for content classification
* Categorizes dark web pages into meaningful groups

### 5. OPSEC Analysis

* Detects DNS leakage
* Identifies external clearnet dependencies
* Performs HTTP header fingerprinting
* Detects metadata exposure and security weaknesses

### 6. Graph Intelligence Analysis

* Builds relationship graphs between entities and websites
* Uses NetworkX for visualization and analysis

### 7. Dashboard

* Flask-based visualization dashboard
* Displays crawling statistics, entity extraction results, OPSEC findings, and graph insights

---

## Installation

### Clone Repository

```bash
git clone https://github.com/DhruvPanchal-cs/DarkScope.git
cd DarkScope
```

### Install Dependencies

```bash
pip install -r requirements.txt
```

### Start Tor Service

Ensure Tor is running locally on:

```text
127.0.0.1:9050
```

### Run the Application

```bash
python app.py
```

---

## Project Workflow

```text
Connect to Tor
        ↓
Crawl .onion Websites
        ↓
Extract HTML & Links
        ↓
Process and Clean Data
        ↓
Perform NLP & ML Analysis
        ↓
Detect OPSEC Vulnerabilities
        ↓
Store Results in MongoDB
        ↓
Visualize Results in Dashboard
```

---

## Repository Structure

```text
DarkScope/
│
├── app.py
├── crawler.py
├── classifier.py
├── dns_analyzer.py
├── header_fingerprint.py
├── identity_correlator.py
├── link_graph.py
├── nlp_pipeline.py
├── opsec_detector.py
├── stix_export.py
├── requirements.txt
├── templates/
└── README.md
```

---

## Applications

* Cybersecurity Research
* Threat Intelligence
* Dark Web Monitoring
* Security Awareness and OPSEC Analysis
* Academic Research

---

## Future Enhancements

* Real-time dark web monitoring
* Deep learning-based classification
* Enhanced identity correlation
* Multi-network support (I2P, Freenet)
* Integration with threat intelligence platforms

---

## Disclaimer

This project is developed strictly for educational and cybersecurity research purposes only. The project does not promote or support illegal activities. Users are responsible for complying with applicable laws and ethical guidelines.

---

## Author

**Dhruv Panchal**
Integrated B.Tech – M.Tech (Cyber Security)
National Forensic Sciences University (NFSU)
