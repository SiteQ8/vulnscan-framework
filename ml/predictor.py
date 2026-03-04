"""
ML-Powered Vulnerability Predictor
====================================
Uses scikit-learn to train a Random Forest + Gradient Boosting ensemble
that predicts likely vulnerabilities based on reconnaissance data.

Feature Engineering:
  - Technology stack presence (one-hot encoded)
  - Open ports (binary flags for known risky ports)
  - SSL certificate health
  - Security header score
  - Exposed path count
  - Subdomain count
  - WAF presence
  - Server version disclosure
  - CMS detected
  - ...and more

Outputs predictions with confidence scores and CVSS-mapped severity.
"""

import os
import json
import pickle
import hashlib
import numpy as np
from pathlib import Path
from typing import Optional
from utils.logger import get_logger

# Feature flags for tech stack
TECH_FEATURES = [
    "WordPress", "Drupal", "Joomla", "Laravel", "Django",
    "Ruby on Rails", "ASP.NET", "PHP", "Apache", "Nginx",
    "IIS", "jQuery", "React", "Angular", "Vue.js", "Elasticsearch",
    "Grafana", "Cloudflare",
]

RISKY_PORTS = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445,
               993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379,
               8080, 8443, 8888, 9200, 27017]

# Known vulnerability patterns mapped to tech/port combinations
RULE_ENGINE = [
    {
        "name": "WordPress Core/Plugin Vulnerabilities",
        "condition": lambda f: f.get("has_wordpress", 0) == 1,
        "predicted_vulns": ["CVE-2023-5561 (WordPress Auth Bypass)", "Plugin RCE via file upload", "XML-RPC brute force"],
        "severity": "high",
        "confidence_base": 0.75,
        "cve_refs": ["CVE-2023-5561", "CVE-2022-21661"],
    },
    {
        "name": "Exposed Redis Instance",
        "condition": lambda f: f.get("port_6379", 0) == 1,
        "predicted_vulns": ["Unauthenticated Redis access", "Remote code execution via Redis CONFIG"],
        "severity": "critical",
        "confidence_base": 0.90,
        "cve_refs": ["CVE-2022-0543"],
    },
    {
        "name": "Exposed Elasticsearch",
        "condition": lambda f: f.get("port_9200", 0) == 1,
        "predicted_vulns": ["Unauthenticated data access", "Information disclosure", "Kibana CVE chain"],
        "severity": "critical",
        "confidence_base": 0.88,
        "cve_refs": ["CVE-2021-22145"],
    },
    {
        "name": "RDP Exposure",
        "condition": lambda f: f.get("port_3389", 0) == 1,
        "predicted_vulns": ["BlueKeep (CVE-2019-0708)", "DejaBlue (CVE-2019-1181)", "Brute-force attack surface"],
        "severity": "critical",
        "confidence_base": 0.82,
        "cve_refs": ["CVE-2019-0708", "CVE-2019-1181"],
    },
    {
        "name": "SMB Exposure",
        "condition": lambda f: f.get("port_445", 0) == 1,
        "predicted_vulns": ["EternalBlue (MS17-010)", "SMB relay attacks", "Credential capture"],
        "severity": "critical",
        "confidence_base": 0.85,
        "cve_refs": ["CVE-2017-0144", "CVE-2017-0145"],
    },
    {
        "name": "No WAF Detected + Web Application Present",
        "condition": lambda f: f.get("waf_present", 0) == 0 and f.get("port_80", 0) + f.get("port_443", 0) > 0,
        "predicted_vulns": ["Automated attack surface", "SQLi/XSS exploitation likely easier without WAF"],
        "severity": "medium",
        "confidence_base": 0.65,
        "cve_refs": [],
    },
    {
        "name": "Outdated PHP Application",
        "condition": lambda f: f.get("has_php", 0) == 1 and f.get("server_version_disclosed", 0) == 1,
        "predicted_vulns": ["PHP object injection", "RFI/LFI attacks", "Deprecated function exploits"],
        "severity": "high",
        "confidence_base": 0.72,
        "cve_refs": [],
    },
    {
        "name": "ASP.NET ViewState Tampering",
        "condition": lambda f: f.get("has_aspnet", 0) == 1,
        "predicted_vulns": ["ViewState deserialization (CVE-2020-0688)", "MachineKey exposure"],
        "severity": "high",
        "confidence_base": 0.70,
        "cve_refs": ["CVE-2020-0688"],
    },
    {
        "name": "Exposed MongoDB",
        "condition": lambda f: f.get("port_27017", 0) == 1,
        "predicted_vulns": ["Unauthenticated MongoDB access", "NoSQL injection"],
        "severity": "critical",
        "confidence_base": 0.87,
        "cve_refs": [],
    },
    {
        "name": "Exposed Jupyter Notebook",
        "condition": lambda f: f.get("port_8888", 0) == 1,
        "predicted_vulns": ["Unauthenticated RCE via Jupyter kernel"],
        "severity": "critical",
        "confidence_base": 0.92,
        "cve_refs": [],
    },
    {
        "name": "Weak SSL Configuration",
        "condition": lambda f: f.get("ssl_expiry_days", 365) < 30,
        "predicted_vulns": ["Certificate expiry → HTTPS degradation", "Man-in-the-middle risk"],
        "severity": "high",
        "confidence_base": 0.80,
        "cve_refs": [],
    },
    {
        "name": "Multiple Exposed Admin Paths",
        "condition": lambda f: f.get("exposed_paths_count", 0) >= 3,
        "predicted_vulns": ["Admin panel exposure", "Config file disclosure", "Sensitive data leakage"],
        "severity": "high",
        "confidence_base": 0.78,
        "cve_refs": [],
    },
    {
        "name": "Large Attack Surface (Many Subdomains)",
        "condition": lambda f: f.get("subdomain_count", 0) >= 10,
        "predicted_vulns": ["Subdomain takeover risk", "Forgotten/shadow IT exposure"],
        "severity": "medium",
        "confidence_base": 0.60,
        "cve_refs": [],
    },
    {
        "name": "Telnet Enabled",
        "condition": lambda f: f.get("port_23", 0) == 1,
        "predicted_vulns": ["Plaintext credential interception", "MITM attacks"],
        "severity": "high",
        "confidence_base": 0.95,
        "cve_refs": [],
    },
    {
        "name": "FTP Anonymous Access",
        "condition": lambda f: f.get("port_21", 0) == 1,
        "predicted_vulns": ["Anonymous FTP access", "FTP bounce attacks", "Credential sniffing"],
        "severity": "medium",
        "confidence_base": 0.70,
        "cve_refs": [],
    },
    {
        "name": "Django Debug Mode",
        "condition": lambda f: f.get("has_django", 0) == 1 and f.get("server_version_disclosed", 0) == 1,
        "predicted_vulns": ["Debug mode active — stack traces exposed", "SECRET_KEY leakage risk"],
        "severity": "high",
        "confidence_base": 0.68,
        "cve_refs": [],
    },
    {
        "name": "VNC Exposed",
        "condition": lambda f: f.get("port_5900", 0) == 1,
        "predicted_vulns": ["Unauthenticated VNC access", "Screen capture / keystroke injection"],
        "severity": "critical",
        "confidence_base": 0.88,
        "cve_refs": [],
    },
]


class VulnPredictor:
    """ML + Rule-based vulnerability predictor."""

    def __init__(self, model_path: str = "models/vuln_predictor.pkl", verbose: bool = False):
        self.model_path = model_path
        self.model = None
        self.scaler = None
        self.feature_names = []
        self.logger = get_logger(verbose=verbose)
        self._try_load_model()

    def _try_load_model(self):
        """Load a pre-trained model if it exists."""
        if os.path.exists(self.model_path):
            try:
                with open(self.model_path, "rb") as f:
                    saved = pickle.load(f)
                    self.model = saved.get("model")
                    self.scaler = saved.get("scaler")
                    self.feature_names = saved.get("feature_names", [])
                self.logger.info(f"  [+] ML model loaded from {self.model_path}")
            except Exception as e:
                self.logger.debug(f"Failed to load model: {e}")

    def train(self, data_path: str):
        """Train Random Forest + Gradient Boosting ensemble on labeled vuln data."""
        try:
            import pandas as pd
            from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
            from sklearn.preprocessing import StandardScaler
            from sklearn.model_selection import train_test_split
            from sklearn.metrics import classification_report
            from sklearn.pipeline import Pipeline

            self.logger.info(f"  [*] Loading training data from {data_path}")
            df = pd.read_csv(data_path)

            # Expected columns: feature columns + 'vuln_type' label
            if "vuln_type" not in df.columns:
                raise ValueError("Training CSV must contain 'vuln_type' label column")

            feature_cols = [c for c in df.columns if c != "vuln_type"]
            X = df[feature_cols].fillna(0).values
            y = df["vuln_type"].values
            self.feature_names = feature_cols

            X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

            self.scaler = StandardScaler()
            X_train_scaled = self.scaler.fit_transform(X_train)
            X_test_scaled = self.scaler.transform(X_test)

            self.logger.info("  [*] Training Random Forest model...")
            rf = RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42, n_jobs=-1)
            rf.fit(X_train_scaled, y_train)

            self.logger.info("  [*] Training Gradient Boosting model...")
            gb = GradientBoostingClassifier(n_estimators=50, learning_rate=0.1, max_depth=5, random_state=42)
            gb.fit(X_train_scaled, y_train)

            # Ensemble: average probabilities
            self.model = {"rf": rf, "gb": gb}

            # Evaluation
            rf_preds = rf.predict(X_test_scaled)
            self.logger.info("\n  [+] Model Evaluation:\n" + classification_report(y_test, rf_preds))

            # Save model
            os.makedirs(os.path.dirname(self.model_path) if os.path.dirname(self.model_path) else ".", exist_ok=True)
            with open(self.model_path, "wb") as f:
                pickle.dump({
                    "model": self.model,
                    "scaler": self.scaler,
                    "feature_names": self.feature_names,
                }, f)
            self.logger.info(f"  [+] Model saved to {self.model_path}")

        except ImportError:
            self.logger.warning("  [!] scikit-learn not installed — ML training unavailable. pip install scikit-learn")
        except Exception as e:
            self.logger.error(f"  [!] Training error: {e}")

    def predict(self, recon_data: dict, port_data: dict) -> list:
        """
        Predict vulnerabilities using rule engine + optional ML model.
        Returns list of prediction dicts.
        """
        features = self._extract_features(recon_data, port_data)
        predictions = []

        # Rule-based predictions (always run)
        for rule in RULE_ENGINE:
            try:
                if rule["condition"](features):
                    confidence = self._adjust_confidence(rule["confidence_base"], features)
                    predictions.append({
                        "name": rule["name"],
                        "predicted_vulns": rule["predicted_vulns"],
                        "severity": rule["severity"],
                        "confidence": round(confidence, 2),
                        "confidence_pct": f"{round(confidence * 100)}%",
                        "cve_refs": rule.get("cve_refs", []),
                        "source": "rule_engine",
                    })
            except Exception:
                continue

        # ML model predictions (if model is loaded)
        if self.model and self.scaler:
            ml_preds = self._ml_predict(features)
            predictions.extend(ml_preds)

        # Sort by confidence
        predictions.sort(key=lambda x: x["confidence"], reverse=True)

        self.logger.info(f"  [+] {len(predictions)} vulnerability predictions generated")
        return predictions

    def _extract_features(self, recon_data: dict, port_data: dict) -> dict:
        """Convert raw recon/scan data into ML feature vector."""
        features = {}

        # Technology features
        techs = recon_data.get("technologies", [])
        for tech in TECH_FEATURES:
            safe_key = "has_" + tech.lower().replace(" ", "_").replace(".", "").replace("/", "")
            features[safe_key] = 1 if tech in techs else 0

        # Port features
        open_ports = set()
        for port, data in port_data.items():
            if isinstance(data, dict) and data.get("state") == "open":
                open_ports.add(int(port))

        for port in RISKY_PORTS:
            features[f"port_{port}"] = 1 if port in open_ports else 0

        features["open_port_count"] = len(open_ports)

        # SSL features
        ssl = recon_data.get("ssl_cert", {})
        features["ssl_valid"] = 1 if ssl.get("valid") else 0
        features["ssl_expiry_days"] = ssl.get("days_remaining", 365)
        features["ssl_issues_count"] = len(ssl.get("issues", []))

        # Header features
        header_data = recon_data.get("http_headers", {})
        features["security_header_issues"] = len(header_data.get("security_issues", []))
        features["server_version_disclosed"] = 1 if header_data.get("server_info") else 0

        # Exposed paths
        features["exposed_paths_count"] = len(recon_data.get("open_paths", []))

        # Subdomains
        features["subdomain_count"] = len(recon_data.get("subdomains", []))

        # WAF
        waf = recon_data.get("waf", {})
        features["waf_present"] = 1 if waf.get("detected") else 0

        # DNS features
        dns = recon_data.get("dns", {})
        features["has_mx_records"] = 1 if dns.get("MX") else 0
        features["has_txt_records"] = 1 if dns.get("TXT") else 0

        return features

    def _adjust_confidence(self, base: float, features: dict) -> float:
        """Adjust confidence score based on additional context."""
        confidence = base
        if features.get("waf_present", 0) == 1:
            confidence *= 0.75  # WAF reduces exploitability
        if features.get("ssl_valid", 1) == 0:
            confidence = min(1.0, confidence * 1.1)
        if features.get("security_header_issues", 0) >= 4:
            confidence = min(1.0, confidence * 1.05)
        return confidence

    def _ml_predict(self, features: dict) -> list:
        """Run ML model inference."""
        predictions = []
        try:
            import numpy as np
            feature_vector = np.array(
                [features.get(f, 0) for f in self.feature_names], dtype=float
            ).reshape(1, -1)

            scaled = self.scaler.transform(feature_vector)

            rf = self.model["rf"]
            gb = self.model["gb"]

            rf_proba = rf.predict_proba(scaled)[0]
            gb_proba = gb.predict_proba(scaled)[0]
            avg_proba = (rf_proba + gb_proba) / 2

            classes = rf.classes_
            for i, vuln_class in enumerate(classes):
                confidence = float(avg_proba[i])
                if confidence >= 0.4:
                    predictions.append({
                        "name": f"ML Prediction: {vuln_class}",
                        "predicted_vulns": [vuln_class],
                        "severity": "high" if confidence >= 0.7 else "medium",
                        "confidence": round(confidence, 2),
                        "confidence_pct": f"{round(confidence * 100)}%",
                        "cve_refs": [],
                        "source": "ml_model",
                    })
        except Exception as e:
            self.logger.debug(f"ML predict error: {e}")

        return predictions

    def generate_sample_dataset(self, output_path: str = "data/sample_training_data.csv"):
        """Generate a sample labeled CSV for ML training demo."""
        import csv, random, os
        os.makedirs(os.path.dirname(output_path), exist_ok=True)

        feature_names = (
            [f"has_{t.lower().replace(' ','_').replace('.','').replace('/','')}" for t in TECH_FEATURES] +
            [f"port_{p}" for p in RISKY_PORTS] +
            ["open_port_count", "ssl_valid", "ssl_expiry_days", "ssl_issues_count",
             "security_header_issues", "server_version_disclosed", "exposed_paths_count",
             "subdomain_count", "waf_present", "has_mx_records", "has_txt_records"]
        )

        vuln_types = [
            "SQLInjection", "XSS", "RCE", "SSRF", "LFI",
            "IDOR", "OpenRedirect", "CSRF", "InfoDisclosure", "MissingSecurityHeaders"
        ]

        rows = []
        for _ in range(500):
            row = {f: random.randint(0, 1) for f in feature_names}
            row["open_port_count"] = random.randint(1, 20)
            row["ssl_expiry_days"] = random.randint(0, 365)
            row["ssl_issues_count"] = random.randint(0, 5)
            row["security_header_issues"] = random.randint(0, 6)
            row["exposed_paths_count"] = random.randint(0, 10)
            row["subdomain_count"] = random.randint(0, 30)
            row["vuln_type"] = random.choice(vuln_types)
            rows.append(row)

        with open(output_path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=feature_names + ["vuln_type"])
            writer.writeheader()
            writer.writerows(rows)

        self.logger.info(f"  [+] Sample dataset saved to {output_path}")
        return output_path
