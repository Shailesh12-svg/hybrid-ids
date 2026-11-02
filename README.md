# 🛡️ Hybrid Intrusion Detection System (Hybrid IDS)

### An Explainable Machine Learning Approach for Network Intrusion Detection Using Rule-Based Detection, XGBoost, and SHAP

## 📌 Overview

The **Hybrid Intrusion Detection System (Hybrid IDS)** is a machine learning-based cybersecurity project designed to identify malicious network traffic and distinguish it from legitimate network activity.

The system combines traditional rule-based detection techniques with the predictive capabilities of **XGBoost**, creating a hybrid approach to network intrusion detection.

To improve model transparency and interpretability, **SHAP (SHapley Additive exPlanations)** is integrated to explain model predictions and identify the network traffic features that contribute most to intrusion detection.

The project also incorporates a **Power BI dashboard** to visualize detection results, attack patterns, and model performance.

## 🎯 Project Objectives

- Develop a hybrid intrusion detection architecture combining rule-based detection and machine learning.
- Detect malicious network traffic using the XGBoost classification algorithm.
- Improve detection transparency using SHAP explainability.
- Analyze network traffic patterns and identify important intrusion indicators.
- Visualize detection insights and model performance through Power BI.
- Evaluate the system using standard classification metrics.

## 🏗️ System Architecture

The proposed system follows a multi-stage detection pipeline:

1. **Dataset Collection:** Load network traffic records from the CICIDS2018 dataset.
2. **Data Preprocessing:** Handle missing values, clean data, encode categorical variables, and prepare features.
3. **Rule-Based Detection:** Apply predefined detection rules to identify suspicious network activity.
4. **Machine Learning Detection:** Use XGBoost to classify network traffic.
5. **Hybrid Detection:** Combine rule-based and machine learning detection results.
6. **Explainable AI:** Apply SHAP to understand feature contributions to model predictions.
7. **Visualization:** Present detection insights and performance indicators using Power BI.

## 📊 Dataset

**Dataset:** CICIDS2018

The Canadian Institute for Cybersecurity's CICIDS2018 dataset contains network traffic records representing benign activities and different categories of cyberattacks.

Dataset characteristics include:

- Network flow-based features.
- Benign network traffic.
- Different malicious traffic categories.
- Statistical and behavioral network indicators.

Dataset source:

https://www.unb.ca/cic/datasets/ids-2018.html

## 🤖 Technologies Used

| Category | Technologies |
|---|---|
| Programming Language | R |
| Machine Learning | XGBoost |
| Rule-Based Detection | Custom detection rules |
| Explainable AI | SHAP |
| Data Processing | dplyr, tidyr, readr |
| Visualization | ggplot2 |
| Evaluation | caret, pROC |
| Dashboard | Microsoft Power BI |
| Dataset | CICIDS2018 |

## 🧠 Machine Learning Model

### XGBoost

XGBoost (Extreme Gradient Boosting) is used as the primary machine learning classifier.

It is a gradient-boosting algorithm that builds an ensemble of decision trees to improve classification performance.

### Rule-Based Detection

The rule-based component applies predefined conditions to identify suspicious network activities.

This provides an additional detection layer alongside machine learning predictions.

### Hybrid Detection Approach

The hybrid architecture combines the outputs of rule-based detection and XGBoost to strengthen intrusion detection.

## 🔍 Explainable AI Using SHAP

One of the important components of this project is model explainability.

SHAP is used to interpret the predictions made by the XGBoost model.

It helps answer questions such as:

- Which network features influence intrusion detection the most?
- Why was a particular network connection classified as malicious?
- Which features contribute towards benign or attack predictions?
- How do individual features influence the final prediction?

SHAP visualizations include:

- SHAP Summary Plot
- SHAP Feature Importance
- SHAP Waterfall Plot

## 📈 Model Performance

The project achieved the following reported accuracy during experimentation:

| Evaluation Metric | Result |
|---|---:|
| Accuracy | **97.84%** |

*Note: Accuracy is an experimental result and should be reported alongside precision, recall, F1-score, and confusion matrix results for a complete evaluation.*

## 📊 Power BI Dashboard

The project integrates Power BI to provide an interactive visualization of intrusion detection results.

Dashboard components can include:

- Benign vs Malicious Traffic Distribution
- Attack Category Distribution
- Model Performance Metrics
- Intrusion Detection Statistics
- Feature Importance Insights
- Network Traffic Analysis

## 📂 Project Structure

```text
Hybrid-IDS/
│
├── dataset/
│   └── README.md
│
├── R/
│   └── hybrid_ids.R
│
├── visualizations/
│   ├── shap_summary.png
│   ├── shap_waterfall.png
│   └── feature_importance.png
│
├── dashboard/
│   └── powerbi_dashboard.png
│
├── results/
│   └── evaluation_results.csv
│
├── README.md
└── LICENSE
```

*The directory structure is a suggested organization. Adjust filenames to match your actual repository.*

## ⚙️ Installation and Execution

### 1. Clone the Repository

```bash
git clone https://github.com/your-username/Hybrid-IDS.git
```

### 2. Navigate to the Project Directory

```bash
cd Hybrid-IDS
```

### 3. Install Required R Packages

```r
required_packages <- c(
  "readr",
  "dplyr",
  "tidyr",
  "stringr",
  "caret",
  "randomForest",
  "xgboost",
  "ggplot2",
  "pROC",
  "SHAPforxgboost",
  "Matrix",
  "scales"
)

install.packages(required_packages)
```

### 4. Prepare the Dataset

Download the CICIDS2018 dataset and place the required CSV files in the dataset directory.

### 5. Run the Project

Open the R script in RStudio and execute:

```r
source("R/hybrid_ids.R")
```

Make sure to update the dataset paths in the script according to your local environment.

## 🚀 Key Contributions

- Hybrid intrusion detection combining rule-based techniques and machine learning.
- XGBoost-based network traffic classification.
- Integration of explainable AI using SHAP.
- Feature-level interpretation of intrusion detection predictions.
- Power BI-based visualization for cybersecurity analysis.

## 🔮 Future Enhancements

- Real-time network traffic monitoring.
- Integration with live packet capture systems.
- Deployment through a Flask or Streamlit application.
- Advanced deep learning-based intrusion detection.
- Automated threat alert generation.
- Integration with Security Information and Event Management (SIEM) systems.

## 👨‍💻 Author

**Shailesh Mallick**

M.Tech – Computer Science | Data Science & Analytics

Interested in Machine Learning, Data Science, Explainable AI, and Cybersecurity.

## 📜 License

This project is intended for academic and research purposes. Add an appropriate open-source license before allowing reuse or redistribution.

---

⭐ If you find this project interesting, consider giving the repository a star!
