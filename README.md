# Phishing Detection Model

## Overview
This project aims to detect phishing websites using machine learning. The model analyzes various features extracted from URLs and predicts whether a given website is **phishing** or **legitimate**.

## Features Used
The model is trained on a set of features including:
- URL-based features (length, special characters, domain age, etc.)
- HTML & JavaScript-based features
- WHOIS and DNS-related information
- Page ranking and traffic-based features

## Dependencies
To run this project, install the following dependencies:
```bash
pip install numpy pandas scikit-learn
```

## Usage
1. **Load the trained model and scaler:**
   ```python
   import pickle
   import numpy as np
   from sklearn.preprocessing import StandardScaler

   # Load saved model and scaler
   with open('phishing_model.pkl', 'rb') as f:
       model = pickle.load(f)
   with open('scaler.pkl', 'rb') as f:
       scaler = pickle.load(f)
   ```

2. **Make predictions:**
   ```python
   # Example input (feature vector)
   X_test = np.array([[26, 17, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 1, 0, 0, 0, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 4, 3, 0, 3, 0, 17, 9, 0, 1.33, 8.5, 1, 0, 0, 0, 0, 0, 0, 0, 5, 0.7, 0.3, 0.1, 1, 0.5, 0.5, 0.2, 0.3, 1, 0, 5, 0, 0.6, 0.4, 0, 0, 1, 1, 0, 0, 0, 0, 1, 0, 50, 2000, 50000, 1, 1, 3]])

   # Scale the input
   X_test_scaled = scaler.transform(X_test)
   
   # Predict
   prediction = model.predict(X_test_scaled)
   print("🚀 Prediction:", "Phishing ❌" if prediction[0] == 1 else "Legitimate ✅")
   ```

## Current Status 🚀
- The model is **not yet fully efficient** and is still being improved.
- Additional feature engineering and fine-tuning are in progress to increase accuracy.
- Future improvements will include deep learning models and enhanced feature selection.

## Contribution
Feel free to contribute by:
- Adding new features to improve accuracy.
- Experimenting with different models.
- Optimizing the dataset for better performance.

## License
This project is open-source and available for modification and improvement.

