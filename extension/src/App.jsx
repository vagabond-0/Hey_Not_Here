import React, { useState, useEffect } from "react";

function App() {
  const [url, setUrl] = useState("");
  const [prediction, setPrediction] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    if (chrome?.tabs) {
      chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        if (tabs.length > 0) {
          const currentUrl = tabs[0].url;
          setUrl(currentUrl);
          checkPhishing(currentUrl); 
        }
      });
    }
  }, []);

  const checkPhishing = async (url) => {
    setLoading(true);
    setError(null);
    try {
      const response = await fetch("http://127.0.0.1:5000/predict", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ url }),
      });

      const data = await response.json();

      if (data.error) {
        setError(data.error);
      } else {
        setPrediction(data.prediction);
      }
    } catch (err) {
      setError("Failed to connect to backend.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ width: "300px", padding: "10px", textAlign: "center" }}>
      <h2>Current Tab URL:</h2>
      <p style={{ wordBreak: "break-all", color: "blue" }}>{url || "Loading..."}</p>

      {loading && <p style={{ color: "orange" }}>Checking...</p>}

      {error && <p style={{ color: "red", fontWeight: "bold" }}>Error: {error}</p>}

      {prediction && (
        <p style={{ color: prediction === "Phishing" ? "red" : "green", fontWeight: "bold" }}>
          {prediction === "Phishing" ? "⚠️ Phishing Detected!" : "✅ Safe Site"}
        </p>
      )}
    </div>
  );
}

export default App;
