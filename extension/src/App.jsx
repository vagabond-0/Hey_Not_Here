import React, { useState, useEffect } from "react";

function App() {
  const [url, setUrl] = useState("");

  useEffect(() => {
    if (chrome?.tabs) {
      chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        if (tabs.length > 0) {
          setUrl(tabs[0].url);
        }
      });
    }
  }, []);

  return (
    <div style={{ width: "300px", padding: "10px", textAlign: "center" }}>
      <h2>Current Tab URL:</h2>
      <p style={{ wordBreak: "break-all", color: "blue" }}>{url || "Loading..."}</p>
    </div>
  );
}

export default App;
