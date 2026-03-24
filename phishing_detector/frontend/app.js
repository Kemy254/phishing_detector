document.addEventListener("DOMContentLoaded", () => {
    const form = document.getElementById("scan-form");
    const urlInput = document.getElementById("url-input");
    const scanBtn = document.getElementById("scan-btn");
    const btnText = document.querySelector(".btn-text");
    const loader = document.querySelector(".loader");
    
    // Results Section elements
    const resultsSection = document.getElementById("results");
    const resultCard = document.querySelector(".result-card");
    const statusIcon = document.getElementById("status-icon");
    const finalVerdict = document.getElementById("final-verdict");
    const analyzedUrl = document.getElementById("analyzed-url");
    
    const ensembleBar = document.getElementById("ensemble-bar");
    const ensembleScoreText = document.getElementById("ensemble-score-text");
    const xgbBar = document.getElementById("xgb-bar");
    const xgbScoreText = document.getElementById("xgb-score-text");
    const cnnBar = document.getElementById("cnn-bar");
    const cnnScoreText = document.getElementById("cnn-score-text");
    
    const systemNote = document.getElementById("system-note");

    // Icons
    const iconSafe = `<svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path><path d="m9 12 2 2 4-4"></path></svg>`;
    const iconDanger = `<svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="7.86 2 16.14 2 22 7.86 22 16.14 16.14 22 7.86 22 2 16.14 2 7.86 7.86 2"></polygon><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>`;

    form.addEventListener("submit", async (e) => {
        e.preventDefault();
        
        const urlToScan = urlInput.value.trim();
        if (!urlToScan) return;

        // Reset UI State
        setLoading(true);
        resultsSection.classList.remove("show");
        
        // Let the unmount animation finish before clearing classes
        setTimeout(() => {
            resultCard.classList.remove("status-safe", "status-malicious");
            resultsSection.classList.add("hidden");
            
            // Initiate the real request
            scanURL(urlToScan);
        }, 300);
    });

    async function scanURL(url) {
        try {
            // Make API Call to FastAPI Backend
            const response = await fetch("http://localhost:8080/predict", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({ url: url })
            });

            if (!response.ok) {
                throw new Error("Failed to connect to the analysis engine.");
            }

            const data = await response.json();
            
            // Artificial delay to show off the scanning animation and loader (UX)
            setTimeout(() => {
                displayResults(data);
                setLoading(false);
            }, 1200);

        } catch (error) {
            console.error("Error:", error);
            alert("Error connecting to the analytical engine. Please ensure the backend is running at http://localhost:8080.");
            setLoading(false);
        }
    }

    function setLoading(isLoading) {
        if (isLoading) {
            scanBtn.disabled = true;
            btnText.classList.add("hidden");
            loader.classList.remove("hidden");
        } else {
            scanBtn.disabled = false;
            btnText.classList.remove("hidden");
            loader.classList.add("hidden");
        }
    }

    function displayResults(data) {
        const isMalicious = data.prediction === "Malicious";
        
        // Update basic info
        analyzedUrl.textContent = data.url;
        finalVerdict.textContent = isMalicious ? "Malicious Detected" : "Safe URL";
        
        // Inject icon
        statusIcon.innerHTML = isMalicious ? iconDanger : iconSafe;
        
        // Handle System Notes (e.g., Models missing)
        if (data.note) {
            systemNote.textContent = data.note;
            systemNote.classList.remove("hidden");
        } else {
            systemNote.classList.add("hidden");
        }

        // Show section
        resultsSection.classList.remove("hidden");
        
        // Trigger reflow
        void resultsSection.offsetWidth;
        
        // Add status classes to trigger CSS color changes
        if (isMalicious) {
            resultCard.classList.add("status-malicious");
        } else {
            resultCard.classList.add("status-safe");
        }
        
        resultsSection.classList.add("show");

        // Animate progress bars
        animateScore(data.ensemble_probability, ensembleBar, ensembleScoreText);
        animateScore(data.xgb_probability, xgbBar, xgbScoreText);
        animateScore(data.cnn_probability, cnnBar, cnnScoreText);
    }

    function animateScore(probability, barElement, textElement) {
        // Reset
        barElement.style.width = "0%";
        textElement.textContent = "0%";
        
        // Calculate percentages
        const percentage = Math.round(probability * 100);
        
        setTimeout(() => {
            barElement.style.width = `${percentage}%`;
            
            // Number incrementing animation
            let start = 0;
            const duration = 1000;
            const increment = percentage / (duration / 16); // ~60fps
            
            if (percentage === 0) {
                textElement.textContent = "0%";
                return;
            }

            const timer = setInterval(() => {
                start += increment;
                if (start >= percentage) {
                    clearInterval(timer);
                    textElement.textContent = `${percentage}%`;
                } else {
                    textElement.textContent = `${Math.floor(start)}%`;
                }
            }, 16);
            
        }, 500); // delay after panel appears
    }
});
