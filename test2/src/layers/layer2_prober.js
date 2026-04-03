/**
 * Layer 2: The Prober (XGBoost via ONNX)
 * Pattern Recognition: A lightweight, local ML model that analyzes URL structure (length, entropy, subdomains) without sending data to the cloud.
 */

// Note: For Chrome Extension use onnxruntime-web (ort.min.js).
// Here we use onnxruntime-node to simulate backend testing.
const ort = require('onnxruntime-node');
const fs = require('fs');
const path = require('path');
const murmurhash = require('murmurhash');

let cachedSession = null;
let popularDomainsFilter = null;

function loadBloomFilter() {
  if (popularDomainsFilter) return;
  try {
    const data = JSON.parse(fs.readFileSync(path.join(__dirname, '../../NoPhishZone/bloom.json'), 'utf8'));
    popularDomainsFilter = {
      m: data.m,
      k: data.k,
      data: data.data
    };
  } catch (err) {
    console.error("Failed to load local Bloom Filter:", err);
  }
}

function checkPopularity(hostname) {
  loadBloomFilter();
  if (!popularDomainsFilter) return false;

  try {
    const rootDomain = hostname.replace(/^www\./, '').toLowerCase();

    for (let i = 0; i < popularDomainsFilter.k; i++) {
        const digest = murmurhash.v3(rootDomain, i);

        const bitIndex = digest % popularDomainsFilter.m;
        const arrayIndex = Math.floor(bitIndex / 32);
        const bitOffset = bitIndex % 32;

        if ((popularDomainsFilter.data[arrayIndex] & (1 << bitOffset)) === 0) { 
            return false;
        }
    }
    return true;
  } catch(e) {
    return false;
  }
}

function getRootDomain(hostname) {
  const parts = hostname.split('.');
  if (parts.length > 2) {
    return parts.slice(-2).join('.');
  }
  return hostname;
}

/**
 * 1. The JavaScript Feature Extractor
 * Converts a raw URL into the numerical array the ONNX model expects.
 */
function extractFeatures(url, domainAgeDays = 30) {
  try {
    const urlObj = new URL(url);
    const hostname = urlObj.hostname;
    
    const hostnameLower = hostname.toLowerCase();
    const rootDomain = getRootDomain(hostname);

    const isPopular = checkPopularity(rootDomain) ? 1.0 : 0.0;

    let infraRiskScore = 0.0;
    if (hostnameLower.endsWith('.tk') || hostnameLower.endsWith('.ml') || hostnameLower.includes('10minutemail') || hostnameLower.includes('tempmail')) {
      infraRiskScore = 1.0;
    } else if (hostnameLower.includes('herokuapp.com') || hostnameLower.includes('vercel.app') || hostnameLower.includes('firebaseapp.com') || hostnameLower.includes('web.app')) {
      infraRiskScore = 0.7;
    }

    return [
      parseFloat(url.length),                                  // 1. url_length
      parseFloat((url.split('.').length - 1)),                 // 2. dot_count
      parseFloat(url.startsWith('https') ? 1 : 0),             // 3. has_https
      parseFloat(/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname) ? 1 : 0), // 4. is_ip_address
      parseFloat(url.replace(/[^0-9]/g, "").length / url.length),// 5. digit_ratio        
      parseFloat((url.match(/[!@#$%^&*(),.?":{}|<>]/g) || []).length), // 6. special_char_count
      parseFloat(domainAgeDays),                               // 7. domain_age_days
      isPopular,                                               // 8. is_popular_domain
      infraRiskScore                                           // 9. infra_risk_score
    ];
  } catch (error) {
    // Fallback if URL is totally invalid
    return [url.length, url.split('.').length - 1, 0, 0, 0, 0, domainAgeDays, 0.0, 0.0];  
  }
}

/**
 * 2. Running the Model in the Extension
 * Loads the trained ONNX model and predicts the probability of phishing.       
 */
async function runSentryCheck(url, domainAge) {
  try {
      const urlObj = new URL(url);
      const hostname = urlObj.hostname;
      const rootDomain = getRootDomain(hostname);

        const PROFESSIONAL_PLATFORMS = ['eventbrite.com', 'zoom.us', 'microsoft.com', 'huggingface.co', 'notion.com', 'notion.site', 'notion.so', 'ngrok.com', 'ngrok.ai', 'google.com', 'itch.io'];

      if (PROFESSIONAL_PLATFORMS.includes(rootDomain)) {
          console.log(`[Layer 2: The Prober] Short-circuiting ML for trusted platform: ${rootDomain}`);
          return 0.001; 
      }

    // 1. Load the model (Do this once and cache it for speed)
    if (!cachedSession) {
      cachedSession = await ort.InferenceSession.create(path.join(__dirname, '../../NoPhishZone/phishing_prober.onnx'));
    }

    // 2. Get the numbers
    // Ensure feature array length is exactly 8
    const featureArray = extractFeatures(url, domainAge);
    if (featureArray.length !== 9) {
        console.error("Feature length mismatch!");
    }

    // 3. Convert to ONNX Tensor
    // Ensure Tensor is created as [1, 9]
    const floatData = Float32Array.from(featureArray);
    const tensor = new ort.Tensor('float32', floatData, [1, 9]);
    // 4. Predict
    // The input name must match the one from `initial_types` during Python training
    const outputs = await cachedSession.run({ float_input: tensor });
    
    // The xgboost ONNX export returns an array of label outputs and probabilities.
    // The second output contains probabilities. Usually it's mapped to output[1].
    const probOutputName = cachedSession.outputNames[1];
    let probability;
    
    // Depending on the version of skl2onnx, the data array structure may vary
    let probData = outputs[probOutputName].data;

    // Convert BigInt64Array/Float32Array etc.
    let parsedProb = 0.5;
    if (outputs[probOutputName].type === 'sequence') {
      try {
        const firstMap = probData[0];
        if (firstMap && typeof firstMap[1n] !== 'undefined') {
          parsedProb = Number(firstMap[1n]);
        } else if (firstMap && typeof firstMap[1] !== 'undefined') {
          parsedProb = Number(firstMap[1]);
        }
      } catch(e) { parsedProb = 0.5; }
    } else if (outputs[probOutputName].type === 'tensor' || outputs[probOutputName].type === 'float32') {
        // Direct array access: probData contains [prob_class_0, prob_class_1]
        // Usually, prob_class_1 is at index 1
        if (outputs[probOutputName].cpuData) {
            probData = outputs[probOutputName].cpuData;
        }
        parsedProb = (probData && probData.length > 1) ? Number(probData[1]) : Number(probData[0]);
    } else {
       if (outputs[probOutputName].cpuData) {
            probData = outputs[probOutputName].cpuData;
       }
       parsedProb = (probData && probData.length > 1) ? Number(probData[1]) : Number(probData[0]);
    }
    probability = parsedProb;

    console.log(`[Layer 2: The Prober] URL: ${url} | RAW OUTPUT PROBABILITY:`, outputs[probOutputName]);
    console.log(`[Layer 2: The Prober] URL: ${url} | Risk Probability: ${probability.toFixed(3)}`);
    return probability;
  } catch (e) {
    console.error("[Layer 2: The Prober] Sentry check failed, falling back to neutral:", e.message);
    return 0.5; // Neutral fallback
  }
}

/**
 * 3. The "Waterfall" Logic
 * Connects the dots to decide whether to Block, Allow, or Pass to AI.
 */
async function localProber(email) {
  console.log(`[Layer 2: The Prober] Analyzing URL structure: ${email.urls.join(', ')}`);

  // Ignore mailto and internal google links to save API calls
  const cleanUrls = email.urls.filter(url => {
    return !url.startsWith('mailto:') && !url.includes('mail.google.com/mail/u/0/#');
  });

  let maxRisk = 0;
  for (const url of cleanUrls) {
    // In a real environment, you'd get domainAge from local cache or pre-check.
    // Here we assume unknown/neutral if not passed previously.
    const risk = await runSentryCheck(url, 365);
    if (risk > maxRisk) maxRisk = risk;
  }

  if (maxRisk > 0.85) {
    return { 
      isSuspicious: true, 
      riskScore: maxRisk * 100, 
      status: "CRITICAL", 
      reason: "Local ML detected high-risk structural patterns (XGBoost ONNX)." 
    };
  } 
  
  if (maxRisk < 0.15) {
    return { 
      isSuspicious: false, 
      riskScore: maxRisk * 100, 
      status: "SAFE", 
      reason: "Local ML verified low-risk structure." 
    };
  }

  // If localRisk is between 0.15 and 0.85, it's a "Grey Area"
  // We return Suspicious = true with a lower score so the Waterfall knows it needs AI.
  return { 
      isSuspicious: false, 
      riskScore: maxRisk * 100, 
      status: "GREY_AREA", 
      reason: "Local ML requires AI escalation." 
  };
}

module.exports = { localProber };




