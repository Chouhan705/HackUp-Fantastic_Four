import streamlit as st
import requests
import json
import base64
import uuid
import re
from datetime import datetime, timezone
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
import os
import sys
import tempfile
from pathlib import Path

try:
    import google.generativeai as genai
except ImportError:
    genai = None

# Ensure the root directory is in the path to import the pipeline
sys.path.append(os.path.abspath(os.path.dirname(__file__)))
from pipeline.orchestrator import Orchestrator

# Import individual attachment scanners for Streamlit evaluation
attachment_analyzers = []
load_errors = []
try:
    from analyzers.attachements.src.analyzers.file_id import MagicAnalyzer
    attachment_analyzers.append(MagicAnalyzer())
except Exception as e: load_errors.append(f"MagicAnalyzer: {e}")
try:
    from analyzers.attachements.src.analyzers.yara_scanner import YaraAnalyzer
    attachment_analyzers.append(YaraAnalyzer())
except Exception as e: load_errors.append(f"YaraAnalyzer: {e}")
try:
    from analyzers.attachements.src.analyzers.office import OfficeAnalyzer
    attachment_analyzers.append(OfficeAnalyzer())
except Exception as e: load_errors.append(f"OfficeAnalyzer: {e}")
try:
    from analyzers.attachements.src.analyzers.pdf import PDFAnalyzer
    attachment_analyzers.append(PDFAnalyzer())
except Exception as e: load_errors.append(f"PDFAnalyzer: {e}")
try:
    from analyzers.attachements.src.analyzers.archive import ArchiveAnalyzer
    attachment_analyzers.append(ArchiveAnalyzer())
except Exception as e: load_errors.append(f"ArchiveAnalyzer: {e}")

st.set_page_config(page_title="Full Pipeline: Analyzers ➔ Orchestrator", layout="wide")
st.title("Phishing Detective - Full End-to-End Pipeline")

if load_errors:
    with st.expander("⚠️ Some Attachment Analyzers Failed to Load"):
        st.warning("If you attach a file, it might bypass these specific checks.")
        for err in load_errors:
            st.error(err)
else:
    st.success("✅ All 5 Deep Attachment Analyzers (Yara, PDF, Magic, Office, Archive) loaded successfully!")

# Sidebar for API Key
st.sidebar.header("Configuration")
gemini_api_key = st.sidebar.text_input("Gemini API Key", type="password", help="Enter your Gemini API key to enable AI-powered summary reports.")
if not genai:
    st.sidebar.warning("Please run `pip install google-generativeai` in your terminal to enable Gemini.")

st.markdown("""
This dashboard simulates the **complete journey** of the data:
1. **Input:** We build a raw email (with optional attachments).
2. **Analyzers:** We send the raw email to the FastAPI `POST /scan` endpoint (Email, Behaviour, NLP, and Attachments).
3. **Transformation:** We take the analyzer's score/flags and convert it into an `Event` object.
4. **Orchestrator:** We feed that `Event` into the Orchestrator, GraphStore, and ChainBuilder.
""")

st.subheader("1. Input Email Details")
col1, col2 = st.columns(2)
with col1:
    sender = st.text_input("From", "attacker@paypa1-security-alert.com")
    recipient = st.text_input("To", "employee@yourcompany.com")
with col2:
    subject = st.text_input("Subject", "URGENT: Immediate action required - Account Suspended")

body = st.text_area("Email Body", "We detected suspicious login attempts. Please verify your account immediately: http://bit.ly/4fakeURLxyz")

# New File uploader for attachments
uploaded_files = st.file_uploader("Attach Files (pdf, bat, txt, etc.)", accept_multiple_files=True)

if st.button("Run Full E2E Analysis"):
    st.markdown("---")
    
    # ---------------------------------------------------------
    # STEP 0: Deep Attachment Analysis (Yara, Magic, PDF, Office)
    # Extract text and flags to feed into the NLP engine!
    # ---------------------------------------------------------
    att_score = 0
    att_flags = []
    att_text_content = ""
    
    if uploaded_files:
        with st.spinner("0. Running Deep Attachment Analysis & Extraction..."):
            for f in uploaded_files:
                f.seek(0)
                file_bytes = f.read()
                f.seek(0)

                # Attempt to extract raw text if it's a text/html file so NLP can read it
                if f.name.endswith(('.txt', '.html', '.csv', '.json', '.bat', '.ps1')):
                    try:
                        extracted = file_bytes.decode('utf-8', errors='ignore')
                        att_text_content += f"\n--- Attachment Source ({f.name}) ---\n{extracted[:5000]}\n" # limit to 5000 chars to avoid blowing up payload
                    except: pass
                # Write to temp file for the analyzers
                import os, tempfile
                from pathlib import Path
                _, ext = os.path.splitext(f.name)
                with tempfile.NamedTemporaryFile(delete=False, suffix=ext) as tmp:
                    tmp.write(file_bytes)
                    tmp_path = Path(tmp.name)

                # Run all imported analyzers
                for analyzer in attachment_analyzers:
                    try:
                        res = analyzer.analyze(tmp_path)
                        if res.get("is_flagged"):
                            att_flags.append(f"{analyzer.name.lower()}_hit_{f.name}")
                            att_score = max(att_score, 85) # High Risk manually applied for flag
                    except Exception as e:
                        pass

                try:
                    os.remove(tmp_path)
                except: pass

            st.success("0. Attachment text and flags extracted.")

    # ---------------------------------------------------------
    # INJECTION: Feed extracted attachment data into the NLP body
    # ---------------------------------------------------------
    enriched_body = body
    if att_flags or att_text_content:
        enriched_body += "\n\n[SYSTEM INJECTION: The following context was extracted from attachments:]\n"
        if att_flags:
            enriched_body += f"Detected Attachment Threat Flags: {', '.join(att_flags)}\n"
        if att_text_content:
            enriched_body += f"Attachment Raw Content:\n{att_text_content}"

    # ---------------------------------------------------------
    # STEP 1: Build the raw MIME email (base64url encoded)
    # ---------------------------------------------------------
    with st.spinner("1. Building raw email with enriched attachments data..."):
        msg = MIMEMultipart()
        msg['From'] = sender
        msg['To'] = recipient
        msg['Subject'] = subject
        msg.attach(MIMEText(enriched_body, 'plain')) # Use the ENRICHED body here!

        # Attach uploaded files to the MIME message
        if uploaded_files:
            for f in uploaded_files:
                f.seek(0)
                part = MIMEApplication(f.read(), Name=f.name)
                part['Content-Disposition'] = f'attachment; filename="{f.name}"'
                msg.attach(part)

        raw_email_bytes = msg.as_bytes()
        raw_email_b64 = base64.urlsafe_b64encode(raw_email_bytes).decode('utf-8')
    st.success(f"1. Email drafted. ({len(uploaded_files) if uploaded_files else 0} attachments included)")

    # ---------------------------------------------------------
    # STEP 2: Send ENRICHED data to Analyzers (FastAPI :8000)...
    # ---------------------------------------------------------
    with st.spinner("2. Sending to NLP & Behavourial Engines via FastAPI..."):
        api_url = "http://localhost:8000/scan"
        msg_id = str(uuid.uuid4())
        payload = {
            "message_id": msg_id,
            "raw_email": raw_email_b64
        }

        try:
            resp = requests.post(api_url, json=payload)
            resp.raise_for_status()
            scan_results = resp.json()
        except requests.exceptions.ConnectionError:
            st.error("Could not connect to the FastAPI server. Make sure uvicorn main:app is running on port 8000.")
            st.stop()
        except Exception as e:
            st.error(f"Error calling Analyzers: {e}")
            st.stop()

    # Inject the attachment signals into the standard API results
    if uploaded_files and (att_score > 0 or att_flags):
        scan_results.setdefault("signals", []).append({
            "engine": "attachment",
            "score": att_score,
            "flags": att_flags
        })

        if att_score > scan_results.get("score", 0):
            scan_results["score"] = att_score
            if att_score >= 70:
                scan_results["verdict"] = "phishing"
            elif att_score >= 40:
                scan_results["verdict"] = "suspicious"
        
        st.success(f"2.5 Detailed Attachment Scans Finished! Overridden Score: {scan_results.get('score', 0)}")

    st.subheader("Engine Breakdown & Flags:")
    cols = st.columns(len(scan_results.get("signals", [])))
    for idx, signal in enumerate(scan_results.get("signals", [])):
        with cols[idx]:
            st.metric(label=f"{signal['engine'].upper()} Engine", value=signal['score'])
            if signal['flags']:
                st.caption("Flags Detected:")
                for flag in signal['flags']:
                    st.write(f"- 🚩 `{flag}`")
            else:
                st.caption("No flags detected.")
                
    with st.expander("View Raw Scanner JSON Response"):
        st.json(scan_results)

    # ---------------------------------------------------------
    # STEP 3: Transform into an Event Object for the Orchestrator
    # ---------------------------------------------------------
    with st.spinner("3. Formatting output into an Event..."):
        # Simple regex to find URLs and Domains for IOCs mapping
        urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', body)
        domains = [u.split('//')[-1].split('/')[0] for u in urls]
        
        # Build the dynamic graph nodes and edges based on the inputs
        nodes = [
            {"id": "node_sender", "type": "email", "entity_id": sender},
            {"id": "node_recipient", "type": "email", "entity_id": recipient}
        ]
        edges = [
            {"source": "node_sender", "target": "node_recipient"}
        ]
        
        for i, u in enumerate(urls):
            node_id = f"node_url_{i}"
            nodes.append({"id": node_id, "type": "url", "entity_id": u})
            edges.append({"source": "node_sender", "target": node_id})
            
        for i, d in enumerate(domains):
            node_id = f"node_domain_{i}"
            nodes.append({"id": node_id, "type": "domain", "entity_id": d})
            edges.append({"source": "node_sender", "target": node_id})

        # Add attachment nodes to graph if they exist
        if uploaded_files:
            for i, f in enumerate(uploaded_files):
                file_id = f"node_file_{i}"
                nodes.append({"id": file_id, "type": "file", "entity_id": f.name})
                edges.append({"source": "node_sender", "target": file_id})

        # Dynamically extract all flags out of the response payload
        all_flags = []
        for signal in scan_results.get("signals", []):
            all_flags.extend(signal.get("flags", []))

        event_doc = {
            "id": msg_id,
            "type": "email",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "iocs": {"emails": [sender], "urls": urls, "domains": domains},
            "score": scan_results.get("score", 0),
            "verdict": scan_results.get("verdict", "safe"),
            "attack_type": all_flags if all_flags else ["phishing"] if scan_results.get("score", 0) >= 40 else [],
            "correlation_keys": {"domains": domains, "emails": [sender]},
            "graph": {
                "nodes": nodes,
                "edges": edges
            }
        }
        st.success("3. Transformed Analyzer output into standard Event framework.")
        with st.expander("View Orchestrator Event Payload"):
            st.json(event_doc)

    # ---------------------------------------------------------
    # STEP 4: Send to Orchestrator (GraphStore, ChainBuilder, RiskEngine)
    # ---------------------------------------------------------
    with st.spinner("4. Feeding Event into Orchestrator..."):
        orchestrator = Orchestrator()
        
        # To form a CHAIN, we need at least TWO related events.
        # Let's generate a second "dummy" event simulating the user clicking the URL.
        # This event shares the exact same domain, causing the Correlator to link them!
        click_event_doc = {
            "id": str(uuid.uuid4()),
            "type": "url",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "iocs": {"urls": urls, "domains": domains},
            "score": 85,
            "verdict": "suspicious",
            "attack_type": ["malicious_url_click"],
            "correlation_keys": {"domains": domains},
            "graph": {
                "nodes": [
                    {"id": "node_user_device", "type": "endpoint", "entity_id": recipient},
                    {"id": "node_clicked_url", "type": "url", "entity_id": urls[0] if urls else "http://malicious.com"}
                ],
                "edges": [
                    {"source": "node_user_device", "target": "node_clicked_url"}
                ]
            }
        }
        
        # Process BOTH the email event AND the subsequent URL click event
        results = orchestrator.process_events([json.dumps(event_doc), json.dumps(click_event_doc)])
        
    st.success("4. Orchestrator processing complete! View the network map and attack chains below.")
    
    # ---------------------------------------------------------
    # STEP 5: AI Cybersecurity Report using Gemini-2.5-Flash
    # ---------------------------------------------------------
    st.markdown("---")
    st.subheader("🤖 5. Executive AI Summary Report")
    if gemini_api_key and genai:
        with st.spinner("Generating security report using Gemini-2.5-Flash..."):
            try:
                genai.configure(api_key=gemini_api_key)
                # Ensure we use gemini-2.5-flash
                model = genai.GenerativeModel('gemini-2.5-flash')
                
                prompt = f"""
                You are an expert Cybersecurity Operations Center (SOC) Analyst.
                I have just run a raw phishing email through our detection pipeline. 
                
                Here are the results from the individual Analyzers (NLP, Behaviour, Headers, Attachments):
                {json.dumps(scan_results, indent=2)}
                
                Here is the threat intelligence output from the Orchestrator. 
                This includes the specific Attack Chains detected:
                {json.dumps(results.get('chains', []), indent=2)}
                
                And the Global Graph Mapping (which maps how the various entities like IPs, Domains, and Emails are connected together across the incident):
                {json.dumps(results.get('global_graph', {}), indent=2)}
                
                Please provide a highly professional, simple, executive-level summary report for this email.
                Use bullet points. Highlight:
                1. The overall verdict and risk score.
                2. Key red flags found in the email content, attachments, and headers.
                3. A brief explanation of the detected attack chain (how the attack progresses from email to victim).
                4. A summary of the Global Network mapping (what specific entities/domains are involved and connected).
                5. Recommended Action.
                Keep it concise and do not mention the raw JSON.
                """
                
                ai_response = model.generate_content(prompt)
                st.write(ai_response.text)
            except Exception as e:
                st.error(f"Failed to generate Gemini AI report: {e}")
    else:
        st.info("Please enter your Gemini API Key in the sidebar to view an AI-generated Executive Summary.")
    
    st.markdown("---")
    col_out_1, col_out_2 = st.columns(2)
    with col_out_1:
        st.subheader("Global Graph Mapping")
        st.info("Notice how the sender, recipient, and extracted URLs are now fully mapped into a graph structure.")
        st.json(results.get("global_graph", {}))
        
    with col_out_2:
        st.subheader("Detected Chains")
        if not results.get("chains"):
            st.warning("No chains detected yet. (Remember: Chains require at least 2 related events to form a multi-step attack path!)")
        else:
            st.json(results.get("chains", []))
