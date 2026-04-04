import sys
import re

with open('streamlit_app.py', 'r', encoding='utf-8') as f:
    text = f.read()

# We want to replace everything from "    # STEP 1: Build the raw MIME email" 
# up to "    # Display Results".

pattern = r"(    # ---------------------------------------------------------\n    # STEP 1: Build the raw MIME email.*?)    # Display Results\n"

new_code = '''    # ---------------------------------------------------------
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
                        att_text_content += f"\\n--- Attachment Source ({f.name}) ---\\n{extracted[:5000]}\\n" # limit to 5000 chars to avoid blowing up payload
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
        enriched_body += "\\n\\n[SYSTEM INJECTION: The following context was extracted from attachments:]\\n"
        if att_flags:
            enriched_body += f"Detected Attachment Threat Flags: {', '.join(att_flags)}\\n"
        if att_text_content:
            enriched_body += f"Attachment Raw Content:\\n{att_text_content}"

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

'''

new_text, count = re.subn(pattern, new_code.replace('\\\\', '\\'), text, flags=re.DOTALL)
if count == 0:
    print("Failed to replace!")
else:
    with open('streamlit_app.py', 'w', encoding='utf-8') as f:
        f.write(new_text)
    print("Replaced successfully!")
