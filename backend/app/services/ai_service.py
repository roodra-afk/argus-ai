import os
import time

from dotenv import load_dotenv
from google import genai

class AIService:
    def __init__(self):
           load_dotenv()
       
           self.client = genai.Client(
               api_key=os.getenv("GEMINI_API_KEY")
           )   
           
    def get_status(self):
        return {
            "service": "AI Service",
            "status": "ready"
        }

    def build_prompt(self, event):
        # MITRE ATT&CK evidence
        if event.mitre_info:
            mitre_text = "\n".join(
                f"- {technique['technique']} - {technique['name']} "
                f"(confidence: {technique['confidence']}; "
                f"evidence: {', '.join(technique['evidence'])})"
                for technique in event.mitre_info
            )
        else:
            mitre_text = "None"
    
        # Suspicious APIs
        if event.pe_info and event.pe_info.get("suspicious_apis"):
            suspicious_apis = "\n".join(
                f"- {api}"
                for api in event.pe_info["suspicious_apis"]
            )
        else:
            suspicious_apis = "None"
    
        # Packer indicators
        if (
            event.pe_info
            and event.pe_info.get("packer")
            and event.pe_info["packer"].get("reasons")
        ):
            packer_reasons = "\n".join(
                f"- {reason}"
                for reason in event.pe_info["packer"]["reasons"]
            )
        else:
            packer_reasons = "None"
    
        # Validation warnings
        if event.validation_warnings:
            validation_warnings = "\n".join(
                f"- {warning}"
                for warning in event.validation_warnings
            )
        else:
            validation_warnings = "None"
    
        # PE information
        if event.pe_info:
            architecture = event.pe_info.get("architecture", "N/A")
            section_count = event.pe_info.get("section_count", "N/A")
            entry_point = event.pe_info.get("entry_point", "N/A")
        else:
            architecture = "N/A"
            section_count = "N/A"
            entry_point = "N/A"
    
        # Entropy
        if event.entropy_info:
            average_entropy = event.entropy_info.get("entropy", "N/A")
        else:
            average_entropy = "N/A"
    
        # VirusTotal
        if event.virustotal_info:
            vt_detections = event.virustotal_info.get("detections", "N/A")
            vt_total = event.virustotal_info.get("total_engines", "N/A")
            virustotal = f"{vt_detections}/{vt_total}"
        else:
            virustotal = "Unavailable"
    
        # Digital signature
        if event.signature_info:
            signed = event.signature_info.get("signed", "Unknown")
        else:
            signed = "Unknown"
    
        return f"""
    You are Argus AI, an expert malware analyst.
    
    Analyze the following static malware-analysis evidence.
    
    STRICT RULES:
    - Use only the evidence provided below.
    - Do not invent facts.
    - Do not assume that common Windows APIs are malicious.
    - A digital signature does not prove that a file is safe.
    - A low VirusTotal detection count does not prove that a detection is a false positive.
    - If VirusTotal reports detections, acknowledge them accurately.
    - Do not claim that a packer exists or does not exist.
    - If the packer heuristic found nothing, say "no packer indicators were detected".
    - Explain MITRE ATT&CK mappings using the supplied evidence.
    - If the evidence is insufficient for a conclusion, explicitly say so.
    - Do not make claims stronger than the evidence supports.
    
    FILE
    Filename: {event.filename}
    Risk Score: {event.risk_score}/100
    Verdict: {event.verdict}
    
    PE INFORMATION
    Architecture: {architecture}
    Sections: {section_count}
    Entry Point: {entry_point}
    
    SUSPICIOUS APIs
    {suspicious_apis}
    
    PACKER ANALYSIS
    {packer_reasons}
    
    VALIDATION WARNINGS
    {validation_warnings}
    
    ENTROPY
    Average Entropy: {average_entropy}
    
    VIRUSTOTAL
    Detections: {virustotal}
    
    DIGITAL SIGNATURE
    Signed: {signed}
    
    MITRE ATT&CK
    {mitre_text}
    
    Respond using exactly this structure:
    
    Summary:
    One short evidence-based paragraph.
    
    Key Findings:
    - Evidence-based finding
    - Evidence-based finding
    - Evidence-based finding
    
    Recommendation:
    One short evidence-based paragraph.
    """

    def generate_explanation(self, event):
        prompt = self.build_prompt(event)
    
        print(f"AI prompt length: {len(prompt)}")
    
        for attempt in range(3):
            try:
                response = self.client.models.generate_content(
                    model="gemini-3.5-flash",
                    contents=prompt,
                )
    
                print(
                    f"AI explanation generated successfully "
                    f"(attempt {attempt + 1})."
                )
    
                return response.text
    
            except Exception as error:
                print(
                    f"AI explanation attempt {attempt + 1} failed: "
                    f"{type(error).__name__}: {error}"
                )
    
                if attempt < 2:
                    time.sleep(2 ** attempt)
    
        return (
            "AI explanation temporarily unavailable. "
            "The static analysis completed successfully, "
            "but the AI analysis service encountered an error."
        )

    def build_chat_prompt(self, event, question):
        return f"""
You are Argus AI, an expert malware analyst.

You have already analyzed the following file.

Filename: {event.filename}
Risk Score: {event.risk_score}/100
Verdict: {event.verdict}

Previous Analysis:
{event.ai_explanation}

The user now asks:

{question}

Answer only using the available analysis.

If the analysis does not contain enough information,
say so instead of making assumptions.

Keep the answer concise, technical, and easy to understand.
"""

    def chat(self, event, question):
        prompt = self.build_chat_prompt(event, question)

        response = self.client.models.generate_content(
            model="gemini-3.5-flash",
            contents=prompt,
        )

        return response.text
                        
ai_service = AIService()
