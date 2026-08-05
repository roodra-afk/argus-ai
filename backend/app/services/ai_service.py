import os

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
        mitre_text = (
            "\n".join(
                f"- {t['technique']} - {t['name']}"
                for t in event.mitre_info
            )
            if event.mitre_info
            else "None"
        )
    
        return f"""
    You are Argus AI, an expert malware analyst.
    
    Your task is to explain the malware analysis results produced by Argus AI.
    
    Do not invent evidence.
    Only use the information provided below.
    If there is not enough evidence, explicitly say so.
    
    Base every conclusion on the observed evidence.
    
    Do not classify software as malicious solely because it imports common Windows APIs.
    
    Treat valid digital signatures and low VirusTotal detection counts as evidence that may reduce confidence in a malicious assessment.
    
    When mentioning MITRE ATT&CK techniques, explain why the observed behavior maps to those techniques instead of simply listing them.

    Do not state that a feature is absent unless the analysis explicitly proves it.
    For heuristic-based checks such as packer detection, describe the result as "no packer indicators were detected" instead of claiming that no packer exists.
    
    Filename: {event.filename}
    Risk Score: {event.risk_score}/100
    Verdict: {event.verdict}
    
    PE Information:
    - Architecture: {event.pe_info["architecture"] if event.pe_info else "N/A"}
    - Sections: {event.pe_info["section_count"] if event.pe_info else "N/A"}
    - Entry Point: {event.pe_info["entry_point"] if event.pe_info else "N/A"}    
    Suspicious APIs:
    {
    "\n".join(
        f"- {api}"
        for api in event.pe_info["suspicious_apis"]
    ) if event.pe_info and event.pe_info["suspicious_apis"] else "None"
    }
    
    Packer Detection:
    {
    "\n".join(
        f"- {reason}"
        for reason in event.pe_info["packer"]["reasons"]
    )
    if (
        event.pe_info
        and event.pe_info.get("packer")
        and event.pe_info["packer"]["reasons"]
    )
    else "None Detected"
    }
    
    Validation Warnings:
    {
    "\n".join(
        f"- {warning}"
        for warning in event.validation_warnings
    ) if event.validation_warnings else "None"
    }
    
    Entropy:
    - Average Entropy: {
    event.entropy_info["entropy"]
    if event.entropy_info
    else "N/A"
    }
    
    VirusTotal:
    - Detections: {
    f"{event.virustotal_info['detections']}/{event.virustotal_info['total_engines']}"
    if event.virustotal_info
    else "Unavailable"
    }
    
    Digital Signature:
    - Signed: {
    event.signature_info["signed"]
    if event.signature_info
    else "Unknown"
    }
    
    MITRE ATT&CK:
    {mitre_text}
    
    Provide your response using the following format:
    
    Summary:
    (One short paragraph.)
    
    Key Findings:
    - Bullet point
    - Bullet point
    - Bullet point
    
    Recommendation:
    (One short paragraph.)
    """

    def generate_explanation(self, event):
        prompt = self.build_prompt(event)
            
        response = self.client.models.generate_content(
            model="gemini-3.6-flash",
            contents=prompt,
        )
            
        return response.text

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
            model="gemini-3.6-flash",
            contents=prompt,
        )

        return response.text
                        
ai_service = AIService()
