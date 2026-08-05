class AIService:
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
            
    Filename: {event.filename}
    Risk Score: {event.risk_score}/100
    Verdict: {event.verdict}
    
    PE Information:
    - Architecture: {event.pe_info["architecture"]}
    - Sections: {event.pe_info["section_count"]}
    - Entry Point: {event.pe_info["entry_point"]}
    
    VirusTotal:
    - Detections: {event.virustotal_info["detections"]}/{event.virustotal_info["total_engines"]}
    
    Digital Signature:
    - Signed: {event.signature_info["signed"]}
    
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
        
ai_service = AIService()
