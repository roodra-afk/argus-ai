from xml.sax.saxutils import escape
from datetime import datetime
from reportlab.platypus import SimpleDocTemplate, Paragraph
from reportlab.lib.styles import getSampleStyleSheet


class ReportService:
    def get_status(self):
        return {
            "service": "Report Service",
            "status": "ready"
        }

    def add_heading(self, story, styles, title):
        story.append(
            Paragraph(
                escape(title),
                styles["Heading2"]
            )
        )
        story.append(Paragraph("", styles["BodyText"]))

    def add_field(self, story, styles, label, value):
        story.append(
            Paragraph(
                f"<b>{label}:</b> {value}",
                styles["BodyText"]
            )
        )

    def generate(self, event, output_path):
        styles = getSampleStyleSheet()

        doc = SimpleDocTemplate(output_path)

        story = []

        story.append(
            Paragraph(
                "Argus AI Malware Analysis Report",
                styles["Heading1"]
            )
        )

        story.append(
            Paragraph(
                "",
                styles["BodyText"]
            )
        )
        
        self.add_heading(
            story,
            styles,
            "Executive Summary"
        )
        
        self.add_field(
            story,
            styles,
            "Filename",
            event.filename
        )
        
        self.add_field(
            story,
            styles,
            "Risk Score",
            f"{event.risk_score}/100"
        )
        
        self.add_field(
            story,
            styles,
            "Verdict",
            event.verdict
        )
        
        self.add_heading(
            story,
            styles,
            "File Information"
        )
        
        self.add_field(
            story,
            styles,
            "SHA256",
            event.sha256
        )
        
        self.add_field(
            story,
            styles,
            "File Size",
            f"{event.file_size:,} bytes"
        )
        
        self.add_field(
            story,
            styles,
            "Detected Type",
            event.detected_type
        )
        
        self.add_field(
            story,
            styles,
            "MIME Type",
            event.mime_type
        )

        self.add_heading(
            story,
            styles,
            "PE Analysis"
        )
                        
        self.add_field(
            story,
            styles,
            "Architecture",
            event.pe_info["architecture"]
        )
                
        self.add_field(
            story,
            styles,
            "Sections",
            event.pe_info["section_count"]
        )
                
        self.add_field(
            story,
            styles,
            "Entry Point",
            event.pe_info["entry_point"]
        )        

        self.add_heading(
            story,
            styles,
            "VirusTotal"
        )
        
        if event.virustotal_info:
            self.add_field(
                story,
                styles,
                "Detections",
                f"{event.virustotal_info['detections']} / {event.virustotal_info['total_engines']}"
            )
        
            self.add_field(
                story,
                styles,
                "Reputation",
                event.virustotal_info["reputation"]
            )
        
            self.add_field(
                story,
                styles,
                "Times Submitted",
                event.virustotal_info["times_submitted"]
            )
        
        else:
            self.add_field(
                story,
                styles,
                "Status",
                "No VirusTotal data available"
            )

        self.add_heading(
            story,
            styles,
            "Digital Signature"
        )
        
        if event.signature_info:
            self.add_field(
                story,
                styles,
                "Signed",
                "Yes" if event.signature_info["signed"] else "No"
            )
        else:
            self.add_field(
                story,
                styles,
                "Status",
                "Unknown"
            )

        self.add_heading(
            story,
            styles,
            "MITRE ATT&CK"
        )
        
        if event.mitre_info:
            for technique in event.mitre_info:
                self.add_field(
                    story,
                    styles,
                    technique["technique"],
                    technique["name"]
                )
        else:
            self.add_field(
                story,
                styles,
                "Techniques",
                "No mapped techniques"
            )

        self.add_heading(
            story,
            styles,
            "Recommendations"
        )
        
        if event.verdict == "Malicious":
            self.add_field(
                story,
                styles,
                "Recommendation",
                "Immediately isolate and investigate this file."
            )
        
        elif event.verdict == "Suspicious":
            self.add_field(
                story,
                styles,
                "Recommendation",
                "Perform additional dynamic analysis before execution."
            )
        
        else:
            self.add_field(
                story,
                styles,
                "Recommendation",
                "No immediate indicators of malicious behavior were found."
            )
        
        if event.signature_info and event.signature_info["signed"]:
            self.add_field(
                story,
                styles,
                "Digital Signature",
                "File is digitally signed."
            )
        
        if event.pe_info["packer"]["detected"]:
            self.add_field(
                story,
                styles,
                "Packer",
                "Possible packer detected. Consider deeper inspection."
            )
        
        if event.virustotal_info:
            if event.virustotal_info["detections"] > 0:
                self.add_field(
                    story,
                    styles,
                    "VirusTotal",
                    f"Detected by {event.virustotal_info['detections']} security vendors."
                )

        story.append(Paragraph("", styles["BodyText"]))
        
        story.append(
            Paragraph(
                "<b>Generated by:</b> Argus AI",
                styles["BodyText"]
            )
        )
        
        story.append(
            Paragraph(
                f"<b>Generated:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                styles["BodyText"]
            )
        )

        doc.build(story)


report_service = ReportService()
