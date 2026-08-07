import { Progress } from "@/components/ui/progress";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";

export default function AnalysisCard({ analysis }) {
    if (!analysis) return null;

    function getBadgeClass(verdict) {
        switch (verdict) {
            case "Benign":
                return "bg-emerald-600 hover:bg-emerald-600";
    
            case "Suspicious":
                return "bg-yellow-600 hover:bg-yellow-600";
    
            case "Malicious":
                return "bg-red-600 hover:bg-red-600";
    
            default:
                return "";
        }
    }

    function getRiskColor(score) {
        if (score <= 25) {
            return "[&_[data-slot=progress-indicator]]:bg-emerald-500";
        }
    
        if (score <= 60) {
            return "[&_[data-slot=progress-indicator]]:bg-yellow-500";
        }
    
        return "[&_[data-slot=progress-indicator]]:bg-red-500";
    }

    function getRiskLabel(score) {
        if (score <= 25) return "Low Risk";
        if (score <= 60) return "Medium Risk";
        return "High Risk";
    }

    return (
        <Card className="mt-8 border border-slate-800 bg-slate-900 shadow-xl">
            <CardContent className="p-8">
                <div className="flex items-center justify-between">
                    <h2 className="text-2xl font-semibold text-white">
                        Analysis Result
                    </h2>

                    <Badge className={getBadgeClass(analysis.verdict)}>
                        {analysis.verdict}
                    </Badge>
                </div>

                <div className="mt-6 grid grid-cols-2 gap-6">
                
                    <div>
                        <p className="text-sm text-slate-400">
                            Filename
                        </p>
                
                        <p className="mt-1 text-lg text-white">
                            {analysis.filename}
                        </p>
                    </div>
                
                    <div>
                        <p className="text-sm text-slate-400">
                            Risk Score
                        </p>
                    
                        <div className="mt-1 flex items-center gap-3">
                            <span className="text-2xl font-bold text-white">
                                {analysis.risk_score}/100
                            </span>
                    
                            <span
                                className={`text-sm font-medium ${
                                    analysis.risk_score <= 25
                                        ? "text-emerald-400"
                                        : analysis.risk_score <= 60
                                        ? "text-yellow-400"
                                        : "text-red-400"
                                }`}
                            >
                                {getRiskLabel(analysis.risk_score)}
                            </span>
                        </div>
                    
                        <div className="mt-3 w-48">
                            <Progress
                                value={analysis.risk_score}
                                className={getRiskColor(analysis.risk_score)}
                            />
                        </div>
                    </div>
                
                    <div>
                        <p className="text-sm text-slate-400">
                            File Type
                        </p>
                
                        <p className="mt-1 text-white">
                            {analysis.detected_type}
                        </p>
                    </div>
                
                    <div>
                        <p className="text-sm text-slate-400">
                            VirusTotal
                        </p>
                
                        <p className="mt-1 text-white">
                            {analysis.vt_detections}/{analysis.vt_total_engines}
                        </p>
                    </div>
                
                    <div>
                        <p className="text-sm text-slate-400">
                            Signed
                        </p>
                
                        <p className="mt-1 text-white">
                            {analysis.signed ? "Yes" : "No"}
                        </p>
                    </div>
                
                    <div>
                        <p className="text-sm text-slate-400">
                            SHA256
                        </p>
                
                        <p className="mt-1 break-all font-mono text-xs text-slate-300">
                            {analysis.sha256.slice(0, 24)}...
                        </p>
                    </div>
                
                </div>

                <div className="mt-8 rounded-lg border border-slate-800 bg-slate-950 p-6">
                    <h3 className="text-lg font-semibold text-white">
                        AI Explanation
                    </h3>
                
                    <div className="mt-6 space-y-8">
                        {analysis.ai_explanation
                            .split("\n\n")
                            .map((section, index) => (
                                <div
                                    key={index}
                                    className="rounded-lg border border-slate-800 bg-slate-900 p-5"
                                >
                                    <p className="whitespace-pre-wrap text-sm leading-8 text-slate-300">
                                        {section}
                                    </p>
                                </div>
                            ))}
                    </div>
                </div>
            </CardContent>
        </Card>
    );
}
