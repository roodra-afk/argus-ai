import { Download } from "lucide-react";
import { useState } from "react";
import { Check, Copy, ShieldCheck } from "lucide-react";

import PEInfoCard from "./PEInfoCard";

import { Progress } from "@/components/ui/progress";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";

export default function AnalysisCard({ analysis }) {
    const [copied, setCopied] = useState(false);

    if (!analysis) return null;

    function getVerdictStyles(verdict) {
        switch (verdict) {
            case "Benign":
                return {
                    badge: "border-emerald-500/30 bg-emerald-950/50 text-emerald-300",
                    dot: "bg-emerald-400",
                    text: "text-emerald-400",
                };

            case "Suspicious":
                return {
                    badge: "border-yellow-500/30 bg-yellow-950/50 text-yellow-300",
                    dot: "bg-yellow-400",
                    text: "text-yellow-400",
                };

            case "Malicious":
                return {
                    badge: "border-red-500/30 bg-red-950/50 text-red-300",
                    dot: "bg-red-400",
                    text: "text-red-400",
                };

            default:
                return {
                    badge: "border-slate-700 bg-slate-800 text-slate-300",
                    dot: "bg-slate-400",
                    text: "text-slate-300",
                };
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

    function getRiskTextColor(score) {
        if (score <= 25) return "text-emerald-400";
        if (score <= 60) return "text-yellow-400";
        return "text-red-400";
    }

    function getRiskLabel(score) {
        if (score <= 25) return "Low Risk";
        if (score <= 60) return "Medium Risk";
        return "High Risk";
    }

    async function copySha256() {
        try {
            await navigator.clipboard.writeText(analysis.sha256);

            setCopied(true);

            setTimeout(() => {
                setCopied(false);
            }, 1500);
        } catch (error) {
            console.error("Failed to copy SHA256:", error);
        }
    }

    const verdictStyles = getVerdictStyles(analysis.verdict);

    return (
        <>
            <Card className="mt-8 overflow-hidden border border-slate-800 bg-slate-900 shadow-xl">
                <CardContent className="p-0">
                    {/* Header */}
                    <div className="border-b border-slate-800 bg-slate-950/70 px-8 py-7">
                        <div className="flex flex-col gap-5 sm:flex-row sm:items-center sm:justify-between">
                            <div>
                                <div className="flex items-center gap-3">
                                    <ShieldCheck className="h-6 w-6 text-blue-400" />

                                    <p className="text-sm font-medium uppercase tracking-widest text-slate-500">
                                        Analysis Result
                                    </p>
                                </div>

                                <h2 className="mt-3 break-all text-3xl font-bold tracking-tight text-white">
                                    {analysis.filename}
                                </h2>

                                <p className="mt-2 text-sm text-slate-500">
                                    {analysis.detected_type}
                                </p>
                            </div>

                            <div className="flex items-center gap-3">
                                <button
                                    type="button"
                                    onClick={() => {
                                        window.open(
                                            `http://localhost:8000/api/v1/analysis/${analysis.sha256}/report`,
                                            "_blank"
                                        );
                                    }}
                                    className="inline-flex items-center gap-2 rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm font-medium text-slate-300 transition-colors hover:border-slate-600 hover:bg-slate-800 hover:text-white"
                                >
                                    <Download className="h-4 w-4" />
                                    Download Report
                                </button>
                            
                                <Badge
                                    className={`w-fit border px-4 py-2 text-sm font-semibold ${verdictStyles.badge}`}
                                >
                                    <span
                                        className={`mr-2 h-2 w-2 rounded-full ${verdictStyles.dot}`}
                                    />
                            
                                    {analysis.verdict}
                                </Badge>
                            </div>
                        </div>
                    </div>

                    {/* Risk Overview */}
                    <div className="grid gap-6 border-b border-slate-800 p-8 lg:grid-cols-[220px_1fr]">
                        <div className="rounded-xl border border-slate-800 bg-slate-950 p-6 text-center">
                            <p className="text-xs font-medium uppercase tracking-widest text-slate-500">
                                Risk Score
                            </p>

                            <div
                                className={`mt-3 text-5xl font-bold ${getRiskTextColor(
                                    analysis.risk_score
                                )}`}
                            >
                                {analysis.risk_score}
                            </div>

                            <p className="mt-1 text-sm text-slate-500">
                                out of 100
                            </p>

                            <p
                                className={`mt-4 text-sm font-semibold ${getRiskTextColor(
                                    analysis.risk_score
                                )}`}
                            >
                                {getRiskLabel(analysis.risk_score)}
                            </p>
                        </div>

                        <div className="flex flex-col justify-center">
                            <div className="flex items-center justify-between">
                                <div>
                                    <p className="text-sm font-semibold text-white">
                                        Risk Assessment
                                    </p>

                                    <p className="mt-1 text-sm text-slate-500">
                                        Static analysis risk score assigned by
                                        Argus.
                                    </p>
                                </div>

                                <span
                                    className={`font-mono text-sm font-semibold ${getRiskTextColor(
                                        analysis.risk_score
                                    )}`}
                                >
                                    {analysis.risk_score}/100
                                </span>
                            </div>

                            <Progress
                                value={analysis.risk_score}
                                className={`mt-5 h-3 bg-slate-800 ${getRiskColor(
                                    analysis.risk_score
                                )}`}
                            />

                            <div className="mt-3 flex justify-between text-xs text-slate-600">
                                <span>Low</span>
                                <span>Medium</span>
                                <span>High</span>
                            </div>
                        </div>
                    </div>

                    {/* Metadata */}
                    <div className="grid gap-px border-b border-slate-800 bg-slate-800 sm:grid-cols-2 lg:grid-cols-4">
                        <div className="bg-slate-900 p-6">
                            <p className="text-xs uppercase tracking-widest text-slate-500">
                                File Type
                            </p>

                            <p className="mt-2 font-medium text-white">
                                {analysis.detected_type}
                            </p>
                        </div>

                        <div className="bg-slate-900 p-6">
                            <p className="text-xs uppercase tracking-widest text-slate-500">
                                VirusTotal
                            </p>

                            <p className="mt-2 font-mono text-lg font-semibold text-white">
                                {analysis.vt_detections}/
                                {analysis.vt_total_engines}
                            </p>

                            <p className="mt-1 text-xs text-slate-500">
                                Engine detections
                            </p>
                        </div>

                        <div className="bg-slate-900 p-6">
                            <p className="text-xs uppercase tracking-widest text-slate-500">
                                Digital Signature
                            </p>

                            <p
                                className={`mt-2 font-semibold ${
                                    analysis.signed
                                        ? "text-emerald-400"
                                        : "text-slate-400"
                                }`}
                            >
                                {analysis.signed
                                    ? "Verified / Signed"
                                    : "Not Signed"}
                            </p>

                            <p className="mt-1 text-xs text-slate-500">
                                Signature status
                            </p>
                        </div>

                        <div className="bg-slate-900 p-6">
                            <p className="text-xs uppercase tracking-widest text-slate-500">
                                SHA-256
                            </p>

                            <p className="mt-2 font-mono text-sm text-slate-300">
                                {analysis.sha256.slice(0, 16)}...
                            </p>

                            <button
                                onClick={copySha256}
                                className="mt-2 flex items-center gap-1.5 text-xs text-blue-400 transition-colors hover:text-blue-300"
                            >
                                {copied ? (
                                    <>
                                        <Check className="h-3.5 w-3.5" />
                                        Copied
                                    </>
                                ) : (
                                    <>
                                        <Copy className="h-3.5 w-3.5" />
                                        Copy full hash
                                    </>
                                )}
                            </button>
                        </div>
                    </div>

                    {/* AI Assessment */}
                    {analysis.ai_explanation && (
                        <div className="p-8">
                            <div className="rounded-xl border border-blue-500/20 bg-blue-950/10">
                                <div className="border-b border-blue-500/10 px-6 py-5">
                                    <p className="text-xs font-medium uppercase tracking-widest text-blue-400">
                                        AI Analyst Assessment
                                    </p>

                                    <p className="mt-1 text-sm text-slate-500">
                                        Evidence-based interpretation of the
                                        static analysis results.
                                    </p>
                                </div>

                                <div className="space-y-5 p-6">
                                    {analysis.ai_explanation
                                        .split("\n\n")
                                        .map((section, index) => (
                                            <div
                                                key={index}
                                                className="rounded-lg border border-slate-800 bg-slate-950/70 p-5"
                                            >
                                                <p className="whitespace-pre-wrap text-sm leading-7 text-slate-300">
                                                    {section}
                                                </p>
                                            </div>
                                        ))}
                                </div>
                            </div>
                        </div>
                    )}
                </CardContent>
            </Card>

            <PEInfoCard
                peInfo={analysis.pe_info}
                mitreInfo={analysis.mitre_info}
            />
        </>
    );
}
