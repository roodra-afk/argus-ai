import { useState } from "react";
import { ArrowLeft, FileSearch } from "lucide-react";

import UploadCard from "@/components/UploadCard";
import AnalysisHistory from "@/components/AnalysisHistory";
import ThreatOverview from "@/components/ThreatOverview";

export default function Dashboard() {
    const [analysis, setAnalysis] = useState(null);
    const [analysisSource, setAnalysisSource] = useState(null);
    const [statsRefresh, setStatsRefresh] = useState(0);

    function handleNewAnalysis(data) {
        setAnalysis(data);
        setAnalysisSource("upload");
    }

    function handleHistoricalAnalysis(data) {
        setAnalysis(data);
        setAnalysisSource("history");

        window.scrollTo({
            top: 0,
            behavior: "smooth",
        });
    }

    function clearAnalysis() {
        setAnalysis(null);
        setAnalysisSource(null);

        window.scrollTo({
            top: 0,
            behavior: "smooth",
        });
    }

    return (
        <main className="min-h-screen bg-slate-950 text-white">
            <div className="mx-auto max-w-7xl px-6 py-12">
                <header className="mb-10">
                    <h1 className="text-5xl font-bold tracking-tight">
                        Argus AI
                    </h1>

                    <p className="mt-3 text-lg text-slate-400">
                        AI-Powered Malware Analysis Platform
                    </p>
                </header>

                <ThreatOverview
                    refreshTrigger={statsRefresh}
                />

                {analysis && analysisSource === "history" && (
                    <div className="mb-8 rounded-xl border border-blue-900/50 bg-blue-950/20 p-5">
                        <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
                            <div className="flex items-start gap-3">
                                <FileSearch className="mt-1 h-5 w-5 text-blue-400" />

                                <div>
                                    <p className="text-sm font-medium text-blue-400">
                                        Historical Analysis
                                    </p>

                                    <h2 className="mt-1 text-xl font-semibold text-white">
                                        {analysis.filename}
                                    </h2>

                                    <p className="mt-1 max-w-2xl truncate font-mono text-xs text-slate-500">
                                        {analysis.sha256}
                                    </p>
                                </div>
                            </div>

                            <button
                                type="button"
                                onClick={clearAnalysis}
                                className="inline-flex items-center justify-center gap-2 rounded-lg border border-slate-700 bg-slate-950 px-4 py-2 text-sm font-medium text-slate-300 transition-colors hover:border-slate-600 hover:bg-slate-800 hover:text-white"
                            >
                                <ArrowLeft className="h-4 w-4" />
                                Back to History
                            </button>
                        </div>
                    </div>
                )}

                <UploadCard
                    analysis={analysis}
                    setAnalysis={setAnalysis}
                    onAnalysisComplete={() => {
                        setStatsRefresh((value) => value + 1);
                    }}
                    onNewAnalysis={handleNewAnalysis}
                />

                <AnalysisHistory
                    onSelectAnalysis={handleHistoricalAnalysis}
                />
            </div>
        </main>
    );
}
