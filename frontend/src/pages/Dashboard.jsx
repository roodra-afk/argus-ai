import { useState } from "react";

import UploadCard from "@/components/UploadCard";
import AnalysisHistory from "@/components/AnalysisHistory";

export default function Dashboard() {
    const [analysis, setAnalysis] = useState(null);

    return (
        <main className="min-h-screen bg-slate-950 text-white">
            <div className="mx-auto max-w-7xl px-6 py-12">
                <header className="mb-10">
                    <h1 className="text-5xl font-bold tracking-tight">
                        ARGUS AI
                    </h1>

                    <p className="mt-3 text-lg text-slate-400">
                        AI-Powered Malware Analysis Platform
                    </p>
                </header>

                <UploadCard
                    analysis={analysis}
                    setAnalysis={setAnalysis}
                />

                <AnalysisHistory
                    onSelectAnalysis={setAnalysis}
                />
            </div>
        </main>
    );
}
