import { useEffect, useState } from "react";
import { RefreshCw } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";

export default function AnalysisHistory({ onSelectAnalysis }) {
    const [analyses, setAnalyses] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);

    async function loadHistory() {
        setLoading(true);
        setError(null);

        try {
            const response = await fetch(
                "http://localhost:8000/api/v1/analysis/history"
            );

            if (!response.ok) {
                throw new Error("Failed to load analysis history");
            }

            const data = await response.json();

            setAnalyses(data);
        } catch (error) {
            console.error(error);
            setError("Unable to load analysis history.");
        } finally {
            setLoading(false);
        }
    }

    async function loadAnalysis(sha256) {
        try {
            const response = await fetch(
                `http://localhost:8000/api/v1/analysis/${sha256}`
            );

            if (!response.ok) {
                throw new Error("Failed to load analysis");
            }

            const data = await response.json();

            onSelectAnalysis(data);
        } catch (error) {
            console.error(error);
            alert("Failed to load the selected analysis.");
        }
    }

    useEffect(() => {
        loadHistory();
    }, []);

    return (
        <Card className="mt-8 border border-slate-800 bg-slate-900 shadow-xl">
            <CardContent className="p-8">
                <div className="flex items-center justify-between">
                    <div>
                        <h2 className="text-2xl font-semibold text-white">
                            Analysis History
                        </h2>

                        <p className="mt-2 text-sm text-slate-400">
                            Previously analyzed malware samples.
                        </p>
                    </div>

                    <Button
                        variant="outline"
                        size="sm"
                        onClick={loadHistory}
                        disabled={loading}
                    >
                        <RefreshCw className="mr-2 h-4 w-4" />
                        Refresh
                    </Button>
                </div>

                {loading ? (
                    <div className="mt-8 text-center text-slate-500">
                        Loading analysis history...
                    </div>
                ) : error ? (
                    <div className="mt-8 text-center text-red-400">
                        {error}
                    </div>
                ) : analyses.length === 0 ? (
                    <div className="mt-8 text-center text-slate-500">
                        No analyses found.
                    </div>
                ) : (
                    <div className="mt-6 overflow-x-auto">
                        <table className="w-full text-left">
                            <thead>
                                <tr className="border-b border-slate-800 text-sm text-slate-500">
                                    <th className="px-4 py-3 font-medium">
                                        Filename
                                    </th>

                                    <th className="px-4 py-3 font-medium">
                                        Verdict
                                    </th>

                                    <th className="px-4 py-3 font-medium">
                                        Risk
                                    </th>

                                    <th className="px-4 py-3 font-medium">
                                        VirusTotal
                                    </th>

                                    <th className="px-4 py-3 font-medium">
                                        Signed
                                    </th>

                                    <th className="px-4 py-3"></th>
                                </tr>
                            </thead>

                            <tbody>
                                {analyses.map((analysis) => (
                                    <tr
                                        key={analysis.id}
                                        className="border-b border-slate-800/60 transition-colors hover:bg-slate-800/40"
                                    >
                                        <td className="px-4 py-4">
                                            <p className="font-medium text-white">
                                                {analysis.filename}
                                            </p>

                                            <p className="mt-1 max-w-xs truncate font-mono text-xs text-slate-500">
                                                {analysis.sha256}
                                            </p>
                                        </td>

                                        <td className="px-4 py-4">
                                            <span
                                                className={
                                                    analysis.verdict === "Benign"
                                                        ? "text-emerald-400"
                                                        : analysis.verdict === "Malicious"
                                                        ? "text-red-400"
                                                        : "text-yellow-400"
                                                }
                                            >
                                                {analysis.verdict}
                                            </span>
                                        </td>

                                        <td className="px-4 py-4">
                                            <span className="font-mono text-white">
                                                {analysis.risk_score}/100
                                            </span>
                                        </td>

                                        <td className="px-4 py-4 text-slate-300">
                                            {analysis.vt_detections}/
                                            {analysis.vt_total_engines}
                                        </td>

                                        <td className="px-4 py-4">
                                            <span
                                                className={
                                                    analysis.signed
                                                        ? "text-emerald-400"
                                                        : "text-slate-500"
                                                }
                                            >
                                                {analysis.signed ? "Yes" : "No"}
                                            </span>
                                        </td>

                                        <td className="px-4 py-4 text-right">
                                            <Button
                                                size="sm"
                                                onClick={() =>
                                                    loadAnalysis(
                                                        analysis.sha256
                                                    )
                                                }
                                            >
                                                View
                                            </Button>
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                )}
            </CardContent>
        </Card>
    );
}
