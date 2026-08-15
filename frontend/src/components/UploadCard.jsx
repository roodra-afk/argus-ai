import { useRef, useState } from "react";
import { UploadCloud } from "lucide-react";

import AnalysisCard from "./AnalysisCard";
import AIChatCard from "./AIChatCard";

import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";

export default function UploadCard({ analysis, setAnalysis }) {
    const fileInputRef = useRef(null);

    const [selectedFile, setSelectedFile] = useState(null);
    const [loading, setLoading] = useState(false);

    async function analyzeFile() {
        if (!selectedFile) return;

        setLoading(true);

        const formData = new FormData();
        formData.append("file", selectedFile);

        try {
            const response = await fetch(
                "http://localhost:8000/api/v1/analysis/upload",
                {
                    method: "POST",
                    body: formData,
                }
            );

            if (!response.ok) {
                throw new Error("Upload failed");
            }

            const data = await response.json();

            setAnalysis(data);
        } catch (error) {
            console.error(error);
            alert("Failed to analyze the file.");
        } finally {
            setLoading(false);
        }
    }

    return (
        <>
            <Card className="border border-slate-800 bg-slate-900 shadow-xl">
                <CardContent className="p-10">
                    <h2 className="text-2xl font-semibold text-white">
                        Upload Malware Sample
                    </h2>

                    <p className="mt-3 text-slate-400">
                        Upload a Windows PE executable for AI-powered static malware
                        analysis.
                    </p>

                    <div
                        onClick={() => fileInputRef.current.click()}
                        className="mt-8 cursor-pointer rounded-xl border-2 border-dashed border-slate-700 p-12 text-center transition-colors hover:border-blue-500"
                    >
                        <UploadCloud className="mx-auto mb-5 h-12 w-12 text-slate-500" />

                        <p className="text-lg text-slate-300">
                            Drag & Drop an executable here
                        </p>

                        {selectedFile ? (
                            <p className="mt-2 text-sm text-emerald-400">
                                {selectedFile.name}
                            </p>
                        ) : (
                            <p className="mt-2 text-sm text-slate-500">
                                or click to browse
                            </p>
                        )}

                        <p className="mt-6 text-xs text-slate-500">
                            Supported formats: .exe • .dll • .sys
                        </p>
                    </div>

                    <input
                        ref={fileInputRef}
                        type="file"
                        accept=".exe,.dll,.sys"
                        hidden
                        onChange={(e) => {
                            if (e.target.files.length > 0) {
                                setSelectedFile(e.target.files[0]);
                            }
                        }}
                    />

                    <div className="mt-8">
                        <Button
                            className="w-full"
                            size="lg"
                            onClick={analyzeFile}
                            disabled={!selectedFile || loading}
                        >
                            {loading ? "Analyzing..." : "Analyze Sample"}
                        </Button>
                    </div>
                </CardContent>
            </Card>

            <AnalysisCard analysis={analysis} />
            
            {analysis && (
                <AIChatCard filename={analysis.filename} />
            )}
        </>
    );
}
