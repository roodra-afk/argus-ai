import { useState } from "react";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";

export default function AIChatCard({ filename }) {
    const [question, setQuestion] = useState("");
    const [answer, setAnswer] = useState(null);
    const [loading, setLoading] = useState(false);

    async function askAI() {
        if (!question.trim() || !filename || loading) {
            return;
        }

        setLoading(true);
        setAnswer(null);

        try {
            const response = await fetch(
                "http://localhost:8000/api/v1/analysis/chat",
                {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json",
                    },
                    body: JSON.stringify({
                        filename,
                        question: question.trim(),
                    }),
                }
            );

            if (!response.ok) {
                throw new Error("AI request failed");
            }

            const data = await response.json();

            setAnswer(data.answer);
        } catch (error) {
            console.error(error);

            setAnswer(
                "Unable to get a response from Argus AI. Please try again."
            );
        } finally {
            setLoading(false);
        }
    }

    return (
        <Card className="mt-8 border border-slate-800 bg-slate-900 shadow-xl">
            <CardContent className="p-8">
                <div>
                    <h2 className="text-2xl font-semibold text-white">
                        Ask Argus AI
                    </h2>

                    <p className="mt-2 text-sm text-slate-400">
                        Ask questions about the analysis of{" "}
                        <span className="font-medium text-slate-300">
                            {filename}
                        </span>
                        .
                    </p>
                </div>

                <div className="mt-6">
                    <Textarea
                        value={question}
                        onChange={(event) => setQuestion(event.target.value)}
                        placeholder="Why was this file classified as benign?"
                        className="min-h-28 border-slate-700 bg-slate-950 text-white placeholder:text-slate-500"
                    />
                </div>

                <div className="mt-4 flex justify-end">
                    <Button
                        onClick={askAI}
                        disabled={!question.trim() || loading}
                    >
                        {loading ? "Thinking..." : "Ask Argus"}
                    </Button>
                </div>

                {answer && (
                    <div className="mt-6 rounded-lg border border-slate-800 bg-slate-950 p-6">
                        <h3 className="text-lg font-semibold text-white">
                            Argus AI
                        </h3>

                        <p className="mt-4 whitespace-pre-wrap text-sm leading-7 text-slate-300">
                            {answer}
                        </p>
                    </div>
                )}
            </CardContent>
        </Card>
    );
}
