import { UploadCloud } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";

export default function Dashboard() {
  return (
    <main className="min-h-screen bg-slate-950 text-white">
      <div className="mx-auto max-w-7xl px-6 py-12">
        {/* Header */}
        <header className="mb-10">
          <h1 className="text-5xl font-bold tracking-tight">
            ARGUS AI
          </h1>

          <p className="mt-3 text-lg text-slate-400">
            AI-Powered Malware Analysis Platform
          </p>
        </header>

        {/* Upload Card */}
        <Card className="border border-slate-800 bg-slate-900 shadow-xl">
            <CardContent className="p-10">
                <h2 className="text-2xl font-semibold text-white">
                    Upload Malware Sample
                </h2>
        
                <p className="mt-3 text-slate-400">
                    Upload a Windows PE executable for AI-powered static malware
                    analysis.
                </p>
        
                <div className="mt-8 rounded-xl border-2 border-dashed border-slate-700 p-12 text-center transition-colors hover:border-blue-500">
                    <UploadCloud className="mx-auto mb-5 h-12 w-12 text-slate-500" />
                    
                    <p className="text-lg text-slate-300">
                        Drag & Drop an executable here
                    </p>
                    
                    <p className="mt-2 text-sm text-slate-500">
                        or click to browse
                    </p>

                    <p className="mt-6 text-xs text-slate-500">
                        Supported formats: .exe • .dll • .sys
                    </p>
                </div>
            </CardContent>
        </Card>
      </div>
    </main>
  );
}
