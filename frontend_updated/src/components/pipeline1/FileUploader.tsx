import { useRef, useState } from 'react';
import { Upload, FileText, X, AlertCircle } from 'lucide-react';

interface FileUploaderProps {
  onUrls: (urls: string[]) => void;
}

export default function FileUploader({ onUrls }: FileUploaderProps) {
  const [dragging, setDragging] = useState(false);
  const [fileName, setFileName]  = useState('');
  const [error, setError]        = useState('');
  const [text, setText]          = useState('');
  const inputRef = useRef<HTMLInputElement>(null);

  function parseLines(raw: string): string[] {
    return raw.split('\n').map(l => l.trim()).filter(l => l.length > 0 && l.startsWith('http'));
  }

  function loadFile(file: File) {
    if (!file.name.endsWith('.txt')) {
      setError('Only .txt files are supported (one URL per line).');
      return;
    }
    const reader = new FileReader();
    reader.onload = e => {
      const content = e.target?.result as string;
      setText(content);
      setFileName(file.name);
      setError('');
    };
    reader.readAsText(file);
  }

  function handleDrop(e: React.DragEvent) {
    e.preventDefault();
    setDragging(false);
    const file = e.dataTransfer.files[0];
    if (file) loadFile(file);
  }

  function handleSubmit() {
    const urls = parseLines(text);
    if (urls.length === 0) {
      setError('No valid URLs found (must start with http).');
      return;
    }
    onUrls(urls);
  }

  const urlCount = parseLines(text).length;

  return (
    <div className="space-y-4">
      {/* Drop zone */}
      <div
        className={`relative border-2 border-dashed rounded-2xl p-8 text-center transition-all duration-200 cursor-pointer
          ${dragging ? 'border-brand/70 bg-brand/10' : 'border-white/10 bg-white/[0.02] hover:border-white/20 hover:bg-white/[0.04]'}`}
        onDragOver={e => { e.preventDefault(); setDragging(true); }}
        onDragLeave={() => setDragging(false)}
        onDrop={handleDrop}
        onClick={() => inputRef.current?.click()}
      >
        <input
          ref={inputRef}
          type="file"
          accept=".txt"
          className="hidden"
          onChange={e => { const f = e.target.files?.[0]; if (f) loadFile(f); }}
        />
        <Upload size={28} className={`mx-auto mb-3 ${dragging ? 'text-brand-light' : 'text-white/30'}`} />
        <p className="text-white/60 text-sm">
          {fileName
            ? <span className="flex items-center justify-center gap-2 text-brand-light"><FileText size={14}/>{fileName}</span>
            : <>Drop a <span className="text-white/90 font-mono">.txt</span> file or click to browse</>
          }
        </p>
        <p className="text-white/30 text-xs mt-1">One URL per line — no limit</p>
      </div>

      {/* Text area — paste URLs directly */}
      <textarea
        className="url-input-area w-full h-40 p-4"
        placeholder="Or paste URLs here (one per line)&#10;https://example.com&#10;http://suspicious-site.tk/login"
        value={text}
        onChange={e => { setText(e.target.value); setFileName(''); setError(''); }}
      />

      {error && (
        <div className="flex items-center gap-2 text-malicious text-sm">
          <AlertCircle size={14}/> {error}
        </div>
      )}

      {/* Submit */}
      <div className="flex items-center gap-4">
        <button
          onClick={handleSubmit}
          disabled={urlCount === 0}
          className="flex items-center gap-2 px-6 py-2.5 rounded-xl bg-brand hover:bg-brand/80
                     text-white font-medium text-sm transition-all duration-200
                     disabled:opacity-40 disabled:cursor-not-allowed"
        >
          Analyze {urlCount > 0 && <span className="font-mono">({urlCount} URLs)</span>}
        </button>

        {text && (
          <button
            onClick={() => { setText(''); setFileName(''); setError(''); }}
            className="flex items-center gap-1.5 text-white/30 hover:text-white/60 text-sm transition-colors"
          >
            <X size={14}/> Clear
          </button>
        )}
      </div>
    </div>
  );
}
