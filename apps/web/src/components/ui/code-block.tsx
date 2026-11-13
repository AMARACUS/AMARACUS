"use client";
import React, { useState } from "react";
import { Check, Copy } from "lucide-react";

interface CodeBlockProps {
  code: string;
  language?: string;
  title?: string;
}

export function CodeBlock({ code, language = "bash", title }: CodeBlockProps) {
  const [copied, setCopied] = useState(false);

  const onCopy = () => {
    navigator.clipboard.writeText(code);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="rounded-xl border border-[#E9EDE7] bg-[#1E201E] text-[#E8ECE7] font-mono text-sm overflow-hidden shadow-card">
      <div className="flex items-center justify-between px-4 py-2 border-b border-[#2C302C] bg-[#171917] text-xs text-[#8E968E]">
        <span>{title || language}</span>
        <button
          onClick={onCopy}
          className="flex items-center gap-1.5 px-2 py-1 rounded hover:bg-[#2C302C] transition-colors text-xs text-[#CBD2C8]"
        >
          {copied ? <Check className="w-3.5 h-3.5 text-[#48BB78]" /> : <Copy className="w-3.5 h-3.5" />}
          <span>{copied ? "Copied" : "Copy"}</span>
        </button>
      </div>
      <pre className="p-4 overflow-x-auto text-xs leading-relaxed">
        <code>{code}</code>
      </pre>
    </div>
  );
}
