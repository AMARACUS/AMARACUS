"use client";
import * as React from "react";
import { X } from "lucide-react";
import { cn } from "@/lib/utils";

interface ModalProps {
  isOpen: boolean;
  onClose: () => void;
  title: string;
  description?: string;
  children: React.ReactNode;
  maxWidth?: string;
}

export function Modal({
  isOpen,
  onClose,
  title,
  description,
  children,
  maxWidth = "max-w-lg"
}: ModalProps) {
  const previousActiveElement = React.useRef<HTMLElement | null>(null);
  const dialogRef = React.useRef<HTMLDivElement>(null);

  // Manage focus restoration and body scroll
  React.useEffect(() => {
    if (isOpen) {
      previousActiveElement.current = document.activeElement as HTMLElement;
      document.body.style.overflow = "hidden";

      // Move focus into the modal once mounted
      const timer = setTimeout(() => {
        if (dialogRef.current) {
          const focusable = dialogRef.current.querySelectorAll<HTMLElement>(
            'button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'
          );
          if (focusable.length > 0) {
            focusable[0].focus();
          } else {
            dialogRef.current.focus();
          }
        }
      }, 30);

      return () => {
        clearTimeout(timer);
        document.body.style.overflow = "unset";
        if (previousActiveElement.current && typeof previousActiveElement.current.focus === "function") {
          previousActiveElement.current.focus();
        }
      };
    } else {
      document.body.style.overflow = "unset";
      if (previousActiveElement.current && typeof previousActiveElement.current.focus === "function") {
        previousActiveElement.current.focus();
      }
    }
  }, [isOpen]);

  // Handle Escape key and focus trap
  React.useEffect(() => {
    if (!isOpen) return;

    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.preventDefault();
        onClose();
        return;
      }

      // Trap focus inside modal
      if (e.key === "Tab" && dialogRef.current) {
        const focusables = Array.from(
          dialogRef.current.querySelectorAll<HTMLElement>(
            'button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'
          )
        ).filter((el) => el.offsetParent !== null || el.getClientRects().length > 0);

        if (focusables.length === 0) {
          e.preventDefault();
          dialogRef.current.focus();
          return;
        }

        const first = focusables[0];
        const last = focusables[focusables.length - 1];

        if (e.shiftKey) {
          if (document.activeElement === first) {
            e.preventDefault();
            last.focus();
          }
        } else {
          if (document.activeElement === last) {
            e.preventDefault();
            first.focus();
          }
        }
      }
    };

    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      {/* Backdrop */}
      <div 
        className="fixed inset-0 bg-black/40 backdrop-blur-xs transition-opacity duration-150 animate-in fade-in"
        onClick={onClose}
        aria-hidden="true"
      />

      {/* Modal Dialog */}
      <div 
        ref={dialogRef}
        tabIndex={-1}
        role="dialog"
        aria-modal="true"
        aria-labelledby="modal-title"
        aria-describedby={description ? "modal-description" : undefined}
        className={cn(
          "relative w-full rounded-2xl border border-[#E9EDE7] bg-white p-6 shadow-xl z-10 space-y-4 max-h-[90vh] overflow-y-auto animate-in zoom-in-95 duration-150 focus:outline-none",
          maxWidth
        )}
      >
        <div className="flex items-start justify-between">
          <div>
            <h2 id="modal-title" className="font-editorial text-2xl font-bold text-[#1A1A1A] tracking-tight">
              {title}
            </h2>
            {description && (
              <p id="modal-description" className="text-xs text-[#636863] mt-1">
                {description}
              </p>
            )}
          </div>
          <button
            onClick={onClose}
            className="rounded-lg p-1.5 text-[#767676] hover:bg-[#F3F2ED] hover:text-[#1A1A1A] transition-colors focus-visible:ring-2 focus-visible:ring-[#008031]"
            aria-label="Close dialog"
          >
            <X className="w-5 h-5" aria-hidden="true" />
          </button>
        </div>

        {children}
      </div>
    </div>
  );
}