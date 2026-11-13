import * as React from "react";
import { cn } from "@/lib/utils";

export interface InputProps extends React.InputHTMLAttributes<HTMLInputElement> {}

const Input = React.forwardRef<HTMLInputElement, InputProps>(
  ({ className, type, ...props }, ref) => {
    return (
      <input
        type={type}
        className={cn(
          "flex h-10 w-full rounded-lg border border-[#E9EDE7] bg-white px-3 py-2 text-sm text-[#1A1A1A] placeholder:text-[#8C928C] transition-all focus-visible:outline-none focus-visible:border-[#008031] focus-visible:ring-1 focus-visible:ring-[#008031] disabled:cursor-not-allowed disabled:opacity-50",
          className
        )}
        ref={ref}
        {...props}
      />
    );
  }
);
Input.displayName = "Input";

export { Input };
