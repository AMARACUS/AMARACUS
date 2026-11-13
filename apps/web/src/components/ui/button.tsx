import * as React from "react";
import { cn } from "@/lib/utils";

export interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: "default" | "outline" | "ghost" | "secondary" | "destructive";
  size?: "default" | "sm" | "lg" | "icon";
}

const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant = "default", size = "default", ...props }, ref) => {
    return (
      <button
        ref={ref}
        className={cn(
          "inline-flex items-center justify-center whitespace-nowrap rounded-lg text-sm font-medium transition-all duration-150 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#008031] focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50",
          {
            "bg-[#008031] text-white shadow-sm hover:bg-[#006827] active:bg-[#00521F]": variant === "default",
            "border border-[#E9EDE7] bg-white text-[#1A1A1A] hover:bg-[#F3F2ED] hover:border-[#D5DAD3]": variant === "outline",
            "bg-[#F0EFEA] text-[#1A1A1A] hover:bg-[#E5E3DC]": variant === "secondary",
            "hover:bg-[#EAF3EC] text-[#1A1A1A] hover:text-[#008031]": variant === "ghost",
            "bg-red-600 text-white hover:bg-red-700 shadow-sm": variant === "destructive",
            "h-9 px-4 py-2": size === "default",
            "h-8 rounded-md px-3 text-xs": size === "sm",
            "h-11 rounded-lg px-6 text-base": size === "lg",
            "h-9 w-9 p-0": size === "icon",
          },
          className
        )}
        {...props}
      />
    );
  }
);
Button.displayName = "Button";

export { Button };
