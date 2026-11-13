import Link from "next/link";
import { ChevronRight } from "lucide-react";
import { JsonLd } from "@/components/json-ld";
import { absoluteUrl } from "@/lib/seo";

export interface Crumb {
  name: string;
  /** Path with a trailing slash. The last crumb is the current page. */
  path: string;
}

export function Breadcrumbs({ items }: { items: Crumb[] }) {
  const trail: Crumb[] = [{ name: "Home", path: "/" }, ...items];

  return (
    <nav aria-label="Breadcrumb" className="max-w-6xl mx-auto px-6 pt-6 text-xs text-[#767676]">
      <ol className="flex flex-wrap items-center gap-1.5">
        {trail.map((crumb, i) => {
          const isLast = i === trail.length - 1;
          return (
            <li key={crumb.path} className="flex items-center gap-1.5">
              {isLast ? (
                <span aria-current="page" className="text-[#1A1A1A] font-medium">{crumb.name}</span>
              ) : (
                <>
                  <Link href={crumb.path} className="hover:text-[#008031]">{crumb.name}</Link>
                  <ChevronRight className="w-3 h-3" aria-hidden="true" />
                </>
              )}
            </li>
          );
        })}
      </ol>
      <JsonLd
        data={{
          "@context": "https://schema.org",
          "@type": "BreadcrumbList",
          itemListElement: trail.map((crumb, i) => ({
            "@type": "ListItem",
            position: i + 1,
            name: crumb.name,
            item: absoluteUrl(crumb.path),
          })),
        }}
      />
    </nav>
  );
}
