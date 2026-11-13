import fs from 'fs';
import path from 'path';

describe('Keyboard Accessibility Audit (WCAG 2.1 AA / Section 508)', () => {
  const webSrcRoot = path.resolve(__dirname, '../../web/src');

  // Helper to recursively collect all tsx files
  function getTsxFiles(dir: string): string[] {
    const entries = fs.readdirSync(dir, { withFileTypes: true });
    let files: string[] = [];
    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        files = files.concat(getTsxFiles(fullPath));
      } else if (entry.isFile() && (entry.name.endsWith('.tsx') || entry.name.endsWith('.jsx'))) {
        files.push(fullPath);
      }
    }
    return files;
  }

  describe('1. Global High-Contrast Focus Visible Indicators & Reduced Motion', () => {
    const globalsCssPath = path.resolve(webSrcRoot, 'app/globals.css');
    const cssContent = fs.readFileSync(globalsCssPath, 'utf8');

    test('Defines high-contrast :focus-visible outline in globals.css', () => {
      expect(cssContent).toMatch(/:focus-visible\s*\{[^}]*outline:\s*2px\s+solid\s+#008031/);
      expect(cssContent).toMatch(/outline-offset:\s*2px/);
    });

    test('Defines @media (prefers-reduced-motion: reduce) respecting user OS animation preferences', () => {
      expect(cssContent).toContain('@media (prefers-reduced-motion: reduce)');
      expect(cssContent).toMatch(/animation-duration:\s*0\.01ms/);
      expect(cssContent).toMatch(/transition-duration:\s*0\.01ms/);
    });
  });

  describe('2. Modal Dialog Primitive Keyboard Focus & Trap Mechanics', () => {
    const modalTsxPath = path.resolve(webSrcRoot, 'components/ui/modal.tsx');
    const modalContent = fs.readFileSync(modalTsxPath, 'utf8');

    test('Tracks previousActiveElement and restores focus when dialog closes (WCAG 2.4.3)', () => {
      expect(modalContent).toMatch(/previousActiveElement\s*=\s*(?:React\.)?useRef<HTMLElement \| null>\(null\)/);
      expect(modalContent).toMatch(/previousActiveElement\.current\.focus\(\)/);
    });

    test('Implements Tab / Shift+Tab keyboard focus trapping to prevent background leakage (Requirement 7)', () => {
      expect(modalContent).toContain('e.key === "Tab"');
      expect(modalContent).toContain('e.shiftKey');
      expect(modalContent).toMatch(/last\.focus\(\)/);
      expect(modalContent).toMatch(/first\.focus\(\)/);
    });

    test('Handles Escape key to dismiss dialog (Requirement 6)', () => {
      expect(modalContent).toContain('e.key === "Escape"');
      expect(modalContent).toMatch(/onClose\(\)/);
    });

    test('Locks body scroll while modal is active and restores on unmount', () => {
      expect(modalContent).toContain('document.body.style.overflow = "hidden"');
      expect(modalContent).toMatch(/document\.body\.style\.overflow\s*=\s*("unset"|prevOverflow)/);
    });

    test('Sets semantic ARIA dialog roles and label/description bindings', () => {
      expect(modalContent).toContain('role="dialog"');
      expect(modalContent).toContain('aria-modal="true"');
      expect(modalContent).toContain('aria-labelledby="modal-title"');
      expect(modalContent).toContain('aria-describedby={description ? "modal-description" : undefined}');
    });
  });

  describe('3. Cookie Settings Modal Focus Management', () => {
    const cookieModalPath = path.resolve(webSrcRoot, 'components/cookie-settings-modal.tsx');
    const cookieModalContent = fs.readFileSync(cookieModalPath, 'utf8');

    test('Implements keyboard focus trapping and Escape handling in CookieSettingsModal', () => {
      expect(cookieModalContent).toContain('e.key === "Escape"');
      expect(cookieModalContent).toContain('e.key === "Tab"');
      expect(cookieModalContent).toContain('previousActiveElement');
    });

    test('Provides visible focus rings for keyboard navigation on category switch toggles', () => {
      expect(cookieModalContent).toMatch(/peer-focus-visible:ring-2/);
      expect(cookieModalContent).toMatch(/peer-focus-visible:ring-\[#008031\]/);
    });
  });

  describe('4. Navigation Menus & Dropdown Keyboard Accessibility', () => {
    const layoutPath = path.resolve(webSrcRoot, 'app/dashboard/dashboard-shell.tsx');
    const layoutContent = fs.readFileSync(layoutPath, 'utf8');

    test('Organization switcher dropdown closes on Escape and returns focus to trigger', () => {
      expect(layoutContent).toContain('orgTriggerRef');
      expect(layoutContent).toContain('e.key === "Escape"');
      expect(layoutContent).toMatch(/orgTriggerRef\.current\?\.focus\(\)/);
    });

    test('Organization switcher has proper ARIA popup, expanded state, and menu/menuitem roles', () => {
      expect(layoutContent).toContain('aria-haspopup="menu"');
      expect(layoutContent).toContain('aria-expanded={orgDropdownOpen}');
      expect(layoutContent).toContain('aria-controls="org-dropdown-menu"');
      expect(layoutContent).toContain('role="menu"');
      expect(layoutContent).toContain('role="menuitem"');
    });

    test('Mobile navigation drawer closes on Escape and returns focus to hamburger button', () => {
      expect(layoutContent).toContain('mobileTriggerRef');
      expect(layoutContent).toMatch(/mobileTriggerRef\.current\?\.focus\(\)/);
    });

    test('Mobile drawer is hidden from tab sequence when closed on small screens (Requirement 9)', () => {
      expect(layoutContent).toMatch(/max-md:invisible/);
    });

    test('Dashboard layout uses the accessible Modal component for Organization creation', () => {
      expect(layoutContent).toMatch(/<Modal\s+isOpen=\{createOrgOpen\}/);
    });
  });

  describe('5. Form Textareas Accessible Labels & IDs', () => {
    test('Every textarea in apps/web has an associated label with matching htmlFor/id or aria-label', () => {
      const files = getTsxFiles(webSrcRoot);
      const unlabeledTextareas: Array<{ file: string; match: string }> = [];

      for (const filePath of files) {
        const content = fs.readFileSync(filePath, 'utf8');
        const textareaRegex = /<textarea\b([^>]*)>/g;
        let match;

        while ((match = textareaRegex.exec(content)) !== null) {
          const attrs = match[1];
          const hasId = /\bid=["']([^"']+)["']/.test(attrs);
          const hasAriaLabel = /\baria-label=["']/.test(attrs);
          const hasAriaLabelledby = /\baria-labelledby=["']/.test(attrs);

          if (hasId) {
            const idMatch = attrs.match(/\bid=["']([^"']+)["']/);
            const id = idMatch ? idMatch[1] : '';
            // Check if there is a matching label htmlFor in the same file
            const hasLabel = new RegExp(`htmlFor=["']${id}["']`).test(content);
            if (!hasLabel && !hasAriaLabel && !hasAriaLabelledby) {
              unlabeledTextareas.push({
                file: path.relative(webSrcRoot, filePath),
                match: match[0],
              });
            }
          } else if (!hasAriaLabel && !hasAriaLabelledby) {
            unlabeledTextareas.push({
              file: path.relative(webSrcRoot, filePath),
              match: match[0],
            });
          }
        }
      }

      expect(unlabeledTextareas).toHaveLength(0);
    });
  });

  describe('6. Horizontally Scrollable Tables Keyboard Accessibility', () => {
    test('All overflow-x-auto table wrappers have tabIndex={0}, role="region", and aria-label', () => {
      const files = getTsxFiles(webSrcRoot);
      const inaccessibleScrollWrappers: Array<{ file: string; line: number }> = [];

      for (const filePath of files) {
        const content = fs.readFileSync(filePath, 'utf8');
        const lines = content.split('\n');

        for (let i = 0; i < lines.length; i++) {
          const line = lines[i];
          // Check if line contains overflow-x-auto and is immediately followed by a table within next few lines
          if (line.includes('overflow-x-auto') && (line.includes('<div') || line.includes('<div\n'))) {
            const followingLines = lines.slice(i, i + 5).join(' ');
            if (followingLines.includes('<table')) {
              const hasTabIndex = /tabIndex=\{?0\}?/.test(followingLines);
              const hasRoleRegion = /role=["']region["']/.test(followingLines);
              const hasAriaLabel = /aria-label=["']/.test(followingLines);

              if (!hasTabIndex || !hasRoleRegion || !hasAriaLabel) {
                inaccessibleScrollWrappers.push({
                  file: path.relative(webSrcRoot, filePath),
                  line: i + 1,
                });
              }
            }
          }
        }
      }

      expect(inaccessibleScrollWrappers).toHaveLength(0);
    });
  });

  describe('7. Custom Tabs & Switchers ARIA Roles', () => {
    test('PKI view tabs define role="tablist" and role="tab" with aria-selected', () => {
      const pkiPath = path.resolve(webSrcRoot, 'app/dashboard/pki/page.tsx');
      const pkiContent = fs.readFileSync(pkiPath, 'utf8');
      expect(pkiContent).toMatch(/role="tablist"[^>]*aria-label="PKI Views"/);
      expect(pkiContent).toContain('aria-selected={activeTab === \'CERTIFICATES\'}');
      expect(pkiContent).toContain('aria-selected={activeTab === \'CAS\'}');
      expect(pkiContent).toContain('aria-selected={activeTab === \'CSRS\'}');
    });

    test('Crypto playground tabs define role="tablist" and role="tab" with aria-selected', () => {
      const cryptoPath = path.resolve(webSrcRoot, 'app/dashboard/crypto/page.tsx');
      const cryptoContent = fs.readFileSync(cryptoPath, 'utf8');
      expect(cryptoContent).toMatch(/role="tablist"[^>]*aria-label="Cryptographic Operations"/);
      expect(cryptoContent).toContain('role="tab"');
      expect(cryptoContent).toContain('aria-selected={isActive}');
    });

    test('Advanced cryptography tabs define role="tablist" and role="tab" with aria-selected', () => {
      const advPath = path.resolve(webSrcRoot, 'app/dashboard/advanced/page.tsx');
      const advContent = fs.readFileSync(advPath, 'utf8');
      expect(advContent).toMatch(/role="tablist"[^>]*aria-label="Advanced Cryptography Modules"/);
      expect(advContent).toContain('role="tab"');
      expect(advContent).toContain('aria-selected={isActive}');
    });

    test('Key management tabs define role="tablist" and role="tab" with aria-selected', () => {
      const keysPath = path.resolve(webSrcRoot, 'app/dashboard/keys/page.tsx');
      const keysContent = fs.readFileSync(keysPath, 'utf8');
      expect(keysContent).toMatch(/role="tablist"[^>]*aria-label="Key Management Views"/);
      expect(keysContent).toContain('aria-selected={activeTab === \'BYOK\'}');
      expect(keysContent).toContain('aria-selected={activeTab === \'INTERNAL\'}');
    });
  });

  describe('8. Custom Filter & Search Inputs Accessible Labels', () => {
    test('Search inputs across dashboard and public pages have accessible aria-labels', () => {
      const apiExp = fs.readFileSync(path.resolve(webSrcRoot, 'app/dashboard/api-explorer/page.tsx'), 'utf8');
      expect(apiExp).toMatch(/aria-label="Search endpoints"/);

      const audit = fs.readFileSync(path.resolve(webSrcRoot, 'app/dashboard/audit/page.tsx'), 'utf8');
      expect(audit).toMatch(/aria-label="Search audit records by action, resource type, or identifier"/);

      const intel = fs.readFileSync(path.resolve(webSrcRoot, 'app/dashboard/intelligence/page.tsx'), 'utf8');
      expect(intel).toMatch(/aria-label="Search cryptographic assets, algorithms, or providers"/);

      const pki = fs.readFileSync(path.resolve(webSrcRoot, 'app/dashboard/pki/page.tsx'), 'utf8');
      expect(pki).toMatch(/aria-label="Search certificates by subject, name, or serial"/);
    });
  });
});
