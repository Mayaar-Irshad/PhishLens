import { REPOSITORY_URL } from '../../config';
import { TOOL_VERSION } from '../../core/version';

export function SiteFooter() {
  return (
    <footer className="site-footer">
      <div className="container site-footer__inner">
        <div className="site-footer__about">
          <p>PhishLens {TOOL_VERSION}. Heuristic analysis for investigation, not a verdict.</p>
          <p className="site-footer__credit">&copy; 2026 Irshad</p>
        </div>
        <p>
          <a href={REPOSITORY_URL} rel="noreferrer noopener">
            Source code and documentation
          </a>
        </p>
      </div>
    </footer>
  );
}
