import { useId, useState } from 'react';
import { LogoMark, ShieldIcon } from './Icons';

export function SiteHeader() {
  const [open, setOpen] = useState(false);
  const detailsId = useId();

  return (
    <header>
      <div className="site-header">
        <div className="container site-header__inner">
          <span className="brand">
            <LogoMark />
            <span className="brand__text">
              <span className="brand__name">PhishLens</span>
              <span className="brand__subtitle">Phishing Email Analyzer</span>
            </span>
          </span>
          <p className="privacy-pill">
            <ShieldIcon />
            <span>
              <span className="privacy-pill__long">Analysis runs in this browser tab. </span>
              Nothing is uploaded.{' '}
              <button
                type="button"
                aria-expanded={open}
                aria-controls={detailsId}
                onClick={() => setOpen(!open)}
              >
                {open ? 'Hide details' : 'Privacy details'}
              </button>
            </span>
          </p>
        </div>
      </div>
      <section
        id={detailsId}
        className="privacy-details"
        hidden={!open}
        aria-label="Privacy details"
      >
        <div className="container privacy-details__inner">
          <div>
            <h2>What happens to your email</h2>
            <ul>
              <li>The message is read and analysed inside this tab, in a background worker.</li>
              <li>It is never uploaded, stored in browser storage or sent to any service.</li>
              <li>Closing the tab or starting a new analysis discards it from memory.</li>
            </ul>
          </div>
          <div>
            <h2>What PhishLens never does</h2>
            <ul>
              <li>Open, fetch or follow links, or look up domains in DNS.</li>
              <li>Render the message&rsquo;s HTML or load its images.</li>
              <li>Open, unpack or run attachments.</li>
            </ul>
          </div>
          <div>
            <h2>Limits to keep in mind</h2>
            <ul>
              <li>Findings are heuristics, not proof of phishing or of safety.</li>
              <li>
                SPF, DKIM and DMARC results are shown as reported in the headers, not verified.
              </li>
              <li>
                Your browser, extensions and operating system are outside PhishLens&rsquo;s control.
              </li>
            </ul>
          </div>
        </div>
      </section>
    </header>
  );
}
