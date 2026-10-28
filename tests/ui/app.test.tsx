// @vitest-environment jsdom
import { act, cleanup, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { AnalysisError } from '../../src/core/errors';
import { DEFAULT_LIMITS } from '../../src/core/limits';
import type { Analyzer } from '../../src/worker/client';
import { buildEmail } from '../helpers';
import { chooseFile, pasteAndAnalyze, renderApp } from './support';

beforeEach(() => {
  vi.spyOn(Storage.prototype, 'setItem');
});

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe('input view', () => {
  it('shows the privacy notice, both input modes and the samples', async () => {
    const { user } = renderApp();
    expect(
      screen.getByRole('heading', { level: 1, name: /Inspect a suspicious email/u }),
    ).toBeTruthy();
    expect(screen.getByText(/Nothing is uploaded/u)).toBeTruthy();
    const toggle = screen.getByRole('button', { name: 'Privacy details' });
    await user.click(toggle);
    expect(toggle.getAttribute('aria-expanded')).toBe('true');
    expect(screen.getByRole('region', { name: 'Privacy details' }).hidden).toBe(false);
    expect(
      screen.getByRole('tab', { name: 'Upload .eml file' }).getAttribute('aria-selected'),
    ).toBe('true');
    expect(
      screen.getAllByRole('button', {
        name: /Credential phishing|Attachment lure|Ordinary newsletter/u,
      }),
    ).toHaveLength(3);
  });

  it('switches input modes with the arrow keys', async () => {
    const { user } = renderApp();
    screen.getByRole('tab', { name: 'Upload .eml file' }).focus();
    await user.keyboard('{ArrowRight}');
    expect(document.activeElement).toBe(screen.getByRole('tab', { name: 'Paste source' }));
    expect(screen.getByLabelText('Raw message or headers')).toBeTruthy();
  });
});

describe('error states', () => {
  it('explains invalid pasted text and keeps the text for correction', async () => {
    const { user } = renderApp();
    await pasteAndAnalyze(user, 'Hello! This is just a paragraph, not an email.');
    const heading = await screen.findByRole('heading', {
      level: 1,
      name: 'No email headers found',
    });
    expect(document.activeElement).toBe(heading);
    expect(document.querySelector('.error-panel')?.textContent).toContain('email header block');
    await user.click(screen.getByRole('button', { name: 'Try another message' }));
    expect(screen.getByLabelText<HTMLTextAreaElement>('Raw message or headers').value).toContain(
      'just a paragraph',
    );
  });

  it('rejects files over the configured size limit before reading them', async () => {
    const { container } = renderApp({ ...DEFAULT_LIMITS, maxInputBytes: 64 });
    const file = new File([buildEmail()], 'big.eml', { type: 'message/rfc822' });
    const read = vi.spyOn(file, 'arrayBuffer');
    chooseFile(container, file);
    expect(await screen.findByRole('heading', { name: 'Message is too large' })).toBeTruthy();
    expect(read).not.toHaveBeenCalled();
  });

  it('rejects unsupported and Outlook .msg files with specific messages', async () => {
    const { container, user } = renderApp();
    chooseFile(container, new File(['%PDF-1.7'], 'invoice.pdf'));
    expect(await screen.findByRole('heading', { name: 'Unsupported file type' })).toBeTruthy();
    await user.click(screen.getByRole('button', { name: 'Try another message' }));
    chooseFile(container, new File(['x'], 'mail.msg'));
    expect(
      await screen.findByRole('heading', { name: 'Outlook .msg files are not supported' }),
    ).toBeTruthy();
  });

  it('can cancel a running analysis', async () => {
    const neverEnding: Analyzer = () => {
      let cancel: () => void = () => undefined;
      const promise = new Promise<never>((_, reject) => {
        cancel = () => reject(new AnalysisError('CANCELLED', 'cancelled'));
      });
      return { promise, cancel: () => cancel() };
    };
    const { user } = renderApp(DEFAULT_LIMITS, neverEnding);
    await user.click(screen.getByRole('button', { name: /Credential phishing/u }));
    expect(await screen.findByRole('heading', { name: /Analysing/u })).toBeTruthy();
    await user.click(screen.getByRole('button', { name: 'Cancel analysis' }));
    expect(
      await screen.findByRole('heading', { name: /Inspect a suspicious email/u }),
    ).toBeTruthy();
    expect(screen.getByRole('status').textContent).toBe('Analysis cancelled.');
  });
});

describe('results view', () => {
  it('analyses an uploaded .eml file and moves focus to the results', async () => {
    const { container } = renderApp();
    chooseFile(
      container,
      new File([buildEmail({ headers: ['Subject: Uploaded file subject'] })], 'message.eml'),
    );
    const heading = await screen.findByRole('heading', { level: 1, name: 'Uploaded file subject' });
    await waitFor(() => expect(document.activeElement).toBe(heading));
    expect(screen.getByText(/message\.eml/u)).toBeTruthy();
  });

  it('shows the assessment, counts and accessible tabs for a sample', async () => {
    const { user } = renderApp();
    await user.click(screen.getByRole('button', { name: /Credential phishing/u }));
    expect(await screen.findByRole('heading', { level: 2, name: 'High concern' })).toBeTruthy();
    expect(screen.getByText(/rule-based rating, not a probability/u)).toBeTruthy();

    const overview = screen.getByRole('tab', { name: 'Overview' });
    overview.focus();
    await user.keyboard('{ArrowRight}');
    const findings = screen.getByRole('tab', { name: /Findings/u });
    expect(findings.getAttribute('aria-selected')).toBe('true');
    expect(document.activeElement).toBe(findings);
    await user.keyboard('{End}');
    expect(screen.getByRole('tab', { name: 'Method' }).getAttribute('aria-selected')).toBe('true');
    expect(screen.getByRole('heading', { name: 'How the assessment is decided' })).toBeTruthy();
  });

  it('expands and collapses findings and filters them by severity', async () => {
    const { user } = renderApp();
    await user.click(screen.getByRole('button', { name: /Credential phishing/u }));
    await user.click(await screen.findByRole('tab', { name: /Findings/u }));
    const panel = screen.getByRole('tabpanel');
    const toggle = within(panel).getByRole('button', {
      name: /Sender or reply domain resembles a well-known brand/u,
    });
    const body = document.getElementById(toggle.getAttribute('aria-controls') ?? '');
    expect(body?.hidden).toBe(true);
    await user.click(toggle);
    expect(toggle.getAttribute('aria-expanded')).toBe('true');
    expect(body?.hidden).toBe(false);
    expect(body?.textContent).toContain('Common legitimate causes');

    const before = within(panel).getAllByRole('button', { expanded: false }).length;
    await user.click(within(panel).getByRole('button', { name: /^High \(\d+\)$/u, pressed: true }));
    expect(within(panel).getAllByRole('button', { expanded: false }).length).toBeLessThan(before);
  });

  it('keeps the severity filter available when it hides every finding', async () => {
    const { user } = renderApp();
    await user.click(screen.getByRole('button', { name: /Credential phishing/u }));
    await user.click(await screen.findByRole('tab', { name: /Findings/u }));
    const panel = screen.getByRole('tabpanel');
    for (const name of [/^High /u, /^Medium /u, /^Low /u, /^Info /u]) {
      await user.click(within(panel).getByRole('button', { name, pressed: true }));
    }
    expect(within(panel).getByText('No findings match the selected severities.')).toBeTruthy();
    expect(within(panel).queryByRole('button', { name: 'Expand all' })).toBeNull();
    await user.click(within(panel).getByRole('button', { name: /^Info /u, pressed: false }));
    expect(within(panel).getByRole('button', { name: 'Expand all' })).toBeTruthy();
  });

  it('lists the number of findings per severity beside the assessment', async () => {
    const { user } = renderApp();
    await user.click(screen.getByRole('button', { name: /Credential phishing/u }));
    await screen.findByRole('heading', { level: 2, name: 'High concern' });
    const ledger = screen.getByLabelText('Findings by severity');
    expect(ledger.tagName).toBe('DL');
    const rows = [...ledger.querySelectorAll('div')].map((row) => [
      row.querySelector('dt')?.textContent,
      row.querySelector('dd')?.textContent,
    ]);
    expect(rows.map(([label]) => label)).toEqual(['High', 'Medium', 'Low', 'Info']);
    expect(rows.every(([, count]) => /^\d+$/u.test(count ?? ''))).toBe(true);
    expect(Number(rows[0]?.[1])).toBeGreaterThan(0);
  });

  it('shows links defanged and never renders them as clickable links', async () => {
    const { user, container } = renderApp();
    await user.click(screen.getByRole('button', { name: /Credential phishing/u }));
    await user.click(await screen.findByRole('tab', { name: /Links/u }));
    expect(
      screen.getAllByText(/hxxp\[:\/\/\]paypal\[\.\]com\[\.\]account-verify\[\.\]example/u).length,
    ).toBeGreaterThan(0);
    const hrefs = [...container.querySelectorAll('a[href]')].map((anchor) =>
      anchor.getAttribute('href'),
    );
    expect(hrefs).toEqual(['#main', 'https://github.com/Mayaar-Irshad/PhishLens']);
  });

  it('analyses an attached message and returns to the parent', async () => {
    const inner =
      'From: Inner Sender <inner@inner.example>\r\nSubject: The inner message\r\nDate: Tue, 20 Oct 2026 09:00:00 +0000\r\n\r\nInner body\r\n';
    const raw = buildEmail({
      headers: ['Subject: Outer message', 'Content-Type: multipart/mixed; boundary="u"'],
      body: `--u\r\nContent-Type: text/plain\r\n\r\nReporting this phish.\r\n--u\r\nContent-Type: message/rfc822\r\nContent-Disposition: attachment; filename="phish.eml"\r\n\r\n${inner}--u--\r\n`,
    });
    const { user } = renderApp();
    await pasteAndAnalyze(user, raw);
    await user.click(await screen.findByRole('tab', { name: /Attachments/u }));
    await user.click(screen.getByRole('button', { name: 'Analyze attached message' }));
    expect(
      await screen.findByRole('heading', { level: 1, name: 'The inner message' }),
    ).toBeTruthy();
    expect(screen.getByText(/Attached to:/u).textContent).toContain('pasted message');
    await user.click(screen.getByRole('button', { name: 'Back to parent message' }));
    expect(await screen.findByRole('heading', { level: 1, name: 'Outer message' })).toBeTruthy();
  });
});

describe('authentication tab', () => {
  it('labels every result as reported and unverified', async () => {
    const { user } = renderApp();
    await user.click(screen.getByRole('button', { name: /Credential phishing/u }));
    await user.click(await screen.findByRole('tab', { name: 'Authentication' }));
    expect(screen.getByRole('heading', { name: 'Reported, not verified' })).toBeTruthy();
    const summary = screen.getByRole('group', { name: /Reported results/u });
    expect(within(summary).getByRole('heading', { name: 'DMARC (reported)' })).toBeTruthy();
    expect(summary.textContent).toContain('fail');
    expect(summary.textContent).toContain('Claimed by mx.recipient.example');
    expect(screen.queryByText(/\bverified pass\b/iu)).toBeNull();
  });
});

describe('untrusted content rendering', () => {
  const payload =
    '<img src=x onerror="window.__xss=1"><script>window.__xss=2</script><iframe src="javascript:alert(1)">';

  it('renders hostile header values, link text and filenames as inert text', async () => {
    const raw = buildEmail({
      headers: [
        `Subject: ${payload}`,
        `From: "${payload.replace(/"/gu, "'")}" <attacker@evil.example>`,
        'Content-Type: multipart/mixed; boundary="z"',
        `Authentication-Results: <b>mx</b>; dmarc=fail (${payload}) header.from=<i>evil.example</i>`,
        `DKIM-Signature: v=1; d=<script>.example; s=${payload}; h=from; b=x; bh=y; a=rsa-sha256`,
      ],
      body:
        `--z\r\nContent-Type: text/html\r\n\r\n<a href="https://evil.example/">${payload}</a><svg onload="window.__xss=3"></svg>\r\n` +
        `--z\r\nContent-Type: text/plain; name="x.txt"\r\nContent-Disposition: attachment; filename="<svg onload=alert(1)>.txt"\r\n\r\nfile\r\n--z--\r\n`,
    });
    const { user, container } = renderApp();
    await pasteAndAnalyze(user, raw);
    await screen.findByRole('heading', { level: 1 });
    for (const tab of [
      /Overview/u,
      /Findings/u,
      /Headers/u,
      /Authentication/u,
      /Links/u,
      /Attachments/u,
    ]) {
      await user.click(screen.getByRole('tab', { name: tab }));
      for (const toggle of container.querySelectorAll<HTMLButtonElement>('.finding__toggle'))
        await user.click(toggle);
      expect(container.querySelectorAll('script, img, iframe, object, embed').length).toBe(0);
      const handlerAttributes = [...container.querySelectorAll('*')].flatMap((element) =>
        [...element.attributes].filter((attribute) => attribute.name.startsWith('on')),
      );
      expect(handlerAttributes).toEqual([]);
    }
    expect((window as unknown as Record<string, unknown>)['__xss']).toBeUndefined();
    expect(screen.getAllByText((text) => text.includes('<script>')).length).toBeGreaterThan(0);
  });

  it('shows hidden direction-changing characters as visible markers', async () => {
    const raw = buildEmail({
      headers: ['Content-Type: multipart/mixed; boundary="r"'],
      body: "--r\r\nContent-Type: text/plain\r\n\r\nhi\r\n--r\r\nContent-Type: text/html\r\nContent-Disposition: attachment; filename*=utf-8''Invoice%E2%80%AEfdp.html\r\n\r\n<p>x</p>\r\n--r--\r\n",
    });
    const { user, container } = renderApp();
    await pasteAndAnalyze(user, raw);
    await user.click(await screen.findByRole('tab', { name: /Attachments/u }));
    const marker = container.querySelector('.attachment-row__name .hidden-char');
    expect(marker?.textContent).toContain('U+202E');
    expect(container.querySelector('.attachment-row__name')?.textContent).not.toContain('\u202E');
  });
});

describe('report export and privacy', () => {
  it('downloads a JSON report generated in memory without the message body', async () => {
    let saved: Blob | undefined;
    const create = vi.fn((blob: Blob) => {
      saved = blob;
      return 'blob:phishlens-test';
    });
    Object.assign(URL, { createObjectURL: create, revokeObjectURL: vi.fn() });
    const click = vi
      .spyOn(HTMLAnchorElement.prototype, 'click')
      .mockImplementation(() => undefined);

    const { user } = renderApp();
    await user.click(screen.getByRole('button', { name: /Credential phishing/u }));
    await user.click(await screen.findByRole('button', { name: 'Export report' }));
    expect(screen.getByRole('checkbox', { name: /Include recipient addresses/u })).toHaveProperty(
      'checked',
      false,
    );
    expect(screen.getByRole('checkbox', { name: /Redact email addresses/u })).toHaveProperty(
      'checked',
      true,
    );
    await user.click(screen.getByRole('button', { name: 'Download JSON' }));

    expect(click).toHaveBeenCalledTimes(1);
    expect(saved?.type).toBe('application/json');
    const json = await saved!.text();
    const report = JSON.parse(json) as { schema: string; privacy: { bodyIncluded: boolean } };
    expect(report.schema).toBe('phishlens-report/1');
    expect(report.privacy.bodyIncluded).toBe(false);
    expect(json).not.toContain('Dear customer');
    expect(json).not.toContain('jane.doe');
    await act(() => Promise.resolve());
    expect(screen.getByText(/Saved phishlens-report-/u)).toBeTruthy();
  });

  it('never writes to browser storage', async () => {
    const { user } = renderApp();
    await user.click(screen.getByRole('button', { name: /Ordinary newsletter/u }));
    await screen.findByRole('heading', { level: 2, name: 'No indicators matched' });
    expect(Storage.prototype.setItem).not.toHaveBeenCalled();
  });
});
