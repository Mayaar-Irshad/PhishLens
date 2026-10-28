// @vitest-environment jsdom
import { act, cleanup, fireEvent, screen, waitFor, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { buildEmail } from '../helpers';
import { renderApp } from './support';

function fileDrag(type: 'dragOver' | 'drop', files: File[] = []) {
  return fireEvent[type](document.body, {
    dataTransfer: { types: ['Files'], files, dropEffect: 'none' },
  });
}

async function clipboardText(): Promise<string> {
  // user-event installs its own clipboard stub when a test calls userEvent.setup().
  return navigator.clipboard.readText();
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

async function openSample(user: ReturnType<typeof renderApp>['user'], name: RegExp) {
  await user.click(screen.getByRole('button', { name }));
  await screen.findByRole('heading', { level: 2, name: /concern|indicators/u });
}

describe('page-wide drag and drop', () => {
  it('always intercepts file drags so the browser never opens a dropped file', () => {
    renderApp();
    expect(fileDrag('dragOver')).toBe(false);
    const textDrag = fireEvent.dragOver(document.body, {
      dataTransfer: { types: ['text/plain'], files: [] },
    });
    expect(textDrag).toBe(true);
  });

  it('analyses a file dropped anywhere, including over the results', async () => {
    renderApp();
    fileDrag('drop', [new File([buildEmail({ headers: ['Subject: First drop'] })], 'one.eml')]);
    expect(await screen.findByRole('heading', { level: 1, name: 'First drop' })).toBeTruthy();
    fileDrag('drop', [new File([buildEmail({ headers: ['Subject: Second drop'] })], 'two.eml')]);
    expect(await screen.findByRole('heading', { level: 1, name: 'Second drop' })).toBeTruthy();
  });
});

describe('input shortcuts', () => {
  it('fills the paste box when headers are pasted anywhere on the input screen', async () => {
    renderApp();
    const raw = buildEmail({ headers: ['Subject: Pasted anywhere'] });
    fireEvent.paste(document.body, { clipboardData: { getData: () => raw } });
    const textarea = await screen.findByLabelText<HTMLTextAreaElement>('Raw message or headers');
    // Text areas normalise line breaks to LF, as browsers do.
    expect(textarea.value).toBe(raw.replace(/\r\n/gu, '\n'));
    expect(screen.getByRole('tab', { name: 'Paste source' }).getAttribute('aria-selected')).toBe(
      'true',
    );
  });

  it('ignores pasted text that does not look like email', () => {
    renderApp();
    fireEvent.paste(document.body, { clipboardData: { getData: () => 'just words' } });
    expect(screen.queryByLabelText('Raw message or headers')).toBeNull();
  });

  it('submits with Ctrl+Enter', async () => {
    const { user } = renderApp();
    await user.click(screen.getByRole('tab', { name: 'Paste source' }));
    const textarea = screen.getByLabelText('Raw message or headers');
    fireEvent.change(textarea, {
      target: { value: buildEmail({ headers: ['Subject: Keyboard submit'] }) },
    });
    fireEvent.keyDown(textarea, { key: 'Enter', ctrlKey: true });
    expect(await screen.findByRole('heading', { level: 1, name: 'Keyboard submit' })).toBeTruthy();
  });
});

describe('navigation and focus', () => {
  it('returns focus to the input heading after "New analysis"', async () => {
    const { user } = renderApp();
    await openSample(user, /Ordinary newsletter/u);
    await user.click(screen.getByRole('button', { name: 'New analysis' }));
    const heading = await screen.findByRole('heading', {
      level: 1,
      name: /Inspect a suspicious email/u,
    });
    await waitFor(() => expect(document.activeElement).toBe(heading));
  });

  it('updates the document title for each view', async () => {
    const { user } = renderApp();
    expect(document.title).toContain('Phishing Email Analyzer');
    await openSample(user, /Credential phishing/u);
    expect(document.title).toBe('High concern \u2013 Analysis \u2013 PhishLens');
  });

  it('moves focus to the method explanation from the verdict', async () => {
    const { user } = renderApp();
    await openSample(user, /Credential phishing/u);
    await user.click(screen.getByRole('button', { name: 'How this is decided' }));
    await waitFor(() =>
      expect(document.activeElement).toBe(
        screen.getByRole('heading', { name: 'How the assessment is decided' }),
      ),
    );
  });

  it('remembers the selected tab when returning from an attached message', async () => {
    const inner =
      'From: inner@inner.example\r\nSubject: Inner\r\nDate: Tue, 20 Oct 2026 09:00:00 +0000\r\n\r\nbody\r\n';
    const raw = buildEmail({
      headers: ['Subject: Outer', 'Content-Type: multipart/mixed; boundary="q"'],
      body: `--q\r\nContent-Type: text/plain\r\n\r\nsee attached\r\n--q\r\nContent-Type: message/rfc822\r\n\r\n${inner}--q--\r\n`,
    });
    const { user } = renderApp();
    await user.click(screen.getByRole('tab', { name: 'Paste source' }));
    fireEvent.change(screen.getByLabelText('Raw message or headers'), { target: { value: raw } });
    await user.click(screen.getByRole('button', { name: 'Analyze message' }));
    await user.click(await screen.findByRole('tab', { name: /Attachments/u }));
    await user.click(screen.getByRole('button', { name: 'Analyze attached message' }));
    await screen.findByRole('heading', { level: 1, name: 'Inner' });
    await user.click(screen.getByRole('button', { name: 'Back to parent message' }));
    await screen.findByRole('heading', { level: 1, name: 'Outer' });
    expect(screen.getByRole('tab', { name: /Attachments/u }).getAttribute('aria-selected')).toBe(
      'true',
    );
  });
});

describe('results features', () => {
  it('shows every high finding on the overview and links to the full list', async () => {
    const { user } = renderApp();
    await openSample(user, /Credential phishing/u);
    const overview = screen.getByRole('tabpanel');
    expect(within(overview).getByText(/Message contains a password field/u)).toBeTruthy();
    await user.click(within(overview).getByRole('button', { name: 'View all findings' }));
    expect(screen.getByRole('tab', { name: /Findings/u }).getAttribute('aria-selected')).toBe(
      'true',
    );
  });

  it('shows a one-line summary on collapsed findings and can expand them all', async () => {
    const { user } = renderApp();
    await openSample(user, /Credential phishing/u);
    await user.click(screen.getByRole('tab', { name: /Findings/u }));
    const panel = screen.getByRole('tabpanel');
    expect(panel.querySelector('.finding__summary')?.textContent).toContain('resembles PayPal');
    await user.click(within(panel).getByRole('button', { name: 'Expand all' }));
    expect(within(panel).queryAllByRole('button', { expanded: false })).toHaveLength(0);
    await user.click(within(panel).getByRole('button', { name: 'Collapse all' }));
    expect(within(panel).queryAllByRole('button', { expanded: true })).toHaveLength(0);
  });

  it('marks the facts that triggered findings', async () => {
    const { user } = renderApp();
    await openSample(user, /Credential phishing/u);
    expect(screen.getAllByText('differs from the From domain').length).toBeGreaterThan(0);
    expect(screen.getByText(/earliest Received header, forgeable/u)).toBeTruthy();
  });

  it('lists defanged indicators and copies them all', async () => {
    const { user } = renderApp();
    await openSample(user, /Credential phishing/u);
    await user.click(screen.getByRole('tab', { name: /Indicators/u }));
    expect(screen.getByText('service[@]paypa1-account-security[.]example')).toBeTruthy();
    await user.click(screen.getByRole('button', { name: 'Copy all indicators' }));
    const copied = await clipboardText();
    expect(copied).toContain('Sender addresses');
    expect(copied).not.toMatch(/https?:\/\//u);
  });

  it('shows the message content as inert, defanged text', async () => {
    const { user, container } = renderApp();
    await openSample(user, /Credential phishing/u);
    await user.click(screen.getByRole('tab', { name: 'Content' }));
    const view = container.querySelector('.content-view');
    expect(view?.textContent).toContain('Dear customer');
    await user.click(screen.getByRole('button', { name: 'HTML source' }));
    expect(container.querySelector('.content-view')?.textContent).toContain(
      '<form action="hxxps[://]collect',
    );
    expect(container.querySelector('.content-view')?.querySelectorAll('*').length).toBe(1);
  });

  it('links the password form target to its finding on the Links tab', async () => {
    const { user } = renderApp();
    await openSample(user, /Credential phishing/u);
    await user.click(screen.getByRole('tab', { name: /Links/u }));
    expect(screen.getByText(/Referenced by: Message contains a password field/u)).toBeTruthy();
  });

  it('shows what attachment inspection found', async () => {
    const { user } = renderApp();
    await openSample(user, /Attachment lure/u);
    await user.click(screen.getByRole('tab', { name: /Attachments/u }));
    expect(screen.getByText(/Archive contents: 1 entry/u)).toBeTruthy();
    expect(screen.getByText(/HTML scan: 0 forms/u)).toBeTruthy();
  });

  it('copies a ticket summary with recipients redacted', async () => {
    const { user } = renderApp();
    await openSample(user, /Credential phishing/u);
    await user.click(screen.getByRole('button', { name: 'Export report' }));
    await user.click(screen.getByRole('button', { name: 'Copy summary' }));
    await act(() => Promise.resolve());
    const copied = await clipboardText();
    expect(copied).toContain('Assessment: High concern');
    expect(copied).not.toContain('jane.doe');
    await user.click(screen.getByRole('button', { name: 'Close' }));
    expect(document.activeElement).toBe(screen.getByRole('button', { name: 'Export report' }));
  });
});
