import { describe, expect, it } from 'vitest';
import {
  listZipEntries,
  looksLikeHtmlSmuggling,
  pdfKeywordCounts,
  pdfUris,
  shortcutTargets,
} from '../src/core/attachment-content';
import { analyze, buildEmail, finding, ruleIds } from './helpers';

const text = (value: string) => new TextEncoder().encode(value);

interface ZipEntrySpec {
  name: string;
  data?: Uint8Array;
  encrypted?: boolean;
}

/** Builds a minimal stored (uncompressed) ZIP archive, optionally without its central directory. */
function zip(entries: ZipEntrySpec[], { centralDirectory = true } = {}): Uint8Array {
  const chunks: Uint8Array[] = [];
  const central: Uint8Array[] = [];
  let offset = 0;
  for (const entry of entries) {
    const name = text(entry.name);
    const data = entry.data ?? text('content');
    const flags = entry.encrypted ? 1 : 0;
    const local = new DataView(new ArrayBuffer(30));
    local.setUint32(0, 0x04034b50, true);
    local.setUint16(4, 20, true);
    local.setUint16(6, flags, true);
    local.setUint32(18, data.length, true);
    local.setUint32(22, data.length, true);
    local.setUint16(26, name.length, true);
    chunks.push(new Uint8Array(local.buffer), name, data);
    const header = new DataView(new ArrayBuffer(46));
    header.setUint32(0, 0x02014b50, true);
    header.setUint16(8, flags, true);
    header.setUint32(20, data.length, true);
    header.setUint32(24, data.length, true);
    header.setUint16(28, name.length, true);
    header.setUint32(42, offset, true);
    central.push(new Uint8Array(header.buffer), name);
    offset += 30 + name.length + data.length;
  }
  if (centralDirectory) {
    const size = central.reduce((total, chunk) => total + chunk.length, 0);
    const end = new DataView(new ArrayBuffer(22));
    end.setUint32(0, 0x06054b50, true);
    end.setUint16(8, entries.length, true);
    end.setUint16(10, entries.length, true);
    end.setUint32(12, size, true);
    end.setUint32(16, offset, true);
    chunks.push(...central, new Uint8Array(end.buffer));
  }
  const out = new Uint8Array(chunks.reduce((total, chunk) => total + chunk.length, 0));
  let position = 0;
  for (const chunk of chunks) {
    out.set(chunk, position);
    position += chunk.length;
  }
  return out;
}

function withAttachment(filename: string, contentType: string, bytes: Uint8Array): string {
  return buildEmail({
    headers: ['Content-Type: multipart/mixed; boundary="att"'],
    body: [
      '--att',
      'Content-Type: text/plain',
      '',
      'Please see the attachment.',
      '--att',
      `Content-Type: ${contentType}; name="${filename}"`,
      `Content-Disposition: attachment; filename="${filename}"`,
      'Content-Transfer-Encoding: base64',
      '',
      Buffer.from(bytes).toString('base64').replace(/.{76}/gu, '$&\r\n'),
      '--att--',
      '',
    ].join('\r\n'),
  });
}

describe('ZIP directory listing', () => {
  it('lists entries from the central directory without extracting them', () => {
    const { entries, total } = listZipEntries(
      zip([{ name: 'docs/' }, { name: 'docs/readme.txt' }, { name: 'run.exe', encrypted: true }]),
    );
    expect(total).toBe(3);
    expect(entries.map((entry) => [entry.name, entry.encrypted])).toEqual([
      ['docs/', false],
      ['docs/readme.txt', false],
      ['run.exe', true],
    ]);
  });

  it('falls back to local headers when the central directory is missing', () => {
    const { entries } = listZipEntries(
      zip([{ name: 'a.txt' }, { name: 'b.js' }], { centralDirectory: false }),
    );
    expect(entries.map((entry) => entry.name)).toEqual(['a.txt', 'b.js']);
  });

  it('copes with garbage', () => {
    expect(
      listZipEntries(new Uint8Array([0x50, 0x4b, 0x03, 0x04, 0xff])).entries.length,
    ).toBeLessThanOrEqual(1);
    expect(listZipEntries(new Uint8Array(0)).entries).toEqual([]);
  });

  it('flags executables, double extensions and active content inside archives', async () => {
    const result = await analyze(
      withAttachment(
        'documents.zip',
        'application/zip',
        zip([{ name: 'Invoice.pdf.exe' }, { name: 'readme.txt' }, { name: 'login.html' }]),
      ),
    );
    const archive = result.attachments[0]?.contents.archive;
    expect(archive?.entries.map((entry) => entry.risk)).toEqual([
      'double extension (.pdf.exe)',
      null,
      'HTML page (.html)',
    ]);
    expect(finding(result, 'ATTACHMENT_ARCHIVE_EXECUTABLE')?.instances[0]?.message).toContain(
      'Invoice.pdf.exe',
    );
    expect(ruleIds(result)).toContain('ATTACHMENT_ARCHIVE_ACTIVE_CONTENT');
  });

  it('detects encryption from any entry, not just the first', async () => {
    const result = await analyze(
      withAttachment(
        'a.zip',
        'application/zip',
        zip([{ name: 'plain.txt' }, { name: 'secret.pdf', encrypted: true }]),
      ),
    );
    expect(result.attachments[0]?.encryptedArchive).toBe(true);
    expect(ruleIds(result)).toContain('ATTACHMENT_ENCRYPTED_ARCHIVE');
  });

  it('does not flag harmless archives beyond the archive note', async () => {
    const result = await analyze(
      withAttachment('photos.zip', 'application/zip', zip([{ name: 'a.jpg' }, { name: 'b.png' }])),
    );
    expect(result.attachments[0]?.flags.map((flag) => flag.ruleId)).toEqual(['ATTACHMENT_ARCHIVE']);
  });
});

describe('Office macro detection', () => {
  it('finds a VBA project inside an Office Open XML document', async () => {
    const docx = zip([
      { name: '[Content_Types].xml' },
      { name: 'word/document.xml' },
      { name: 'word/vbaProject.bin' },
    ]);
    const result = await analyze(
      withAttachment(
        'report.docx',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        docx,
      ),
    );
    expect(result.attachments[0]?.contents.macros).toBe(true);
    expect(result.attachments[0]?.contents.archive).toBeNull();
    expect(finding(result, 'ATTACHMENT_MACRO_DOCUMENT')?.instances[0]?.message).toContain(
      'VBA macro project',
    );
  });

  it('does not flag an ordinary .docx', async () => {
    const docx = zip([{ name: '[Content_Types].xml' }, { name: 'word/document.xml' }]);
    const result = await analyze(
      withAttachment(
        'report.docx',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        docx,
      ),
    );
    expect(result.attachments[0]?.flags).toEqual([]);
  });

  it('finds a VBA project in a legacy OLE document', async () => {
    const ole = new Uint8Array(2048);
    ole.set([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]);
    ole.set(new Uint8Array([...'_VBA_PROJECT'].flatMap((char) => [char.charCodeAt(0), 0])), 600);
    const result = await analyze(withAttachment('budget.xls', 'application/vnd.ms-excel', ole));
    expect(ruleIds(result)).toContain('ATTACHMENT_MACRO_DOCUMENT');
  });
});

describe('PDF triage', () => {
  it('counts active-content keywords, including #-escaped names', () => {
    expect(
      pdfKeywordCounts(
        '/Type /Catalog /OpenAction 5 0 R /J#61vaScript (app.alert) /JS /Launch /URI (x)',
      ),
    ).toEqual([
      { keyword: 'JavaScript', count: 1 },
      { keyword: 'JS', count: 1 },
      { keyword: 'Launch', count: 1 },
      { keyword: 'OpenAction', count: 1 },
      { keyword: 'URI', count: 1 },
    ]);
  });

  it('extracts literal and hex URI actions', () => {
    const hex = Buffer.from('https://hex.example/a').toString('hex');
    expect(pdfUris(`/URI (https://evil.example/p\\(1\\)) /URI <${hex}>`)).toEqual([
      'https://evil.example/p(1)',
      'https://hex.example/a',
    ]);
  });

  it('reports PDF links and active content in a full analysis', async () => {
    const pdf = text(
      '%PDF-1.7\n1 0 obj << /Type /Catalog /OpenAction 2 0 R >> endobj\n2 0 obj << /S /JavaScript /JS (app.launchURL) >> endobj\n3 0 obj << /S /URI /URI (http://198.51.100.9/pay) >> endobj\n%%EOF',
    );
    const result = await analyze(withAttachment('invoice.pdf', 'application/pdf', pdf));
    expect(ruleIds(result)).toContain('ATTACHMENT_PDF_ACTIVE');
    const link = result.urls.find((url) => url.host === '198.51.100.9');
    expect(link?.sources).toEqual([{ kind: 'pdf-link', attachment: 'invoice.pdf' }]);
    expect(link?.flags.map((flag) => flag.ruleId)).toContain('URL_IP_HOST');
  });

  it('does not flag a plain PDF', async () => {
    const result = await analyze(
      withAttachment(
        'report.pdf',
        'application/pdf',
        text('%PDF-1.7\n<< /Type /Page /Contents 4 0 R >>\n%%EOF'),
      ),
    );
    expect(result.attachments[0]?.flags).toEqual([]);
  });
});

describe('HTML and SVG attachments', () => {
  it('flags login forms and extracts their links with the attachment name', async () => {
    const page =
      '<html><body><form action="https://collect.example/post"><input name="u"><input type="password" name="p"></form><a href="https://www.bank.example.evil.example/">www.bank.example</a></body></html>';
    const result = await analyze(withAttachment('Secure_Message.html', 'text/html', text(page)));
    expect(result.attachments[0]?.contents.html).toMatchObject({ forms: 1, passwordFields: 1 });
    expect(ruleIds(result)).toEqual(
      expect.arrayContaining(['ATTACHMENT_HTML', 'ATTACHMENT_CREDENTIAL_FORM']),
    );
    const action = result.urls.find((url) => url.host === 'collect.example');
    expect(action?.sources[0]).toEqual({ kind: 'html-form', attachment: 'Secure_Message.html' });
  });

  it('detects HTML smuggling', async () => {
    const payload = 'A'.repeat(6000);
    const page = `<html><body><script>var b = atob("${payload}"); var blob = new Blob([b]); var a = document.createElement("a"); a.href = URL.createObjectURL(blob); a.download = "invoice.iso"; a.click();</script></body></html>`;
    expect(looksLikeHtmlSmuggling(page, page)).toBe(true);
    const result = await analyze(withAttachment('voicemail.html', 'text/html', text(page)));
    expect(finding(result, 'ATTACHMENT_HTML_SMUGGLING')?.severity).toBe('high');
  });

  it('does not treat ordinary scripts as smuggling', () => {
    expect(
      looksLikeHtmlSmuggling('document.title = "x"; console.log(atob("aGk="));', '<p>short</p>'),
    ).toBe(false);
  });

  it('extracts script redirects', async () => {
    const page =
      '<html><head><script>window.location.href = "https://redirect.example/landing";</script></head></html>';
    const result = await analyze(withAttachment('open.htm', 'text/html', text(page)));
    expect(result.urls.find((url) => url.host === 'redirect.example')?.sources[0]?.kind).toBe(
      'html-script',
    );
  });
});

describe('shortcuts and text attachments', () => {
  it('extracts Internet Shortcut targets', async () => {
    expect(
      shortcutTargets('[InternetShortcut]\r\nURL=file://198.51.100.4/share/run.exe\r\n'),
    ).toEqual(['file://198.51.100.4/share/run.exe']);
    const result = await analyze(
      withAttachment(
        'Document.url',
        'application/octet-stream',
        text('[InternetShortcut]\r\nURL=https://evil.example/doc\r\n'),
      ),
    );
    expect(ruleIds(result)).toContain('ATTACHMENT_EXECUTABLE');
    expect(result.urls.find((url) => url.host === 'evil.example')?.sources[0]?.kind).toBe(
      'shortcut',
    );
  });

  it('extracts links from calendar invitations, including folded lines', async () => {
    const ics =
      'BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nDESCRIPTION:Join the review at https://meet.phish\r\n .example/room\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n';
    const result = await analyze(withAttachment('invite.ics', 'text/calendar', text(ics)));
    expect(result.urls.map((url) => url.normalized)).toContain('https://meet.phish.example/room');
  });

  it('does not scan attached email messages as text', async () => {
    const result = await analyze(
      withAttachment(
        'fwd.eml',
        'message/rfc822',
        text('From: a@b.example\r\n\r\nhttps://inner.example/'),
      ),
    );
    expect(result.urls.map((url) => url.host)).not.toContain('inner.example');
  });
});
