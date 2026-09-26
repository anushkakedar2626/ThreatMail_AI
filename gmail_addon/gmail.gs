/**
 * ThreatMail AI — Gmail Workspace Add-on
 * Final demo-mode contextual security panel.
 *
 * IMPORTANT:
 * This version intentionally uses four controlled demo fixtures.
 * It does NOT call the backend.
 *
 * The Gmail Add-on is therefore safe to demo locally while the
 * full ThreatMail investigation website remains the destination
 * for "View Investigation".
 */

// ============================================================
// CONFIGURATION
// ============================================================

const THREATMAIL_WEB_URL = 'https://threat-mail-ai.vercel.app';

const INVESTIGATION_QUERY_PARAM = 'caseId';


// ============================================================
// FOUR FINAL DEMO EMAILS
// ============================================================

const DEMO_EMAILS = {

  // ----------------------------------------------------------
  // EMAIL 1 — SAFE
  // ----------------------------------------------------------

  'Scheduled Maintenance Notice': {
    caseId: 'TM-DEMO-001',
    classification: 'LOW',
    score: 0,
    sender: 'IT Operations',
    action: 'LEFT IN INBOX',

    spf: 'PASS',
    dkim: 'PASS',
    dmarc: 'PASS',

    ip: '192.0.2.60',
    location: 'Pune, Maharashtra, India',

    summary:
      'Routine internal maintenance notification. No suspicious indicators were detected.',

    evidence: [
      'Routine maintenance notification',
      'No suspicious authentication indicators',
      'No quarantine action required'
    ]
  },


  // ----------------------------------------------------------
  // EMAIL 2 — SUSPICIOUS
  // ----------------------------------------------------------

  'Invoice Review Reminder': {
    caseId: 'TM-DEMO-002',
    classification: 'SUSPICIOUS',
    score: 30,
    sender: 'Accounts Payable',
    action: 'LEFT IN INBOX',

    spf: 'PASS',
    dkim: 'PASS',
    dmarc: 'PASS',

    ip: '192.0.2.60',
    location: 'Pune, Maharashtra, India',

    summary:
      'The message contains a controlled suspicious invoice-review URL and urgency language.',

    evidence: [
      'Controlled suspicious invoice URL',
      'Payment-review request',
      'Urgency / processing-delay language'
    ]
  },


  // ----------------------------------------------------------
  // EMAIL 3 — HIGH
  // ----------------------------------------------------------

  'Confidential: urgent gift card purchase': {
    caseId: 'TM-DEMO-003',
    classification: 'HIGH',
    score: 62,
    sender: 'Anushka Kedar',
    action: 'QUARANTINED FROM INBOX',

    // Personal Gmail demo:
    // Authentication information is not treated as a reliable
    // failure signal. Display NOT FOUND in the Add-on.
    spf: 'NOT_FOUND',
    dkim: 'NOT_FOUND',
    dmarc: 'NOT_FOUND',

    ip: '192.0.2.60',
    location: 'Pune, Maharashtra, India',

    summary:
      'Executive-impersonation pattern requesting urgent gift-card purchases.',

    evidence: [
      'Executive impersonation',
      'Urgent gift-card request',
      'Reply / communication anomaly'
    ]
  },


  // ----------------------------------------------------------
  // EMAIL 4 — CRITICAL
  // ----------------------------------------------------------

  'Urgent: Verify your account within 24 hours': {
    caseId: 'TM-DEMO-004',
    classification: 'CRITICAL',
    score: 80,
    sender: 'Anushka Kedar',
    action: 'QUARANTINED FROM INBOX',

    // Personal Gmail demo:
    // Authentication is displayed as PASS.
    spf: 'PASS',
    dkim: 'PASS',
    dmarc: 'PASS',

    ip: '192.0.2.60',
    location: 'Pune, Maharashtra, India',

    summary:
      'Credential-theft phishing message using account-verification urgency.',

    evidence: [
      'Credential-theft phishing pattern',
      'Account verification request',
      'Controlled phishing URL',
      'Urgency / suspension language'
    ]
  }

};


// ============================================================
// GMAIL CONTEXTUAL TRIGGER
// ============================================================

function onGmailMessage(e) {

  if (!e || !e.gmail || !e.gmail.messageId) {
    return createErrorCard('No Gmail message was detected.');
  }

  const accessToken = e.gmail.accessToken;

  GmailApp.setCurrentMessageAccessToken(accessToken);

  const message = GmailApp.getMessageById(e.gmail.messageId);

  if (!message) {
    return createErrorCard('Unable to read this Gmail message.');
  }

  const subject = message.getSubject() || '(No subject)';
  const sender = message.getFrom() || '(Unknown sender)';

  return createSecurityCard(subject, sender);
}


// ============================================================
// MAIN SECURITY CARD
// ============================================================

function createSecurityCard(subject, sender) {

  const demo = getDemoBySubject(subject);

  if (!demo) {
    return createUnknownMessageCard(subject, sender);
  }

  const header = CardService.newCardHeader()
    .setTitle('ThreatMail AI')
    .setSubtitle('Email Forensic Intelligence');


  // ----------------------------------------------------------
  // CURRENT EMAIL
  // ----------------------------------------------------------

  const emailSection = CardService.newCardSection()
    .setHeader('CURRENT EMAIL')
    .addWidget(
      CardService.newDecoratedText()
        .setTopLabel('Subject')
        .setText(truncateText(subject, 160))
    )
    .addWidget(
      CardService.newDecoratedText()
        .setTopLabel('Sender')
        .setText(truncateText(sender, 160))
    );


  // ----------------------------------------------------------
  // RISK HERO
  // ----------------------------------------------------------

  const riskSection = CardService.newCardSection()
    .setHeader('SECURITY ANALYSIS');

  riskSection.addWidget(
    createRiskGraphic(demo.score)
  );

  riskSection.addWidget(
    CardService.newDecoratedText()
      .setTopLabel('Classification')
      .setText(demo.classification)
  );

  riskSection.addWidget(
    CardService.newDecoratedText()
      .setTopLabel('Risk Score')
      .setText(demo.score + ' / 100')
  );

  riskSection.addWidget(
    CardService.newDecoratedText()
      .setTopLabel('Gmail Action')
      .setText(demo.action)
  );


  // ----------------------------------------------------------
  // AUTHENTICATION
  // ----------------------------------------------------------

  const authSection = CardService.newCardSection()
    .setHeader('AUTHENTICATION');

  authSection
    .addWidget(createAuthRow('SPF', demo.spf))
    .addWidget(createAuthRow('DKIM', demo.dkim))
    .addWidget(createAuthRow('DMARC', demo.dmarc));


  // ----------------------------------------------------------
  // INFRASTRUCTURE
  // ----------------------------------------------------------

  const infrastructureSection = CardService.newCardSection()
    .setHeader('INFRASTRUCTURE');

  infrastructureSection
    .addWidget(
      CardService.newDecoratedText()
        .setTopLabel('IP')
        .setText(demo.ip)
    )
    .addWidget(
      CardService.newDecoratedText()
        .setTopLabel('Location')
        .setText(demo.location)
    )
    .addWidget(
      CardService.newDecoratedText()
        .setTopLabel('Data Source')
        .setText('SYNTHETIC DEMO DATA')
    )
    .addWidget(
      CardService.newTextParagraph()
        .setText(
          'Controlled synthetic demonstration data. ' +
          'This does not represent the actual sender location.'
        )
    );


  // ----------------------------------------------------------
  // EVIDENCE
  // ----------------------------------------------------------

  const evidenceSection = CardService.newCardSection()
    .setHeader('KEY EVIDENCE');

  evidenceSection.addWidget(
    CardService.newTextParagraph()
      .setText(
        '<b>' +
        escapeHtml(demo.summary) +
        '</b>'
      )
  );

  demo.evidence.forEach(function(item) {

    evidenceSection.addWidget(
      CardService.newDecoratedText()
        .setText('• ' + escapeHtml(item))
    );

  });


  // ----------------------------------------------------------
  // INVESTIGATION BUTTON
  // ----------------------------------------------------------

  const investigationUrl =
    buildInvestigationUrl(demo.caseId);

  const investigationSection =
    CardService.newCardSection()
      .setHeader('INVESTIGATION');

  investigationSection.addWidget(
    CardService.newTextButton()
      .setText('VIEW INVESTIGATION')
      .setTextButtonStyle(
        CardService.TextButtonStyle.FILLED
      )
      .setOpenLink(
        CardService.newOpenLink()
          .setUrl(investigationUrl)
          .setOpenAs(
            CardService.OpenAs.FULL_SIZE
          )
          .setOnClose(
            CardService.OnClose.RELOAD
          )
      )
  );

  investigationSection.addWidget(
    CardService.newDecoratedText()
      .setTopLabel('Case ID')
      .setText(demo.caseId)
  );


  // ----------------------------------------------------------
  // BUILD CARD
  // ----------------------------------------------------------

  return CardService.newCardBuilder()
    .setHeader(header)
    .addSection(emailSection)
    .addSection(riskSection)
    .addSection(authSection)
    .addSection(infrastructureSection)
    .addSection(evidenceSection)
    .addSection(investigationSection)
    .build();
}


// ============================================================
// RISK GRAPHIC
// ============================================================

function createRiskGraphic(score) {

  /*
   * CardService does not support arbitrary HTML/CSS.
   *
   * This creates a compact visual "risk meter" using Unicode
   * circles. The large percentage remains the primary signal.
   */

  const filled = Math.round(score / 10);
  const empty = 10 - filled;

  const meter =
    '●'.repeat(filled) +
    '○'.repeat(empty);

  return CardService.newTextParagraph()
    .setText(
      '<b>RISK LEVEL</b><br>' +
      '<font size="6">' + score + '%</font><br>' +
      '<font size="2">' + meter + '</font>'
    );
}


// ============================================================
// AUTHENTICATION ROW
// ============================================================

function createAuthRow(name, status) {

  const normalized =
    String(status || '')
      .trim()
      .toUpperCase();

  let displayStatus;

  if (
    normalized === 'PASS' ||
    normalized === 'PASSED'
  ) {

    displayStatus = '✓ PASS';

  } else if (
    normalized === 'NOT_FOUND' ||
    normalized === 'NOT FOUND' ||
    normalized === 'UNKNOWN' ||
    normalized === ''
  ) {

    displayStatus = '— NOT FOUND';

  } else {

    // For the personal Gmail demo, do not display FAIL.
    // If authentication cannot be reliably established,
    // present it as unavailable instead.
    displayStatus = '— NOT FOUND';
  }

  return CardService.newDecoratedText()
    .setTopLabel(name)
    .setText(displayStatus);
}


// ============================================================
// DEMO MATCHING
// ============================================================

function getDemoBySubject(subject) {

  const normalized = normalizeSubject(subject);

  const keys = Object.keys(DEMO_EMAILS);

  for (let i = 0; i < keys.length; i++) {

    const key = keys[i];

    if (normalizeSubject(key) === normalized) {
      return DEMO_EMAILS[key];
    }

  }

  return null;
}


function normalizeSubject(subject) {

  return String(subject || '')
    .trim()
    .toLowerCase();
}


// ============================================================
// INVESTIGATION URL
// ============================================================

function buildInvestigationUrl(caseId) {

  return THREATMAIL_WEB_URL +
    '?' +
    encodeURIComponent(INVESTIGATION_QUERY_PARAM) +
    '=' +
    encodeURIComponent(caseId);
}


// ============================================================
// UNKNOWN EMAIL
// ============================================================

function createUnknownMessageCard(subject, sender) {

  const header = CardService.newCardHeader()
    .setTitle('ThreatMail AI')
    .setSubtitle('Email Forensic Intelligence');

  const section = CardService.newCardSection()
    .setHeader('CURRENT EMAIL')
    .addWidget(
      CardService.newDecoratedText()
        .setTopLabel('Subject')
        .setText(truncateText(subject, 160))
    )
    .addWidget(
      CardService.newDecoratedText()
        .setTopLabel('Sender')
        .setText(truncateText(sender, 160))
    )
    .addWidget(
      CardService.newTextParagraph()
        .setText(
          'This message is not one of the four controlled ' +
          'ThreatMail AI demonstration fixtures.'
        )
    )
    .addWidget(
      CardService.newDecoratedText()
        .setTopLabel('Status')
        .setText('DEMO FIXTURE NOT MATCHED')
    );

  return CardService.newCardBuilder()
    .setHeader(header)
    .addSection(section)
    .build();
}


// ============================================================
// ERROR CARD
// ============================================================

function createErrorCard(message) {

  return CardService.newCardBuilder()
    .setHeader(
      CardService.newCardHeader()
        .setTitle('ThreatMail AI')
        .setSubtitle('Gmail Security Add-on')
    )
    .addSection(
      CardService.newCardSection()
        .addWidget(
          CardService.newTextParagraph()
            .setText(escapeHtml(message))
        )
    )
    .build();
}


// ============================================================
// HOMEPAGE
// ============================================================

function onHomepage(e) {

  const header = CardService.newCardHeader()
    .setTitle('ThreatMail AI')
    .setSubtitle('Email Forensic Intelligence');

  const section = CardService.newCardSection()
    .setHeader('SOC COMMAND CENTER')
    .addWidget(
      CardService.newTextParagraph()
        .setText(
          '<b>ThreatMail AI</b><br>' +
          'AI-assisted email forensic intelligence for Gmail.'
        )
    )
    .addWidget(
      CardService.newDecoratedText()
        .setTopLabel('Demo Environment')
        .setText('4 CONTROLLED EMAIL FIXTURES')
    )
    .addWidget(
      CardService.newDecoratedText()
        .setTopLabel('Detection Coverage')
        .setText('LOW • SUSPICIOUS • HIGH • CRITICAL')
    )
    .addWidget(
      CardService.newTextParagraph()
        .setText(
          'Open one of the four demo emails to inspect its ' +
          'risk profile and launch the full investigation.'
        )
    );

  return [
    CardService.newCardBuilder()
      .setHeader(header)
      .addSection(section)
      .build()
  ];
}


// ============================================================
// UTILITIES
// ============================================================

function truncateText(text, maxLength) {

  if (!text) {
    return '(Not available)';
  }

  return text.length > maxLength
    ? text.substring(0, maxLength - 3) + '...'
    : text;
}


function escapeHtml(text) {

  return String(text || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function monitorThreatMailDemo() {
  const labelName = 'ThreatMail AI';
  let label = GmailApp.getUserLabelByName(labelName);

  if (!label) {
    label = GmailApp.createLabel(labelName);
  }

  const subjects = [
    'Urgent: Verify your account within 24 hours',
    'Confidential: urgent gift card purchase'
  ];

  let result = '';

  subjects.forEach(function(subject) {
    const threads = GmailApp.search(
      'in:inbox subject:"' + subject + '"'
    );

    result += subject + ' → found ' + threads.length + ' thread(s)\n';

    threads.forEach(function(thread) {
      thread.addLabel(label);
      thread.moveToArchive();
      result += '  → LABELLED + ARCHIVED\n';
    });
  });

  throw new Error(result);
}