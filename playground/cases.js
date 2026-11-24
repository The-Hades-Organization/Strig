// The examples. Each case is a policy in the three syntaxes and the questions to put to it. The
// questions are data (who, what, where): the page asks the engine and shows what it answers.
// Only conditions the released language already has are used here.

export const CASES = [
  {
    id: 'documents',
    title: 'Documents',
    desc: 'Roles inherit; grants sit on a project.',
    text: {
      blocks: `// Documents of an organization: who may read, edit and manage them.
language blocks

target_kinds = [project, folder, document]
broad_targets = [org]

permission project.view {
  label = "View project"
  targets = [project]
}

// Reading a document follows from viewing its project.
permission document.view {
  targets = [project, folder, document]
  implied_by = [project.view]
}

permission document.edit {
  targets = [project, folder, document]
  depends_on = [document.view]  // never alone
}

role viewer {
}

role editor {
  inherits = [viewer]
}

role manager {
  inherits = [editor]
}

// Ana runs the project.
subject user:ana {
  assign manager {
    scope = project:apollo
  }
}

subject user:bruno {
  assign editor {
    scope = project:apollo
  }
}

grant g-view {
  effect = allow
  subject = role viewer
  permission = project.view
  target = project
  scope = org:acme
}

grant g-edit {
  effect = allow
  subject = role editor
  permission = document.edit
  target = project
  scope = org:acme
}
`,
      rules: `// Documents of an organization: who may read, edit and manage them.
language rules

kinds document, folder, project
broad org

permission project.view on project label "View project"
// Reading a document follows from viewing its project.
permission document.view on project, folder, document implied by project.view
permission document.edit on project, folder, document depends_on document.view
  // never alone

role editor inherits viewer
role manager inherits editor
role viewer

// Ana runs the project.
user:ana has role manager in project:apollo
user:bruno has role editor in project:apollo

g-view: allow role viewer to project.view on project in org:acme
g-edit: allow role editor to document.edit on project in org:acme
`,
      actors: `// Documents of an organization: who may read, edit and manage them.
language actors

role editor inherits viewer

role manager inherits editor

role viewer
  in org:acme
    allow project.view on project as g-view

role editor
  in org:acme
    allow document.edit on project as g-edit

// Ana runs the project.
subject user:ana
  role manager in project:apollo

subject user:bruno
  role editor in project:apollo

catalog
  kinds document, folder, project
  broad org
  project.view on project label "View project"
  // Reading a document follows from viewing its project.
  document.view on project, folder, document implied by project.view
  document.edit on project, folder, document depends_on document.view
    // never alone
`,
    },
    asks: [
      { title: 'Bruno edits a document in Apollo', subject: 'user:bruno', permission: 'document.edit', path: [['org', 'acme'], ['project', 'apollo'], ['folder', 'legal'], ['document', 'spec']] },
      { title: 'Ana edits a document in Apollo', subject: 'user:ana', permission: 'document.edit', path: [['org', 'acme'], ['project', 'apollo'], ['folder', 'legal'], ['document', 'spec']] },
      { title: 'Bruno edits a document in Zephyr', subject: 'user:bruno', permission: 'document.edit', path: [['org', 'acme'], ['project', 'zephyr'], ['folder', 'public'], ['document', 'plan']] },
    ],
  },
  {
    id: 'conditions',
    title: 'Conditions',
    desc: 'Attributes decide; a deny wins.',
    text: {
      blocks: `language blocks

target_kinds = [project, document]
strategy = deny_overrides

permission document.view {
  targets = [project, document]
}

permission document.edit {
  targets = [project, document]
  implied_by = [document.view]
}

role editor {
}

subject user:ana {
  attrs {
    dept = "legal"
    level = 3
    active = true
  }
  principals = [ana]
  assign editor {
  }
}

// Legal may edit what is theirs.
grant g-dept {
  effect = allow
  subject = role editor
  permission = document.edit
  target = document
  when = subject.dept == "legal" and subject.level >= 2
}

grant g-freeze {
  effect = deny
  subject = anyone
  permission = document.edit
  target = project:apollo
  when = subject.active == false
}

grant g-user {
  effect = allow
  subject = user ana
  permission = document.view
  target = document:spec  // one document
}
`,
      rules: `language rules

kinds document, project
strategy deny_overrides

permission document.view on project, document
permission document.edit on project, document implied by document.view

role editor

user:ana has role editor
user:ana has principal ana
user:ana has attr active = true
user:ana has attr dept = "legal"
user:ana has attr level = 3

// Legal may edit what is theirs.
g-dept: allow role editor to document.edit on document when subject.dept == "legal" and subject.level >= 2
g-freeze: deny anyone to document.edit on project:apollo when subject.active == false
g-user: allow user ana to document.view on document:spec
  // one document
`,
      actors: `language actors

role editor
  // Legal may edit what is theirs.
  allow document.edit on document when subject.dept == "legal" and subject.level >= 2 as g-dept

anyone
  deny document.edit on project:apollo when subject.active == false as g-freeze

user ana
  role editor
  principal ana
  attr active = true
  attr dept = "legal"
  attr level = 3
  allow document.view on document:spec as g-user
    // one document

catalog
  kinds document, project
  document.view on project, document
  document.edit on project, document implied by document.view

engine
  strategy deny_overrides
`,
    },
    asks: [
      { title: 'Ana edits the spec', subject: 'user:ana', permission: 'document.edit', path: [['project', 'apollo'], ['document', 'spec']] },
      { title: 'Ana edits while her account is frozen', subject: 'user:ana', attrs: { active: false }, permission: 'document.edit', path: [['project', 'apollo'], ['document', 'spec']] },
      { title: 'Ana reads the spec', subject: 'user:ana', permission: 'document.view', path: [['project', 'apollo'], ['document', 'spec']] },
    ],
  },
  {
    id: 'order',
    title: 'Order decides',
    desc: 'Swap two lines, change the ruling.',
    text: {
      blocks: `language blocks

strategy = first_applicable
target_kinds = [doc]

permission doc.read {
  targets = [doc]
  label = "Read a document"
}

role editor {
}

// A deny wins by coming first.
grant g-deny {
  effect = deny
  subject = role editor
  permission = doc.read
  target = doc
}

grant g-allow {
  effect = allow
  subject = role editor
  permission = doc.read
  target = doc
}
`,
      rules: `language rules

strategy first_applicable
kinds doc

permission doc.read on doc label "Read a document"

role editor

// A deny wins by coming first.
g-deny: deny role editor to doc.read on doc
g-allow: allow role editor to doc.read on doc
`,
      actors: `language actors

role editor
  // A deny wins by coming first.
  deny doc.read on doc as g-deny
  allow doc.read on doc as g-allow

catalog
  kinds doc
  doc.read on doc label "Read a document"

engine
  strategy first_applicable
`,
    },
    asks: [
      { title: 'An editor reads a document', subject: { kind: 'user', id: 'visitor', roles: [{ role: 'editor' }] }, label: 'role editor', permission: 'doc.read', path: [['doc', 'd1']] },
    ],
  },
  {
    id: 'typo',
    title: 'A typo to fix',
    desc: 'An unknown permission, with a hint.',
    flaw: true,
    text: {
      blocks: `language blocks

target_kinds = [doc]

permission doc.read {
  targets = [doc]
}

permission doc.edit {
  targets = [doc]
  depends_on = [doc.read]
}

role editor {
}

subject user:bruno {
  assign editor {
  }
}

grant g-read {
  effect = allow
  subject = role editor
  permission = doc.read
  target = doc
}

// Editors may change documents.
grant g-edit {
  effect = allow
  subject = role editor
  permission = doc.write
  target = doc
}
`,
      rules: `language rules

kinds doc

permission doc.read on doc
permission doc.edit on doc depends_on doc.read

role editor

user:bruno has role editor

g-read: allow role editor to doc.read on doc
// Editors may change documents.
g-edit: allow role editor to doc.write on doc
`,
      actors: `language actors

role editor
  allow doc.read on doc as g-read
  // Editors may change documents.
  allow doc.write on doc as g-edit

subject user:bruno
  role editor

catalog
  kinds doc
  doc.read on doc
  doc.edit on doc depends_on doc.read
`,
    },
    asks: [
      { title: 'Bruno edits a document', subject: 'user:bruno', permission: 'doc.edit', path: [['doc', 'd1']] },
    ],
  },
];
