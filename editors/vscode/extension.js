'use strict';

const path = require('path');
const { spawnSync } = require('child_process');
const vscode = require('vscode');
const { LanguageClient, TransportKind } = require('vscode-languageclient/node');

const INSTALL = 'cargo install --git https://github.com/The-Hades-Organization/Strig strig-lsp --locked';
const INSTALL_CLI = 'cargo install strig-cli --locked';

let client;

function setting(name) {
  return vscode.workspace.getConfiguration('strig').get(name);
}

/** True when `binary` can be started: a path that exists, or a name that PATH resolves. */
function runnable(binary) {
  const probe = spawnSync(binary, ['--help'], { stdio: 'ignore', timeout: 5000 });
  return !(probe.error && probe.error.code === 'ENOENT');
}

async function explainMissing(binary, install, what) {
  const copy = 'Copy install command';
  const choice = await vscode.window.showErrorMessage(
    `Strig: cannot start \`${binary}\`. Install ${what} with \`${install}\`, or set the path in the strig settings.`,
    copy,
    'Open settings',
  );
  if (choice === copy) {
    await vscode.env.clipboard.writeText(install);
  } else if (choice === 'Open settings') {
    await vscode.commands.executeCommand('workbench.action.openSettings', 'strig');
  }
}

async function startServer() {
  const command = setting('server.path') || 'strig-lsp';
  if (!runnable(command)) {
    await explainMissing(command, INSTALL, 'the language server');
    return;
  }
  client = new LanguageClient(
    'strig',
    'Strig',
    { command, transport: TransportKind.stdio },
    {
      documentSelector: [{ language: 'strig' }, { pattern: '**/*.strig-test.json' }],
    },
  );
  await client.start();
}

async function stopServer() {
  if (client) {
    const stopping = client;
    client = undefined;
    await stopping.stop();
  }
}

async function runPolicyTests() {
  const editor = vscode.window.activeTextEditor;
  const folder = editor
    ? path.dirname(editor.document.uri.fsPath)
    : vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders[0].uri.fsPath;
  if (!folder) {
    vscode.window.showWarningMessage('Strig: open a policy file or a folder first.');
    return;
  }
  const cli = setting('cli.path') || 'strig';
  if (!runnable(cli)) {
    await explainMissing(cli, INSTALL_CLI, 'the `strig` command');
    return;
  }
  await vscode.workspace.saveAll(false);
  const terminal = vscode.window.createTerminal({ name: 'Strig tests', cwd: folder });
  terminal.show();
  terminal.sendText(`${JSON.stringify(cli)} test .`);
}

async function activate(context) {
  context.subscriptions.push(
    vscode.commands.registerCommand('strig.runPolicyTests', runPolicyTests),
    vscode.commands.registerCommand('strig.restartServer', async () => {
      await stopServer();
      await startServer();
    }),
    vscode.workspace.onDidChangeConfiguration(async (event) => {
      if (event.affectsConfiguration('strig.server.path')) {
        await stopServer();
        await startServer();
      }
    }),
  );
  await startServer();
}

async function deactivate() {
  await stopServer();
}

module.exports = { activate, deactivate };
