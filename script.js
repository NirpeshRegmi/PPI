const MAX_EXTRA_NAMES = 3;
let extraNameCount = 0;
let selectedFiles = [];

function addName(btn) {
  if (extraNameCount >= MAX_EXTRA_NAMES) return;

  btn.style.display = 'none';

  const container = document.getElementById('extra-names');
  const newRow = document.createElement('div');
  newRow.className = 'name-row';
  extraNameCount++;

  const showPlus = extraNameCount < MAX_EXTRA_NAMES;

  newRow.innerHTML = `
    <input type="text" placeholder="Full Name" class="text-input" />
    ${showPlus ? `<button type="button" onclick="addName(this)">+</button>` : ''}
  `;

  container.appendChild(newRow);
}

function renderFileList(files) {
  const list = document.getElementById('file-list');
  list.innerHTML = '';
  files.forEach(file => {
    const p = document.createElement('p');
    p.textContent = file.name;
    list.appendChild(p);
  });
}

// File input
document.getElementById('file-input').addEventListener('change', function () {
  selectedFiles = Array.from(this.files);
  renderFileList(selectedFiles);
});

// Drag and drop
const dropZone = document.getElementById('drop-zone');

dropZone.addEventListener('dragover', (e) => {
  e.preventDefault();
  dropZone.classList.add('drag-over');
});

dropZone.addEventListener('dragleave', (e) => {
  if (!dropZone.contains(e.relatedTarget)) {
    dropZone.classList.remove('drag-over');
  }
});

dropZone.addEventListener('drop', (e) => {
  e.preventDefault();
  dropZone.classList.remove('drag-over');
  const allowed = /\.(pdf|docx|xlsx)$/i;
  const files = Array.from(e.dataTransfer.files).filter(f => allowed.test(f.name));
  if (files.length) {
    selectedFiles = files;
    renderFileList(selectedFiles);
  }
});

async function submitForm() {
  if (selectedFiles.length === 0) {
    alert('Please choose at least one file before submitting.');
    return;
  }

  const nameInputs = document.querySelectorAll('.text-input');
  const clientNames = Array.from(nameInputs)
    .map(i => i.value.trim())
    .filter(Boolean);

  document.getElementById('upload-section').style.display = 'none';
  const spinner = document.getElementById('spinner');
  spinner.style.display = 'flex';

  try {
    const formData = new FormData();
    selectedFiles.forEach(file => formData.append('files', file));
    clientNames.forEach(name => formData.append('client_names', name));

    const response = await fetch('/process', {
      method: 'POST',
      body: formData,
    });

    if (!response.ok) throw new Error(`Server error: ${response.status}`);

    const data = await response.json();

    spinner.style.display = 'none';
    renderResults(data.results);

  } catch (err) {
    spinner.style.display = 'none';
    document.getElementById('upload-section').style.display = 'block';
    alert(`Error: ${err.message}`);
  }
}

function renderResults(results) {
  const output = document.getElementById('output');
  const outputText = document.getElementById('output-text');

  let html = '';
  for (const r of results) {
    if (r.error) {
      html += `<p><strong>${r.filename}</strong>: ⚠ ${r.error}</p>`;
      continue;
    }

    const bytes = Uint8Array.from(atob(r.download), c => c.charCodeAt(0));
    const blob = new Blob([bytes], { type: r.mime });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `redacted_${r.filename}`;
    a.click();
    URL.revokeObjectURL(url);

    html += `<p><strong>${r.filename}</strong> — redacted file downloading...</p>`;
  }

  outputText.innerHTML = html || 'No results returned.';
  output.style.display = 'flex';
}

function resetForm() {
  document.getElementById('extra-names').innerHTML = '';
  extraNameCount = 0;
  selectedFiles = [];

  const originalBtn = document.getElementById('more');
  originalBtn.style.display = 'inline-block';

  document.getElementById('file-list').innerHTML = '';
  document.getElementById('file-input').value = '';

  document.querySelectorAll('.text-input').forEach(i => i.value = '');

  document.getElementById('output').style.display = 'none';
  document.getElementById('upload-section').style.display = 'block';
}
