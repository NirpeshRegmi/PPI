const MAX_EXTRA_NAMES = 3;
let extraNameCount = 0;

function addName(btn) {
  if (extraNameCount >= MAX_EXTRA_NAMES) return;

  // Hide the + button on the last row
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

// Show selected file names under the button
document.getElementById('file-input').addEventListener('change', function () {
  const list = document.getElementById('file-list');
  list.innerHTML = '';
  Array.from(this.files).forEach(file => {
    const p = document.createElement('p');
    p.textContent = file.name;
    list.appendChild(p);
  });
});

function submitForm() {
  const files = document.getElementById('file-input').files;
  if (files.length === 0) {
    alert('Please choose at least one file before submitting.');
    return;
  }

  // Show spinner, hide upload form
  document.getElementById('upload-section').style.display = 'none';
  const spinner = document.getElementById('spinner');
  spinner.style.display = 'flex';

  // Simulate upload delay (replace with real API call later)
  setTimeout(() => {
    spinner.style.display = 'none';
    const output = document.getElementById('output');
    output.style.display = 'flex';
    document.getElementById('output-text').textContent =
      `${files.length} document${files.length > 1 ? 's' : ''} uploaded successfully.`;
  }, 2500);
}

function resetForm() {
  // Reset extra names
  document.getElementById('extra-names').innerHTML = '';
  extraNameCount = 0;

  // Restore + button on original last name row
  const originalBtn = document.getElementById('more');
  originalBtn.style.display = 'inline-block';

  // Clear file list
  document.getElementById('file-list').innerHTML = '';
  document.getElementById('file-input').value = '';

  // Clear all text inputs
  document.querySelectorAll('.text-input').forEach(i => i.value = '');

  // Show upload section again
  document.getElementById('output').style.display = 'none';
  document.getElementById('upload-section').style.display = 'block';
}